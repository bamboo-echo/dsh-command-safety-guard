/**
 * 外部语料跑分器：把 AI 生成的命令语料喂给插件的 tools/pre-execute 监听器。
 * 只驱动监听器，不执行任何命令。
 * 运行：node run-corpus.mjs <文件1> <文件2> ...
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const MODE = process.env.CORPUS_MODE === 'ai' ? 'ai' : 'local'
const HERE = path.dirname(fileURLToPath(import.meta.url))
const BUNDLE = path.join(HERE, '..', 'command-safety-guard', 'index.js')
const mod = await import(pathToFileURL(BUNDLE).href)

// 走插件真实的 Config schema 做校验 + 补默认值，与宿主的激活路径一致。
// 不再需要 Schema 全局桩：插件自己从 node_modules 解析 schemastery。
const cfgOf = (c) => mod.Config(c)

const captured = {}
const fakeCtx = {
  logger: { info() {}, warn() {}, error() {} },
  on(event, listener) { captured.listener = listener; return () => {} },
  effect(fn) { const d = fn(); return () => d && d() },
}
mod.apply(fakeCtx, cfgOf(MODE === 'ai'
  ? {
      mode: 'ai', action: 'deny',
      aiBaseUrl: 'http://127.0.0.1:1234/v1', aiApiKey: '', aiModel: 'local-model',
      aiScope: 'longtail', aiStructured: 'json_schema', aiNoThink: 'auto',
      aiNoThinkMaxLen: 100, aiTimeoutMs: 30000, aiFailOpen: true,
    }
  : { mode: 'local', action: 'deny' }))

const tool = 'mcp__fauxnix__bash'

async function runFile(file) {
  let raw = readFileSync(file, 'utf8').trim()
  // 容错：剥掉 markdown 代码围栏
  raw = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/,'')
  const arr = JSON.parse(raw)
  if (!Array.isArray(arr)) throw new Error('不是 JSON 数组')

  const stat = {
    file, total: arr.length, agree: 0,
    falsePositive: [],   // 插件拦 / 语料说放  → 我的误拦，必须修
    miss: [],            // 插件放 / 语料说拦  → 我的盲区 或 语料标错
    gray: [],            // confidence=low 的分歧（无论方向）
  }
  const mech = {}
  const t0 = Date.now()

  for (const item of arr) {
    const cmd = typeof item === 'string' ? item : item.cmd
    if (typeof cmd !== 'string' || !cmd.trim()) continue
    const want = (typeof item === 'object' && item.verdict) || 'block'
    const conf = (item && item.confidence) || 'high'
    const why = (item && item.why) || ''
    const mechanism = (item && item.mechanism) || 'unknown'
    mech[mechanism] = (mech[mechanism] || 0) + 1

    let got = 'allow'
    try {
      const res = await captured.listener({ name: tool, arguments: { command: cmd } }, async () => ({ kind: 'allow' }))
      got = res && (res.kind === 'deny' || res.kind === 'ask') ? 'block' : 'allow'
    } catch (e) {
      got = 'error'
    }

    if (got === want) { stat.agree++; continue }
    const rec = { cmd, want, got, conf, why, mechanism, reason: '' }
    if (got === 'block' && want === 'allow') {
      stat.falsePositive.push(rec)
      rec.reason = '误拦'
    } else if (got === 'allow' && want === 'block') {
      stat.miss.push(rec)
      rec.reason = '漏拦'
    } else {
      rec.reason = `异常(${got})`
      stat.miss.push(rec)
    }
    if (conf === 'low') stat.gray.push(rec)
  }
  stat.ms = Date.now() - t0
  stat.mech = mech
  return stat
}

/* ---------------- 报告 ---------------- */
const pad = (s, n) => String(s).padEnd(n)
function report(s) {
  const rate = ((s.agree / s.total) * 100).toFixed(1)
  console.log(`\n${'='.repeat(72)}`)
  console.log(`📄 ${s.file}`)
  console.log(`   共 ${s.total} 条 | 一致 ${s.agree} (${rate}%) | 耗时 ${(s.ms / 1000).toFixed(1)}s`)
  console.log(`   误拦(插件拦/语料放): ${s.falsePositive.length}  |  漏拦(插件放/语料拦): ${s.miss.length}  |  其中灰区(confidence=low): ${s.gray.length}`)
  const top = Object.entries(s.mech).sort((a, b) => b[1] - a[1]).slice(0, 12)
  console.log(`   mechanism Top: ${top.map(([k, v]) => `${k}×${v}`).join('  ')}`)

  if (s.falsePositive.length) {
    console.log(`\n   🔴 误拦清单（${s.falsePositive.length} 条，这些必须修）`)
    const byMech = {}
    for (const r of s.falsePositive) (byMech[r.mechanism] ||= []).push(r)
    for (const [m, list] of Object.entries(byMech)) {
      console.log(`   ── ${m} (${list.length})`)
      for (const r of list.slice(0, 8)) console.log(`      ${r.cmd.length > 96 ? r.cmd.slice(0, 96) + '…' : r.cmd}`)
      if (list.length > 8) console.log(`      …另 ${list.length - 8} 条`)
    }
  }

  if (s.miss.length) {
    console.log(`\n   🟡 漏拦清单（${s.miss.length} 条，可能是盲区也可能是语料标错）`)
    const byMech = {}
    for (const r of s.miss) (byMech[r.mechanism] ||= []).push(r)
    for (const [m, list] of Object.entries(byMech)) {
      console.log(`   ── ${m} (${list.length})`)
      for (const r of list.slice(0, 6)) {
        console.log(`      [${r.conf}] ${r.cmd.length > 92 ? r.cmd.slice(0, 92) + '…' : r.cmd}`)
        console.log(`           语料理由: ${r.why}`)
      }
      if (list.length > 6) console.log(`      …另 ${list.length - 6} 条`)
    }
  }
}

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('用法: node run-corpus.mjs <语料文件> ...')
  process.exit(2)
}
const stats = await Promise.all(files.map((f) => runFile(f)))
for (const s of stats) report(s)

const fp = stats.reduce((a, s) => a + s.falsePositive.length, 0)
const miss = stats.reduce((a, s) => a + s.miss.length, 0)
const total = stats.reduce((a, s) => a + s.total, 0)
const agree = stats.reduce((a, s) => a + s.agree, 0)
console.log(`\n${'='.repeat(72)}`)
console.log(`🏁 总计 ${total} 条 | 一致 ${agree} (${((agree / total) * 100).toFixed(1)}%) | 误拦 ${fp} | 漏拦 ${miss}`)
process.exit(0)

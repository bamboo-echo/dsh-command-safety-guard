/**
 * command-safety-guard 离线测试台（不属于插件分发包，仅开发验证用）
 * 运行：node test-command-safety-guard.mjs
 */
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const BUNDLE = path.join(HERE, '..', 'command-safety-guard', 'index.js')
const mod = await import(pathToFileURL(BUNDLE).href)

// 走插件真实的 Config schema 做校验 + 补默认值，与宿主的激活路径一致。
// 不再需要 Schema 全局桩：插件自己从 node_modules 解析 schemastery。
const cfgOf = (c) => mod.Config(c)

const logs = []
const fakeCtx = {
  logger: {
    info: (m) => logs.push(['info', m]),
    warn: (m) => logs.push(['warn', m]),
    error: (m) => logs.push(['error', m]),
  },
  on(event, listener) {
    captured.event = event
    captured.listener = listener
    return () => {}
  },
  effect(fn) {
    const dispose = fn()
    return () => dispose && dispose()
  },
}
const captured = {}

mod.apply(fakeCtx, cfgOf({ mode: 'local', action: 'deny' }))
const listener = captured.listener
if (!listener) throw new Error('未能捕获 tools/pre-execute 监听器')

const run = async (command, { tool = 'mcp__fauxnix__bash', args, config } = {}) => {
  if (config) {
    captured.listener = null
    mod.apply(fakeCtx, cfgOf(config))
  }
  const exec = { name: tool, arguments: args === undefined ? { command } : args }
  return captured.listener(exec, async () => ({ kind: 'allow' }))
}

/* ---- 用例 ---- */
const B64 = Buffer.from('Remove-Item -Recurse -Force C:\\Users\\alice', 'utf16le').toString('base64')

const BLOCK = [
  // 系统盘根 / 盘根
  ['rm -rf /', 'bash'],
  ['rm -rf / --no-preserve-root', 'bash'],
  ['rm -rf /*', 'bash'],
  ['rm -rf /c', 'bash'],
  ['rm -rf C:\\', 'bash'],
  ['rm -rf C:', 'bash'],
  ['rm -rf "C:/"', 'bash'],
  ['rd /s /q C:\\', 'bash'],
  ['del /f /s /q C:\\*', 'bash'],
  ['rm -rf //', 'bash'],
  // 用户主目录
  ['rm -rf ~', 'bash'],
  ['rm -rf ~/', 'bash'],
  ['rm -rf $HOME', 'bash'],
  ['rm -rf %USERPROFILE%', 'bash'],
  ['rm -rf /c/Users/alice', 'bash'],
  ['rm -rf /c/Users/alice/', 'bash'],
  ['rm -rf /Users/alice', 'bash'],
  ['rm -rf /home', 'bash'],
  ['rm -rf C:\\Users', 'bash'],
  // 桌面 / 文档
  ['rm -rf ~/Desktop', 'bash'],
  ['rm -rf ~/Desktop/*', 'bash'],
  ['rm -rf /c/Users/alice/Desktop', 'bash'],
  ["rm -rf '/c/Users/alice/桌面'", 'bash'],
  ['rm -rf /c/Users/alice/Documents', 'bash'],
  ['rm -rf /home/alice/Desktop', 'bash'],
  ['rm -rf $env:USERPROFILE\\Desktop', 'bash'],
  ['Remove-Item -Recurse -Force $env:USERPROFILE', 'pwsh'],
  ['Remove-Item -Recurse -Force C:\\Users\\alice\\Desktop', 'pwsh'],
  ['Remove-Item -LiteralPath $HOME -Recurse -Force', 'pwsh'],
  ['rm -rf "$HOME/Desktop"', 'bash'],
  // 系统关键目录
  ['rm -rf C:\\Windows', 'bash'],
  ['rm -rf C:\\Windows\\System32', 'bash'],
  ['rm -rf /etc', 'bash'],
  ['rm -rf /usr', 'bash'],
  ['rm -rf "C:\\Program Files"', 'bash'],
  ['rm -rf C:\\ProgramData', 'bash'],
  // 格式化 / 分区销毁
  ['format C: /q', 'bash'],
  ['mkfs.ext4 /dev/sda1', 'bash'],
  ['dd if=/dev/zero of=/dev/sda bs=1M', 'bash'],
  ['wipefs -a /dev/sdb1', 'bash'],
  ['diskpart /s clean.txt', 'bash'],
  ['shred -n 1 /dev/sdc', 'bash'],
  ['vssadmin delete shadows /all', 'bash'],
  // 嵌套与组合
  ['sudo rm -rf /', 'bash'],
  ['bash -c "rm -rf /"', 'bash'],
  ["bash -c 'rm -rf ~'", 'bash'],
  ['pwsh -Command "Remove-Item -Recurse C:\\Users\\alice"', 'bash'],
  [`powershell -EncodedCommand ${B64}`, 'bash'],
  ['cd / && rm -rf *', 'bash'],
  ['cd ~ && rm -rf *', 'bash'],
  ['cd C:\\ && rd /s /q .', 'bash'],
  ['cd /c/Users/alice/Desktop && rm -rf *', 'bash'],
  ['rm -rf /mnt/c', 'bash'],
  ['rm -rf /mnt/c/Users/alice', 'bash'],
  ['find / -maxdepth 1 -delete', 'bash'],
  ['find /home -delete', 'bash'],
  ['git clean -fdx /', 'bash'],
  // 开关形态与大小写变体
  ['rm -fr /', 'bash'],
  ['rm -R -f /', 'bash'],
  ['rm --recursive --force /', 'bash'],
  ['RD /S /Q C:\\Windows', 'bash'],
  ["rm -rf 'C:\\Program Files (x86)'", 'bash'],
  ['Remove-Item -Recurse C:\\', 'pwsh'],
  ['rm -rf /c/Users', 'bash'],
  ['rm -rf ~/*', 'bash'],
  ['rm -rf /root', 'bash'],
  ['rm -rf /home/user', 'bash'],
  // 包装器（sudo / env / xargs）之后必须照样识别
  ['sudo rm -rf /', 'bash'],
  ['sudo -E rm -rf ~', 'bash'],
  ['sudo mkfs.ext4 /dev/sda', 'bash'],
  ["rm -rf '/c/Program Files (x86)'", 'bash'],
  // .. 回溯绕过：绝对路径必须词法解析后收敛到根 / 主目录
  ['rm -rf /c/Users/alice/AppData/Local/Temp/../../..', 'bash'],
  ['rm -rf /c/Users/alice/AppData/Local/Temp/../../../../..', 'bash'],
  ['rm -rf C:\\Users\\alice\\AppData\\Local\\Temp\\..\\..\\..', 'bash'],
  ['rm -rf /tmp/../..', 'bash'],
  ['rm -rf "$HOME/AppData/Local/Temp/../../.."', 'bash'],
  ['rm -rf /c/Users/alice/Desktop/../..', 'bash'],
  ['rm -rf /c/Users/alice/./Desktop/../Documents', 'bash'],
  ['rm -rf /c/Users/alice/AppData/Local/Temp/*/../../../..', 'bash'],
]

const ALLOW = [
  ['rm -rf node_modules', 'bash'],
  ['rm -rf dist build', 'bash'],
  ['rm -rf ./dist', 'bash'],
  ['rm -rf C:\\Users\\alice\\project\\dist', 'bash'],
  ['rm -rf /c/Users/alice/projects/myapp/node_modules', 'bash'],
  ['rm -rf ~/projects/myapp/dist', 'bash'],
  ['rm -rf /tmp/cache/*', 'bash'],
  ['rm -rf C:\\Users\\alice\\AppData\\Local\\Temp\\*', 'bash'],
  ['rm -rf .next', 'bash'],
  ['rm file.txt', 'bash'],
  ['rm -f file.txt', 'bash'],
  ['rmdir empty-dir', 'bash'],
  ['del /q build\\output.txt', 'bash'],
  ['rm -rf C:\\Windows\\Temp', 'bash'],
  ['rm -rf /etc/nginx', 'bash'],
  ['rm -rf /var/log/nginx/*', 'bash'],
  ['git clean -fdx', 'bash'],
  ['git clean -fd', 'bash'],
  ["find . -name '*.log' -delete", 'bash'],
  ['find build -type f -mtime +7 -delete', 'bash'],
  ['find . -type d -name node_modules -exec rm -rf {} +', 'bash'],
  ['rm -rf *', 'bash'],
  ['rm -rf .', 'bash'],
  // .. 回溯后的深层路径仍是日常路径，必须放行
  ['rm -rf /tmp/foo/../bar', 'bash'],
  ['rm -rf ./dist/../build', 'bash'],
  ['rm -rf "$HOME/AppData/Local/Temp/../.."', 'bash'],
  ['rm -rf /c/Users/alice/AppData/Local/Temp/*/../../..', 'bash'],
  ['rm -rf /c/Users/alice/AppData/Local/Temp/csg-test/Users/alice', 'bash'],
  ['cd /tmp && rm -rf *', 'bash'],
  ['cd ~/projects && rm -rf *', 'bash'],
  ['npm run clean', 'bash'],
  ['rm -rf C:\\Users\\alice\\project', 'bash'],
  ['rm -rf /c/Users/alice/Desktop/old-project', 'bash'],
  ['rm -rf /home/alice/projects/app', 'bash'],
  ['echo hello', 'bash'],
  ['rm -rf ./build/../build', 'bash'],
  ['rm -rf "$HOME/projects/app/dist"', 'bash'],
  ['mv folder /tmp/', 'bash'],
  ['cp -r src dst', 'bash'],
  ['rm -rf ../build', 'bash'],
  ['cd ~/projects/app && rm -rf ../build', 'bash'],
  ['docker build -t app .', 'bash'],
  ['rm -rf target/', 'bash'],
  ['Remove-Item -Recurse -Force .\\dist', 'pwsh'],
  ['Remove-Item -Recurse -Force $PSScriptRoot\\build', 'pwsh'],
  ['rm -rf C:\\Users\\alice\\AppData\\Roaming\\npm-cache', 'bash'],
  ['rm -rf /c/Users/alice/Desktop/my-project/dist', 'bash'],
  ['pnpm install && rm -rf node_modules/.cache', 'bash'],
  // 用户真实工作区与个人深层目录
  ['rm -rf /c/Users/alice/Desktop/my-project', 'bash'],
  ['rm -rf ~/Documents/项目', 'bash'],
  ['rm -rf /home/user/.cache', 'bash'],
  ['echo rm -rf /', 'bash'],
  ['ls -la /', 'bash'],
  ['cat /etc/passwd', 'bash'],
]

let failed = 0
const check = async (cmd, tool, expect) => {
  const res = await run(cmd, { tool })
  const kind = res && res.kind
  if (kind !== expect) {
    failed++
    console.log(`✗ [${expect}] 实际=${kind}  ${cmd}`)
    if (res && res.reason) console.log(`     reason: ${String(res.reason).split('\n')[2] || ''}`)
  }
}

for (const [cmd, tool] of BLOCK) await check(cmd, tool, 'deny')
for (const [cmd, tool] of ALLOW) await check(cmd, tool, 'allow')

/* ---- 第二轮：个人数据目录 / 凭据 / 应用数据 / 挂载卷 ---- */
const BLOCK2 = [
  ['rm -rf ~/Downloads', 'bash'],
  ['rm -rf ~/Downloads/*', 'bash'],
  ['rm -rf ~/Downloads/', 'bash'],
  ['rm -rf C:\\Users\\alice\\Downloads', 'bash'],
  ['rm -rf /c/Users/alice/Downloads', 'bash'],
  ['rm -rf /home/alice/Downloads', 'bash'],
  ['rm -rf ~/下载', 'bash'],
  ['rm -rf ~/Pictures', 'bash'],
  ['rm -rf ~/图片', 'bash'],
  ['rm -rf ~/Videos', 'bash'],
  ['rm -rf ~/Music', 'bash'],
  ['rm -rf ~/Documents', 'bash'],
  ['rm -rf ~/文档', 'bash'],
  ['rm -rf ~/Desktop/*', 'bash'],
  ['rm -rf ~/Contacts', 'bash'],
  ['rm -rf ~/Favorites', 'bash'],
  ['rm -rf "~/Saved Games"', 'bash'],
  ['rm -rf ~/Public', 'bash'],
  ['rm -rf ~/OneDrive', 'bash'],
  ['rm -rf C:\\Users\\alice\\OneDrive\\Documents', 'bash'],
  ['rm -rf ~/.ssh', 'bash'],
  ['rm -rf ~/.gnupg', 'bash'],
  ['rm -rf ~/.password-store', 'bash'],
  ['rm -rf ~/.aws', 'bash'],
  ['rm -rf ~/.kube', 'bash'],
  ['rm -rf ~/.azure', 'bash'],
  ['rm -rf ~/.config/gcloud', 'bash'],
  ['rm -rf ~/Library/Keychains', 'bash'],
  ['rm -rf "~/AppData/Local/Google/Chrome/User Data"', 'bash'],
  ['rm -rf "~/AppData/Local/Microsoft/Edge/User Data"', 'bash'],
  ['rm -rf ~/AppData/Roaming/Mozilla/Firefox/Profiles', 'bash'],
  ['rm -rf ~/AppData/Roaming/Microsoft/Protect', 'bash'],
  ['rm -rf ~/AppData/Local/Microsoft/Outlook', 'bash'],
  ['rm -rf "~/Documents/WeChat Files"', 'bash'],
  ['rm -rf /mnt/data', 'bash'],
  ['rm -rf /mnt/data/Users/alice', 'bash'],
  ['rm -rf /media/alice/backup-disk', 'bash'],
  ['rm -rf /Volumes/MyDisk', 'bash'],
  ['rm -rf //wsl.localhost/Ubuntu', 'bash'],
  ['rm -rf \\\\wsl.localhost\\Ubuntu-22.04', 'bash'],
  ['Remove-Item -Recurse -Force $env:USERPROFILE\\Downloads', 'pwsh'],
  ['Remove-Item -Recurse -Force "$HOME/.ssh"', 'pwsh'],
  ['rd /s /q C:\\Users\\alice\\Downloads', 'cmd'],
  ['cd ~ && rm -rf Downloads', 'bash'],
  ['cd ~/Downloads && rm -rf *', 'bash'],
  ['rm -rf "C:/Users/alice/Downloads/*"', 'bash'],
  ['rm -rf ~/.ssh/*', 'bash'],
  ['rm -rf "C:\\Users\\alice\\Documents\\WeChat Files"', 'bash'],
  ['rm -rf /home/alice/OneDrive/Documents', 'bash'],
]
const ALLOW2 = [
  ['rm -rf ~/Downloads/old-installer', 'bash'],
  ['rm -rf ~/Downloads/installer.exe', 'bash'],
  ['rm -rf ~/Downloads/*/tmp', 'bash'],
  ['rm -rf ~/Documents/项目', 'bash'],
  ['rm -rf ~/Documents/GitHub/repo/node_modules', 'bash'],
  ['rm -rf ~/Pictures/screenshots/old', 'bash'],
  ['rm -rf ~/OneDrive/工作/临时文件', 'bash'],
  ['rm -rf ~/Desktop/my-project', 'bash'],
  ['rm -rf /mnt/data/project', 'bash'],
  ['rm -rf /media/alice/backup-disk/old-backup', 'bash'],
  ['rm -rf /mnt/data/Users/alice/projects/app', 'bash'],
  ['rm -rf //wsl.localhost/Ubuntu/home/alice/project', 'bash'],
  ['rm -rf ~/project/.docker', 'bash'],
  ['rm -rf ~/AppData/Local/Temp/csg-test', 'bash'],
  ['rm -rf ~/.cache', 'bash'],
  ['rm -rf ~/.npm/_cacache', 'bash'],
  ['rm -rf ~/.m2/repository', 'bash'],
  ['rm -rf ~/.cargo/registry', 'bash'],
  ['rm -rf ~/AppData/Local/Google/Chrome/User Data/Default/Cache', 'bash'],
  ['rm -rf ~/Documents/WeChat Files/backup', 'bash'],
  ['rm -rf /c/Users/alice/Downloads/*/old', 'bash'],
  ['rm -rf "~/AppData/Roaming/Mozilla/Firefox/Profiles/*/cache2"', 'bash'],
]
for (const [cmd, tool] of BLOCK2) await check(cmd, tool, 'deny')
for (const [cmd, tool] of ALLOW2) await check(cmd, tool, 'allow')

/* ---- 边界情形 ---- */
// 非命令类工具一律不审查
{
  const res = await run('', { tool: 'read', args: { file_path: 'C:/x' } })
  if (res.kind !== 'allow') { failed++; console.log('✗ read 工具被误拦') }
}
// bash_batch：任一子命令命中即拦
{
  const res = await run('', {
    tool: 'mcp__fauxnix__bash_batch',
    args: { steps: [{ id: 'a', command: 'echo hi' }, { id: 'b', command: 'rm -rf /' }] },
  })
  if (res.kind !== 'deny') { failed++; console.log('✗ bash_batch 未拦截') }
}
// action=ask
{
  const res = await run('rm -rf /', { config: { mode: 'local', action: 'ask' } })
  if (res.kind !== 'ask') { failed++; console.log(`✗ ask 模式未生效（${res.kind}）`) }
  else console.log(`  ask 模式提示语: ${res.displayReason}`)
}
// extraTools
{
  const res = await run('rm -rf /', { tool: 'my-shell-tool', config: { mode: 'local', action: 'deny', extraTools: 'my-shell-tool' } })
  if (res.kind !== 'deny') { failed++; console.log('✗ extraTools 未生效') }
}
// extraPaths
{
  const res = await run('rm -rf /srv/backup', { config: { mode: 'local', action: 'deny', extraPaths: '/srv/backup' } })
  if (res.kind !== 'deny') { failed++; console.log('✗ extraPaths 未生效') }
}

/* ---- AI 模式（mock fetch） ---- */
const realFetch = globalThis.fetch
const fetchCalls = []
const mockFetch = (reply) => {
  globalThis.fetch = async (url, init) => {
    fetchCalls.push({ url: String(url), body: init && init.body ? JSON.parse(init.body) : null })
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: reply } }] }),
    }
  }
}
const aiCfg = { mode: 'ai', action: 'deny', aiApiKey: 'dummy-key-not-real', aiModel: 'm', aiBaseUrl: 'https://api.example.invalid/v1' }
// 本地规则看不出破坏意图的命令（长尾），才会送 AI
const LONGTAIL = 'python -c "import shutil; shutil.rmtree(\'C:/Users/alice/Documents\')"'

mockFetch('{"verdict":"dangerous","reason":"删除整个用户主目录"}')
{
  const res = await run(LONGTAIL, { config: aiCfg })
  if (res.kind !== 'deny') { failed++; console.log('✗ AI dangerous 未拦截') }
  else console.log(`  AI dangerous 提示语: ${String(res.reason).split('\n')[2] || ''}`)
  if (fetchCalls.length === 0) { failed++; console.log('✗ 长尾命令未送 AI') }
}
mockFetch('{"verdict":"safe","reason":"项目内依赖清理"}')
{
  // 本地规则已能判定的日常清理：默认 longtail 范围下根本不该送 AI（零延迟零打扰）
  fetchCalls.length = 0
  const res = await run('rm -rf node_modules', { config: aiCfg })
  if (res.kind !== 'allow') { failed++; console.log('✗ AI safe 误拦') }
  if (fetchCalls.length !== 0) { failed++; console.log('✗ 日常清理被送了 AI（应为零打扰）') }
}
mockFetch('```json\n{"verdict":"dangerous","reason":"格式化了系统盘"}\n```')
{
  const res = await run(LONGTAIL, { config: { ...aiCfg, aiModel: 'm2' } })
  if (res.kind !== 'deny') { failed++; console.log('✗ AI markdown 围栏未解析') }
}
// 同样的命令命中缓存，不再重复请求
{
  fetchCalls.length = 0
  await run(LONGTAIL, { config: aiCfg })
  if (fetchCalls.length !== 0) { failed++; console.log('✗ 判定缓存未生效') }
}
// aiScope=risky 时，日常清理也会送 AI
mockFetch('{"verdict":"dangerous"}')
{
  fetchCalls.length = 0
  const res = await run('rm -rf node_modules', { config: { ...aiCfg, aiScope: 'risky' } })
  if (res.kind !== 'deny') { failed++; console.log('✗ aiScope=risky 未生效') }
  if (fetchCalls.length !== 1) { failed++; console.log('✗ aiScope=risky 未送 AI') }
}
// AI 故障 + failOpen
globalThis.fetch = async () => { throw new Error('network down') }
{
  const res = await run(LONGTAIL, { config: { ...aiCfg, aiFailOpen: true, aiModel: 'm-failopen' } })
  if (res.kind !== 'allow') { failed++; console.log('✗ AI 故障 failOpen 未放行') }
  const res2 = await run(LONGTAIL, { config: { ...aiCfg, aiFailOpen: false, aiModel: 'm3' } })
  if (res2.kind !== 'deny') { failed++; console.log('✗ AI 故障 failClosed 未拦截') }
}
// 远端未配 key => 跳过 AI
{
  const res = await run(LONGTAIL, { config: { mode: 'ai', action: 'deny' } })
  if (res.kind !== 'allow') { failed++; console.log('✗ 远端无 key 时误拦') }
}
// 本地端点（LM Studio）无需 key
mockFetch('{"verdict":"dangerous","reason":"脚本内删除用户文档"}')
{
  const res = await run(LONGTAIL, {
    config: { mode: 'ai', action: 'deny', aiBaseUrl: 'http://127.0.0.1:1234/v1', aiModel: 'minicpm-v', aiApiKey: '' },
  })
  if (res.kind !== 'deny') { failed++; console.log('✗ 本地端点免 key 未生效') }
  else console.log('  本地端点免 key: 已生效')
}
// aiExtraBody 追加进请求体（思考开关）
mockFetch('{"verdict":"safe"}')
{
  fetchCalls.length = 0
  await run(LONGTAIL, {
    config: { ...aiCfg, aiModel: 'm4', aiExtraBody: '{"chat_template_kwargs":{"enable_thinking":false},"max_tokens":50}' },
  })
  const sent = fetchCalls[0] && fetchCalls[0].body
  const kwargs = sent && sent.chat_template_kwargs && sent.chat_template_kwargs.enable_thinking
  if (kwargs !== false) { failed++; console.log('✗ aiExtraBody 未透传') }
  else if (!sent || sent.max_tokens !== 50) { failed++; console.log('✗ aiExtraBody 未覆盖 max_tokens') }
  else console.log('  aiExtraBody 透传: 已生效')
}
// 结构化输出：本地端点走 json_schema，远端走 json_object，off 则不带
// 注意：aiNoThink=true 时本地端点走 prefill、不带 response_format，
// 所以这里显式设 'auto' 来单独考察 response_format 的选择逻辑。
{
  const fmtOf = async (cfg) => {
    mockFetch('{"verdict":"safe"}')
    fetchCalls.length = 0
    await run(LONGTAIL, { config: { ...cfg, aiNoThink: 'auto', aiModel: `m-fmt-${Math.random()}` } })
    const sent = fetchCalls[0] && fetchCalls[0].body
    return sent && sent.response_format ? sent.response_format.type : null
  }
  const local = await fmtOf({ ...aiCfg, aiBaseUrl: 'http://127.0.0.1:1234/v1', aiApiKey: '' })
  if (local !== 'json_schema') { failed++; console.log(`✗ 本地端点应走 json_schema（实得 ${local}）`) }
  const remote = await fmtOf(aiCfg)
  if (remote !== 'json_object') { failed++; console.log(`✗ 远端应走 json_object（实得 ${remote}）`) }
  const off = await fmtOf({ ...aiCfg, aiStructured: 'off' })
  if (off !== null) { failed++; console.log(`✗ off 时不应带 response_format（实得 ${off}）`) }
  if (local === 'json_schema' && remote === 'json_object' && off === null) {
    console.log('  结构化输出: 本地 json_schema / 远端 json_object / off 关闭')
  }
}
// aiNoThink：prefill 空 think 块，并且不再带 response_format
{
  const fmtAndMsgs = async (cfg) => {
    mockFetch('{"verdict":"safe"}')
    fetchCalls.length = 0
    await run(LONGTAIL, { config: { ...cfg, aiModel: `m-nothink-${Math.random()}` } })
    const sent = fetchCalls[0] && fetchCalls[0].body
    return {
      rf: sent && sent.response_format ? sent.response_format.type : null,
      last: sent && sent.messages ? sent.messages[sent.messages.length - 1] : null,
    }
  }
  const off = await fmtAndMsgs({ ...aiCfg, aiBaseUrl: 'http://127.0.0.1:1234/v1', aiApiKey: '', aiNoThink: false })
  if (off.rf !== 'json_schema') { failed++; console.log('✗ 开思考时应带 json_schema') }
  if (off.last && off.last.role === 'assistant') { failed++; console.log('✗ 开思考时不应有 prefill') }
  const on = await fmtAndMsgs({ ...aiCfg, aiBaseUrl: 'http://127.0.0.1:1234/v1', aiApiKey: '', aiNoThink: true })
  if (on.rf !== null) { failed++; console.log('✗ 关思考时不应带 response_format（互斥）') }
  if (!on.last || on.last.role !== 'assistant' || !/think/.test(String(on.last.content))) {
    failed++; console.log('✗ 关思考时缺少 prefill')
  } else {
    console.log('  aiNoThink: prefill 生效且不带 response_format')
  }
}
// aiNoThink 下模型漂成散文 => 只认 JSON，按放行处理（不能误拦日常操作）
mockFetch('The command is a standard robocopy for cleaning build output. It copies files and looks safe.')
{
  const res = await run(LONGTAIL, { config: { ...aiCfg, aiModel: 'm-nothink-prose', aiNoThink: true } })
  if (res.kind !== 'allow') { failed++; console.log('✗ 关思考+散文被误拦') }
  else console.log('  aiNoThink 散文兜底: 按放行')
}
// 模型返回乱码 reason 时，提示语应退回通用说明而不是把乱码抛给用户
mockFetch('{"verdict":"dangerous","reason":"\\u039c\\uf17f\\u03b4\\u03b5\\u03b6\\u03b7\\u03b8\\u03b9"}')
{
  const res = await run(LONGTAIL, { config: { ...aiCfg, aiModel: 'm-garble' } })
  if (res.kind !== 'deny') { failed++; console.log('✗ 乱码 reason 时未拦截') }
  else if (/[\u0370-\u1fff]/.test(String(res.reason))) { failed++; console.log('✗ 乱码 reason 未被清洗') }
  else console.log('  乱码 reason 清洗: 已生效')
}
// AI 模式下本地规则仍然兜底
mockFetch('{"verdict":"safe"}')
{
  const res = await run('rm -rf /', { config: { ...aiCfg, aiModel: 'm5' } })
  if (res.kind !== 'deny') { failed++; console.log('✗ AI 模式下本地规则未兜底') }
}
globalThis.fetch = realFetch

console.log(`\n拦截用例 ${BLOCK.length + BLOCK2.length} 条 / 放行用例 ${ALLOW.length + ALLOW2.length} 条 + 边界 12 项`)
console.log(failed === 0 ? '✅ 全部通过' : `❌ 失败 ${failed} 项`)
process.exit(failed === 0 ? 0 : 1)

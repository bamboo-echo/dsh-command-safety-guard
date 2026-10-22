# command-safety-guard

本地命令安全拦截插件（DeepSeek Harness / Cordis Host 插件）。

挂在 `tools/pre-execute` 瀑布上，在命令执行前审查命令类工具的参数。

## 工具名怎么认

插件不绑定任何特定 MCP 服务器，按工具名里的关键词判断是否属于「命令执行」：
`bash` / `sh` / `zsh` / `pwsh` / `powershell` / `cmd` / `shell` / `console` / `terminal`。

所以 DSH 自带的 `pwsh` 直接覆盖，MCP 服务器的 `mcp__<server>__bash` 这类前缀名也覆盖。
名字里没有这些关键词的工具（比如某个自定义的 `exec_task`）用配置项 `extraTools`
补上，逗号分隔。

非命令类工具（`read` / `glob` / `grep` / `write` / `edit`）不会被审查，
即使参数文本里含 `rm -rf` 之类字样。参数里优先取 `command` / `script` / `text`
等键承载的命令行；其他字段（例如 `pwsh` 必填的 `description`）不当命令分析。

命令行文本按工具名推断 shell：名字含 `pwsh` / `powershell` 按 PowerShell 解析，
含 `cmd` 按 cmd 解析，其余按 bash 解析。反斜杠在 bash 里是转义符、在
PowerShell / cmd 里是路径分隔符，两种语义都会跑一遍，取先命中的结果。

## 拦截范围（命中即拒绝）

判据是「目录本身被整体删除 / 清空」。目录内部的单个文件或子目录是日常操作，放行。

| 类别 | 例子 |
| --- | --- |
| 系统盘根 / 盘根全量删除 | `rm -rf /`、`rm -rf /*`、`rm -rf C:\`、`rd /s /q D:\` |
| 用户主目录全量删除 | `rm -rf ~`、`rm -rf /c/Users/<user>`、`Remove-Item -Recurse -Force $env:USERPROFILE`、`userdel -r <用户>` |
| 全部用户配置目录 | `rm -rf C:\Users`、`rm -rf /home` |
| 个人数据目录（不可再生） | `rm -rf ~/Downloads`、`rm -rf ~/Documents`、`rm -rf ~/Desktop`、`~/Pictures`、`~/Videos`、`~/Music`、`~/Contacts`、`~/Favorites`、`~/Public`，及中文目录名；`rsync -a --delete <空目录>/ ~/Documents/`、`unison A B -force A` |
| 云同步目录 | `rm -rf ~/OneDrive`、`~/Dropbox`、`~/Google Drive`（会连带清空云端与其他设备） |
| 凭据 / 身份目录与文件 | `~/.ssh`、`~/.gnupg`、`~/.password-store`、`~/.aws`、`~/.aws/credentials`、`~/.kube/config`、`~/.local/share/keyrings`、`~/.netrc`、`AppData\Roaming\Microsoft\Protect`、`...\Credentials`、`...\Crypto` |
| 浏览器 / 邮件 / IM 数据 | Chrome / Edge 的 `User Data`、Firefox `Profiles`、`AppData\Local\Microsoft\Outlook`、`~\Documents\WeChat Files`、`~\Documents\Tencent Files` |
| 系统关键目录（含关键深层路径） | `rm -rf C:\Windows`、`/etc`、`/usr`、`/var`、`'C:\Program Files'`，以及 `/etc/ssh`、`/etc/passwd`、`/etc/sudoers`、`/var/lib/mysql`、`/var/lib/docker`、`/usr/bin`、`/boot/grub`、`/boot/efi/EFI` |
| 挂载卷 / 网络共享 | `rm -rf /mnt/data`、`rm -rf /media/<user>/<disk>`、`rm -rf /Volumes/<vol>`、`rm -rf \\wsl.localhost\<distro>` |
| 格式化 / 分区销毁 | `format C:`、`mkfs.ext4 /dev/sda1`、`diskpart`、`dd if=/dev/zero of=/dev/sda`、`Clear-Disk`、`nvme format`、`hdparm --security-erase`、`diskutil eraseDisk` |
| 卷影副本 / 备份删除 | `vssadmin delete shadows /all`、`wbadmin delete catalog` |
| 注册表整个配置项 | `reg delete HKLM\SOFTWARE /f`、`reg delete HKCU\Software /f`（删单个子键放行） |
| sdelete 覆写受保护目录 | `sdelete -p 3 -s ~/Documents`（`-z` 只清零空闲空间，放行） |
| 循环 / 管道批量删除 | `for d in ~/Documents; do rm -rf "$d"; done`、`for /d %d in (C:\Users\x\*) do @rd /s /q "%d"`、`ls ~/Documents \| xargs rm -rf`、`echo 'rm -rf ~/Documents' \| bash` |

## 放行范围

- 普通文件删除、单目录删除（非递归）
- 构建输出与依赖清理：`dist`、`build`、`node_modules`、`\.next`、`target`、`out`、`coverage`、`.cache`
- 临时目录 / 日志 / 缓存清理（`~/.cache`、`~/.npm/_cacache`、`~/.m2/repository`、`~/.cargo/registry`、浏览器 `...\Cache`）
- `git clean -fdx`（无显式危险 pathspec 时）
- 带过滤条件的 `find … -delete`：`find . -name '*.log' -delete`、`find build -type f -mtime +7 -delete`
- **受保护目录内部**的删除：`~/Downloads/old-installer`、`~/Documents/GitHub/repo/node_modules`、`~/Desktop/my-projects`
- 通配段后还有层级的定向清理：`~/Downloads/*/tmp`、`~/Downloads/*/old`（只删嵌套子目录，不是清空）
- 挂载卷内的普通路径：`/mnt/data/project`、`//wsl.localhost/Ubuntu/home/<user>/project`
- 系统关键目录的**深层子路径**操作（如 `C:\Windows\Temp`、`/etc/nginx/nginx.conf`）

## 两种模式

### 1. local（默认，无需任何 API Key）

纯本地确定性规则：解析命令 → 展开 `~` / `$env:` / `%VAR%` → 词法解析 `.`/`..` → 路径分级判定。
不拦的情形：非递归删除、`git clean`、带过滤条件的 `find -delete`、受保护目录内部的子路径。
审查器内部出错时放行并记日志，不阻塞工作流。

### 2. ai（本地规则兜底 + 外接 AI 复核）

本地规则先拦灾难级命令，这一层与 AI 是否可用无关。之后只把本地规则看不出破坏意图的
命令送 AI 复核（默认 `aiScope: longtail`）——`python -c "shutil.rmtree(...)"` 内联删数据、
`robocopy /MIR` 镜像清空、`docker run -v <宿主目录>`、变量拼出来的路径、
带过滤条件的 `find -delete`，以及服务级数据销毁（`DROP DATABASE`、`redis-cli FLUSHALL`、
`terraform destroy`、`aws s3 rm --recursive`、`kubectl delete pvc --all`、
`mdadm --zero-superblock` 等）。日常清理不送 AI。

端点故障时按 `aiFailOpen` 决定放行还是拒绝；放行会退回纯本地规则，上述长尾手段随之漏掉。

| | local | ai |
| --- | --- | --- |
| 灾难级命令（已知路径 + 删除/格式化动词） | 拦得住 | 拦得住（本地层先拦） |
| 长尾手段（脚本内联删、robocopy /MIR、容器挂载、变量拼接） | 拦不住 | 有机会拦住 |
| 延迟 | 0 | 只在长尾命令上付一次推理（有缓存，同命令不重复请求） |
| 误拦日常操作的风险 | 无（确定性） | 有，取决于模型水平；`aiFailOpen` 控制 AI 故障时是否放行 |
| 可复现性 | 完全可复现 | 同一条命令可能两次结论不同 |

`aiExtraBody` 原样合并进请求体，用于传模型的私有参数（思考开关、采样参数等），
也可覆盖 `max_tokens` / `temperature`。

## 配置

插件导出 `Config` schema，宿主在两处用它：激活时校验（非法值直接报错，例如
`$.mode expected "local" | "ai" but got "aii"`），以及在「设置 → 插件」渲染表单，
`aiApiKey` 是掩码输入。

`cordis.patch.yml` 只有插入行，`config` 留空走默认值（`mode: local`）。配置写在
profile 的 `cordis.patch.yml` 里（本机私有，不进版本库）：

```yaml
# <DSH 配置目录>/profiles/<profile>/cordis.patch.yml
- id: command-safety-guard
  name: "@local/dsh-command-safety-guard"
  config:
    mode: ai
    action: deny
    aiBaseUrl: 'https://api.example.com/v1'
    aiApiKey: '<key>'
    aiModel: '<模型名>'
    aiScope: longtail
    aiStructured: json_object
    aiNoThink: true
    aiTimeoutMs: 60000
    aiFailOpen: true
```

配置项与默认值：

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `mode` | `local` | `local` = 纯本地确定性规则；`ai` = 本地兜底 + AI 复核 |
| `action` | `deny` | `deny` = 直接拒绝；`ask` = 弹窗确认后放行 |
| `extraTools` | `''` | 额外视作命令执行的工具名，逗号分隔 |
| `extraPaths` | `''` | 额外保护的路径，逗号分隔，支持 `*` |
| `aiBaseUrl` | `https://api.deepseek.com/v1` | OpenAI 兼容 Base URL，本地模型用 `http://127.0.0.1:1234/v1` |
| `aiApiKey` | `''` | 本地端点可留空；掩码输入 |
| `aiModel` | `deepseek-chat` | 模型名 |
| `aiTimeoutMs` | `15000` | 超时（毫秒）。本地小模型建议 15000~30000；开思考要 60000+ |
| `aiFailOpen` | `true` | AI 故障时放行（本地规则仍兜底） |
| `aiScope` | `longtail` | `longtail` = 只送本地看不出破坏意图的；`risky` = 全送 |
| `aiStructured` | `auto` | `auto` / `json_schema` / `json_object` / `off` |
| `aiNoThink` | `true` | `true` / `false` / `auto`（按命令长度分流） |
| `aiNoThinkMaxLen` | `100` | `auto` 模式下「短命令」阈值 |
| `aiExtraBody` | `''` | 追加进请求体的 JSON，用于模型私有参数 |

改完配置后在插件管理里把 `command-safety-guard` 关一次再开即可生效。

## 依赖与安装

`package.json` 声明 `@deepseek-ai/schemastery`（约 204 KB，含 `cosmokit` 与
`@standard-schema/spec`），导出 `Config` 需要它。

装在插件自己的 `node_modules` 里而不是靠 profile 提供：本地 bundle 走 `link:` 安装，
Node 解析到的是真实路径（开发目录），向上找不到 profile 的 `node_modules`，宿主包
import 一律失败。出厂包把 schemastery 声明为 `peerDependencies`，本地开发的 bundle 得自带。

```bash
cd command-safety-guard
npm install
```

装进 profile 用 `plugin_manager`（`install_bundle`，target = 插件目录的绝对路径）。

## 实现说明

- 钩子：`tools/pre-execute` 瀑布，返回 `{ kind: 'deny', reason }` / `{ kind: 'ask', reason }`，其余情况 `next()`。
- 命令行解析：引号感知的 shell 词法切分，支持 `&&`、`||`、`;`、`|`、换行分段，
  逐段识别删除类 / 格式化类命令，处理 `bash -c` / `cmd /c` / `powershell -Command` 嵌套，
  跟踪 `cd` 后的当前目录，统一展开环境变量与 `~`。
- 绝对路径做词法 `.` / `..` 解析：`rm -rf /c/Users/x/AppData/Local/Temp/../../..`
  收敛成 `/c/Users/x` 后判为主目录全删，回溯出根则判盘根。
- `export const Config` 描述全部配置项，宿主据此校验 + 渲染表单；插件内还有一层
  `normalizeConfig` 兜底，容忍 YAML 里写成字符串的数字与布尔。
- 审查器内部异常一律放行并记日志。

## 已验证（安装后实机）

装进 desktop profile 后用真实工具调用验证过，期望拦截的用例都指向不存在的路径：

| 命令 | 结果 |
| --- | --- |
| `rm -rf <临时目录>/benign` | ✅ 放行并真实执行（退出码 0） |
| `rm -rf /c/Users/csg-nonexistent-user-xyz123` | ⛔ 拦截：全量删除用户主目录 |
| `rm -rf '/c/Users/csg-nonexistent-user-xyz123/Desktop'` | ⛔ 拦截：全量删除用户桌面目录 |
| `rm -rf /c/Users/csg-nonexistent-user-xyz123/Downloads` | ⛔ 拦截：全量删除用户下载目录 |
| `rm -rf /c/Users/csg-nonexistent-user-xyz123/Downloads/old-installer` | ✅ 放行（受保护目录内部是日常操作） |
| `rm -rf /c/Users/csg-nonexistent-user-xyz123/Downloads/*/old` | ✅ 放行（通配段后还有层级，定向清理） |
| `rm -rf /c/Users/csg-nonexistent-user-xyz123/Pictures` | ⛔ 拦截：照片 / 视频 / 音乐目录 |
| `rm -rf /c/Users/csg-nonexistent-user-xyz123/.ssh` | ⛔ 拦截：凭据 / 身份目录 |
| `rm -rf "…/AppData/Local/Google/Chrome/User Data"` | ⛔ 拦截：浏览器数据目录 |
| `rm -rf /mnt/csg-no-such-volume` | ⛔ 拦截：整个挂载数据卷 |
| `rm -rf /mnt/csg-no-such-volume/projects/app` | ✅ 放行（卷内普通路径） |
| `rm -rf /z` | ⛔ 拦截：全量删除整个磁盘 |
| `mkfs.ext4 /dev/sdzz99` | ⛔ 拦截：磁盘格式化 / 分区销毁 |
| `rm -rf /c/Users/… ; echo done` | ⛔ 拦截（多语句取第一段判定） |
| `pwsh -Command "Remove-Item -Recurse -Force C:\Users\…"` | ⛔ 拦截（嵌套 shell） |
| `rd /s /q C:\Users\…` | ⛔ 拦截（cmd 开关形态） |

AI 层（mode=ai，本地端点）实机：

| 命令 | 结果 |
| --- | --- |
| `node -e "fs.rmSync('…/Pictures',{recursive:true})"` | ⛔ AI 拦截（本地规则看不出） |
| `robocopy … /MIR` | ⛔ AI 拦截 |
| `docker run -v C:\:/host alpine rm -rf /host/Users/…` | ⛔ AI 拦截 |
| `rm -rf node_modules` | ✅ 直接放行（长尾范围外，不发请求） |
| `node -e "console.log(...)"` | ✅ AI 判 safe 后放行 |

本地端点上 `aiNoThink: true` 走 prefill 压思考，代价是拿不到结构化输出
（grammar 会拒绝 think 标签），模型返回的散文由解析层的关键词兜底。远端端点用
顶层 `enable_thinking: false`，可以同时保留 `response_format`。

Config 校验：把 `mode` 写成 `aii` 再启用插件，激活被拒：

```
command-safety-guard: ValidationError: invalid config:
  - $.mode expected "local" | "ai" but got "aii" (at mode)
```

离线用例台在仓库的 `test/` 目录。用例台通过插件真实的 `Config` schema 校验并补默认值，
与宿主的激活路径一致：

```bash
node test/test-command-safety-guard.mjs          # 128 条拦截 + 76 条放行，另有边界与 AI 模式用例
node test/matrix-command-safety-guard.mjs local  # 285 条分层矩阵（纯本地规则）
node test/matrix-command-safety-guard.mjs ai     # 同上，实机跑 AI 层
node test/run-corpus.mjs <语料.json> ...         # 外部语料跑分，CORPUS_MODE=ai 跑 AI 层
```

用例台只驱动 `tools/pre-execute` 监听器，不执行命令；期望拦截的用例都指向不存在的路径。

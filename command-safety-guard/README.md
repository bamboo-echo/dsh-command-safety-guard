# command-safety-guard

本地命令安全拦截插件（DeepSeek Harness / Cordis Host 插件）。

在命令执行前审查所有命令类工具调用（`bash` / `pwsh` / `cmd` / 持久 shell 等），
**只拦截灾难级破坏性操作**，日常操作零干扰。

## 拦截范围（命中即拒绝）

一律以「**目录本身被整体删除 / 清空**」为判据；目录内部的单个文件或子目录是日常操作，放行。

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

## 放行范围（零干扰）

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
误报防护：只删不递归的不拦；`git clean` 默认放行；`find` 带过滤条件不拦；
受保护目录内部的子路径一律放行。宁可漏报，不误报。
**响应延迟 = 0，结果可复现。**

### 2. ai（本地规则兜底 + 外接 AI 复核）

本地规则先拦灾难级命令（这一层永远生效，AI 挂不挂都一样）；
随后只把「**本地规则看不出破坏意图**」的命令送 AI 二次复核（默认 `aiScope: longtail`）——
例如用 `python -c "shutil.rmtree(...)"` 内联删数据、`robocopy /MIR` 镜像清空、
`docker run -v <宿主目录>`、变量拼出来的路径、带过滤条件的 `find -delete`，
以及服务级数据销毁（`DROP DATABASE`、`redis-cli FLUSHALL`、`terraform destroy`、
`aws s3 rm --recursive`、`kubectl delete pvc --all`、`mdadm --zero-superblock` 等）。
日常清理（`rm -rf node_modules` 这类）根本不送 AI，**零延迟、零打扰**。

| | local | ai |
| --- | --- | --- |
| 灾难级命令（已知路径 + 删除/格式化动词） | 拦得住 | 拦得住（本地层先拦） |
| 长尾手段（脚本内联删、robocopy /MIR、容器挂载、变量拼接） | 拦不住 | 有机会拦住 |
| 延迟 | 0 | 只在长尾命令上付一次推理（有缓存，同命令不重复请求） |
| 误拦日常操作的风险 | 无（确定性） | 有，取决于模型水平；`aiFailOpen` 控制 AI 故障时是否放行 |
| 可复现性 | 完全可复现 | 同一条命令可能两次结论不同 |

本地模型（LM Studio / Ollama）配置示例：

```yaml
config:
  mode: ai
  action: deny
  aiBaseUrl: 'http://127.0.0.1:1234/v1'   # 本地端点无需 aiApiKey
  aiModel: 'minicpm-v-4.7-1b'
  aiScope: longtail        # 只送本地规则看不见的（默认）
  aiStructured: json_schema
  aiTimeoutMs: 25000
  aiFailOpen: true
```

`aiExtraBody` 原样合并进请求体，用来传模型的私有参数（思考开关、采样参数等），
也可用它覆盖 `max_tokens` / `temperature`。

### 小模型接进来的五个坑（都已处理）

1. **不按 JSON 回答**：小模型会返回英文散文。必须开结构化输出——
   LM Studio 只认 `json_schema`（不认 `json_object`，会报 400），
   云端（DeepSeek / SiliconFlow）用 `json_object`；`aiStructured: auto` 会按端点自动选。
2. **思考内容吃掉 token 预算**：`max_tokens: 300` 会被 reasoning 占满，返回空 content。
   已提到 1200。
3. **`chat_template_kwargs.enable_thinking` 在 SiliconFlow 上会让请求挂死**：
   45 秒无响应。正确写法是**顶层 `enable_thinking: false`**（Qwen3 标准做法）。
   在 LM Studio 上该参数则完全不透传给 GGUF，只能用 prefill 空 think 块。
4. **不带 `stream: false` 也会挂**：SiliconFlow 在缺少该字段时会把响应挂住不返回，已永远带上。
5. **中文被双重转义 / 输出乱码**：模型会把中文写成字面 `\uXXXX`，或吐一串希腊字母乱码。
   解析层已做反转义 + 乱码清洗，失败时退回通用理由，不会把乱码抛给用户。

### 思考开关的实测结论（Qwen3-8B @ SiliconFlow，12 条用例）

| 配置 | 延迟 | 结果 |
| --- | --- | --- |
| 开思考 | **15–90s** | 9/9 |
| 关思考 + 旧提示词 | 0.9–3.4s | 会把 `rm -rf ./dist` 误判成 dangerous |
| 关思考 + 补「判断依据是目标路径，不是手段」策略句 | **0.9–3.4s** | **11/12** |
| 关思考 + 策略句 + `analyzeContainerRun` 确定性补丁 | **0.0–9.3s** | **12/12** |

关思考唯一漏的是 `docker run -v <宿主目录>:…` ——需要推理挂载映射。
这条已由确定性规则补上：解析 `-v` / `--volume` **左侧的宿主路径**直接判定，
不经过模型，0.0s 出结果。

所以当前配置 `aiNoThink: true`（全部关思考）在又快又准之间取到了平衡点。
想换回开思考把 `aiNoThink` 设成 `false`，代价是每条 15–90 秒。

## 配置

安装后插件会被登记进当前 profile（`<DSH 配置目录>/profiles/<profile>/package.json`
的 `dsh.profile.bundles` + `link:` 依赖），本 bundle 自带的 `cordis.patch.yml`
就是它的插入行，配置写在这里：

```yaml
# command-safety-guard/cordis.patch.yml
# 完整配置项（示例为 SiliconFlow Qwen3-8B，全部关思考）
- insert:
    - id: command-safety-guard
      name: '@local/dsh-command-safety-guard'
      config:
        mode: ai              # local = 纯本地规则 | ai = 本地兜底 + AI 复核
        action: deny          # deny = 直接拒绝 | ask = 弹窗确认后放行
        extraTools: ''        # 额外视作命令执行工具的工具名，逗号分隔
        extraPaths: ''        # 额外保护路径，逗号分隔，支持 * 通配符
        aiBaseUrl: 'https://api.siliconflow.cn/v1'   # 或 http://127.0.0.1:1234/v1（本地模型）
        aiApiKey: ''          # 本地端点可留空；⚠️ 真实密钥切勿提交进版本库
        aiModel: 'Qwen/Qwen3-8B'
        aiScope: longtail     # longtail = 只送本地规则看不见的 | risky = 全送
        aiStructured: auto    # auto = 本地 json_schema / 远端 json_object
        aiNoThink: true       # true = 全关思考（快） | false = 全开（准但慢） | auto = 分流
        aiTimeoutMs: 60000
        aiFailOpen: true      # AI 故障时放行（本地规则仍兜底）
```

> **密钥安全**：`cordis.patch.yml` 是受版本控制的文件。填了真实 `aiApiKey` 之后，
> 建议执行 `git update-index --skip-worktree command-safety-guard/cordis.patch.yml`，
> 让 git 忽略你本地的这份修改，密钥就不会被误提交。

改完配置后，在插件管理里把 `command-safety-guard` 关一次再开（或重启 DSH）即可生效。
也可以用 profile 的 `cordis.patch.yml` 追加一行 `- id: command-safety-guard` +
`config:` 来覆盖（profile 补丁层后置生效）。

## 实现说明

- 钩子：`tools/pre-execute` 瀑布（返回 `{ kind: 'deny', reason }` / `{ kind: 'ask', reason }`，其余情况返回 `next()`）。
- 命令行解析：引号感知的 shell 词法切分，支持 `&&`、`||`、`;`、`|`、换行分段，
  逐段识别删除类 / 格式化类命令，处理 `bash -c` / `cmd /c` / `powershell -Command` 嵌套，
  跟踪 `cd` 后的当前目录，统一展开环境变量与 `~`。
- 绝对路径会**词法解析 `.` / `..`**：`rm -rf /c/Users/x/AppData/Local/Temp/../../..`
  这类「深层路径 + 回溯」写法会被收敛成 `/c/Users/x` 后判为主目录全删（回溯出根则判盘根）。
- 健壮性：审查器内部任何异常都放行并记日志，绝不因插件缺陷阻塞工作流。
- 零依赖：插件不 import 任何宿主包（含 `@deepseek-ai/schemastery`），
  因为本地 bundle 的真实路径在 profile 的 `node_modules` 之外，import 会直接导致加载失败；
  代价是插件不出现在设置界面的表单里，配置只能走 `cordis.patch.yml`。

## 已验证（安装后实机）

安装到 desktop profile 后用真实工具调用验证过：

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

**AI 层实机（mode=ai + MiniCPM-V 4.7 1B @ 127.0.0.1:1234）**：

| 命令 | 结果 |
| --- | --- |
| `node -e "fs.rmSync('…/Pictures',{recursive:true})"` | ⛔ AI 拦截（本地规则看不出） |
| `robocopy … /MIR` | ⛔ AI 拦截 |
| `docker run -v C:\:/host alpine rm -rf /host/Users/…` | ⛔ AI 拦截 |
| `rm -rf node_modules` | ✅ 直接放行（长尾范围外，不发请求、零延迟） |
| `node -e "console.log(...)"` | ✅ AI 判 safe 后放行 |

离线用例台（不属于分发包，在仓库的 `test/` 目录）：

```bash
node test/test-command-safety-guard.mjs          # 128 条拦截 + 76 条放行 + 12 项边界
node test/matrix-command-safety-guard.mjs local  # 285 条分层矩阵（纯本地规则）
node test/matrix-command-safety-guard.mjs ai     # 同上，实机跑 AI 层
node test/run-corpus.mjs <语料.json> ...         # 外部语料跑分，CORPUS_MODE=ai 跑 AI 层
```

用例台只驱动插件的 `tools/pre-execute` 监听器，**不执行任何命令**。
所有期望「拦截」的用例都指向不存在的路径，即使判定失误也不会造成破坏。

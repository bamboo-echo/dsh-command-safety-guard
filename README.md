# dsh-command-safety-guard

DeepSeek Harness 插件。挂在 `tools/pre-execute` 瀑布上，在命令执行前审查命令类工具的参数。

不绑定特定 MCP 服务器：按工具名里的关键词（`bash` / `pwsh` / `cmd` / `shell` /
`terminal` 等）判断是否属于命令执行，DSH 自带的 `pwsh` 与 `mcp__<server>__bash`
这类前缀名都覆盖；认不出的用配置项 `extraTools` 补上。`read` / `write` / `glob`
这类非命令工具不审查。

判据是「目录本身被整体删除或清空」。目录内部的单个文件和子目录属于日常操作，放行。
默认 `mode: local`，纯本地确定性规则，不需要 API Key。设成 `ai` 会额外把本地规则
看不出破坏意图的命令送 OpenAI 兼容端点复核。

## 拦截范围

| 类别 | 例子 |
| --- | --- |
| 盘根 / 系统根全量删除 | `rm -rf /`、`rm -rf /*`、`rm -rf C:\`、`rd /s /q D:\` |
| 用户主目录全量删除 | `rm -rf ~`、`rm -rf /c/Users/<user>`、`Remove-Item -Recurse -Force $env:USERPROFILE`、`userdel -r <用户>` |
| 全部用户配置目录 | `rm -rf C:\Users`、`rm -rf /home` |
| 个人数据目录 | `~/Downloads`、`~/Documents`、`~/Desktop`、`~/Pictures`、`~/Videos`、`~/Music`、`~/Contacts`、`~/Favorites`、`~/Public`，及中文目录名 |
| 云同步目录 | `rm -rf ~/OneDrive`、`~/Dropbox`、`~/Google Drive` |
| 凭据 / 身份目录 | `~/.ssh`、`~/.gnupg`、`~/.aws/credentials`、`~/.kube/config`、`AppData\Roaming\Microsoft\Protect` |
| 浏览器 / 邮件 / IM 数据 | Chrome / Edge 的 `User Data`、Firefox `Profiles`、`~\Documents\WeChat Files` |
| 系统关键目录 | `rm -rf C:\Windows`、`/etc`、`/usr`、`/var`、`'C:\Program Files'`，以及 `/etc/ssh`、`/etc/passwd`、`/var/lib/docker`、`/boot/efi/EFI` |
| 挂载卷 / 网络共享 | `rm -rf /mnt/data`、`rm -rf /media/<user>/<disk>`、`rm -rf \\wsl.localhost\<distro>` |
| 格式化 / 分区销毁 | `format C:`、`mkfs.ext4 /dev/sda1`、`diskpart`、`dd if=/dev/zero of=/dev/sda`、`Clear-Disk`、`nvme format`、`diskutil eraseDisk` |
| 卷影副本 / 备份删除 | `vssadmin delete shadows /all`、`wbadmin delete catalog` |
| 注册表整个配置项 | `reg delete HKLM\SOFTWARE /f`（删单个子键放行） |
| sdelete 覆写受保护目录 | `sdelete -p 3 -s ~/Documents`（`-z` 只清零空闲空间，放行） |
| 循环 / 管道批量删除 | `for d in ~/Documents; do rm -rf "$d"; done`、`ls ~/Documents \| xargs rm -rf`、`echo 'rm -rf ~/Documents' \| bash` |
| 镜像同步清空 | `rsync -a --delete <空目录>/ ~/Documents/`、`robocopy <空目录> <目标> /MIR`、`unison A B -force A` |
| 容器挂载宿主目录 | `docker run -v <宿主目录>:/data alpine rm -rf /data` |
| 脚本内联删 | `python -c "shutil.rmtree('~/Documents')"`、`node -e "fs.rmSync('~/Pictures',{recursive:true})"` |

更细的清单（路径回溯收敛、嵌套 shell、`cd` 后的当前目录跟踪）见
[`command-safety-guard/README.md`](command-safety-guard/README.md)。

## 放行范围

- 普通文件删除、非递归的单目录删除
- 构建输出与依赖：`dist`、`build`、`node_modules`、`.next`、`target`、`out`、`coverage`、`.cache`
- 缓存与临时目录：`~/.cache`、`~/.npm/_cacache`、`~/.cargo/registry`
- `git clean -fdx`（无显式危险 pathspec 时）
- 带过滤条件的 `find … -delete`：`find . -name '*.log' -delete`
- 受保护目录内部的删除：`~/Downloads/old-installer`、`~/Documents/GitHub/repo/node_modules`
- 通配段后还有层级的定向清理：`~/Downloads/*/tmp`
- 挂载卷内的普通路径：`/mnt/data/project`
- 系统关键目录的深层子路径：`C:\Windows\Temp`、`/etc/nginx/nginx.conf`
- `#` 注释里的危险字样、`echo` / `printf` 输出的危险字符串

## 安装

依赖 `@deepseek-ai/schemastery`（导出 `Config` 用，约 204 KB）：

```bash
cd command-safety-guard
npm install
```

装在插件自己的 `node_modules` 里，因为本地 bundle 走 `link:` 安装，Node 解析到真实路径后
向上找不到 profile 的 `node_modules`。出厂包把 schemastery 声明为 `peerDependencies`，
本地开发的 bundle 得自带。

装进 profile 用 `plugin_manager`：

```
install_bundle，target = 本目录的绝对路径
```

配置在「设置 → 插件」里改，`aiApiKey` 是掩码输入。bundle 自带的 `cordis.patch.yml`
只有插入行，`config` 留空；要写配置写在 profile 的 `cordis.patch.yml` 里：

```yaml
# <DSH 配置目录>/profiles/<profile>/cordis.patch.yml
- id: command-safety-guard
  name: "@local/dsh-command-safety-guard"
  config:
    mode: ai
    aiBaseUrl: 'https://api.example.com/v1'
    aiApiKey: '<key>'
    aiModel: '<模型名>'
```

激活时宿主按 `Config` schema 校验配置，非法值直接报错。

## 两种模式

| | `local`（默认） | `ai` |
| --- | --- | --- |
| 灾难级命令（已知路径 + 删除/格式化动词） | 拦得住 | 拦得住（本地层先拦） |
| 长尾手段（脚本内联删、robocopy /MIR、容器挂载、变量拼接） | 拦不住 | 有机会拦住 |
| 延迟 | 0 | 只在长尾命令上付一次推理，有缓存 |
| 误拦日常操作 | 无 | 有，取决于模型水平 |
| 可复现性 | 完全可复现 | 同一条命令可能两次结论不同 |
| 需要 API Key | 不需要 | 需要（本地模型可留空） |

`ai` 接任何 OpenAI 兼容端点，云端或本地推理端都可以。

它的两个实际约束：依赖端点可达性，`aiFailOpen: true` 时端点故障会退回纯本地规则，
脚本内联删这类长尾手段跟着漏；关思考下单次复核 1–5 秒。
服务级数据销毁（`DROP DATABASE`、`redis-cli FLUSHALL`、`terraform destroy`、
`aws s3 rm --recursive`）和 Linux 存储层工具（`mdadm` / `pvremove` / `cryptsetup` /
`zpool` / `btrfs`）没有确定性规则，拦住与否取决于模型。

## 测试

```bash
node test/test-command-safety-guard.mjs          # 128 拦 + 76 放，另有边界与 AI 模式用例
node test/matrix-command-safety-guard.mjs local  # 285 条分层矩阵
node test/matrix-command-safety-guard.mjs ai     # 同上，实机跑 AI 层
node test/run-corpus.mjs <语料.json> ...         # 外部语料跑分，CORPUS_MODE=ai 跑 AI 层
```

用例台只驱动 `tools/pre-execute` 监听器，不执行命令；期望拦截的用例都指向不存在的路径。

当前数字：矩阵 285/285，用例台 128 拦 + 76 放全过，1739 条对抗语料误拦 0。

对抗语料的生成提示词（用来穷尽盲区，不是在已知范围内填空）见
[`docs/corpus-generation-prompt.md`](docs/corpus-generation-prompt.md)。

## 结构

```
command-safety-guard/     插件本体
  index.js                逻辑 + Config schema
  cordis.patch.yml        插入行
  package.json            声明 schemastery 依赖
  README.md               完整清单、配置项、实测数据
  locale/  icon.svg
  node_modules/           npm install 生成，已 gitignore
test/                     离线用例台
docs/                     语料生成提示词
LICENSE                   MIT
```

## License

MIT

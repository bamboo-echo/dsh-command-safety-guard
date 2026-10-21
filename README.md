# dsh-command-safety-guard

**A pre-execution safety interceptor for DeepSeek Harness — blocks catastrophic destructive
commands, stays completely out of the way for everyday cleanup.**

在每条命令执行前做一次审查，**只拦灾难级破坏性操作**（系统盘根全删、用户主目录/桌面/下载
目录整体删除、磁盘格式化……），日常的 `rm -rf node_modules` / `dist` / `build` 零干扰。

- **零依赖、零 import**：不依赖任何宿主包，本地 bundle 直接可用
- **默认纯本地确定性规则**：0 延迟、结果可复现、不需要任何 API Key
- **可选 AI 复核**：只把「本地规则看不出破坏意图」的长尾命令送 AI，日常清理不发请求
- **宁可漏报，不误报**：审查器内部任何异常都放行，绝不因插件缺陷阻塞工作流

---

## 它会拦什么

一律以「**目录本身被整体删除 / 清空**」为判据；目录内部的单个文件或子目录是日常操作，放行。

| 类别 | 例子 |
| --- | --- |
| 系统盘根 / 盘根全量删除 | `rm -rf /`、`rm -rf /*`、`rm -rf C:\`、`rd /s /q D:\` |
| 用户主目录全量删除 | `rm -rf ~`、`rm -rf /c/Users/<user>`、`Remove-Item -Recurse -Force $env:USERPROFILE`、`userdel -r <用户>` |
| 全部用户配置目录 | `rm -rf C:\Users`、`rm -rf /home` |
| 个人数据目录（不可再生） | `rm -rf ~/Downloads`、`~/Documents`、`~/Desktop`、`~/Pictures`、`~/Videos`、`~/Music`、`~/Contacts`、`~/Favorites`、`~/Public`，及中文目录名 |
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

完整清单（含放行范围、路径回溯收敛、嵌套 shell 处理等）见
[`command-safety-guard/README.md`](command-safety-guard/README.md)。

## 它放行什么

- 普通文件删除、单目录删除（非递归）
- 构建输出与依赖清理：`dist`、`build`、`node_modules`、`.next`、`target`、`out`、`coverage`、`.cache`
- 临时 / 日志 / 缓存清理（`~/.cache`、`~/.npm/_cacache`、`~/.cargo/registry`）
- `git clean -fdx`（无显式危险 pathspec 时）
- 带过滤条件的 `find … -delete`：`find . -name '*.log' -delete`
- **受保护目录内部**的删除：`~/Downloads/old-installer`、`~/Documents/GitHub/repo/node_modules`
- 通配段后还有层级的定向清理：`~/Downloads/*/tmp`
- 挂载卷内的普通路径：`/mnt/data/project`
- 系统关键目录的深层子路径：`C:\Windows\Temp`、`/etc/nginx/nginx.conf`
- `#` 注释里的危险字样、`echo` / `printf` 输出的危险字符串

## 安装

本地 bundle 安装（无需 npm publish）：

```bash
git clone https://github.com/bamboo-echo/dsh-command-safety-guard.git
```

1. 把仓库里的 `command-safety-guard/` 目录放到一个固定位置（例如 `<plugins>/command-safety-guard`）。
2. 在目标 profile 的 `package.json` 里登记它 —— `<DSH 配置目录>/profiles/<profile>/package.json`：

```json
{
  "dependencies": {
    "@local/dsh-command-safety-guard": "link:<绝对路径>/command-safety-guard"
  },
  "dsh": {
    "profile": {
      "bundles": [
        "@local/dsh-command-safety-guard"
      ]
    }
  }
}
```

3. 重启 DSH，或在插件管理里启用 `command-safety-guard`。

插入行与默认配置就在 bundle 自带的 `command-safety-guard/cordis.patch.yml` 里，改配置后
把插件关一次再开即可生效。

> **密钥安全**：`cordis.patch.yml` 是受版本控制的文件。填了真实 `aiApiKey` 之后请执行
> `git update-index --skip-worktree command-safety-guard/cordis.patch.yml`，
> 让 git 忽略本地这份修改。

## 两种模式

| | `local`（默认） | `ai` |
| --- | --- | --- |
| 灾难级命令（已知路径 + 删除/格式化动词） | 拦得住 | 拦得住（本地层先拦） |
| 长尾手段（脚本内联删、robocopy /MIR、容器挂载、变量拼接） | 拦不住 | 有机会拦住 |
| 延迟 | 0 | 只在长尾命令上付一次推理（有缓存） |
| 误拦日常操作的风险 | 无（确定性） | 有，取决于模型水平 |
| 可复现性 | 完全可复现 | 同一条命令可能两次结论不同 |
| 需要 API Key | 不需要 | 需要（本地模型可留空） |

`ai` 模式 = 本地规则兜底 + 外接 OpenAI 兼容接口复核。任何 OpenAI 兼容端点都能接
（SiliconFlow / DeepSeek / LM Studio / Ollama / vLLM …）。

## 验证

离线用例台只驱动插件的 `tools/pre-execute` 监听器，**不执行任何命令**；
所有期望「拦截」的用例都指向不存在的路径，即使判定失误也不会造成破坏。

```bash
node test/test-command-safety-guard.mjs          # 128 条拦截 + 76 条放行 + 12 项边界
node test/matrix-command-safety-guard.mjs local  # 285 条分层矩阵（纯本地规则）
node test/matrix-command-safety-guard.mjs ai     # 同上，实机跑 AI 层
node test/run-corpus.mjs <语料.json> ...         # 外部语料跑分，CORPUS_MODE=ai 跑 AI 层
```

当前结果：**285/285** 矩阵通过、**128 拦 + 76 放 + 12 边界** 全过、
1739 条对抗语料**误拦 0**。

对抗语料的生成提示词（用来穷尽盲区，而不是在已知范围内填空）见
[`docs/corpus-generation-prompt.md`](docs/corpus-generation-prompt.md)。

## 已知边界

- **AI 层依赖端点可达性**：`aiFailOpen: true` 时端点故障自动降级为纯本地规则，
  不会拦日常操作，但脚本内联删这类长尾手段会漏。
- **AI 层有 1–5 秒延迟**（关思考）。只对本地规则看不出破坏意图的命令触发。
- **服务级数据销毁**（`DROP DATABASE`、`redis-cli FLUSHALL`、`terraform destroy`、
  `aws s3 rm --recursive`、`mdadm --zero-superblock` 等）目前只进 AI 触发范围，
  没有确定性规则，召回取决于模型水平。
- **Linux 存储层工具**（`mdadm` / `pvremove` / `cryptsetup` / `zpool` / `btrfs`）同上。

## 仓库结构

```
command-safety-guard/     插件本体（拷进 DSH 插件目录即可）
  index.js                全部逻辑，零依赖
  cordis.patch.yml        插入行 + 默认配置
  package.json
  README.md               完整拦截/放行清单、配置项、实测数据
  locale/  icon.svg
test/                     离线用例台（不属于分发包）
docs/                     语料生成提示词
LICENSE                   MIT
```

## License

[MIT](LICENSE)

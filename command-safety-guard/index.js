/**
 * command-safety-guard — 本地命令安全拦截插件（DSH Host plugin）
 *
 * 通过 `tools/pre-execute` 瀑布钩子在命令执行前审查所有命令类工具调用：
 *
 *   1. 只拦截「灾难级破坏性操作」——命中即拒绝执行并说明原因：
 *      - 系统盘 / 盘根的全量删除（rm -rf /、rm -rf C:\、rd /s /q C:\ …）
 *      - 用户主目录、桌面/文档目录的全量删除（rm -rf ~、Remove-Item -Recurse $env:USERPROFILE …）
 *      - 系统关键目录的全量删除（Windows、System32、Program Files、/etc、/usr …）
 *      - 格式化 / 分区表销毁类命令（format、mkfs.*、diskpart、wipefs、dd of=/dev/sdX …）
 *   2. 日常操作零干扰：普通文件删除、构建输出清理（dist/build/node_modules）、
 *      临时目录清理、git clean、带过滤条件的 find -delete 等一律放行。
 *   3. 两种审核模式（配置项 `mode`）：
 *      - local：纯本地确定性规则，无需任何 API Key（默认）
 *      - ai：本地规则兜底 + 外接 OpenAI 兼容 AI 复核破坏性命令
 *
 * 设计原则：宁可漏报（放行），不可误报（阻断日常操作）。任何内部异常都放行，
 * 绝不因插件自身缺陷阻塞用户的正常工作流。
 */

'use strict'

import Schema from '@deepseek-ai/schemastery'

/* ------------------------------------------------------------------ *
 * 常量表
 * ------------------------------------------------------------------ */

/** 视作「命令执行」的工具名关键词（命中即审查其参数） */
const COMMAND_TOOL_HINTS = ['bash', 'sh', 'zsh', 'pwsh', 'powershell', 'cmd', 'shell', 'console', 'terminal']

/** 参数中承载命令行文本的键名 */
const COMMAND_KEYS = new Set(['command', 'commands', 'cmd', 'script', 'code', 'text', 'input', 'line', 'program', 'exec', 'cmdline'])

/** 命令包装器：跳过它们看真正的可执行名 */
const WRAPPERS = new Set(['sudo', 'doas', 'nohup', 'setsid', 'env', 'command', 'builtin', 'time', 'nice', 'ionice', 'stdbuf', 'xargs'])

/** 删除类命令（bash / cmd / PowerShell 三类都覆盖） */
const DELETE_EXES = new Set(['rm', 'rmdir', 'del', 'erase', 'rd', 'ri', 'remove-item'])

/** cmd 内建删除命令（用 /s /q 形式的开关） */
const CMD_DELETE_EXES = new Set(['del', 'erase', 'rd', 'rmdir'])

/** 磁盘格式化 / 分区销毁类命令：出现即灾难级 */
const DISK_WIPE_EXES = new Set([
  'format', 'format.com', 'mkfs', 'diskpart', 'wipefs', 'mformat',
  'clear-disk', 'initialize-disk', 'format-volume', 'remove-partition',
  'newfs', 'gdisk', 'sgdisk', 'parted', 'fdisk',
])

/** 同属格式化家族、但只在目标是真块设备时才危险的命令 */
const MKFS_EXES = new Set(['mke2fs', 'mkswap', 'mkfs.fat', 'mkfs.vfat', 'mkfs.ntfs', 'mkfs.ext4'])

/** macOS 磁盘擦除 */
const DISKUTIL_WIPE_EXES = new Set(['eraseDisk', 'eraseVolume', 'zeroDisk', 'randomDisk', 'secureErase'])

/** 目标是真块设备 / 盘符，而不是磁盘镜像文件 */
function isBlockDeviceOrDrive(p) {
  const s = String(p || '').toLowerCase().replace(/\\/g, '/')
  if (!s) return false
  if (/^[a-z]:$/i.test(s)) return true
  if (s.startsWith('/dev/')) return true
  if (s.startsWith('//./physicaldrive') || s.startsWith('//./harddisk')) return true
  return false
}

/** 开关型 token：-x / --xxx，以及 cmd 的 /s /q 短开关（不能把 /dev/sdb1 这种路径当开关） */
function isFlagToken(t) {
  return /^--?[a-z0-9]/i.test(t) || /^\/[a-z0-9]{1,3}$/i.test(t)
}

/** PowerShell 磁盘操作 cmdlet：用 -DriveLetter C 指定盘符 */
const DISK_CMDLETS = new Set(['clear-disk', 'initialize-disk', 'format-volume', 'remove-partition'])

/**
 * 格式化类命令分级：目标是真块设备（/dev/sda、C:）才灾难级；
 * 目标是普通文件（./tmp/fake.img 这类磁盘镜像）属于日常操作，放行——
 * 否则所有拿镜像文件做实验的人都会被拦死。
 */
function analyzeFormatTool(rawExe, exe, tokens, idx) {
  // diskpart 是磁盘销毁的经典入口，且能执行任意脚本，一律拦
  if (exe === 'diskpart') {
    return { kind: 'disk-wipe', summary: `diskpart 可执行任意磁盘/分区销毁操作：${rawExe}` }
  }
  // 这四个 cmdlet 只操作物理磁盘（盘符/磁盘号都是参数），没有「镜像文件」变体，一律拦
  if (DISK_CMDLETS.has(exe)) {
    return { kind: 'disk-wipe', summary: `磁盘 / 分区销毁操作：${rawExe}` }
  }
  const rest = tokens.slice(idx + 1)
  const positional = rest.filter((t) => !isFlagToken(t))
  // Format-Volume -DriveLetter C：盘符是不带冒号的单个字母
  const psDrive = DISK_CMDLETS.has(exe) && rest.some((t) => /^[a-z]$/i.test(t))
  if (positional.some((t) => isBlockDeviceOrDrive(t)) || psDrive) {
    return { kind: 'disk-wipe', summary: `磁盘格式化 / 分区销毁命令：${rawExe}` }
  }
  // 没有目标却仍是格式化命令（format、mkfs 家族、磁盘 cmdlet）=> 交互式格式化，拦
  if (positional.length === 0 && (exe === 'format' || exe === 'format.com' || exe === 'mkfs'
    || MKFS_EXES.has(exe) || /^mkfs\./.test(exe) || /^newfs\./.test(exe) || DISK_CMDLETS.has(exe))) {
    return { kind: 'disk-wipe', summary: `磁盘格式化 / 分区销毁命令：${rawExe}` }
  }
  // fdisk -l / parted -l 这类只读列举，或目标是镜像文件 => 放行
  return null
}

/** 系统关键目录（删除其整体即灾难级；更深层的子路径视为日常操作） */
const CRITICAL_SYSTEM = new Set([
  'windows', 'program files', 'program files (x86)', 'programdata',
  'documents and settings', 'system volume information', '$recycle.bin',
  'boot', 'recovery',
  'etc', 'bin', 'sbin', 'usr', 'var', 'lib', 'lib32', 'lib64', 'libx32',
  'proc', 'sys', 'dev', 'srv', 'opt', 'run',
  // macOS / 其他 Unix 的关键顶层目录
  'system', 'library', 'applications', 'private', 'volumes',
])

/** 盘符挂载前缀（WSL / Cygwin 的盘根等价物） */
const DRIVE_PREFIX_DIRS = new Set(['mnt', 'cygdrive'])

/** 挂载卷根前缀：整卷被删即灾难级（/mnt/data、/media/<user>/<disk>、/Volumes/<vol>） */
const MOUNT_ROOTS = new Set(['mnt', 'media', 'cygdrive', 'volumes'])

/** UNC 共享根（WSL 分发、网络共享）：整台共享被删即灾难级 */
const UNC_HOSTS = new Set(['wsl.localhost', 'wsl$', 'localhost'])

/**
 * 日志 / 缓存类目录：整体删要拦，但带过滤条件的定向清理（日志轮转）是日常操作，放行。
 */
const FILTER_TOLERANT_DEEP = new Set([
  'var/log', 'var/log/audit', 'var/log/journal', 'var/cache', 'var/tmp', 'tmp',
])

/** Windows 系统目录下的关键子目录 */
const CRITICAL_SYSTEM_SUB = new Set([
  'system32', 'syswow64', 'winsxs', 'servicing', 'config', 'boot', 'assembly', 'firmware',
])

/**
 * 系统关键目录的深层子路径里「仍不可整体删除」的白名单。
 * 默认策略是系统目录的深层子路径放行（C:\Windows\Temp、/etc/nginx 都是日常清理），
 * 但下面这些路径删掉会直接毁掉认证/网络/启动/包管理/服务状态，必须拦。
 */
const CRITICAL_DEEP_PATHS = new Set([
  // 认证与账户
  'etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow', 'etc/sudoers', 'etc/sudoers.d',
  'etc/pam.d', 'etc/security', 'etc/ssh', 'etc/ssl', 'etc/ssl/certs', 'etc/ssl/private',
  // 启动
  'boot/grub', 'boot/grub2', 'boot/efi', 'boot/loader', 'boot/vmlinuz', 'boot/initrd.img', 'boot/initramfs',
  'etc/grub.d', 'etc/default/grub', 'etc/crypttab', 'etc/mdadm', 'etc/mdadm.conf',
  // 网络
  'etc/network', 'etc/netplan', 'etc/networkmanager', 'etc/sysconfig/network-scripts',
  'etc/hosts', 'etc/resolv.conf', 'etc/iptables',
  // 包管理 / 服务状态
  'var/lib/dpkg', 'var/lib/rpm', 'var/lib/pacman', 'var/lib/apt', 'var/lib/systemd',
  'var/lib/docker', 'var/lib/containerd', 'var/lib/kubelet', 'var/lib/etcd',
  'var/spool/cron', 'var/spool/cron/crontabs', 'var/spool/mail', 'var/spool/at',
  // 服务数据（数据库 / 中间件 / 制品库）
  'var/lib/mysql', 'var/lib/postgresql', 'var/lib/mariadb', 'var/lib/mongodb', 'var/lib/redis',
  'var/lib/rabbitmq', 'var/lib/elasticsearch', 'var/lib/grafana', 'var/lib/jenkins',
  // 日志与审计
  'var/log', 'var/log/audit', 'var/log/journal', 'var/log/auth.log', 'var/log/secure',
  // 系统命令与库
  'usr/bin', 'usr/sbin', 'usr/lib', 'usr/lib64', 'bin', 'sbin', 'lib', 'lib64',
  'lib/modules', 'lib/firmware', 'lib32', 'libx32',
  'usr/lib/modules', 'usr/lib/systemd', 'usr/share/zoneinfo',
  // 单元/规则/审计配置（服务直接失效且无备份）
  'etc/systemd/system', 'etc/udev/rules.d', 'etc/logrotate.d', 'etc/rsyslog.d', 'etc/audit',
  'etc/apparmor.d', 'etc/selinux', 'etc/cron.d', 'etc/cron.daily',
])

/**
 * 用户主目录下的「不可再生个人数据目录」：整体删除即灾难级。
 * key = 目录名（小写，含中文与本地化名），value = 命中级别。
 * 语义：这些目录「本身」被全量删除才拦截；其内部子目录 / 文件属于日常操作。
 */
const DATA_ROOTS = new Map([
  ['downloads', 'downloads'], ['下载', 'downloads'], ['下载目录', 'downloads'],
  ['documents', 'documents'], ['文档', 'documents'], ['mydocuments', 'documents'], ['my documents', 'documents'],
  ['desktop', 'desktop'], ['桌面', 'desktop'],
  ['pictures', 'media'], ['图片', 'media'], ['mypictures', 'media'], ['my pictures', 'media'],
  ['photos', 'media'], ['照片', 'media'],
  ['videos', 'media'], ['视频', 'media'], ['my videos', 'media'], ['movies', 'media'], ['影片', 'media'],
  ['music', 'media'], ['音乐', 'media'], ['my music', 'media'],
  ['contacts', 'personal'], ['通讯录', 'personal'], ['favorites', 'personal'], ['收藏夹', 'personal'],
  ['saved games', 'personal'], ['searches', 'personal'], ['3d objects', 'personal'],
  ['public', 'personal'], ['sites', 'personal'],
  ['onedrive', 'cloud'], ['dropbox', 'cloud'], ['google drive', 'cloud'], ['icloud', 'cloud'],
])

/**
 * 深层受保护路径（凭据 / 身份 / 浏览器邮件与IM数据）：以「目录片段后缀」匹配，命中即灾难级。
 * 这些目录删掉不可再生（私钥、保存的密码、书签、聊天记录、本地邮件）。
 */
const PROTECTED_TAILS = [
  { segs: ['.ssh'], kind: 'credentials' },
  { segs: ['.gnupg'], kind: 'credentials' },
  { segs: ['.password-store'], kind: 'credentials' },
  { segs: ['.pki'], kind: 'credentials' },
  { segs: ['.aws'], kind: 'credentials' },
  { segs: ['.kube'], kind: 'credentials' },
  { segs: ['.azure'], kind: 'credentials' },
  { segs: ['.config', 'gcloud'], kind: 'credentials' },
  { segs: ['library', 'keychains'], kind: 'credentials' },
  { segs: ['appdata', 'roaming', 'microsoft', 'credentials'], kind: 'credentials' },
  { segs: ['appdata', 'local', 'microsoft', 'credentials'], kind: 'credentials' },
  { segs: ['appdata', 'roaming', 'microsoft', 'protect'], kind: 'credentials' },
  { segs: ['appdata', 'local', 'microsoft', 'protect'], kind: 'credentials' },
  { segs: ['appdata', 'roaming', 'microsoft', 'crypto'], kind: 'credentials' },
  { segs: ['appdata', 'roaming', 'microsoft', 'systemcertificates'], kind: 'credentials' },
  { segs: ['appdata', 'local', 'google', 'chrome', 'user data'], kind: 'appdata' },
  { segs: ['appdata', 'local', 'google', 'chromium', 'user data'], kind: 'appdata' },
  { segs: ['appdata', 'local', 'microsoft', 'edge', 'user data'], kind: 'appdata' },
  { segs: ['appdata', 'local', 'microsoft', 'edge core', 'user data'], kind: 'appdata' },
  { segs: ['appdata', 'roaming', 'mozilla', 'firefox', 'profiles'], kind: 'appdata' },
  { segs: ['appdata', 'roaming', 'microsoft', 'windows', 'recent'], kind: 'appdata' },
  { segs: ['appdata', 'local', 'microsoft', 'outlook'], kind: 'appdata' },
  { segs: ['appdata', 'roaming', 'microsoft', 'outlook'], kind: 'appdata' },
  { segs: ['documents', 'outlook 文件'], kind: 'appdata' },
  { segs: ['documents', 'wechat files'], kind: 'appdata' },
  { segs: ['documents', 'tencent files'], kind: 'appdata' },
  // 凭据「文件」：删掉同样不可恢复（令牌、私钥、集群凭据）
  { segs: ['.aws', 'credentials'], kind: 'credentials' },
  { segs: ['.aws', 'config'], kind: 'credentials' },
  { segs: ['.kube', 'config'], kind: 'credentials' },
  { segs: ['.gnupg', 'private-keys-v1.d'], kind: 'credentials' },
  { segs: ['.gnupg', 'pubring.kbx'], kind: 'credentials' },
  { segs: ['.local', 'share', 'keyrings'], kind: 'credentials' },
  { segs: ['.config', 'keepassxc'], kind: 'credentials' },
  { segs: ['.bitwarden'], kind: 'credentials' },
  { segs: ['.1password'], kind: 'credentials' },
  { segs: ['.docker', 'config.json'], kind: 'credentials' },
  { segs: ['.netrc'], kind: 'credentials' },
  { segs: ['.npmrc'], kind: 'credentials' },
  { segs: ['.pypirc'], kind: 'credentials' },
  { segs: ['.config', 'rclone', 'rclone.conf'], kind: 'credentials' },
  { segs: ['.azure'], kind: 'credentials' },
  { segs: ['.oci'], kind: 'credentials' },
  { segs: ['.aliyun'], kind: 'credentials' },
  { segs: ['.tccli'], kind: 'credentials' },
]

/** 目录切换命令（用于跟踪「当前目录是否灾难级」） */
const CD_EXES = new Set(['cd', 'chdir', 'pushd', 'set-location', 'sl'])

/** 目标为「当前目录整体」的写法（不含 ..，.. 走相对路径解析） */
const CWD_WIPE_TARGETS = new Set(['.', './', '.\\', '*', '.*', './*', '.\\*'])

/** find 的过滤型测试参数（带过滤的删除不算全量删除） */
const FIND_FILTER_TESTS = new Set([
  '-name', '-iname', '-path', '-ipath', '-regex', '-iregex', '-type', '-size',
  '-mtime', '-mmin', '-atime', '-ctime', '-newer', '-perm', '-user', '-group',
  '-links', '-inum', '-empty', '-samefile', '-ilname', '-lname',
])

/** find 的基础路径属于这些级别时，带过滤条件也不许整体扫 */
const NEVER_SWEEP_KINDS = new Set(['root', 'drive', 'system', 'mount', 'unc', 'users-index'])

/** 受保护目录名集合（用于「通配段后仍指向受保护目录」的判定） */
const PROTECTED_TAIL_NAMES = new Set([
  ...DATA_ROOTS.keys(),
  ...PROTECTED_TAILS.map((t) => t.segs[t.segs.length - 1]),
  'users', 'home', 'root',
])

/** PowerShell 取值型参数（-Path C:\x 形式） */
const PS_VALUE_PARAMS = new Set(['-path', '-literalpath', '-filepath'])

/** 展开环境变量时使用的键 */
const ENV_KEYS = [
  'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'SYSTEMDRIVE', 'SYSTEMROOT', 'WINDIR',
  'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMDATA', 'USERNAME', 'COMPUTERNAME',
  'APPDATA', 'LOCALAPPDATA', 'PUBLIC', 'TEMP', 'TMP',
]

/**
 * 审计用系统提示词。
 * 针对小模型（1B~8B）做过实测调优：必须给足 dangerous 的 few-shot 样本，
 * 否则模型会把 robocopy /MIR、docker -v 这类手段判成 safe。
 */
const AI_SYSTEM_PROMPT = [
  '你是命令安全审计员。只依据命令本身判断，不要臆测目录用途。',
  'dangerous = 不可恢复的大规模数据损毁：',
  '  1) 删除整个系统盘/盘根（rm -rf /、rm -rf C:\\、format、mkfs、diskpart clean、dd of=/dev/sdX）',
  '  2) 删除整个用户主目录，或其「下载/文档/桌面/图片/视频/音乐」目录本身',
  '  3) 删除凭据目录（.ssh/.gnupg/.aws/.kube）或浏览器 User Data',
  '  4) 用脚本、robocopy /MIR、docker -v 挂载宿主目录、变量拼接路径等方式清空上述目录',
  '  5) 强制覆写 / 摧毁恢复能力的工具：sdelete、cipher /w、shred、dd of=、reg delete ... /f、',
  '     wbadmin delete、vssadmin delete、diskpart clean、Clear-Disk、Format-Volume',
  '**判断依据是目标路径，不是手段**：同样的 rmSync / rmtree / rm -rf，',
  '   指向项目内的构建输出或依赖目录（./dist、./build、./node_modules、./target）算 safe；',
  '   指向用户主目录、个人数据目录、凭据目录、系统目录才算 dangerous。',
  'safe = 日常操作：删构建输出(node_modules/dist/build/out/coverage/.next)、清临时目录与缓存、',
  '  删项目内文件、删受保护目录内部的单个文件或子目录、git clean、移动文件、mkdir。',
  '注意：robocopy /MIR 到用户文档目录 = 清空该目录，判 dangerous；',
  'docker run -v <宿主盘>:... 里执行 rm -rf = 清空宿主目录，判 dangerous。',
  '示例：',
  '用户：python -c "import shutil; shutil.rmtree(\'C:/Users/x/Documents\')"',
  '输出：{"verdict":"dangerous","reason":"脚本删除整个用户文档目录"}',
  '用户：robocopy C:\\empty C:\\Users\\x\\Documents /MIR',
  '输出：{"verdict":"dangerous","reason":"robocopy 镜像清空用户文档目录"}',
  '用户：docker run -v C:\\:/host alpine rm -rf /host/Users/x',
  '输出：{"verdict":"dangerous","reason":"容器内删宿主整个用户目录"}',
  '用户：docker run --rm -v /c/Users:/users alpine sh -c "rm -rf /users/x"',
  '输出：{"verdict":"dangerous","reason":"容器内路径映射到宿主用户目录并清空"}',
  '用户：node -e "require(\'fs\').rmSync(\'C:/Users/x/Pictures\',{recursive:true})"',
  '输出：{"verdict":"dangerous","reason":"脚本递归删除用户图片目录"}',
  '用户：python3 -c "import shutil; shutil.rmtree(\'./build\')"',
  '输出：{"verdict":"safe","reason":"脚本清理项目构建目录"}',
  '用户：ruby -e \'require "fileutils"; FileUtils.rm_rf("./node_modules")\'',
  '输出：{"verdict":"safe","reason":"脚本清理项目依赖目录"}',
  '用户：set P=C:\\Users\\x\\Documents && rd /s /q %P%',
  '输出：{"verdict":"dangerous","reason":"变量拼接后删整个文档目录"}',
  '用户：$P = "C:\\Users\\x\\Downloads"; Remove-Item -Recurse -Force $P',
  '输出：{"verdict":"dangerous","reason":"变量拼接后删整个下载目录"}',
  '用户：sdelete -p 3 -s C:\\Users\\x\\Documents',
  '输出：{"verdict":"dangerous","reason":"sdelete 覆盖删除用户文档目录"}',
  '用户：cipher /w:C:\\Users\\x\\Documents',
  '输出：{"verdict":"dangerous","reason":"cipher /w 反复覆写用户文档目录所在磁盘空间"}',
  '用户：reg delete HKCU\\Software /f',
  '输出：{"verdict":"dangerous","reason":"强删整个注册表软件配置项"}',
  '用户：wbadmin delete catalog',
  '输出：{"verdict":"dangerous","reason":"删除备份目录，摧毁系统恢复能力"}',
  '用户：rm -rf node_modules',
  '输出：{"verdict":"safe","reason":"清理项目依赖"}',
  '用户：rm -rf ~/Downloads/old-installer',
  '输出：{"verdict":"safe","reason":"删下载目录内的子目录"}',
  '用户：reg query HKLM\\SOFTWARE',
  '输出：{"verdict":"safe","reason":"只读查询注册表"}',
  '用户：wbadmin get versions',
  '输出：{"verdict":"safe","reason":"只读查询备份版本"}',
  '用户：git clean -fdx',
  '输出：{"verdict":"safe","reason":"清理项目内未跟踪文件，标准构建清理"}',
  '用户：docker system prune -f',
  '输出：{"verdict":"safe","reason":"清理悬空容器镜像网络，日常维护"}',
  '用户：docker volume prune -f',
  '输出：{"verdict":"safe","reason":"清理未被引用的卷，日常维护"}',
  '用户：printf \'%s\\n\' \'mkfs.ext4 /dev/sda\'',
  '输出：{"verdict":"safe","reason":"仅打印字符串，不执行任何命令"}',
  '用户：echo "rm -rf /" > note.txt',
  '输出：{"verdict":"safe","reason":"仅把字符串写入文件，不执行"}',
  '用户：robocopy .\\src .\\dst /MIR /XD node_modules .git',
  '输出：{"verdict":"safe","reason":"项目目录内镜像同步"}',
  '用户：docker run -v C:\\Users\\x\\project:/app node npm test',
  '输出：{"verdict":"safe","reason":"挂载项目目录跑测试，不涉及删除"}',
  '用户：node -e "require(\'fs\').mkdirSync(\'C:/Users/x/AppData/Local/Temp/y\',{recursive:true})"',
  '输出：{"verdict":"safe","reason":"创建临时目录"}',
  '**只判定「会真正执行」的命令**：echo / printf / cat / grep 只是输出或写入文本，',
  '   即使文本里含 mkfs、rm -rf 等字样也一律判 safe。',
].join('\n')

/** 结构化输出的 JSON Schema（LM Studio 走 json_schema，云端走 json_object） */
const AI_VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['safe', 'dangerous'] },
    reason: { type: 'string' },
  },
  required: ['verdict', 'reason'],
  additionalProperties: false,
}

/** 关思考用的 prefill：已闭合的空 think 段，模型只能从段后继续输出 */
const NO_THINK_PREFILL = 'imini\n\n</think>\n\n'

/** 需要送 AI 复核的「看起来有破坏性」的命令特征（aiScope=risky 时使用） */
const RISKY_RE = new RegExp([
  '(^|[^a-z0-9_-])(rm|rmdir|unlink|del|erase|remove-item|ri|rd)\\s',
  'format\\s', 'mkfs', 'diskpart', 'wipefs', 'shred', 'sdelete',
  'clear-disk', 'initialize-disk', 'format-volume', 'remove-partition',
  'git\\s+clean', 'find\\b[^|;]*-delete', 'vssadmin', 'dd\\s',
  'truncate\\s', '>\\s*/dev/', 'Set-Content', 'Out-File',
].join('|'), 'i')

/**
 * 只有「本地确定性规则看不见破坏意图」的命令才值得送 AI（aiScope=longtail，默认）：
 * 词法分析已经能判定的（rm/rd/Remove-Item + 已知路径）不再送，
 * 这样日常清理不会每条都付出一次推理延迟，也不会被小模型的误判打断。
 */
const LONGTAIL_RE = new RegExp([
  // 用脚本语言内联删数据：路径藏在字符串里，静态词法分析看不见
  '(python|python3|py|node|perl|ruby|php)\\s+[^|;]*(-c|-e)\\s',
  'shutil\\.rmtree', 'os\\.(remove|unlink|removedirs|system|popen)', 'subprocess',
  'fs\\.rmSync', 'rimraf\\s', '\\bexec\\s*\\(', '\\beval\\s*\\(',
  // 非删除类但同样能清空目标的工具
  'robocopy\\b[^|;]*(\\/mir|\\/purge)', '\\bsdelete\\b',
  'diskpart', '\\bformat\\s+[a-z]:', '\\bmkfs\\b',
  // 容器里挂载宿主目录再删
  '(docker|podman|nerdctl)\\s+run\\b[^|;]*-v\\s',
  // 变量拼出来的路径（无法静态展开，本地规则只能放弃）
  '(%[a-z_][a-z0-9_]*%|\\$\\{?[a-z_][a-z0-9_]*\\}?)',
  // 带过滤条件的 find -delete：可能精准删光某一类文件
  'find\\b[^|;]*-delete',
  // git clean 的激进形态
  'git\\s+clean\\b[^|;]*-[a-z]*f[a-z]*[dx]',
  // PowerShell 强制递归删除（路径含变量/拼接时本地规则判不出）
  'remove-item\\b[^|;]*-recurse',
  // 卷影副本 / 备份目录删除（本地规则只认字面 vssadmin/wbadmin，变量形态交给 AI）
  'vssadmin\\b[^|;]*delete', 'wbadmin\\b[^|;]*delete',
  // 服务级数据销毁：本地规则管文件系统，这些交给 AI 判断严重程度
  '\\b(mysql|psql|mongo|mongosh|redis-cli|rabbitmqctl|kafka-topics|etcdctl|consul)\\b',
  '\\b(rake|rails|sequelize|typeorm|prisma)\\s+.*\\b(db:(drop|reset)|schema:drop|migrate\\s+reset)\\b',
  'manage\\.py\\s+(flush|reset_db)', 'django-admin\\s+(flush|reset_db)',
  '\\b(terraform|pulumi)\\s+destroy', '\\b(kubectl|helm)\\b[^|;]*\\b(delete|uninstall|destroy)\\b',
  '\\baws\\s+(s3\\s+rm|secretsmanager\\s+delete|kms\\s+schedule-key-deletion)',
  '\\bgcloud\\s+(storage\\s+rm|kms\\s+keys\\s+versions\\s+destroy)',
  '\\baz\\s+(storage\\s+blob\\s+delete-batch|keyvault\\s+(secret|key|certificate)\\s+delete)',
  '\\b(rclone\\s+(purge|sync\\s+.*--delete)|restic\\s+forget|borg\\s+delete|tmutil\\s+delete)',
  '\\b(docker|podman)\\s+(system\\s+prune|volume\\s+(rm|prune))',
  // 循环 / 管道删除：路径在命令文本里可见的已由确定性规则（analyzeForLoop /
  // analyzePipelineDelete）拦住，这里不再送 AI——看不见路径的 AI 也只能猜，只会添误拦。
  '\\b(userdel|deluser)\\b[^|;]*-[a-z]*r',
  '\\b(rsync|unison)\\b[^|;]*--delete',
  '\\b(takeown|icacls|cacls)\\b',
  '\\b(git\\s+(push\\s+--force|filter-branch|filter-repo|reflog\\s+expire)|git\\s+gc\\s+--prune=now)',
  '\\b(shutdown|reboot|halt|poweroff|init\\s+[06]|telinit|kexec|systemctl\\s+(poweroff|isolate|set-default))\\b',
  '\\b(iptables|nft|ufw|firewall-cmd)\\b[^|;]*(-F|flush|reset|disable|panic)',
  '\\b(mdadm|pvremove|pvcreate|vgremove|lvremove|cryptsetup|zpool|btrfs|dmsetup|losetup|blkdiscard|nvme|hdparm|diskutil|e2fsck|xfs_repair|e2image)\\b',
  '\\b(mke2fs|mkswap|mkfs)\\b',
].join('|'), 'i')

/**
 * 「只是输出/写入文本、不会真正执行」的命令。
 * 这些命令即使文本里含 mkfs、rm -rf 等字样也不该送 AI——模型会照着字面判成危险。
 */
const TEXT_ONLY_EXE_RE = /^\s*(echo|printf|cat|grep|egrep|fgrep|rg|head|tail|less|more|type|man|help)\b/i

/** 是否该送 AI：触发词命中，且不是「纯文本输出」命令 */
function shouldSendToAi(text) {
  if (!LONGTAIL_RE.test(text)) return false
  // 取第一条语句的第一个词
  const first = text.split(/[\n;|&]/)[0].trim().split(/\s+/)[0] ?? ''
  if (TEXT_ONLY_EXE_RE.test(first)) return false
  return true
}

/** AI 判定结果缓存：同样的命令不重复付推理延迟 */
const AI_VERDICT_CACHE = new Map()
const AI_CACHE_LIMIT = 200

/**
 * 「无风险快路」判定：只有又短、又不碰任何受保护路径、又不是无路径破坏工具的命令，
 * 才配走关思考快路。长度本身不是风险代理——`wbadmin delete catalog` 只有 22 字符却很危险，
 * 而一长串 node_modules 清理虽然长却无害，所以要看内容而不是长度。
 */
const PROTECTED_PATH_HINT_RE = new RegExp([
  '(^|[^a-z0-9])(users|home|desktop|documents|downloads|pictures|videos|music|movies|photos',
  '|contacts|favorites|onedrive|dropbox|saved games|public|sites|volumes',
  '|\\.ssh|\\.gnupg|\\.aws|\\.kube|\\.azure|\\.password-store|keychains|user data|profiles',
  '|windows|system32|syswow64|program files|programdata|recycle\\.bin|boot|etc|usr|var|bin|sbin|lib|proc|sys|opt|srv',
  '|下载|文档|桌面|图片|视频|音乐|影片|照片|通讯录|收藏夹|用户)',
  '|/mnt/|/media/|/cygdrive/|/dev/(sd|hd|nvme|mmcblk|vd)|physicaldrive',
  '|wsl\\.localhost|wsl\\$',
].join(''), 'i')

/** 不带路径也能造成破坏的工具：不能因为「短」就走快路 */
const PATHLESS_DESTRUCTIVE_RE = new RegExp([
  '\\b(format|mkfs|diskpart|wipefs|shred|sdelete|cipher|vssadmin|wbadmin)\\b',
  '\\breg\\s+delete', '\\bclear-disk', '\\binitialize-disk', '\\bformat-volume',
  '\\bremove-partition', '\\bdd\\s', '\\bgit\\s+clean', '\\brmtree', '\\brm\\s+-[a-z]*r',
].join('|'), 'i')

function canUseFastPath(text, cfg) {
  if (String(text).length > cfg.aiNoThinkMaxLen) return false
  if (PROTECTED_PATH_HINT_RE.test(text)) return false
  if (PATHLESS_DESTRUCTIVE_RE.test(text)) return false
  return true
}

/* ------------------------------------------------------------------ *
 * 配置
 * ------------------------------------------------------------------ */

const DEFAULT_CONFIG = {
  mode: 'local',            // 'local' | 'ai'
  action: 'deny',           // 'deny' | 'ask'
  extraTools: '',           // 额外视作命令执行工具的工具名，逗号分隔
  extraPaths: '',           // 额外保护的路径，逗号分隔（支持 * 通配符）
  aiBaseUrl: 'https://api.deepseek.com/v1',
  aiApiKey: '',
  aiModel: 'deepseek-chat',
  aiTimeoutMs: 15000,
  aiFailOpen: true,
  aiScope: 'longtail',      // 'longtail'（默认，只送本地规则看不见的）| 'risky'（所有破坏性外观命令都送）
  aiStructured: 'auto',     // 'auto'（本地端点用 json_schema、远端用 json_object）| 'json_schema' | 'json_object' | 'off'
  aiNoThink: true,         // 全部关思考（用户指定）。实测：关思考 + 完整提示词 = 11/12、0.9–3.4s；
                           // 唯一漏的 docker -v 挂载已由 analyzeContainerRun 确定性规则补上
  aiNoThinkMaxLen: 100,     // auto 模式下命令长度 ≤ 此值才关思考
  aiExtraBody: '',          // 追加进请求体的 JSON，用于模型私有参数
}

/**
 * 配置 Schema。宿主在激活插件前用它校验并补全 `config`，
 * 设置界面也按它渲染表单，所以这里写全描述与默认值。
 *
 * 注意：本插件安装为 `link:` 本地 bundle 时，真实路径在 profile 的 node_modules
 * 之外，Node 向上解析不到宿主包 —— 因此 schemastery 装在插件自己的 node_modules 里
 * （见 package.json 的 dependencies）。出厂包把它声明为 peerDependencies，
 * 本地开发 bundle 则必须自带，否则 import 直接失败。
 */
export const Config = Schema.object({
  mode: Schema.union([
    Schema.const('local').description('纯本地确定性规则，零延迟、无需 API Key（推荐）'),
    Schema.const('ai').description('本地规则兜底 + 外接 AI 复核长尾命令'),
  ]).default('local').description('审核模式'),

  action: Schema.union([
    Schema.const('deny').description('直接拒绝执行并说明原因'),
    Schema.const('ask').description('弹窗请用户确认，确认后才放行'),
  ]).default('deny').description('命中灾难级规则时的动作'),

  extraTools: Schema.string()
    .default('')
    .description('额外视作「命令执行」而纳入审查的工具名，逗号分隔（内置已覆盖 bash/pwsh/cmd 等）'),

  extraPaths: Schema.string()
    .default('')
    .description('额外登记为受保护的路径，逗号分隔，支持 * 通配符'),

  aiBaseUrl: Schema.string()
    .default('https://api.deepseek.com/v1')
    .description('OpenAI 兼容接口 Base URL，仅 mode=ai 生效。本地模型用 http://127.0.0.1:1234/v1'),

  aiApiKey: Schema.string()
    .default('')
    .role('secret')
    .description('AI 接口 API Key，仅 mode=ai 生效。aiBaseUrl 指向 localhost / 127.0.0.1 时可留空'),

  aiModel: Schema.string()
    .default('deepseek-chat')
    .description('AI 模型名，仅 mode=ai 生效'),

  aiTimeoutMs: Schema.number()
    .min(1000)
    .default(15000)
    .description('AI 复核超时（毫秒）。本地小模型建议 15000~30000；开思考模式要放到 60000 以上'),

  aiFailOpen: Schema.boolean()
    .default(true)
    .description('AI 调用失败时是否放行。true=放行并记日志（本地规则仍兜底）；false=拒绝执行'),

  aiScope: Schema.union([
    Schema.const('longtail').description('只送本地规则看不出破坏意图的命令，日常清理零延迟零打扰（推荐）'),
    Schema.const('risky').description('所有带破坏性外观的命令都送 AI，更严但每条清理都要等一次推理'),
  ]).default('longtail').description('送 AI 复核的范围'),

  aiStructured: Schema.union([
    Schema.const('auto').description('本地端点用 json_schema、远端用 json_object（推荐）'),
    Schema.const('json_schema').description('强制 json_schema（LM Studio 只认这个）'),
    Schema.const('json_object').description('强制 json_object（DeepSeek / SiliconFlow 等云端）'),
    Schema.const('off').description('关闭结构化输出，不推荐：小模型会返回散文'),
  ]).default('auto').description('是否锁死 AI 输出结构'),

  aiNoThink: Schema.union([
    Schema.const(true).description('全部关思考：0.9~3.4s，实测 12/12'),
    Schema.const(false).description('全部开思考：15~90s，能推理更难的情形'),
    Schema.const('auto').description('按命令长度分流，短命令关思考'),
  ]).default(true).description('思考开关'),

  aiNoThinkMaxLen: Schema.number()
    .min(1)
    .default(100)
    .description('auto 模式下判定「短命令」的长度阈值（字符数），仅 aiNoThink=auto 生效'),

  aiExtraBody: Schema.string()
    .default('')
    .description('追加进 AI 请求体的 JSON 字符串，用于传模型私有参数（思考开关、采样参数等），优先级最高'),
})

/*
 * 配置项说明（在 profile 的 cordis.patch.yml 中以 config: 传入，见 README.md）：
 *
 *   mode        'local' | 'ai'   审核模式。local = 纯本地确定性规则，无需 API Key（默认）；
 *                                ai = 本地规则兜底 + 外接 OpenAI 兼容 AI 复核破坏性命令
 *   action      'deny' | 'ask'   命中时的动作。deny = 直接拒绝（默认）；ask = 请用户确认
 *   extraTools  逗号分隔的工具名，额外视作「命令执行」而纳入审查
 *   extraPaths  逗号分隔的路径，额外登记为受保护（支持 * 通配符）
 *   aiBaseUrl   OpenAI 兼容接口 Base URL（mode=ai）。本地模型用 http://127.0.0.1:1234/v1
 *   aiApiKey    AI 接口 API Key。仅当 aiBaseUrl 指向 localhost / 127.0.0.1 时可留空
 *   aiModel     AI 模型名
 *   aiTimeoutMs AI 复核超时（毫秒）。本地小模型建议 15000~30000；开思考模式要放到 60000 以上
 *   aiFailOpen  AI 调用失败是否放行（true=放行并记日志；false=拒绝执行）
 *   aiScope     longtail（默认）= 只把「本地规则看不出破坏意图」的命令送 AI，日常清理零延迟零打扰；
 *               risky = 所有带破坏性外观的命令都送 AI（更严，但每条清理都要等一次推理）
 *   aiStructured auto（默认）= 本地端点(localhost/127.0.0.1)用 json_schema、远端用 json_object，锁死输出结构；
 *               json_schema / json_object / off 可强制指定。小模型强烈建议开着，否则它不按 JSON 回答
 *   aiNoThink   true（当前配置）= 全部关思考。false = 全部开思考（15–90s，能推理更难的情形）；
 *               'auto' = 按内容分流。实测见 README「思考开关的实测结论」
 *   aiNoThinkMaxLen auto 模式下判定「短命令」的长度阈值（默认 100 字符）
 *   aiExtraBody 追加进请求体的 JSON 字符串，用于模型私有参数，例如思考开关：
 *               '{"chat_template_kwargs":{"enable_thinking":false}}'
 *               （注意：LM Studio 的 chat-completions 端点不会把 chat_template_kwargs 传给 GGUF 运行时，
 *                 对 MiniCPM 系列无效；也可用它覆盖 max_tokens / temperature 等，extraBody 优先级最高）
 *
 * 说明：本插件刻意保持「零 import」——不依赖 @deepseek-ai/schemastery 等宿主包，
 * 以免本地 bundle 的真实路径无法解析 profile 的 node_modules 而加载失败。
 * 因此不导出 Config schema，配置由 cordis.patch.yml 的 config 块直接传入，
 * 由下方 normalizeConfig 做校验与兜底。
 */

function normalizeConfig(config) {
  const c = config && typeof config === 'object' ? config : {}
  const str = (v, d) => (typeof v === 'string' && v.trim() ? v.trim() : d)
  // YAML 里常把数字/布尔写成字符串，这里统一容忍，避免静默落到默认值
  const num = (v, d) => {
    const n = typeof v === 'string' ? Number(v.trim()) : v
    return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : d
  }
  const bool = (v, d) => {
    if (typeof v === 'boolean') return v
    if (typeof v === 'string') {
      const s = v.trim().toLowerCase()
      if (s === 'true' || s === '1' || s === 'yes') return true
      if (s === 'false' || s === '0' || s === 'no') return false
    }
    return d
  }
  const list = (v) => {
    if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean)
    if (typeof v === 'string') return v.split(',').map((x) => x.trim()).filter(Boolean)
    return []
  }
  return {
    mode: c.mode === 'ai' ? 'ai' : 'local',
    action: c.action === 'ask' ? 'ask' : 'deny',
    extraTools: list(c.extraTools).map((x) => x.toLowerCase()),
    extraPaths: list(c.extraPaths),
    aiBaseUrl: str(c.aiBaseUrl, DEFAULT_CONFIG.aiBaseUrl).replace(/\/+$/, ''),
    aiApiKey: typeof c.aiApiKey === 'string' ? c.aiApiKey.trim() : '',
    aiModel: str(c.aiModel, DEFAULT_CONFIG.aiModel),
    aiTimeoutMs: num(c.aiTimeoutMs, DEFAULT_CONFIG.aiTimeoutMs),
    aiFailOpen: bool(c.aiFailOpen, true),
    aiScope: c.aiScope === 'risky' ? 'risky' : 'longtail',
    aiStructured: ['auto', 'json_schema', 'json_object', 'off'].includes(c.aiStructured) ? c.aiStructured : 'auto',
    aiNoThink: bool(c.aiNoThink, 'auto'),
    aiNoThinkMaxLen: num(c.aiNoThinkMaxLen, DEFAULT_CONFIG.aiNoThinkMaxLen),
    aiExtraBody: typeof c.aiExtraBody === 'string' ? c.aiExtraBody.trim() : '',
  }
}

/* ------------------------------------------------------------------ *
 * 入口
 * ------------------------------------------------------------------ */

/** 依赖 tools 服务：保证注册钩子时命令执行管线已就绪 */
export const inject = ['tools']

export function apply(ctx, config) {
  const cfg = normalizeConfig(config)
  const logger = ctx.logger

  ctx.effect(() => {
    const dispose = ctx.on('tools/pre-execute', async (exec, next) => {
      try {
        const verdict = await reviewExecution(exec, cfg, logger)
        if (verdict) return verdict
      } catch (error) {
        logger.warn(`command-safety-guard: 审查器内部错误，按放行处理：${errorMessage(error)}`)
      }
      return next()
    })
    return () => dispose()
  })

  logger.info(`command-safety-guard: 已启用（mode=${cfg.mode}, action=${cfg.action}）`)
}

/* ------------------------------------------------------------------ *
 * 审查主流程
 * ------------------------------------------------------------------ */

async function reviewExecution(exec, cfg, logger) {
  const commands = extractCommands(exec, cfg)
  if (commands.length === 0) return null

  // 1) 本地确定性规则：灾难级命中立即阻断（AI 模式同样以此为准绳）
  for (const item of commands) {
    const finding = analyzeCommandLine(item.text, item.shell, cfg)
    if (finding) {
      logger.warn(`command-safety-guard: 拦截灾难级命令 [${finding.kind}] ${finding.summary}（工具 ${exec.name}）`)
      return makeDecision(finding, cfg, exec)
    }
  }

  // 2) AI 模式：只对「本地规则看不见破坏意图」的命令做二次复核
  if (cfg.mode === 'ai') {
    for (const item of commands) {
      const send = cfg.aiScope === 'risky'
        ? RISKY_RE.test(item.text)
        : shouldSendToAi(item.text)
      if (!send) continue
      const verdict = await aiReviewCached(item.text, cfg, logger)
      if (verdict && verdict.dangerous) {
        logger.warn(`command-safety-guard: AI 判定危险并拦截：${verdict.reason || '（无理由）'}`)
        return makeDecision({ kind: 'ai', summary: `AI 审核判定为灾难级破坏性操作：${verdict.reason || '存在不可恢复的数据损毁风险'}` }, cfg, exec)
      }
    }
  }

  return null
}

/** 本地规则是否覆盖不到、值得送 AI 的判定入口（带缓存 + 关思考自适应） */
async function aiReviewCached(text, cfg, logger) {
  const key = `${cfg.aiModel}\u0000${cfg.aiNoThink}\u0000${text}`
  if (AI_VERDICT_CACHE.has(key)) return AI_VERDICT_CACHE.get(key)

  const short = canUseFastPath(text, cfg)
  const tryNoThink = cfg.aiNoThink === true || (cfg.aiNoThink === 'auto' && short)

  let verdict = null
  if (tryNoThink) {
    verdict = await aiReview([{ text, shell: 'bash' }], cfg, logger, true)
    // 关思考时没有 grammar 约束，小模型容易漂成散文；认不出 JSON 就改开思考重试一次，
    // 保证「短命令省延迟」不会把复杂判断一起省掉。
    if (!verdict || !verdict.parsed) {
      logger.info(`command-safety-guard: 关思考未得到合法 JSON，改开思考重试（${text.slice(0, 60)}）`)
      verdict = await aiReview([{ text, shell: 'bash' }], cfg, logger, false)
    }
  } else {
    verdict = await aiReview([{ text, shell: 'bash' }], cfg, logger, false)
  }

  if (AI_VERDICT_CACHE.size >= AI_CACHE_LIMIT) {
    const oldest = AI_VERDICT_CACHE.keys().next().value
    AI_VERDICT_CACHE.delete(oldest)
  }
  AI_VERDICT_CACHE.set(key, verdict)
  return verdict
}

function makeDecision(finding, cfg, exec) {
  const reason = [
    `[command-safety-guard] 已拦截灾难级破坏性命令，本次未执行。`,
    `工具：${exec.name}`,
    `原因：${finding.summary}`,
    `范围说明：本插件只拦截灾难级破坏性操作（系统盘根目录、用户主目录/桌面的全量删除、格式化等）；`,
    `日常文件删除、构建输出清理、临时目录清理等操作不受影响。`,
    `如需继续：请人工确认该操作确有必要，再手动执行；或在插件配置中把 action 改为 ask（改为弹窗确认）。`,
  ].join('\n')

  if (cfg.action === 'ask') {
    return { kind: 'ask', reason, displayReason: finding.summary }
  }
  return { kind: 'deny', reason }
}

/* ------------------------------------------------------------------ *
 * 命令提取
 * ------------------------------------------------------------------ */

function extractCommands(exec, cfg) {
  const name = String(exec.name || '').toLowerCase()
  const extra = cfg.extraTools.includes(name)
  const hinted = COMMAND_TOOL_HINTS.some((hint) => name.includes(hint))
  if (!extra && !hinted) return []

  let shell = 'bash'
  if (name.includes('pwsh') || name.includes('powershell')) shell = 'pwsh'
  else if (name.includes('cmd')) shell = 'cmd'
  else if (name.includes('fauxnix_translate')) shell = 'none'

  const texts = collectCommandStrings(exec.arguments)
  return texts.map((text) => ({ text, shell }))
}

/** 递归收集参数中的命令行文本（优先取 command/text 等键，取不到再退回所有字符串） */
function collectCommandStrings(value, out = [], depth = 0) {
  if (depth > 6) return out
  if (typeof value === 'string') {
    if (value.trim()) out.push(value)
    return out
  }
  if (Array.isArray(value)) {
    for (const item of value) collectCommandStrings(item, out, depth + 1)
    return out
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (COMMAND_KEYS.has(key.toLowerCase())) collectCommandStrings(item, out, depth + 1)
      else if (item && typeof item === 'object') collectCommandStrings(item, out, depth + 1)
    }
    if (out.length === 0) {
      for (const item of Object.values(value)) {
        if (typeof item === 'string' && item.trim()) out.push(item)
      }
    }
  }
  return out
}

/* ------------------------------------------------------------------ *
 * 命令行分析
 * ------------------------------------------------------------------ */

/**
 * 分析一整段命令行（可能含多条语句），返回首个灾难级命中。
 * 反斜杠在 bash 里是转义符、在 cmd/PowerShell 里是路径分隔符，两种语义下
 * 同一条命令的Token不同，所以各跑一遍、取先命中的结果：
 *   - `rm -rf /home/x/Docu\ments`：转义语义下等于 Documents（要拦）
 *   - `rm -rf C:\Users\<user>`：字面语义下才是 Windows 路径（要拦）
 *   - `find … -exec rm -f {} \;`：两种语义下 `\;` 都必须是字面 token，不能当语句分隔符
 */
function analyzeCommandLine(line, shell, cfg) {
  if (typeof line !== 'string' || !line.trim()) return null
  // bash 的 `#` 注释：非引号内、位于词首的 `#` 起其后整行都是注释。
  // 不剥掉会把 `rm -rf ./build # 别执行 rm -rf /` 里的注释当成第二条语句而误拦。
  if (shell !== 'cmd' && shell !== 'pwsh') line = stripBashComment(line)
  for (const unescape of [true, false]) {
    // cwd 只在命令行自身用 cd 显式设定后才被视为「已知」，
    // 避免用宿主进程 cwd 臆测 shell 真实工作目录而导致误报。
    const state = { shell, cwd: null, cwdKnown: false, cfg }
    const flat = tokenizeFlat(line, unescape)

    // 整行层面的结构：for 循环删除、管道删除（这两类跨语句段，必须先看）
    const structural = analyzeForLoop(flat, state) || analyzePipelineDelete(flat, state)
    if (structural) return structural

    const segments = scanSegments(line, unescape)
    for (const tokens of segments) {
      const finding = analyzeSegment(tokens, state)
      if (finding) return finding
    }
  }
  return null
}

/** 剥掉 bash 行内注释：引号内的 `#` 和词中的 `#`（如 `a#b`）不算注释 */
function stripBashComment(line) {
  let quote = null
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (quote) {
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i)
    }
  }
  return line
}

/**
 * 整行扁平切词：与 scanSegments 同样的词法，但把 `;` `&` `|` 也作为 token 输出、不切段。
 * for 循环和管道删除都跨语句段，需要在扁平 token 流上匹配。
 */
function tokenizeFlat(line, unescape) {
  const tokens = []
  let token = ''
  let inToken = false
  let quote = null
  const flush = () => {
    if (inToken) {
      tokens.push(token)
      token = ''
      inToken = false
    }
  }
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (quote) {
      if (ch === quote) quote = null
      else {
        token += ch
        inToken = true
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      inToken = true
      continue
    }
    if (ch === '\\') {
      const next = line[i + 1]
      if (next === '\n') {
        i++
        continue
      }
      if (next !== undefined) {
        token += unescape ? next : ch + next
        inToken = true
        i++
      }
      continue
    }
    if (ch === '\n' || ch === ';' || ch === '&' || ch === '|') {
      flush()
      // && 与 || 合成一个 token
      if ((ch === '&' || ch === '|') && line[i + 1] === ch) {
        tokens.push(ch + ch)
        i++
      } else {
        tokens.push(ch)
      }
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flush()
      continue
    }
    token += ch
    inToken = true
  }
  flush()
  return tokens
}

const SEGMENT_SEPARATORS = new Set([';', '&', '|', '&&', '||', '\n'])

/**
 * for 循环删除：`for d in <路径>; do rm -rf "$d"; done`、
 * `for /d %d in (C:\Users\x\*) do @rd /s /q "%d"`。
 * 只认「循环体含删除命令 + 迭代路径本身受保护」这一种确定性命中。
 */
function analyzeForLoop(tokens, state) {
  for (let i = 0; i < tokens.length; i++) {
    if (basename(tokens[i]).toLowerCase() !== 'for') continue
    const inIdx = tokens.findIndex((t, j) => j > i && t.toLowerCase() === 'in')
    const doIdx = tokens.findIndex((t, j) => j > inIdx && t.toLowerCase() === 'do')
    if (inIdx < 0 || doIdx < 0) continue

    const paths = tokens.slice(inIdx + 1, doIdx)
      .filter((t) => !SEGMENT_SEPARATORS.has(t))
      .map((t) => t.replace(/^[({\[]+/, '').replace(/[)}\]]+$/, ''))
      .filter((t) => t && !t.startsWith('-') && !/^%[a-z]$/i.test(t) && !/^\$\{?[a-z]\}?$/i.test(t))

    const body = tokens.slice(doIdx + 1)
    const hasDelete = body.some((t) => DELETE_EXES.has(basename(t).toLowerCase().replace(/^@/, '')))
    if (!hasDelete) continue

    for (const p of paths) {
      const verdict = classifyTarget(p, state)
      if (verdict) return verdict
    }
  }
  return null
}

/**
 * 管道删除：
 *   - `ls /home/x/Documents | xargs rm -rf`：上游产出路径，下游批量删
 *   - `echo 'rm -rf /home/x/Documents' | bash`：管道里喂给 shell 的字面命令
 * 只在「命令文本里能看见受保护路径」时命中；路径来自文件/网络的下游一律放行。
 */
function analyzePipelineDelete(tokens, state) {
  const xargsIdx = tokens.findIndex((t) => basename(t).toLowerCase() === 'xargs')
  if (xargsIdx >= 0) {
    const downstream = tokens.slice(xargsIdx + 1)
    const hasDelete = downstream.some((t) => DELETE_EXES.has(basename(t).toLowerCase()))
    if (hasDelete) {
      for (const t of tokens) {
        if (SEGMENT_SEPARATORS.has(t) || t.startsWith('-')) continue
        const verdict = classifyTarget(t, state)
        if (verdict) return verdict
      }
    }
  }
  // echo/printf '<删除命令>' | bash
  const pipedShell = tokens.some((t) => ['bash', 'sh', 'zsh', 'dash'].includes(basename(t).toLowerCase()))
  if (pipedShell) {
    for (let i = 0; i < tokens.length; i++) {
      const exe = basename(tokens[i]).toLowerCase()
      if (exe !== 'echo' && exe !== 'printf') continue
      for (let j = i + 1; j < tokens.length; j++) {
        if (SEGMENT_SEPARATORS.has(tokens[j])) break
        if (tokens[j].startsWith('-')) continue
        // printf 的格式串里带 \n \t 转义，先还原成真字符再分析
        const payload = tokens[j].replace(/\\n/g, '\n').replace(/\\t/g, '\t')
        const finding = analyzeCommandLine(payload, 'bash', state.cfg)
        if (finding) return finding
      }
    }
  }
  return null
}

/** 按引号 / 分号 / 换行 / && || | 切分成语句段，每段是 token 数组 */
function scanSegments(line, unescape) {
  const segments = []
  let tokens = []
  let token = ''
  let inToken = false
  let quote = null

  const flushToken = () => {
    if (inToken) {
      tokens.push(token)
      token = ''
      inToken = false
    }
  }
  const flushSegment = () => {
    flushToken()
    if (tokens.length > 0) segments.push(tokens)
    tokens = []
  }

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (quote) {
      if (ch === quote) quote = null
      else {
        token += ch
        inToken = true
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      inToken = true
      continue
    }
    if (ch === '\\') {
      // 反斜杠转义：`\;` 是字面分号（find -exec 的终止符），`Docu\ments` 等于 `Documents`。
      // 只有「反斜杠 + 换行」是续行，直接丢弃。
      const next = line[i + 1]
      if (next === '\n') {
        i++
        continue
      }
      if (next !== undefined) {
        if (unescape) token += next
        else token += ch + next
        inToken = true
        i++
      }
      continue
    }
    if (ch === '\n' || ch === ';' || ch === '&' || ch === '|') {
      flushSegment()
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      flushToken()
      continue
    }
    token += ch
    inToken = true
  }
  flushSegment()
  return segments
}

/** 分析单条语句段 */
function analyzeSegment(tokens, state) {
  if (!tokens || tokens.length === 0) return null

  let idx = 0
  // 跳过包装器（sudo / env / xargs …）与环境变量赋值；包装器后的选项（sudo -E）也跳过
  while (idx < tokens.length) {
    const base = basename(tokens[idx]).toLowerCase()
    if (WRAPPERS.has(base)) {
      idx++
      while (idx < tokens.length
        && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx]) || tokens[idx].startsWith('-'))) idx++
      continue
    }
    break
  }
  if (idx >= tokens.length) return null

  const rawExe = basename(tokens[idx])
  const exe = rawExe.toLowerCase().replace(/\.(exe|com|bat|ps1|psm1|sh)$/, '')

  // 嵌套 shell：bash -c "..." / cmd /c "..." / powershell -Command "..."
  const nested = analyzeNestedShell(exe, tokens, idx + 1, state)
  if (nested) return nested

  if (CD_EXES.has(exe)) return analyzeCd(tokens, idx + 1, state)

  if (exe === 'find') return analyzeFind(tokens, idx + 1, state)

  if (exe === 'git') return analyzeGit(tokens, idx + 1, state)

  if (exe === 'rsync' || exe === 'unison') return analyzeMirrorSync(exe, tokens, idx + 1, state)

  if (exe === 'docker' || exe === 'podman' || exe === 'nerdctl') return analyzeContainerRun(tokens, idx + 1, state)

  if (exe === 'userdel' || exe === 'deluser') return analyzeUserdel(tokens, idx + 1, state)

  if (exe === 'dd') return analyzeDd(tokens, idx + 1, state)

  if (exe === 'shred') return analyzeShred(tokens, idx + 1, state)

  if (exe === 'sdelete') return analyzeSdelete(tokens, idx + 1, state)

  if (exe === 'reg') return analyzeReg(tokens, idx + 1, state)

  if (exe === 'vssadmin' || exe === 'wbadmin') {
    const args = tokens.slice(idx + 1).map((t) => t.toLowerCase())
    if (args.includes('delete')) {
      const what = exe === 'vssadmin' ? '卷影副本（系统还原/备份恢复点）' : '备份目录（系统恢复能力）'
      return { kind: 'backup-destroy', summary: `删除${what}会摧毁系统的备份与恢复能力` }
    }
    return null
  }

  if (DISK_WIPE_EXES.has(exe) || /^mkfs\./.test(exe) || /^newfs\./.test(exe) || MKFS_EXES.has(exe)) {
    return analyzeFormatTool(rawExe, exe, tokens, idx)
  }

  if (exe === 'nvme') {
    const args = tokens.slice(idx + 1).map((t) => t.toLowerCase())
    if (args.some((a) => ['format', 'sanitize', 'erase', 'security-erase'].includes(a))) {
      return { kind: 'disk-wipe', summary: `NVMe 磁盘格式化 / 安全擦除：${rawExe}` }
    }
    return null
  }

  if (exe === 'hdparm') {
    const args = tokens.slice(idx + 1).map((t) => t.toLowerCase())
    if (args.some((a) => a.startsWith('--security-erase'))) {
      return { kind: 'disk-wipe', summary: 'ATA 安全擦除会不可恢复地清空磁盘' }
    }
    return null
  }

  if (DISKUTIL_WIPE_EXES.has(exe)) {
    return { kind: 'disk-wipe', summary: `macOS 磁盘擦除：${rawExe}` }
  }

  if (exe === 'blkdiscard') {
    for (const t of tokens.slice(idx + 1)) {
      if (!t.startsWith('-') && isBlockDeviceOrDrive(t)) {
        return { kind: 'disk-wipe', summary: `blkdiscard 丢弃块设备 ${t} 上的全部数据` }
      }
    }
    return null
  }

  if (DELETE_EXES.has(exe)) return analyzeDelete(exe, tokens, idx + 1, state)

  return null
}

/** bash -c / cmd /c / powershell -Command 等嵌套执行 */
function analyzeNestedShell(exe, tokens, startIdx, state) {
  const shellExes = new Set(['bash', 'sh', 'dash', 'zsh', 'cmd', 'powershell', 'pwsh'])
  if (!shellExes.has(exe)) return null

  let payload = null
  let childShell = 'bash'
  for (let i = startIdx; i < tokens.length; i++) {
    const t = tokens[i]
    const low = t.toLowerCase()
    if (low === '-c' || low === '/c' || low === '/k') {
      payload = tokens.slice(i + 1).join(' ')
      childShell = exe === 'cmd' ? 'cmd' : 'bash'
      break
    }
    if (low === '-command' || low === '-encodedcommand') {
      payload = low === '-encodedcommand'
        ? decodeBase64Utf16(tokens[i + 1] || '')
        : tokens.slice(i + 1).join(' ')
      childShell = 'pwsh'
      break
    }
    if (t.startsWith('-') || t.startsWith('/')) continue
  }
  if (!payload) return null
  return analyzeCommandLine(payload, childShell, state.cfg)
}

function decodeBase64Utf16(text) {
  try {
    return Buffer.from(text, 'base64').toString('utf16le')
  } catch {
    return ''
  }
}

/** cd / Set-Location：跟踪当前目录（仅在被显式设定后视为已知） */
function analyzeCd(tokens, startIdx, state) {
  let target = null
  for (let i = startIdx; i < tokens.length; i++) {
    const t = tokens[i]
    if (t.startsWith('-')) continue
    if (t === '-') return null // cd - 回到上一个目录，无法静态推断
    target = t
    break
  }
  // cd 不带参数 = 回到主目录
  if (target === null) {
    state.cwd = normalizePath(homeDirPath())
    state.cwdKnown = true
    return null
  }
  const norm = normalizePath(target)
  if (!norm) return null
  if (isAbsolutePath(norm)) {
    state.cwd = norm
    state.cwdKnown = true
    return null
  }
  // 相对目录：只有当前目录已知时才可解析
  if (state.cwdKnown) state.cwd = resolvePath(state.cwd, norm)
  return null
}

/** find … -delete / -exec rm */
function analyzeFind(tokens, startIdx, state) {
  const paths = []
  let hasDelete = false
  let filtered = false
  let i = startIdx

  while (i < tokens.length) {
    const t = tokens[i]
    const low = t.toLowerCase()
    if (low === '-delete') {
      hasDelete = true
      i++
      continue
    }
    if (low === '-exec' || low === '-execdir' || low === '-ok' || low === '-okdir') {
      const cmd = []
      i++
      while (i < tokens.length && tokens[i] !== ';' && tokens[i] !== '+') {
        cmd.push(tokens[i])
        i++
      }
      const exe = basename(cmd[0] || '').toLowerCase()
      if (DELETE_EXES.has(exe)) {
        hasDelete = true
        for (const arg of cmd.slice(1)) {
          if (!arg.startsWith('-') && arg !== '{}') paths.push(arg)
        }
      }
      continue
    }
    if (FIND_FILTER_TESTS.has(low)) {
      filtered = true
      i += 2
      continue
    }
    if (t.startsWith('-')) {
      i++
      continue
    }
    if (t === '(' || t === ')' || t === '!' || t === '{}') {
      i++
      continue
    }
    paths.push(t)
    i++
  }

  if (!hasDelete) return null

  // 系统级根路径（/、盘根、系统目录、挂载卷）即使带过滤条件也不能整体扫，
  // 例如 `find / -type f -delete` 会删光整个文件系统的文件。
  // 例外：日志 / 缓存目录的定向清理（日志轮转）属于日常操作。
  let pending = null
  for (const p of paths) {
    const verdict = classifyTarget(p, state)
    if (!verdict) continue
    if (NEVER_SWEEP_KINDS.has(verdict.kind) && !verdict.filterTolerant) return verdict
    if (!pending) pending = verdict
  }
  // 个人目录等：不带过滤条件才算「全量删除」
  if (filtered) return null
  if (pending) return pending

  // find . -delete 形式：只有当前目录本身灾难级时才阻断
  if (state.cwdKnown) {
    const finding = classifyNorm(state.cwd, state.cfg.extraPaths)
    if (finding) {
      return { kind: finding.kind, base: finding.base, summary: `全量删除当前目录 ${finding.base || state.cwd} 下的所有内容` }
    }
  }
  return null
}

/**
 * 容器挂载：`docker run -v <宿主路径>:<容器路径> … rm -rf …`
 * 宿主路径就在 `-v` / `--volume` 的左边，直接用确定性规则判定，
 * 不需要模型去推理挂载映射（这正是关思考时唯一漏掉的一类）。
 */
function analyzeContainerRun(tokens, startIdx, state) {
  const rest = tokens.slice(startIdx)
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i]
    const low = t.toLowerCase()
    let spec = null
    if (low === '-v' || low === '--volume') spec = rest[i + 1]
    else if (low.startsWith('--volume=')) spec = t.slice('--volume='.length)
    else if (/^-v/.test(t) && t.length > 2) spec = t.slice(2)
    if (!spec) continue
    // 宿主路径是冒号左侧；Windows 盘符（C:\x）也含冒号，取最后一段之前的部分
    const host = spec.includes(':') && !/^[a-z]:/i.test(spec)
      ? spec.slice(0, spec.indexOf(':'))
      : (/^[a-z]:/i.test(spec) ? spec.slice(0, 2) + spec.slice(2).split(':')[0] : spec)
    if (!host) continue
    const verdict = classifyTarget(host, state)
    if (verdict) return verdict
  }
  return null
}

/**
 * rsync / unison 的镜像清空：`rsync -a --delete <空目录>/ <受保护目录>/`
 * 会把目标清空成和源一致。危险在于**目标**，源是什么无关。
 */
function analyzeMirrorSync(exe, tokens, startIdx, state) {
  const rest = tokens.slice(startIdx)
  const flags = rest.filter((t) => t.startsWith('-')).map((t) => t.toLowerCase())
  let wipes = false
  if (exe === 'rsync') {
    wipes = flags.some((f) => f === '--delete' || f === '--del' || f === '--delete-before'
      || f === '--delete-after' || f === '--delete-during' || f === '--delete-delay')
  } else {
    // unison -force <root>：把指定根强制同步成对方
    const forceIdx = rest.findIndex((t) => t.toLowerCase() === '-force')
    wipes = forceIdx >= 0
  }
  if (!wipes) return null

  const positional = rest.filter((t) => !t.startsWith('-'))
  if (exe === 'unison') {
    // unison root1 root2 -force root1 的语义是「把 root2 覆写成 root1」，
    // 所以被摧毁的目标是「没有被 -force 指定的那个根」。
    const forceIdx = rest.findIndex((t) => t.toLowerCase() === '-force')
    const forced = forceIdx >= 0 ? rest[forceIdx + 1] : positional[1]
    const target = positional.find((p) => p !== forced) ?? positional[1]
    const verdict = classifyTarget(target, state)
    if (verdict) return verdict
    return null
  }
  // rsync：最后一个位置参数是目标
  if (positional.length >= 2) {
    const verdict = classifyTarget(positional[positional.length - 1], state)
    if (verdict) return verdict
  }
  return null
}

/**
 * userdel -r <用户>：连用户主目录和邮箱一起删。
 * 主目录按 /home/<user> 或 C:\Users\<user> 推断。
 */
function analyzeUserdel(tokens, startIdx, state) {
  const rest = tokens.slice(startIdx)
  const removes = rest.some((t) => /^(-r|--remove|-rf)$/i.test(t))
  if (!removes) return null
  const user = rest.find((t) => !t.startsWith('-'))
  if (!user) return null
  for (const base of ['/home', 'C:/Users', '/Users', '/mnt/c/Users']) {
    const verdict = classifyTarget(`${base}/${user}`, state)
    if (verdict) return verdict
  }
  return null
}

/** git clean：只检查显式 pathspec，默认（无 pathspec）是项目内日常清理 */
function analyzeGit(tokens, startIdx, state) {
  const paths = []
  let afterDashDash = false
  for (let i = startIdx; i < tokens.length; i++) {
    const t = tokens[i]
    if (t === '--') {
      afterDashDash = true
      continue
    }
    if (!afterDashDash && t.startsWith('-')) continue
    paths.push(t)
  }
  for (const p of paths) {
    const verdict = classifyTarget(p, state)
    if (verdict) return verdict
  }
  return null
}

/** dd if=… of=<设备> */
function analyzeDd(tokens, startIdx) {
  for (let i = startIdx; i < tokens.length; i++) {
    const t = tokens[i]
    const m = /^of=(.+)$/i.exec(t)
    const target = m ? m[1] : (/^of$/i.test(t) ? tokens[i + 1] : null)
    if (target && isDevicePath(target)) {
      return { kind: 'disk-wipe', summary: `dd 直接写入磁盘设备 ${target}（等同于格式化/擦除）` }
    }
  }
  return null
}

/** shred <设备> */
function analyzeShred(tokens, startIdx) {
  for (const t of tokens.slice(startIdx)) {
    if (!t.startsWith('-') && isDevicePath(t)) {
      return { kind: 'disk-wipe', summary: `shred 擦除磁盘设备 ${t}` }
    }
  }
  return null
}

/**
 * sdelete：只有目标是受保护目录、且不是 `-z`（清零空闲空间，不毁数据）时才拦。
 * 删单个文件仍属日常操作。
 */
function analyzeSdelete(tokens, startIdx) {
  const flags = tokens.slice(startIdx).filter((t) => /^[-/]/.test(t)).map((t) => t.toLowerCase())
  if (flags.includes('-z')) return null // 只覆写空闲空间，不删除数据
  for (const t of tokens.slice(startIdx)) {
    if (t.startsWith('-')) continue
    const verdict = classifyTarget(t, { shell: 'cmd', cwd: null, cwdKnown: false, cfg: { extraPaths: [] } })
    if (verdict) {
      return { kind: 'overwrite', base: verdict.base, summary: `sdelete 覆写并删除受保护目录 ${verdict.base}（数据不可恢复）` }
    }
  }
  return null
}

/**
 * reg delete：只拦「删整个配置项」这种不可恢复的操作，
 * 删单个应用的子键属于日常维护（卸载残留），放行。
 * 这条边界小模型画不稳，所以用确定性规则而不是问 AI。
 */
const CRITICAL_REG_KEYS = new Set([
  'hklm', 'hklm\\software', 'hklm\\system', 'hklm\\sam', 'hklm\\security',
  'hkcr', 'hkcu\\software', 'hku\\.default',
])

function analyzeReg(tokens, startIdx) {
  const args = tokens.slice(startIdx).map((t) => t.toLowerCase())
  if (!args.includes('delete')) return null
  for (const t of tokens.slice(startIdx)) {
    if (t.startsWith('-') || t === 'delete') continue
    const key = t.replace(/^["']|["']$/g, '').replace(/\//g, '\\').replace(/\\+$/, '')
    const low = key.toLowerCase()
    const norm = low
      .replace(/^hkey_local_machine(\\|$)/, 'hklm$1')
      .replace(/^hkey_current_user(\\|$)/, 'hkcu$1')
      .replace(/^hkey_classes_root(\\|$)/, 'hkcr$1')
      .replace(/^hkey_users(\\|$)/, 'hku$1')
    if (CRITICAL_REG_KEYS.has(norm)) {
      return { kind: 'registry', base: key, summary: `强删整个注册表配置项 ${key}（会导致大量软件/系统功能失效）` }
    }
    return null // 只检查第一个路径参数
  }
  return null
}

/** rm / del / rd / Remove-Item 等删除命令 */
function analyzeDelete(exe, tokens, startIdx, state) {
  // cmd 内建删除命令（del/erase/rd/rmdir）用 /s /q 形式的开关；
  // 对这类可执行名，/x 形态的 token 一律按开关解析（bash 下也不会把 /s 当路径）
  const isCmdBuiltin = CMD_DELETE_EXES.has(exe)
  const targets = []
  let recursive = false
  let i = startIdx

  while (i < tokens.length) {
    const t = tokens[i]
    const low = t.toLowerCase()

    if (isCmdBuiltin && /^\/[a-z0-9]{1,3}$/i.test(t)) {
      if (/^\/s$/i.test(t)) recursive = true
      i++
      continue
    }
    if (t.startsWith('-') && t.length > 1) {
      if (low.startsWith('--')) {
        if (low.includes('recursive')) recursive = true
      } else if (/[rR]/.test(t)) {
        recursive = true
      }
      if (PS_VALUE_PARAMS.has(low) && i + 1 < tokens.length) {
        targets.push(tokens[i + 1])
        i += 2
        continue
      }
      i++
      continue
    }
    targets.push(t)
    i++
  }

  // 非递归删除无法构成「全量删除」，一律放行
  if (!recursive) return null

  for (const raw of targets) {
    const verdict = classifyTarget(raw, state)
    if (verdict) return verdict
  }
  return null
}

/* ------------------------------------------------------------------ *
 * 路径判定
 * ------------------------------------------------------------------ */

function basename(p) {
  const s = String(p || '')
  const idx = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'))
  return idx >= 0 ? s.slice(idx + 1) : s
}

function homeDirPath() {
  return process.env.USERPROFILE || process.env.HOME
    || `${process.env.HOMEDRIVE || ''}${process.env.HOMEPATH || ''}`
    || process.cwd()
}

function envValue(key) {
  const upper = key.toUpperCase()
  if (!ENV_KEYS.includes(upper)) return ''
  if (upper === 'HOME' && !process.env.HOME) return homeDirPath()
  if (upper === 'HOMEDRIVE' || upper === 'HOMEPATH') {
    return process.env.HOMEDRIVE && process.env.HOMEPATH
      ? `${process.env.HOMEDRIVE}${process.env.HOMEPATH}`
      : ''
  }
  return process.env[upper] || ''
}

/** 展开 ~、$VAR、${VAR}、%VAR%、$env:VAR，统一分隔符，折叠重复斜杠 */
function normalizePath(raw) {
  let s = String(raw || '').trim()
  if (!s) return ''
  if (s === '~' || s.startsWith('~/') || s.startsWith('~\\')) {
    s = homeDirPath() + s.slice(1)
  }
  s = s.replace(/\$env:([A-Za-z_][A-Za-z0-9_]*)/g, (m, k) => envValue(k) || m)
  s = s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, k) => envValue(k) || m)
  s = s.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, k) => envValue(k) || m)
  s = s.replace(/%([^%\s]+)%/g, (m, k) => envValue(k) || m)
  s = s.replace(/\\/g, '/')
  s = s.replace(/\/{2,}/g, '/')
  // 绝对路径必须词法解析 . / ..，否则 `rm -rf /c/Users/x/AppData/Local/Temp/../../..`
  // 这类「深层路径 + 回溯」写法能绕过基路径分级，直接摸到盘根/主目录。
  if (isAbsolutePath(s)) s = collapseDotSegments(s)
  return s
}

/**
 * 词法解析绝对路径中的 . 与 ..（不动相对路径——相对路径的 .. 由 resolvePath 处理）。
 * 回溯超出根时收敛到根：`/a/../..` → `/`，`C:/a/../..` → `C:/`（= 盘根，判灾难级）。
 */
function collapseDotSegments(s) {
  const drive = /^([a-z]:)(?=\/|$)/i.exec(s)
  const prefix = drive ? `${drive[1]}/` : (s.startsWith('/') ? '/' : '')
  const rest = drive ? s.slice(drive[0].length) : s
  const out = []
  for (const seg of rest.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      if (out.length > 0) out.pop()
      continue // 已到根：绝对路径无法越过根，收敛
    }
    out.push(seg)
  }
  if (drive) return `${prefix}${out.join('/')}`
  return `${prefix}${out.join('/')}`
}

/** 是否为绝对路径（含盘符绝对路径，C: 与 C:/ 都算） */
function isAbsolutePath(norm) {
  return norm === '/' || norm.startsWith('/') || /^[a-z]:(\/|$)/i.test(norm)
}

/** 把相对路径解析到已知的当前目录上 */
function resolvePath(cwd, target) {
  const t = normalizePath(target)
  if (!t) return null
  if (isAbsolutePath(t)) return t
  if (!cwd) return null
  const parts = cwd.split('/').filter(Boolean)
  for (const seg of t.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') {
      parts.pop()
      continue
    }
    parts.push(seg)
  }
  return `/${parts.join('/')}`
}

/** 判定单个删除目标是否灾难级；命中返回 finding，否则 null */
function classifyTarget(raw, state) {
  let t = String(raw || '').trim()
  if (!t) return null
  t = t.replace(/^[(``]+/, '').replace(/[)`]+$/, '').trim()
  if (!t) return null

  const norm = normalizePath(t)
  if (!norm) return null

  // 「当前目录整体」类目标：rm -rf . / rm -rf *
  if (CWD_WIPE_TARGETS.has(t) || CWD_WIPE_TARGETS.has(t.toLowerCase())) {
    if (!state.cwdKnown) return null
    const finding = classifyNorm(state.cwd, state.cfg.extraPaths)
    if (finding) {
      return {
        kind: finding.kind,
        base: finding.base,
        summary: `全量删除当前目录 ${finding.base || state.cwd} 下的所有内容`,
      }
    }
    return null
  }

  // 相对路径：仅在 cwd 已知（命令行自身 cd 设定过）时才解析
  if (!isAbsolutePath(norm)) {
    if (!state.cwdKnown) return null
    return classifyNorm(resolvePath(state.cwd, norm), state.cfg.extraPaths)
  }

  return classifyNorm(norm, state.cfg.extraPaths)
}

/** 对规范化后的绝对路径做分级判定，命中返回 { kind, base, summary } */
function classifyNorm(norm, extraPaths) {
  if (!norm) return null
  const raw = norm.split('/').filter(Boolean)
  let segs = raw
  let driveRelative = false

  // 1) Windows 盘符前缀：C:/、c:\
  if (segs.length > 0 && /^[a-z]:$/i.test(segs[0])) {
    driveRelative = true
    segs = segs.slice(1)
  }
  // 2) Git Bash / MSYS 的 /c/Users/... 形式
  if (!driveRelative && segs.length > 1 && /^[a-z]$/i.test(segs[0]) && process.platform === 'win32') {
    driveRelative = true
    segs = segs.slice(1)
  }
  // 3) WSL / Cygwin 的 /mnt/c/...、/cygdrive/c/... 形式
  if (!driveRelative && segs.length > 1
    && DRIVE_PREFIX_DIRS.has(segs[0].toLowerCase()) && /^[a-z]$/i.test(segs[1])) {
    driveRelative = true
    segs = segs.slice(2)
  }
  // 4) 挂载卷根：/mnt/<卷名>/…、/media/<用户>/<盘名>/…、/Volumes/<卷名>/…
  //    卷根本体 = 整块数据卷，删掉即灾难级；卷内路径按普通路径分级。
  //    盘符型挂载（/mnt/c、/cygdrive/d）视为「不允许任何整体扫」，
  //    命名卷（/mnt/backup）只拦无条件全删，带过滤条件的定向清理放行。
  let mountRoot = false
  let mountIsDrive = false
  if (!driveRelative && segs.length > 0 && MOUNT_ROOTS.has(segs[0].toLowerCase())) {
    const head = segs[0].toLowerCase()
    let inner = segs.slice(1)
    if (head === 'media' && inner.length > 0) inner = inner.slice(1) // /media/<user>/<disk>/…
    if (inner.length === 0) {
      mountRoot = true
      segs = []
    } else {
      mountIsDrive = /^[a-z]$/i.test(inner[0])
      segs = inner.slice(1) // 去掉卷名，余下为卷内路径
      if (segs.length === 0) mountRoot = true
    }
  }
  // 5) UNC 共享根：\\wsl.localhost\<分发>\…、\\<主机>\<共享>\…
  let uncRoot = false
  if (!driveRelative && segs.length > 0 && UNC_HOSTS.has(segs[0].toLowerCase())) {
    const inner = segs.slice(1)
    if (inner.length === 0) {
      uncRoot = true
      segs = []
    } else {
      segs = inner.slice(1) // 去掉共享 / 分发名，余下为共享内路径
      if (segs.length === 0) uncRoot = true
    }
  }

  // 通配符：取第一个通配段之前的「基路径」
  const base = []
  let wildcardIdx = -1
  for (let i = 0; i < segs.length; i++) {
    const p = segs[i]
    if (/[*?]/.test(p)) {
      wildcardIdx = i
      break
    }
    base.push(p)
  }
  if (wildcardIdx >= 0 && wildcardIdx !== segs.length - 1) {
    // 通配段后面还有层级（如 ~/Downloads/*/tmp）=> 通常是定向清理嵌套子目录，放行；
    // 但若基路径本身灾难级、且后半段指向受保护目录（/home/*/Documents、/home/*/.ssh），仍要拦
    const baseLevel = classifyBase(base, driveRelative)
    if (baseLevel) {
      const tail = segs.slice(wildcardIdx + 1).map((p) => p.toLowerCase())
      if (tail.some((t) => PROTECTED_TAIL_NAMES.has(t))) {
        return { kind: baseLevel, base: baseNorm, summary: describe(baseLevel, baseNorm) }
      }
    }
    return null
  }
  // 去掉末尾通配段：`~/Downloads/*` 等价于删除整个目录内容，按 `~/Downloads` 判定；
  // `/*` 去掉后 base 为空 => 仍是「根目录全删」，交由分级处理
  if (wildcardIdx >= 0) segs = segs.slice(0, wildcardIdx)
  const driveLetter = raw.length > 0 && /^[a-z]:$/i.test(raw[0]) ? raw[0] : ''
  const baseNorm = `${driveLetter}/${base.join('/')}`

  if (mountRoot || uncRoot) {
    const kind = uncRoot ? 'unc' : (mountIsDrive ? 'mount' : 'mount-volume')
    return { kind, base: baseNorm, summary: describe(kind, norm) }
  }

  // 真实主目录前缀（兼容被迁移出 C:\Users 的配置目录）
  const homeLevel = homePrefixLevel(baseNorm)
  if (homeLevel) {
    return { kind: homeLevel, base: baseNorm, summary: describe(homeLevel, baseNorm) }
  }

  // 凭据 / 浏览器 / 邮件 / IM 等不可再生数据目录（深层后缀匹配）
  const tail = matchProtectedTail(base)
  if (tail) {
    return { kind: tail.kind, base: baseNorm, summary: describe(tail.kind, baseNorm) }
  }

  // 用户通过 extraPaths 显式保护的路径
  const extra = matchExtraPath(baseNorm, extraPaths)
  if (extra) {
    return { kind: 'extra', base: baseNorm, summary: describe('extra', extra) }
  }

  const level = classifyBase(base, driveRelative)
  if (!level) return null

  const finding = { kind: level, base: baseNorm, summary: describe(level, baseNorm) }
  // 日志 / 缓存目录：`find /var/log -name '*.gz' -delete` 这类日志轮转是日常操作
  if (FILTER_TOLERANT_DEEP.has(base.join('/').toLowerCase())) finding.filterTolerant = true
  return finding
}

/** 深层受保护路径匹配：路径尾部片段与 PROTECTED_TAILS 完全相等即命中 */
function matchProtectedTail(base) {
  if (base.length === 0) return null
  const lower = base.map((p) => p.toLowerCase())
  for (const entry of PROTECTED_TAILS) {
    const k = entry.segs.length
    if (lower.length < k) continue
    let hit = true
    for (let i = 0; i < k; i++) {
      if (lower[lower.length - k + i] !== entry.segs[i]) { hit = false; break }
    }
    if (hit) return entry
  }
  return null
}

/** 基路径是否落在真实用户主目录下（且恰好是主目录本身或其个人数据目录） */
function homePrefixLevel(baseNorm) {
  const home = normalizePath(homeDirPath()).replace(/\/+$/, '')
  if (!home || home === '/') return null
  if (baseNorm === home) return 'home'
  if (!baseNorm.startsWith(`${home}/`)) return null
  const rest = baseNorm.slice(home.length + 1).split('/').filter(Boolean)
  if (rest.length !== 1) return null
  const first = rest[0].toLowerCase()
  if (DATA_ROOTS.has(first)) return DATA_ROOTS.get(first)
  return null
}

/** 基路径分级：返回灾难级级别或 null */
function classifyBase(base, driveRelative) {
  if (base.length === 0) return driveRelative ? 'drive' : 'root'
  const lower = base.map((p) => p.toLowerCase())
  const n = base.length
  const isWin = process.platform === 'win32'

  // 盘根（Git Bash 的 /c 形式；带盘符的前缀已在 classifyNorm 剥离）
  if (n === 1) {
    if (!driveRelative && /^[a-z]$/i.test(lower[0]) && isWin) return 'drive'
    if (lower[0] === 'root') return 'home'
    if (lower[0] === 'users' || lower[0] === 'home') return 'users-index'
    if (segMatchesCritical(lower[0])) return 'system'
    return null
  }

  // 用户目录树：<users|home>/<user>[/<个人目录>]
  if (lower[0] === 'users' || lower[0] === 'home') {
    if (n === 2) return 'home'
    if (n === 3 && DATA_ROOTS.has(lower[2])) return DATA_ROOTS.get(lower[2])
    if (n === 4 && lower[2] === 'onedrive' && DATA_ROOTS.has(lower[3])) return DATA_ROOTS.get(lower[3])
    return null
  }

  // 系统关键目录（仅整体或直属通配删除算灾难级，深层子路径放行）
  if (segMatchesCritical(lower[0])) {
    if (n === 2 && CRITICAL_SYSTEM_SUB.has(lower[1])) return 'system'
    // 少数深层路径删掉会直接毁掉认证/网络/启动/包管理/服务状态
    if (CRITICAL_DEEP_PATHS.has(base.join('/').toLowerCase())) return 'system'
    return null
  }

  // 其余深层路径：日常操作
  return null
}

/**
 * 顶级目录名是否属于系统关键目录。
 * 兼容 "Program Files (x86)" / "Windows.old" / "System Volume Information" 之类变体：
 * 关键名之后紧跟空白、点、括号或连字符才算同一目录。
 */
function segMatchesCritical(seg) {
  const s = String(seg || '').toLowerCase().trim()
  for (const c of CRITICAL_SYSTEM) {
    if (s === c) return c
    if (s.startsWith(c) && /^[\s.\-(]/.test(s.slice(c.length))) return c
  }
  return null
}

function describe(level, display, raw) {
  switch (level) {
    case 'root':
      return `全量删除系统根目录 ${display || '/'}（该操作会摧毁整个文件系统）`
    case 'drive':
      return `全量删除整个磁盘 ${display}（该操作会摧毁盘上全部数据）`
    case 'mount':
      return `全量删除整个挂载数据卷 ${display}（该操作会摧毁卷上全部数据）`
    case 'mount-volume':
      return `全量删除整个挂载数据卷 ${display}（该操作会摧毁卷上全部数据）`
    case 'unc':
      return `全量删除整个网络共享 / WSL 分发 ${display}（该操作会摧毁共享内全部数据）`
    case 'home':
      return `全量删除用户主目录 ${display}`
    case 'desktop':
      return `全量删除用户桌面目录 ${display}`
    case 'documents':
      return `全量删除用户文档目录 ${display}`
    case 'downloads':
      return `全量删除用户下载目录 ${display}（下载内容通常没有备份）`
    case 'media':
      return `全量删除用户照片 / 视频 / 音乐目录 ${display}（这类数据通常没有备份）`
    case 'personal':
      return `全量删除用户个人数据目录 ${display}（联系人 / 收藏夹等不可再生）`
    case 'cloud':
      return `全量删除云同步目录 ${display}（会连带清空云端与其他设备的数据）`
    case 'credentials':
      return `全量删除凭据 / 身份目录 ${display}（私钥、保存的密码与证书删掉不可恢复）`
    case 'appdata':
      return `全量删除应用数据目录 ${display}（浏览器数据 / 邮件 / 聊天记录等删掉不可恢复）`
    case 'users-index':
      return `全量删除全部用户配置目录 ${display}`
    case 'system':
      return `全量删除系统关键目录 ${display}（会导致系统无法启动）`
    case 'disk-wipe':
      return '执行磁盘格式化 / 分区表销毁操作'
    case 'backup-destroy':
      return `删除系统备份/恢复组件 ${display}（会摧毁系统的自我修复能力）`
    case 'registry':
      return `强删整个注册表配置项 ${display}（会导致大量软件与系统功能失效）`
    case 'overwrite':
      return `覆写并删除受保护目录 ${display}（数据不可恢复）`
    case 'extra':
      return `全量删除受保护目录 ${display}（该路径已在插件 extraPaths 中登记保护）`
    case 'ai':
      return String(raw)
    default:
      return `全量删除 ${display}`
  }
}

/**
 * 匹配用户配置的额外保护路径。
 * 语义：目标必须是受保护路径本身，或其「直属通配子项」（/srv/backup 或 /srv/backup/*）；
 * 受保护路径的更深层子路径属于日常操作，不拦截。
 */
function matchExtraPath(norm, extraPaths) {
  if (!extraPaths || extraPaths.length === 0) return null
  const parts = norm.split('/').filter(Boolean)
  for (const raw of extraPaths) {
    const pat = normalizePath(raw).split('/').filter(Boolean)
    if (pat.length === 0) continue
    const wildcardTail = parts.length === pat.length + 1 && /[*?]/.test(parts[parts.length - 1])
    if (parts.length !== pat.length && !wildcardTail) continue
    let ok = true
    for (let i = 0; i < pat.length; i++) {
      const p = pat[i]
      if (p === '**') continue
      if (/[*?]/.test(p)) {
        if (!wildcardMatch(parts[i], p)) {
          ok = false
          break
        }
      } else if (String(parts[i]).toLowerCase() !== p.toLowerCase()) {
        ok = false
        break
      }
    }
    if (ok) return `/${pat.join('/')}`
  }
  return null
}

function wildcardMatch(text, pattern) {
  const esc = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`^${esc}$`, 'i').test(text)
}

function isDevicePath(p) {
  const s = String(p || '').toLowerCase().replace(/\\/g, '/')
  return /^\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|zd|loop|disk|mapper|md)/.test(s)
    || s.startsWith('//./physicaldrive')
    || s.startsWith('//./harddisk')
}

/* ------------------------------------------------------------------ *
 * AI 复核
 * ------------------------------------------------------------------ */

/** 本地端点（LM Studio / Ollama / vLLM 等）不需要 API Key */
function isLocalEndpoint(url) {
  return /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)(:\d+)?(\/|$)/i.test(String(url || ''))
}

/**
 * 结构化输出：本地端点(LM Studio)只认 json_schema，云端(DeepSeek/OpenAI)用 json_object。
 * 返回 null 表示不带 response_format。
 */
function buildResponseFormat(cfg) {
  const kind = cfg.aiStructured === 'auto'
    ? (isLocalEndpoint(cfg.aiBaseUrl) ? 'json_schema' : 'json_object')
    : cfg.aiStructured
  if (kind === 'off') return null
  if (kind === 'json_schema') {
    return { type: 'json_schema', json_schema: { name: 'verdict', strict: true, schema: AI_VERDICT_SCHEMA } }
  }
  return { type: 'json_object' }
}

async function aiReview(commands, cfg, logger, noThinkOverride) {
  const noThink = noThinkOverride === undefined ? cfg.aiNoThink === true : noThinkOverride === true
  if (!cfg.aiApiKey && !isLocalEndpoint(cfg.aiBaseUrl)) {
    logger.warn('command-safety-guard: mode=ai 但未配置 aiApiKey，跳过 AI 复核，仅以本地规则判定')
    return null
  }
  // 关思考有两种机制，按端点选：
  //   - 本地端点（LM Studio）：chat_template_kwargs 不会透传给 GGUF，只能用 prefill 空 think 块
  //   - 远端（Qwen3 / SiliconFlow 等）：顶层 `enable_thinking: false`，且能同时保留结构化输出
  // 注意：`chat_template_kwargs.enable_thinking` 在 SiliconFlow 上会让请求挂住不返回，千万别用。
  const usePrefill = noThink && isLocalEndpoint(cfg.aiBaseUrl)
  const responseFormat = usePrefill ? null : buildResponseFormat(cfg)
  const messages = [
    { role: 'system', content: AI_SYSTEM_PROMPT },
    { role: 'user', content: commands.map((c) => c.text).join('\n') },
  ]
  if (usePrefill) {
    // prefill 一个「空思考块」：模型从已闭合的 think 段之后继续生成，等价于关掉思考。
    // 注意它和 json_schema 互斥（grammar 会拒绝 prefill 里的 think 标签，llama.cpp 报 400）。
    messages.push({ role: 'assistant', content: NO_THINK_PREFILL })
  }
  let extra = {}
  if (cfg.aiExtraBody) {
    try {
      extra = JSON.parse(cfg.aiExtraBody)
    } catch (error) {
      logger.warn(`command-safety-guard: aiExtraBody 不是合法 JSON，已忽略：${errorMessage(error)}`)
    }
  }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), cfg.aiTimeoutMs)
  try {
    const headers = { 'content-type': 'application/json' }
    if (cfg.aiApiKey) headers.authorization = `Bearer ${cfg.aiApiKey}`
    const res = await fetch(`${cfg.aiBaseUrl}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: cfg.aiModel,
        temperature: 0,
        // 小模型开思考时 reasoning 会占掉大量 token，300 会被截断成空 content
        max_tokens: 1200,
        // 部分端点（SiliconFlow）在缺少 stream:false 时会把响应挂住不返回
        stream: false,
        messages,
        // 远端关思考：顶层 enable_thinking（SiliconFlow/Qwen3 的标准做法）
        ...noThink && !usePrefill ? { enable_thinking: false } : {},
        ...responseFormat === null ? {} : { response_format: responseFormat },
        ...extra,
      }),
      signal: controller.signal,
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json()
    const content = data?.choices?.[0]?.message?.content
    // 关思考时没有 grammar 约束，模型容易漂成散文；此时只认 JSON，不搞关键词兜底，
    // 避免把一段解释文字误判成 dangerous 而拦下日常操作。
    return parseVerdict(typeof content === 'string' ? content : '', logger, noThink)
  } catch (error) {
    const msg = errorMessage(error)
    if (cfg.aiFailOpen) {
      logger.warn(`command-safety-guard: AI 复核失败，按放行处理（aiFailOpen=true）：${msg}`)
      return null
    }
    return { dangerous: true, reason: `AI 复核失败且 aiFailOpen=false：${msg}` }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * 清洗模型返回的理由文本。
 * 小模型偶发把中文输出成乱码（字符落到希腊/科普特等区），这种文本对用户没有信息量，
 * 直接判为无效，让调用方退回通用说明。
 */
function sanitizeReason(text) {
  let s = String(text == null ? '' : text).replace(/\s+/g, ' ').trim()
  if (!s) return ''
  let bad = 0
  for (const ch of s) {
    const c = ch.codePointAt(0)
    const ok = (c >= 0x20 && c <= 0x7e)          // ASCII 可打印
      || (c >= 0x4e00 && c <= 0x9fff)            // CJK 汉字
      || (c >= 0x3000 && c <= 0x303f)            // CJK 标点
      || (c >= 0xff00 && c <= 0xffef)            // 全角字符
    if (!ok) bad++
  }
  if (bad / s.length > 0.15) return ''
  return s.length > 80 ? `${s.slice(0, 80)}…` : s
}

function verdictFrom(verdict, reason) {
  const v = String(verdict || '').toLowerCase()
  return {
    dangerous: v === 'dangerous' || v === 'block' || v === 'deny',
    // 先反转义（小模型会把中文双重转义成字面 \uXXXX），再清洗乱码
    reason: sanitizeReason(unescapeJsonString(reason)),
    parsed: true,
  }
}

function unescapeJsonString(s) {
  return String(s || '')
    .replace(/\\u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\n/g, ' ')
    .replace(/\\t/g, ' ')
    .replace(/\\r/g, ' ')
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\')
}

/**
 * 解析模型返回的判定。小模型的 JSON 时常不规范（截断、多余文本、字段顺序乱），
 * 所以依次尝试：整体 JSON.parse → 正则抽 verdict/reason → 关键词兜底。
 * jsonOnly=true（关思考、无 grammar 约束）时禁用关键词兜底：认不出 JSON 就放行，
 * 宁可漏审，也不能把解释文字误判成 dangerous。
 */
function parseVerdict(text, logger, jsonOnly) {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text)
  const candidate = fenced ? fenced[1] : text
  const jsonMatch = /\{[\s\S]*\}/.exec(candidate)
  if (jsonMatch) {
    try {
      const obj = JSON.parse(jsonMatch[0])
      return verdictFrom(obj.verdict, obj.reason)
    } catch {
      /* 落到正则抽取 */
    }
    const v = /"verdict"\s*:\s*"(safe|dangerous|block|deny)"/i.exec(candidate)
    if (v) {
      const r = /"reason"\s*:\s*"((?:[^"\\]|\\.)*)"/i.exec(candidate)
      if (logger) {
        logger.warn(`command-safety-guard: AI 返回的 JSON 无法直接解析，已按字段抽取：${candidate.replace(/\s+/g, ' ').slice(0, 120)}`)
      }
      return verdictFrom(v[1], r ? unescapeJsonString(r[1]) : '')
    }
  }
  if (jsonOnly) {
    if (logger) {
      logger.warn(`command-safety-guard: 关思考下模型未返回 JSON，本次按放行处理：${candidate.replace(/\s+/g, ' ').slice(0, 100)}`)
    }
    return { dangerous: false, reason: '', parsed: false }
  }
  if (/dangerous|block|deny|拒绝|危险|灾难/i.test(candidate)) {
    return { dangerous: true, reason: sanitizeReason(unescapeJsonString(candidate)), parsed: false }
  }
  return { dangerous: false, reason: '', parsed: false }
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error)
}

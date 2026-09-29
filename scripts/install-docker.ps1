# SafeTrace: 安装 Docker Desktop（需要管理员权限）
#
# 由主会话以「提权」方式启动：会弹一次 UAC，请点「是」。
# 全过程日志写到 install-docker.log，主会话读它来判断进度。
#
# 顺序说明：
#   1. 先启用 WSL2 相关 Windows 功能（dism）—— 这是 Docker Desktop 的前提，
#      且**必须重启**才生效；
#   2. 再装 Docker Desktop（winget）；
#   3. 报告是否需要重启。
# 注意：本脚本**不自动重启**，由人决定何时重启（重启会中断正在演示的服务）。

$ErrorActionPreference = 'Continue'
$log = 'E:\code\ai-threat-intel-demo-v1\install-docker.log'

function Log($msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg
  Write-Host $line
  Add-Content -Path $log -Value $line -Encoding UTF8
}

Set-Content -Path $log -Value ("=== Docker 安装开始 {0} ===" -f (Get-Date)) -Encoding UTF8

# ── 0. 确认是管理员 ────────────────────────────────────────────
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$isAdmin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "当前用户: $($id.Name)  管理员: $isAdmin"
if (-not $isAdmin) {
  Log 'ERROR: 未获得管理员权限，无法继续。请在弹出的 UAC 里点「是」。'
  exit 1
}

# ── 1. 启用 WSL2 相关功能 ─────────────────────────────────────
Log '--- 1/3 启用 Windows 功能（WSL + VirtualMachinePlatform）---'
foreach ($f in 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform') {
  $before = (dism /online /get-featureinfo /featurename:$f 2>&1 | Select-String -Pattern '^State :') -join ''
  Log "  $f 当前状态: $before"
}
$r1 = dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart 2>&1
Log ("  WSL 启用结果: " + (($r1 | Select-String -Pattern '操作成功|The operation completed|错误|Error') -join ' | '))
$r2 = dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart 2>&1
Log ("  VirtualMachinePlatform 启用结果: " + (($r2 | Select-String -Pattern '操作成功|The operation completed|错误|Error') -join ' | '))

# ── 2. 安装 Docker Desktop ────────────────────────────────────
Log '--- 2/3 安装 Docker Desktop（winget，下载较大，请耐心）---'
$w = Get-Command winget -ErrorAction SilentlyContinue
if (-not $w) {
  Log 'ERROR: 找不到 winget，无法自动安装。请手动下载 Docker Desktop。'
  exit 1
}
$r3 = winget install --id Docker.DockerDesktop -e --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1
$r3 | ForEach-Object { Log ("  " + $_) }
$wingetExit = $LASTEXITCODE
Log "  winget 退出码: $wingetExit"

# ── 3. 结果与后续 ─────────────────────────────────────────────
Log '--- 3/3 检查结果 ---'
$dockerExe = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
if (Test-Path $dockerExe) { Log "OK: 已安装 $dockerExe" } else { Log "未找到 $dockerExe（可能安装未完成或需重启后完成）" }

# 是否需要重启：WSL 功能刚启用时必然需要
$needReboot = $false
try {
  $pending = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop
  if ($pending) { $needReboot = $true }
} catch { }
try {
  $wslPending = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Stop
  if ($wslPending) { $needReboot = $true }
} catch { }

Log "需要重启: $needReboot"
Log '=== 完成 ==='
if ($needReboot) {
  Log '下一步：请**手动重启**，重启后 Docker Desktop 才会可用；然后回来告诉我，我接着起 compose。'
}
Log '（本脚本不会自动重启，避免打断正在运行的服务）'

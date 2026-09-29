# 直连 GitHub 下载 WSL 2.7.14 的 MSI 并安装（绕开 403 / 卡住的 winget）
#
# 为什么走这条路：
#   - Windows 功能（WSL / VirtualMachinePlatform）**已启用**（已复核）；
#   - `wsl --install`（含 `--web-download`）都报「远程调用失败(403)」；
#   - `winget install Microsoft.WSL` 两次卡死（CPU 0.4s、数分钟无下载）；
#   - 但 **GitHub release 资产本身可直连**：
#     `wsl.2.7.14.0.x64.msi` 实测 HTTP 200、247MB。
#   所以直接下 MSI 再 msiexec 装，最可靠。
#
# 以管理员身份运行（msiexec 安装需要）。

$ErrorActionPreference = 'Continue'
$log = 'E:\code\ai-threat-intel-demo-v1\install-wsl-msi.log'
$msi = 'E:\code\ai-threat-intel-demo-v1\wsl.2.7.14.0.x64.msi'
$url = 'https://github.com/microsoft/WSL/releases/download/2.7.14/wsl.2.7.14.0.x64.msi'

function Log($m) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
  Write-Host $line
  try { Add-Content -Path $log -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}
Set-Content -Path $log -Value ("=== install-wsl-msi {0} ===" -f (Get-Date)) -Encoding UTF8 -ErrorAction SilentlyContinue

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Log 'ERROR: 需要管理员权限'
  exit 1
}
Log "已提权: $($id.Name)"

# 清掉卡住的 winget（它会占用下载锁）
Get-Process -Name winget -ErrorAction SilentlyContinue | ForEach-Object {
  try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; Log "已停止 winget PID $($_.Id)" }
  catch { Log "停止 winget 失败: $($_.Exception.Message)" }
}

# ── 1. 下载 ────────────────────────────────────────────────────
if ((Test-Path $msi) -and ((Get-Item $msi).Length -gt 200MB)) {
  Log "已有完整 MSI（$([math]::Round((Get-Item $msi).Length/1MB,1))MB），跳过下载"
} else {
  Log "开始下载 $url"
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    # 不用 -UseBasicParsing 的进度条会拖慢；直接下到文件
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $msi -TimeoutSec 1800 -UseBasicParsing -ErrorAction Stop
    $sw.Stop()
    Log "下载完成: $([math]::Round((Get-Item $msi).Length/1MB,1))MB，耗时 $([math]::Round($sw.Elapsed.TotalSeconds))s"
  } catch {
    Log "下载失败: $($_.Exception.Message)"
    exit 1
  }
}

# ── 2. 安装 ────────────────────────────────────────────────────
Log '--- msiexec /i（静默）---'
$msiLog = 'E:\code\ai-threat-intel-demo-v1\wsl-msiexec.log'
$p = Start-Process -FilePath 'msiexec.exe' `
  -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$msiLog`"") `
  -Wait -PassThru
Log "msiexec 退出码: $($p.ExitCode)  （0=成功, 3010=成功但需重启）"

# ── 3. 复核 ────────────────────────────────────────────────────
Log '--- 复核 ---'
$svc = Get-Service WslService -ErrorAction SilentlyContinue
Log "WslService: $(if ($svc) { $svc.Status } else { '仍不存在' })"
(& wsl --version 2>&1) | ForEach-Object { Log ("  " + $_) }
(& wsl --status 2>&1) | ForEach-Object { Log ("  " + $_) }

$pend = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
Log "RebootPending = $pend"
Log '=== 完成 ==='
if ($p.ExitCode -eq 3010 -or $pend) { Log '需要重启。' }

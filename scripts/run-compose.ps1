# SafeTrace: 起全栈 compose（Docker 装好并**重启之后**再跑这个）
#
# 为什么单独一个脚本：装 Docker 与"起全栈"是两件事，
# 中间隔一次**重启**（WSL2 组件启用后必须重启才生效）。所以拆开，
# 重启完直接跑这个，不用再回到安装流程。
#
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run-compose.ps1
#   powershell ... -File scripts\run-compose.ps1 -Down      # 停掉并清理
#   powershell ... -File scripts\run-compose.ps1 -WebPort 5181

param(
  [switch]$Down,
  [switch]$SkipPortCheck,
  [int]$WebPort = 5173,
  [string]$ProjectName = 'safetrace'
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$log = Join-Path $root 'run-compose.log'

function Log($msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg
  Write-Host $line
  try { Add-Content -Path $log -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

Set-Content -Path $log -Value ("=== run-compose {0} ===" -f (Get-Date)) -Encoding UTF8 -ErrorAction SilentlyContinue
Set-Location $root

function Get-ComposeCmd {
  # 新版是 `docker compose`（子命令），老版是 `docker-compose`（独立 exe）。都试。
  & docker compose version *> $null
  if ($LASTEXITCODE -eq 0) { return @('docker', 'compose') }
  $legacy = Get-Command docker-compose -ErrorAction SilentlyContinue
  if ($legacy) { return @('docker-compose') }
  return $null
}

# ── 1. 前置检查 ───────────────────────────────────────────────
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Log 'ERROR: 找不到 docker。请先跑 scripts\install-docker.ps1 并**重启**。'
  exit 1
}

# 引擎可能还没起来（Docker Desktop 刚重启，或没开机自启）
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
  Log 'Docker 引擎未运行，尝试启动 Docker Desktop…'
  $exe = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
  if (Test-Path $exe) {
    Start-Process -FilePath $exe | Out-Null
    Log '  已拉起，等待引擎就绪（最多 180s）…'
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
      Start-Sleep -Seconds 3
      & docker info *> $null
      if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    }
    if (-not $ready) { Log 'ERROR: 等待引擎超时。请手动确认 Docker Desktop 已启动（可能需要先重启系统）。'; exit 1 }
    Log '  引擎已就绪'
  } else {
    Log "ERROR: 引擎未运行且找不到 $exe"
    exit 1
  }
}
Log 'Docker 引擎正常'

$compose = Get-ComposeCmd
if (-not $compose) { Log 'ERROR: 找不到 docker compose / docker-compose'; exit 1 }
Log ("使用 compose 命令: " + ($compose -join ' '))

# ── 2. 端口占用检查（本地服务会撞 8000/web 端口）─────────────
# 本仓的 compose 把 api 映射到 8000、web 映射到 5173。
# 开发时本地可能已跑着 uvicorn(8000) 与 vite(5180)，直接 up 会因端口占用失败，
# 而且报错信息不直观（容易被当成"compose 坏了"）。所以先查再动手。
if (-not $SkipPortCheck) {
  foreach ($p in 8000, $WebPort) {
    $conn = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
      $procId = $conn[0].OwningProcess
      $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$procId" -ErrorAction SilentlyContinue
      Log "WARN: 端口 $p 已被占用 (PID $procId, $($proc.Name))"
      Log "      请先停掉本地服务，或用 -WebPort 换端口；确实要强行继续加 -SkipPortCheck"
      if ($p -eq 8000) { Log '      提示：本地后端一般是 `python -m uvicorn aiintel.api.main:app --port 8000`' }
      if ($p -eq $WebPort) { Log "      提示：本地前端一般是 vite（可用 -WebPort 5181 避开）" }
      exit 2
    }
  }
  Log "端口 8000 / $WebPort 均空闲"
}

# ── 3. 组合环境变量覆盖 ───────────────────────────────────────
# 目的：把容器里的 DSN/Redis 指向 compose 内的服务名，
# 而不是 .env 里的 SQLite 路径（容器里没有 E: 盘）。
$override = Join-Path $env:TEMP 'safetrace-compose-override.yml'
@"
services:
  api:
    environment:
      POSTGRES_DSN: postgresql+psycopg://intel:intel@postgres:5432/intel
      REDIS_URL: redis://redis:6379/0
"@ | Set-Content -Path $override -Encoding UTF8
Log "已生成覆盖文件: $override（把容器内 DSN 指向服务名 postgres/redis）"

if ($Down) {
  Log '--- docker compose down -v ---'
  & $compose[0] @($compose[1..($compose.Count-1)]) -p $ProjectName -f docker-compose.yml -f $override down -v 2>&1 |
    ForEach-Object { Log ("  " + $_) }
  Log '已停止并清理卷'
  exit 0
}

# ── 4. 起全栈 ─────────────────────────────────────────────────
Log '--- docker compose up -d --build（首次会构建镜像，较慢）---'
$args = @()
if ($compose.Count -gt 1) { $args += $compose[1..($compose.Count-1)] }
$args += @('-p', $ProjectName, '-f', 'docker-compose.yml', '-f', $override, 'up', '-d', '--build')
& $compose[0] @args 2>&1 | ForEach-Object { Log ("  " + $_) }
$upExit = $LASTEXITCODE
Log "compose up 退出码: $upExit"

Log '--- 服务状态 ---'
$psArgs = @()
if ($compose.Count -gt 1) { $psArgs += $compose[1..($compose.Count-1)] }
$psArgs += @('-p', $ProjectName, '-f', 'docker-compose.yml', '-f', $override, 'ps')
& $compose[0] @psArgs 2>&1 | ForEach-Object { Log ("  " + $_) }

# ── 5. 冒烟 ───────────────────────────────────────────────────
Log '--- 冒烟：等 api 健康 ---'
$healthy = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Seconds 5
  try {
    $r = Invoke-RestMethod 'http://127.0.0.1:8000/health' -TimeoutSec 5
    Log "  /health -> $($r | ConvertTo-Json -Compress)"
    $healthy = $true
    break
  } catch { }
}
if (-not $healthy) { Log '  WARN: 40 次轮询内 /health 未就绪，请查看 docker compose logs api' }

# ── 6. 在容器里跑 accept.py（这才是 E-05 真正要的"全栈验证"）──
Log '--- 在容器内跑 python -m scripts.accept ---'
$execArgs = @()
if ($compose.Count -gt 1) { $execArgs += $compose[1..($compose.Count-1)] }
$execArgs += @('-p', $ProjectName, '-f', 'docker-compose.yml', '-f', $override, 'exec', '-T', 'api', 'python', '-m', 'scripts.accept')
& $compose[0] @execArgs 2>&1 | ForEach-Object { Log ("  " + $_) }
Log "accept 退出码: $LASTEXITCODE"

Log '=== 完成 ==='
Log "  前端: http://localhost:$WebPort"
Log '  API : http://localhost:8000/docs'
Log '  看日志: docker compose -p safetrace logs -f api'

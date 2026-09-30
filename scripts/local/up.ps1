# SafeTrace local stack launcher (no Docker).
# Starts Qdrant + llama-server (embedding) + llama-server (chat) as background processes.
# Usage: pwsh scripts/local/up.ps1 [-SkipModels]
# NOTE: comment/ASCII lines only; Chinese only inside echo strings.

param(
  [switch]$SkipModels
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$modelsDir = $env:SAFETRACE_MODELS_DIR
if (-not $modelsDir) { $modelsDir = "D:\AgentPrograms\safetrace-models" }
$thirdParty = Join-Path $root "third_party"
$qdrantExe = Join-Path $thirdParty "qdrant\qdrant.exe"
$logDir = Join-Path $root ".tmp\local"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Resolve-LlamaServer {
  $cmd = Get-Command llama-server -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidates = @(
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-server.exe"
  )
  foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
  throw "llama-server not found. Install with: winget install ggml.llamacpp"
}

function Wait-Url($url, $timeoutSeconds) {
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
      if ($r.StatusCode -eq 200) { return $true }
    } catch {
      if ($_.Exception.Response.StatusCode.value__ -eq 200) { return $true }
    }
    Start-Sleep -Milliseconds 800
  }
  return $false
}

# ---- 1. Qdrant ----
$qdrantRunning = $false
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:6333/readyz" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
  if ($r.StatusCode -eq 200) { $qdrantRunning = $true }
} catch { }

if (-not $qdrantRunning) {
  if (-not (Test-Path $qdrantExe)) {
    throw "Qdrant binary missing. Run: pwsh scripts/local/bootstrap.ps1"
  }
  $env:QDRANT__SERVICE__HOST = "127.0.0.1"
  $env:QDRANT__STORAGE__STORAGE_PATH = Join-Path $root "qdrant-storage"
  New-Item -ItemType Directory -Force -Path $env:QDRANT__STORAGE__STORAGE_PATH | Out-Null
  $qdrantLog = Join-Path $logDir "qdrant.log"
  $qdrantErr = Join-Path $logDir "qdrant.err"
  Start-Process -FilePath $qdrantExe -WorkingDirectory $thirdParty -RedirectStandardOutput $qdrantLog -RedirectStandardError $qdrantErr -WindowStyle Hidden
  Write-Output "[local] qdrant starting on :6333"
} else {
  Write-Output "[local] qdrant already running"
}
if (-not (Wait-Url "http://127.0.0.1:6333/readyz" 60)) { throw "Qdrant did not become ready" }

# ---- 2. llama-server embedding (bge-m3, dim 1024) ----
$embedUp = $false
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:8081/v1/models" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
  if ($r.StatusCode -eq 200) { $embedUp = $true }
} catch { }

if (-not $embedUp) {
  if ($SkipModels) {
    Write-Output "[local] embedding server skipped (-SkipModels)"
  } else {
    $llama = Resolve-LlamaServer
    $embModel = Join-Path $modelsDir "bge-m3-Q8_0.gguf"
    if (-not (Test-Path $embModel)) { throw "embedding model missing: $embModel" }
    Start-Process -FilePath $llama -ArgumentList "-m","$embModel","--embedding","--host","127.0.0.1","--port","8081","-ngl","99","-c","2048" -WorkingDirectory $modelsDir -RedirectStandardOutput "$logDir\emb.log" -RedirectStandardError "$logDir\emb.err" -WindowStyle Hidden
    Write-Output "[local] embedding server starting on :8081"
  }
} else {
  Write-Output "[local] embedding server already running"
}
if (-not $SkipModels) {
  if (-not (Wait-Url "http://127.0.0.1:8081/v1/models" 120)) { throw "embedding server did not become ready" }
}

# ---- 3. llama-server chat (Qwen2.5-7B-Instruct, Jev logits scoring base) ----
$chatUp = $false
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:8080/v1/models" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
  if ($r.StatusCode -eq 200) { $chatUp = $true }
} catch { }

if (-not $chatUp) {
  if ($SkipModels) {
    Write-Output "[local] chat server skipped (-SkipModels)"
  } else {
    $llama = Resolve-LlamaServer
    $chatModel = Join-Path $modelsDir "Qwen2.5-7B-Instruct-Q4_K_M.gguf"
    if (-not (Test-Path $chatModel)) { throw "chat model missing: $chatModel" }
    Start-Process -FilePath $llama -ArgumentList "-m","$chatModel","--host","127.0.0.1","--port","8080","-ngl","99","-c","8192" -WorkingDirectory $modelsDir -RedirectStandardOutput "$logDir\chat.log" -RedirectStandardError "$logDir\chat.err" -WindowStyle Hidden
    Write-Output "[local] chat server starting on :8080"
  }
} else {
  Write-Output "[local] chat server already running"
}
if (-not $SkipModels) {
  if (-not (Wait-Url "http://127.0.0.1:8080/v1/models" 180)) { throw "chat server did not become ready" }
}

Write-Output ""
Write-Output "[local] ready"
Write-Output "  qdrant        http://127.0.0.1:6333"
Write-Output "  embedding     http://127.0.0.1:8081/v1  (bge-m3, dim 1024)"
Write-Output "  chat          http://127.0.0.1:8080/v1  (Qwen2.5-7B-Instruct)"

# SafeTrace local stack bootstrap: fetch binaries and models (no Docker).
# Idempotent: existing files are skipped unless -Force is given.
# Usage: pwsh scripts/local/bootstrap.ps1 [-Force]

param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$thirdParty = Join-Path $root "third_party"
$qdrantDir = Join-Path $thirdParty "qdrant"
$modelsDir = $env:SAFETRACE_MODELS_DIR
if (-not $modelsDir) { $modelsDir = "D:\AgentPrograms\safetrace-models" }

$QDRANT_VERSION = "v1.19.1"
$QDRANT_URL = "https://github.com/qdrant/qdrant/releases/download/$QDRANT_VERSION/qdrant-x86_64-pc-windows-msvc.zip"

$EMB_MODEL = "bge-m3-Q8_0.gguf"
$EMB_URL = "https://huggingface.co/gpustack/bge-m3-GGUF/resolve/main/$EMB_MODEL"

$CHAT_MODEL = "Qwen2.5-7B-Instruct-Q4_K_M.gguf"
$CHAT_URL = "https://huggingface.co/lmstudio-community/Qwen2.5-7B-Instruct-GGUF/resolve/main/$CHAT_MODEL"

function Get-File($url, $outPath, $label) {
  if ((Test-Path $outPath) -and (-not $Force)) {
    Write-Output "[bootstrap] $label already present, skipping ($outPath)"
    return
  }
  $dir = Split-Path $outPath -Parent
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Write-Output "[bootstrap] downloading $label ..."
  # Do NOT add --noproxy for external hosts: this machine routes through a local proxy.
  $tmp = "$outPath.part"
  curl.exe -sL -o $tmp $url
  if ($LASTEXITCODE -ne 0) { throw "download failed: $url" }
  Move-Item -Force $tmp $outPath
  $size = [math]::Round((Get-Item $outPath).Length / 1MB, 1)
  Write-Output "[bootstrap] $label done ($size MB)"
}

# ---- 1. llama.cpp runtime ----
$llamaCmd = Get-Command llama-server -ErrorAction SilentlyContinue
if ($llamaCmd) {
  Write-Output "[bootstrap] llama-server present: $($llamaCmd.Source)"
} else {
  Write-Output "[bootstrap] installing llama.cpp via winget ..."
  winget install --id ggml.llamacpp --exact --accept-source-agreements --accept-package-agreements --disable-interactivity
  if ($LASTEXITCODE -ne 0) { throw "winget install ggml.llamacpp failed" }
}

# ---- 2. Qdrant Windows binary ----
$qdrantExe = Join-Path $qdrantDir "qdrant.exe"
if ((Test-Path $qdrantExe) -and (-not $Force)) {
  Write-Output "[bootstrap] qdrant.exe already present, skipping"
} else {
  Write-Output "[bootstrap] downloading Qdrant $QDRANT_VERSION ..."
  New-Item -ItemType Directory -Force -Path $qdrantDir | Out-Null
  $zip = Join-Path $qdrantDir "qdrant-win.zip"
  curl.exe -sL -o $zip $QDRANT_URL
  if ($LASTEXITCODE -ne 0) { throw "Qdrant download failed" }
  Expand-Archive -Path $zip -DestinationPath $qdrantDir -Force
  Remove-Item $zip -Force -ErrorAction SilentlyContinue
  Write-Output "[bootstrap] Qdrant installed to $qdrantExe"
}

# ---- 3. models ----
Get-File $EMB_URL (Join-Path $modelsDir $EMB_MODEL) "embedding model ($EMB_MODEL)"
Get-File $CHAT_URL (Join-Path $modelsDir $CHAT_MODEL) "chat model ($CHAT_MODEL)"

Write-Output ""
Write-Output "[bootstrap] all assets ready"
Write-Output "  models dir: $modelsDir"
Write-Output "  next step: pwsh scripts/local/up.ps1"

# SafeTrace local stack shutdown (no Docker).
# Stops Qdrant and both llama-server instances by port match.
# Usage: pwsh scripts/local/down.ps1

param(
  [switch]$KeepQdrant
)

$ErrorActionPreference = "Stop"

function Stop-ByPort($port, $label) {
  $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  if (-not $conns) {
    Write-Output "[local] $label not listening on :$port"
    return
  }
  $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
  foreach ($procId in $pids) {
    try {
      $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
      if ($p) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        Write-Output "[local] stopped $label (pid $procId, $($p.ProcessName))"
      }
    } catch { }
  }
}

if (-not $KeepQdrant) { Stop-ByPort 6333 "qdrant" }
Stop-ByPort 8081 "llama-server(embedding)"
Stop-ByPort 8080 "llama-server(chat)"

Write-Output "[local] shutdown complete"

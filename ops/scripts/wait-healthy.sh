#!/usr/bin/env bash
# =============================================================================
# wait-healthy.sh — 等待 SafeTrace P0 基础设施全部就绪
#
# 检查项：
#   1) qdrant   HTTP GET http://127.0.0.1:6333/readyz 期望 200
#   2) postgres docker compose exec postgres pg_isready（docker 不可用时跳过并提示）
#   3) langfuse HTTP GET http://127.0.0.1:3000/api/public/health（可选，默认跳过）
#
# 行为：
#   - 全部所需项就绪 -> 打印 PASS 汇总，退出码 0
#   - 超时（默认 120s，可用环境变量 WAIT_TIMEOUT 覆盖）-> 打印 FAIL 汇总，退出码 1
#   - langfuse 可选检查：设 WITH_LANGFUSE=1 时才等待，否则记 SKIP 不阻塞
#
# 用法：bash ops/scripts/wait-healthy.sh
# =============================================================================
set -euo pipefail

# 脚本位于 ops/scripts/，仓库根目录在上两级
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/ops/docker-compose.yml"

TIMEOUT="${WAIT_TIMEOUT:-120}"
DEADLINE=$(( SECONDS + TIMEOUT ))

QDRANT_URL="${QDRANT_URL:-http://127.0.0.1:6333}"
LANGFUSE_URL="${LANGFUSE_URL:-http://127.0.0.1:3000}"
PG_USER="${POSTGRES_USER:-safetrace}"
PG_DB="${POSTGRES_DB:-safetrace}"

# 汇总行：PASS / FAIL / SKIP 三种前缀
RESULTS=()

log() { printf '[wait-healthy] %s\n' "$*"; }

# docker 二进制存在且守护进程可达才算可用
docker_ready() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# 轮询某个 HTTP 端点直到返回 200 或超时；成功记 PASS，超时记 FAIL
wait_http_200() {
  local url="$1" name="$2" code
  while (( SECONDS < DEADLINE )); do
    code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      RESULTS+=("PASS $name")
      log "PASS $name <- $url"
      return 0
    fi
    sleep 2
  done
  RESULTS+=("FAIL $name")
  log "FAIL $name：${TIMEOUT}s 内未就绪 <- $url"
  return 1
}

# 轮询 postgres；docker 不可用时记 SKIP 并提示无 Docker 备选路径
wait_postgres() {
  if ! docker_ready; then
    RESULTS+=("SKIP postgres")
    log "SKIP postgres：docker 不可用，未执行 pg_isready（无 Docker 备选：SQLITE_PATH 指向本地 .sqlite 即可）"
    return 0
  fi
  while (( SECONDS < DEADLINE )); do
    if docker compose -f "$COMPOSE_FILE" exec -T postgres \
        pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
      RESULTS+=("PASS postgres")
      log "PASS postgres <- pg_isready -U $PG_USER -d $PG_DB"
      return 0
    fi
    sleep 2
  done
  RESULTS+=("FAIL postgres")
  log "FAIL postgres：${TIMEOUT}s 内 pg_isready 未通过（docker compose -f $COMPOSE_FILE ps 看状态）"
  return 1
}

log "等待基础设施就绪（超时 ${TIMEOUT}s）……"

# 1) qdrant：宿主机 HTTP 探活，必须有 Docker 之外也能独立判断
wait_http_200 "$QDRANT_URL/readyz" "qdrant" || true

# 2) postgres：经 docker compose exec 探活；无 docker 则跳过
wait_postgres || true

# 3) langfuse：可选，默认不等待
if [[ "${WITH_LANGFUSE:-0}" == "1" ]]; then
  wait_http_200 "$LANGFUSE_URL/api/public/health" "langfuse" || true
else
  RESULTS+=("SKIP langfuse")
  log "SKIP langfuse：可选检查未开启（需要时设 WITH_LANGFUSE=1）"
fi

# ---- 汇总 -------------------------------------------------------------------
log "汇总："
FAILED=0
for row in "${RESULTS[@]}"; do
  printf '  %s\n' "$row"
  if [[ "$row" == FAIL* ]]; then
    FAILED=1
  fi
done

if (( FAILED )); then
  log "有服务未就绪（已等 ${TIMEOUT}s），请查 docker compose 日志后重试"
  exit 1
fi

log "PASS：所需基础设施已就绪"

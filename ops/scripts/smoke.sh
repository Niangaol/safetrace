#!/usr/bin/env bash
# =============================================================================
# smoke.sh — SafeTrace 冒烟总入口
#
# 行为：
#   - docker 可用：先跑 ops/scripts/wait-healthy.sh 等基础设施就绪，再 npm run smoke
#   - docker 不可用：直接 npm run smoke（冒烟本身零容器依赖，离线读 fixtures）
#   - package.json 里没有 smoke 脚本：提示先等 Lead 接线，退出码 1
#
# 用法：bash ops/scripts/smoke.sh
# =============================================================================
set -euo pipefail

# 脚本位于 ops/scripts/，仓库根目录在上两级
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

log() { printf '[smoke] %s\n' "$*"; }

# docker 二进制存在且守护进程可达才算可用
docker_ready() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# npm run smoke 是否存在（读 package.json 的 scripts.smoke）
smoke_script_defined() {
  node -e 'const p = require("./package.json"); process.exit(p.scripts && p.scripts.smoke ? 0 : 1)'
}

if docker_ready; then
  log "docker 可用：先等待基础设施就绪（qdrant / postgres）"
  # wait-healthy 超时会以非零码退出，set -e 直接带崩本脚本，符合预期
  bash "$ROOT_DIR/ops/scripts/wait-healthy.sh"
else
  log "docker 不可用：冒烟零容器依赖，直接运行（向量库走 Qdrant 单文件二进制或 SQLite 备选）"
fi

if ! smoke_script_defined; then
  log "未找到 npm run smoke：scripts/smoke.ts 还没接线，请先等 Lead 完成骨架后再跑"
  exit 1
fi

log "运行 npm run smoke……"
npm run smoke

log "冒烟完成"

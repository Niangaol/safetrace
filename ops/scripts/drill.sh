#!/usr/bin/env bash
# A-06 · 自愈演练（台账 A-06 验收命令）。
# 全链路：检测→降级→故障注入→重投失败→指数退避→恢复→重放销档→验证→Trace 外发。
# 全部离线（MemoryEventStore + 内存 Trace 桩），不碰生产库、不发真实网络请求。
#
# 用法（仓库根目录）：
#   bash ops/scripts/drill.sh
# 或：npm run selfheal:drill
set -euo pipefail

cd "$(dirname "$0")/../.."

if ! command -v node >/dev/null 2>&1; then
  echo "drill: 未找到 node（需要 Node >= 24）" >&2
  exit 1
fi

echo "drill: SafeTrace 自愈演练开始（$(date -u +%Y-%m-%dT%H:%M:%SZ)）"
if node --import tsx scripts/selfheal-drill.ts; then
  echo "drill: 演练通过（exit 0）"
else
  status=$?
  echo "drill: 演练失败（exit $status）；自愈链路不可信，按 S1 级缺陷处理" >&2
  exit "$status"
fi

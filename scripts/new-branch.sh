#!/usr/bin/env bash
# 从最新 main 切出规范分支（docs/GITHUB-FLOW.md 第二节）
# 用法：scripts/new-branch.sh <type> <line> <slug>
#   scripts/new-branch.sh feat ingest kev-connector   -> feat/ingest-kev-connector
#   scripts/new-branch.sh contract schemas-v1         -> contract/schemas-v1（line 可省略）
set -euo pipefail

TYPE="${1:-}"; LINE="${2:-}"; SLUG="${3:-}"
case "$TYPE" in
  feat|fix|contract|exp|chore|docs|test|refactor|ops) ;;
  *) echo "type 必须是 feat|fix|contract|exp|chore|docs|test|refactor|ops" >&2; exit 1;;
esac

if [ -n "$LINE" ] && [ -z "$SLUG" ]; then SLUG="$LINE"; LINE=""; fi
if [ -z "$SLUG" ]; then echo "缺少主题名，例如：new-branch.sh feat ingest kev-connector" >&2; exit 1; fi

git fetch origin --quiet 2>/dev/null || echo "[提示] 无 origin 或离线，从本地 main 切出"
BASE="main"
git rev-parse --verify --quiet origin/main >/dev/null && BASE="origin/main"
BRANCH="${TYPE}/${LINE:+${LINE}-}${SLUG}"
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  echo "分支已存在：$BRANCH（直接切换）" >&2
  git checkout "$BRANCH"
else
  git checkout -b "$BRANCH" "$BASE"
fi

if [ "$TYPE" = "contract" ]; then
  echo "" >&2
  echo "[契约分支] 必须走 docs/GITHUB-FLOW.md 第五节：只追加不删改、三线 sign-off。" >&2
fi
echo "当前分支：$(git branch --show-current)"

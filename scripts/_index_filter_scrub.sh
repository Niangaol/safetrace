#!/bin/sh
# filter-branch --index-filter 用：把 tests/test_config_api.py 里的真实 key 换成假串。
#
# 为什么用独立 sh 脚本：Git for Windows 用 sh 执行过滤器，
# 在 PowerShell 里内联引号会被多层解析搞坏（实测报 ParameterSpecifiedAlready）。
# 放进文件里，两层解析都省掉。
#
# 注意：git show :"path" 读的是**索引**里的版本（index-filter 阶段正是要改索引）。

set -e

PY=python
SCRUB=/e/code/ai-threat-intel-demo-v1/scripts/_git_filter_scrub_key.py
TARGET=tests/test_config_api.py

if git ls-files --error-unmatch "$TARGET" >/dev/null 2>&1; then
  BLOB=$(git show ":$TARGET" | "$PY" "$SCRUB" | git hash-object -w --stdin)
  git update-index --cacheinfo "100644,$BLOB,$TARGET"
fi

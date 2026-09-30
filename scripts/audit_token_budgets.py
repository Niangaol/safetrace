"""审计所有 LLM 调用点的 max_tokens，标出"开了思维但预算过低"的。

规则（来自 core/llm.py）：
- `THINKING_TASKS = {enrich, reason, chat}` → **会开思维**，思维计入 completion；
- `PRO_TASKS = {enforce, reason}` → 走 pro 档，实测 pro 档思维可达 **1591** token。

所以：开思维却给 <1200 的预算 = 预算大概率被思维吃光 → 正文为空 →
调用方静默降级到兜底路径（不报错，只是能力悄悄失效）。
"""

from __future__ import annotations

import ast
from pathlib import Path

THINKING = {"enrich", "reason", "chat"}
FLOOR = 1200  # 实测 pro 档 reason 思维 1591；低于此值留不出正文空间

SRC = Path("src")
rows: list[tuple[str, int, str, int]] = []

for path in sorted(SRC.rglob("*.py")):
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if "max_tokens" not in kw or "task" not in kw:
            continue
        try:
            budget = ast.literal_eval(kw["max_tokens"])
            task = ast.literal_eval(kw["task"])
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(budget, int) or not isinstance(task, str):
            continue
        rows.append((str(path.relative_to(SRC.parent)), node.lineno, task, budget))

print(f"=== 开思维（{sorted(THINKING)}）的调用点 ===")
bad = 0
for f, ln, task, budget in sorted(rows, key=lambda r: r[3]):
    if task not in THINKING:
        continue
    flag = "  ⚠ 预算可能被思维吃光" if budget < FLOOR else ""
    if budget < FLOOR:
        bad += 1
    print(f"  {f}:{ln:<5} task={task:9} max_tokens={budget:<6}{flag}")

print()
print("=== 不开思维的调用点（小预算合理）===")
for f, ln, task, budget in sorted(rows, key=lambda r: r[3]):
    if task in THINKING:
        continue
    print(f"  {f}:{ln:<5} task={task:9} max_tokens={budget}")

print()
print(f"合计 {len(rows)} 个调用点；其中开思维且预算 <{FLOOR} 的 **{bad}** 个")

"""防回归：**开了思维的 LLM 调用必须有足够 token 预算**。

## 为什么需要这条约束

本仓模型**强制输出思维链，且思维计入 `completion_tokens`**
（见 `core/llm.py` 的注释与 `LLMResult.reasoning_tokens`）。

于是 `max_tokens` 的含义不是"正文能写多长"，而是"**思维 + 正文**一共多少"。
若按"输出只有正文"来设预算，预算会被思维吃光 → `content` 为空、
`finish_reason=length`，而 **HTTP 仍是 200**。

更麻烦的是调用方通常有兜底：拿不到结果就静默降级到规则/模板路径。
所以这类缺陷的表现不是报错，而是"**LLM 那一路从不生效**"
—— 实测发现两处：
- `enrich.consistency` 给了 **200**（实测该档思维可达 **1591**）→
  冲突理由永远是模板句；
- `enrich.cvss` 给了 **700** → 影响说明永远是规则通用句。

这条测试用 AST 扫描所有调用点，把"开了思维却预算过低"直接判为失败。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"

#: 与 `core/llm.py::THINKING_TASKS` 保持一致。**硬编码是故意的**：
#: 若有人往 THINKING_TASKS 里加任务（打开思维），这条测试会提醒他
#: 同时检查各调用点的预算是否还够。
THINKING_TASKS = {"enrich", "reason", "chat"}

#: 开思维时的最低预算。依据：实测同一模型在 `reason` 档思维用到 **1591** token，
#: 低于此值留不出正文空间。
MIN_THINKING_BUDGET = 1500


def _calls() -> list[tuple[str, int, str, int]]:
    out: list[tuple[str, int, str, int]] = []
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover
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
            except Exception:  # noqa: BLE001 - 非字面量（如变量）跳过
                continue
            if isinstance(budget, int) and isinstance(task, str):
                out.append((str(path.relative_to(SRC.parent)), node.lineno, task, budget))
    return out


def test_thinking_calls_have_adequate_budget() -> None:
    """**核心防回归**：开思维的调用点预算不得低于阈值。"""

    offenders = [
        (f, ln, task, budget)
        for f, ln, task, budget in _calls()
        if task in THINKING_TASKS and budget < MIN_THINKING_BUDGET
    ]
    assert not offenders, (
        "以下调用开了思维但 token 预算过低，思维会吃光预算导致正文为空、"
        "并**静默**降级到兜底路径：\n"
        + "\n".join(
            f"  {f}:{ln} task={task} max_tokens={b} (需 >= {MIN_THINKING_BUDGET})"
            for f, ln, task, b in offenders
        )
    )


def test_thinking_task_set_matches_core() -> None:
    """本测试硬编码的 THINKING_TASKS 必须与 core/llm.py 实际一致。

    否则 `core` 里新增一个开思维的任务时，这条防线会静默失效。
    """

    from aiintel.core.llm import THINKING_TASKS as CORE_THINKING

    assert set(CORE_THINKING) == THINKING_TASKS, (
        f"core 里是 {sorted(CORE_THINKING)}，测试里写的是 {sorted(THINKING_TASKS)}；"
        f"请同步两边并复查所有调用点预算"
    )


@pytest.mark.parametrize("task", sorted(THINKING_TASKS))
def test_each_thinking_task_has_at_least_one_caller(task: str) -> None:
    """开思维的任务**多数**该有显式调用点。

    `chat` 是路由默认档，调用点通常不显式传 `task="chat"`，所以对它豁免 ——
    否则这条"每条任务都要有调用点"的断言会因为默认档而误报。
    """

    if task == "chat":
        pytest.skip("chat 是默认档，调用点一般不显式传该值")
    assert any(t == task for _, _, t, _ in _calls()), f"没有 task={task!r} 的调用点"


def test_budget_rule_catches_a_low_budget() -> None:
    """自检：这条防线必须真能抓到低预算，而不是空转。

    构造一个"开了思维却只给 200"的假调用点，确认识别逻辑会判它不合格。
    """

    fake = [("fake.py", 1, "reason", 200), ("fake.py", 2, "enrich", 700)]
    offenders = [
        (f, ln, task, b)
        for f, ln, task, b in fake
        if task in THINKING_TASKS and b < MIN_THINKING_BUDGET
    ]
    assert len(offenders) == 2

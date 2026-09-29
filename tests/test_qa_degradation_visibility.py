"""问答降级必须**显式**上报（红线 3：禁止静默兜底）。

## 修的是什么

`get_llm().stream()` 的契约是 `AsyncIterator[str]` —— 只 yield 文本。
而流式调用**中途失败**时，router 内部会降级到本地模型（`_local_result`），
"降级了"这件事只体现在被丢弃的 `LLMResult.degraded` 上。

`QAAgent` 原先的 `degraded` 只由 `verdict.score < 0.5`（答案质量）决定，
于是**云端不可达 → 回退本地模型**时 `done.degraded` 仍是 `false`：
用户拿到一个看似正常的答案，完全不知道它不是云端模型产出的。

这与本项目红线第 3 条「兜底必须显式 —— 降级响应必须带 `degraded_to`
与用户可见标记，**禁止静默兜底**」直接冲突。

## 修法

router 增加单调递增的 `degrade_count`（任何降级路径都会 +1），
`QAAgent` 在流式调用前后做快照比较 → 任何路径的降级都能被发现，
并在 `done` 事件里给出 `degraded_reason` 与 `llm_degraded`。
"""

from __future__ import annotations

import pytest

from aiintel.services.qa.agent import QAAgent

EVIDENCE = [
    {
        "chunk_key": "vuln:v1#0",
        "owner_type": "vuln",
        "owner_id": "CVE-2026-0001",
        "content": "vLLM 存在远程代码执行 [S1]",
        "rerank_score": 0.91,
    }
]


@pytest.fixture()
def agent_with_degraded_llm(monkeypatch, stub_llm, fake_bus):
    """LLM 桩在流式调用时把自己的降级计数 +1，模拟"中途失败→降级本地"。"""

    stub_llm(
        '{"sub_questions": ["有哪些漏洞"], "queries": ["vllm"], "intent": "查"}',
        degrade_in_stream=True,
    )
    bus, _ = fake_bus
    agent = QAAgent(bus=bus)

    async def fake_retrieve(self, queries, top_k=8):
        return [dict(e) for e in EVIDENCE]

    monkeypatch.setattr(QAAgent, "retrieve", fake_retrieve)
    return agent


async def test_llm_degradation_is_reported_when_score_is_fine(
    agent_with_degraded_llm: QAAgent,
) -> None:
    """核心回归：**答案质量分正常**（stub 的 self-check 会给高分），
    但 LLM 降级了 —— `done.degraded` 必须为 true。

    修复前这条会失败：旧逻辑只看 `verdict.score < 0.5`。
    """

    events = [e async for e in agent_with_degraded_llm.answer_stream("vLLM 有哪些漏洞？")]
    done = events[-1]
    assert done["event"] == "done"
    assert done["degraded"] is True, (
        "LLM 降级未被上报 —— 用户会以为这是云端模型的正常输出（静默兜底）"
    )
    assert done.get("llm_degraded") is True, '应单独暴露"模型降级"标志'
    assert "降级" in (done.get("degraded_reason") or ""), (
        f"必须给出降级原因，实际: {done.get('degraded_reason')!r}"
    )


@pytest.fixture()
def agent_with_healthy_llm(monkeypatch, stub_llm, fake_bus):
    """对照组：LLM 不降级（默认桩）。"""

    stub_llm('{"sub_questions": ["有哪些漏洞"], "queries": ["vllm"], "intent": "查"}')
    bus, _ = fake_bus
    agent = QAAgent(bus=bus)

    async def fake_retrieve(self, queries, top_k=8):
        return [dict(e) for e in EVIDENCE]

    monkeypatch.setattr(QAAgent, "retrieve", fake_retrieve)
    return agent


async def test_no_degradation_means_flag_stays_false(agent_with_healthy_llm: QAAgent) -> None:
    """反向断言：没有降级时不能误报（避免"永远显示降级"而无意义）。"""

    events = [e async for e in agent_with_healthy_llm.answer_stream("vLLM 有哪些漏洞？")]
    done = events[-1]
    assert done["event"] == "done"
    assert done.get("llm_degraded") is False
    assert "LLM 降级" not in (done.get("degraded_reason") or "")


def test_router_exposes_monotonic_degrade_count() -> None:
    """router 必须提供单调递增的降级计数（调用方靠它做前后快照）。"""

    from aiintel.core.llm import LLMRouter

    router = LLMRouter()
    assert hasattr(router, "degrade_count"), "缺少 degrade_count，调用方无法发现降级"
    before = router.degrade_count
    assert isinstance(before, int)
    router.note_degraded(node="test", reason="单元测试")
    assert router.degrade_count == before + 1, "note_degraded 必须使其递增"

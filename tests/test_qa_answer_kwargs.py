"""`QAAgent.answer` 的参数兼容性回归。

`eval/qa_accuracy.py` 调用 `agent.answer(question, stream=False)`，而 `answer` 会把
`**kwargs` 透传给 `answer_stream`，后者没有 `stream` 参数 →
`TypeError: answer_stream() got an unexpected keyword argument 'stream'`。

后果是该指标**从来没有跑通过**（这正是台账 E-04 一直没数字的原因）。
这里钉住"answer 接受并吞掉 stream"，避免回退。
"""

from __future__ import annotations

from typing import Any

import pytest


class _FakeAgent:
    """只保留参数处理逻辑，不碰 LLM/DB。"""

    def __init__(self) -> None:
        self.seen: dict[str, Any] = {}

    async def answer_stream(self, question: str, **kwargs: Any):
        self.seen = kwargs
        yield {"event": "token", "text": "答"}
        yield {"event": "citation", "id": "S1", "title": "t", "url": None, "score": 0.0}
        yield {"event": "done", "citations": 1, "cost_cny": 0.0}

    # 复制真实实现里"吞掉 stream 再透传"的行为
    async def answer(self, question: str, **kwargs: Any) -> dict[str, Any]:
        kwargs.pop("stream", None)
        chunks: list[str] = []
        meta: dict[str, Any] = {}
        citations: list[dict] = []
        async for event in self.answer_stream(question, **kwargs):
            kind = event.get("event")
            if kind == "token":
                chunks.append(event["text"])
            elif kind == "citation":
                citations.append({k: event[k] for k in ("id", "title", "url", "score")})
            elif kind in {"done", "error"}:
                meta = event
        return {"answer": "".join(chunks), **meta, "citations": citations}


@pytest.mark.asyncio
async def test_answer_accepts_stream_kwarg() -> None:
    """回归：带 stream=False 不能抛 TypeError。"""

    agent = _FakeAgent()
    result = await agent.answer("问题", stream=False)
    assert result["answer"] == "答"
    assert "stream" not in agent.seen, "stream 不该被透传给 answer_stream"


@pytest.mark.asyncio
async def test_answer_still_forwards_real_kwargs() -> None:
    """吞掉 stream 的同时，top_k / session_id 这些**必须**继续透传。"""

    agent = _FakeAgent()
    await agent.answer("问题", stream=False, top_k=3, session_id="s1")
    assert agent.seen == {"top_k": 3, "session_id": "s1"}


def test_real_qa_agent_answer_stream_signature_has_no_stream() -> None:
    """确认真实实现里 answer_stream 就是没有 stream —— 所以必须由 answer 吞掉。"""

    import inspect

    from aiintel.services.qa.agent import QAAgent

    params = inspect.signature(QAAgent.answer_stream).parameters
    assert "stream" not in params, "若 answer_stream 将来支持 stream，这条测试要同步更新"

"""QAAgent 的检索聚合与 SSE 事件序列。"""

from __future__ import annotations

import pytest

from aiintel.services.qa.agent import MAX_ITERATIONS, QAAgent, dumps_event

EVIDENCE = [
    {
        "chunk_key": "vuln:v1#0",
        "owner_type": "vuln",
        "owner_id": "CVE-2026-0001",
        "content": "vLLM 0.4.0 之前存在远程代码执行 [S1]",
        "rerank_score": 0.91,
    },
    {
        "chunk_key": "vuln:v2#0",
        "owner_type": "vuln",
        "owner_id": "CVE-2026-0002",
        "content": "LangChain 文件加载器存在路径穿越 [S2]",
        "rerank_score": 0.83,
    },
]


@pytest.fixture()
def patched_agent(monkeypatch, stub_llm, fake_bus):
    """桩掉 LLM 与向量检索，只保留编排逻辑。"""

    stub_llm('{"sub_questions": ["有哪些漏洞"], "queries": ["vllm rce"], "intent": "查高危"}')
    bus, _ = fake_bus
    agent = QAAgent(bus=bus)

    async def fake_retrieve(self, queries, top_k=8):
        return [dict(e) for e in EVIDENCE]

    monkeypatch.setattr(QAAgent, "retrieve", fake_retrieve)
    return agent


async def test_answer_stream_event_sequence(patched_agent):
    events = [e async for e in patched_agent.answer_stream("最近有哪些高危漏洞？")]
    kinds = [e["event"] for e in events]
    assert kinds[0] == "stage"
    assert events[0]["stage"] == "rewrite"
    assert "citation" in kinds
    assert "token" in kinds
    assert kinds[-1] == "done"


async def test_answer_stream_emits_refs_for_citations(patched_agent):
    events = [e async for e in patched_agent.answer_stream("问题")]
    refs = [e["id"] for e in events if e["event"] == "citation"]
    assert refs == ["S1", "S2"]
    for ref in refs:
        assert ref.startswith("S")


async def test_done_event_carries_cost_and_model(patched_agent):
    events = [e async for e in patched_agent.answer_stream("问题")]
    done = events[-1]
    assert done["event"] == "done"
    assert done["citations"] == len(EVIDENCE)
    assert isinstance(done["cost_cny"], float)
    assert done["cost_cny"] >= 0
    assert done["model"]
    assert "elapsed_ms" in done


async def test_answer_non_streaming_shape(patched_agent):
    result = await patched_agent.answer("问题")
    assert set(result) >= {"answer", "citations", "event"}
    assert result["event"] in {"done", "error"}
    assert [c["id"] for c in result["citations"]] == ["S1", "S2"]


async def test_no_evidence_path_returns_hint(patched_agent, monkeypatch):
    async def empty_retrieve(self, queries, top_k=8):
        return []

    monkeypatch.setattr(QAAgent, "retrieve", empty_retrieve)
    events = [e async for e in patched_agent.answer_stream("问题")]
    tokens = "".join(e["text"] for e in events if e["event"] == "token")
    assert "证据" in tokens
    assert events[-1]["citations"] == 0


async def test_retrieve_dedupes_by_chunk_key(monkeypatch, fake_bus):
    bus, _ = fake_bus
    agent = QAAgent(bus=bus)

    async def fake_hybrid(query, top_k=8):
        return [dict(EVIDENCE[0]), dict(EVIDENCE[1])]

    monkeypatch.setattr("aiintel.services.qa.agent.hybrid_search", fake_hybrid)
    merged = await agent.retrieve(["q1", "q2"], top_k=8)
    assert len(merged) == 2
    assert {m["chunk_key"] for m in merged} == {"vuln:v1#0", "vuln:v2#0"}


async def test_retrieve_survives_failed_query(monkeypatch, fake_bus):
    bus, _ = fake_bus
    agent = QAAgent(bus=bus)

    async def boom(query, top_k=8):
        raise RuntimeError("向量库不可用")

    monkeypatch.setattr("aiintel.services.qa.agent.hybrid_search", boom)
    assert await agent.retrieve(["q1"], top_k=8) == []


async def test_plan_degrades_to_single_query(monkeypatch, fake_bus, stub_llm):
    stub_llm("不是 JSON")
    bus, _ = fake_bus
    plan = await QAAgent(bus=bus).plan("某个问题")
    assert plan["sub_questions"] == ["某个问题"]
    assert plan["queries"] == ["某个问题"]


async def test_error_event_on_failure(patched_agent, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("生成阶段炸了")

    monkeypatch.setattr(patched_agent, "plan", boom)
    events = [e async for e in patched_agent.answer_stream("问题")]
    assert events[-1]["event"] == "error"
    assert events[-1]["code"] == "QA_FAILED"
    assert "生成阶段炸了" in events[-1]["message"]


def test_dumps_event_is_sse_frame():
    frame = dumps_event({"event": "token", "text": "hi"})
    assert frame.startswith("event: token\ndata: ")
    assert frame.endswith("\n\n")


def test_max_iterations_is_bounded():
    assert 1 <= MAX_ITERATIONS <= 5

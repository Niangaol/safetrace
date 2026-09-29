"""事件因果链：raw.docs -> intel.items -> enrich.items -> qa.answers。

权威信封的 `causation_id` 指向触发本事件的上游 `event_id`。这条链一旦断掉，
"这条结论从哪来的"就无从追溯，所以这里逐跳断言，而不是只测信封长得对。
"""

from __future__ import annotations

import json

import pytest

from aiintel.agents import nodes
from aiintel.agents.state import new_state
from aiintel.core.events import (
    TOPIC_ENRICH_EVIDENCE,
    TOPIC_ENRICH_ITEMS,
    TOPIC_ENRICH_TRIAGE,
    TOPIC_INTEL_ITEMS,
    TOPIC_RAW_DOCS,
    EventBus,
)


@pytest.fixture()
def bus(monkeypatch):
    """把节点里的全局 bus 换成内存版，并记录每条事件的因果来源。"""

    class FakeRedis:
        def __init__(self) -> None:
            self.published: list[tuple[str, str]] = []

        async def publish(self, channel: str, message: str) -> int:
            self.published.append((channel, message))
            return 1

    redis = FakeRedis()
    fake = EventBus(redis_client=redis)
    monkeypatch.setattr(nodes, "bus", fake)
    return fake, redis


def _envelopes(redis) -> list[dict]:
    return [json.loads(raw) for _, raw in redis.published]


@pytest.fixture()
def pipeline_stubs(monkeypatch):
    """把节点里的服务层换成确定性的假实现，只保留事件编排逻辑。

    ⚠️ 假数据必须**字段齐全**：载荷现在要过权威 Schema，缺 `external_id` / `url`
    会直接违约。以前随手写的短字典能过，正是因为载荷没被校验过。
    """

    from aiintel.services.enrich import agent as enrich_agent
    from aiintel.services.ingest import dedup, pipeline

    async def fake_poll_sources(sources, mode):
        return [
            {
                "id": "raw-1",
                "source": "nvd",
                "external_id": "CVE-2026-10001",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-10001",
                "title": "示例漏洞",
                "content_text": "描述",
                "fetched_at": "2026-09-29T00:00:00+00:00",
                "published_at": "2026-09-28T00:00:00+00:00",
                "cve_id": "CVE-2026-10001",
            }
        ]

    async def fake_persist(items):
        return len(items)

    async def fake_normalize(items):
        return [
            {
                "id": "raw-1",
                "cve_id": "CVE-2026-10001",
                "title": "示例漏洞",
                "description": "描述",
                "severity": "critical",
                "cvss_score": 9.8,
                "published_at": "2026-09-28T00:00:00+00:00",
            }
        ]

    def fake_merge(items):
        return [
            {
                "id": "raw-1",
                "cve_id": "CVE-2026-10001",
                "title": "示例漏洞",
                "description": "描述",
                "severity": "critical",
                "cvss_score": 9.8,
                "published_at": "2026-09-28T00:00:00+00:00",
                "merged_raw_ids": ["raw-1"],
                "merge_type": "exact",
            }
        ]

    class FakeEnrichAgent:
        async def run(self, vuln):
            return [
                {
                    "dimension": "cvss",
                    "confidence": 0.9,
                    "source": ["nvd", "computed"],
                    "evidence": [
                        {
                            "evidence_id": "ev-1",
                            "source": "nvd",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-10001",
                            "snippet": "CVSS 9.8",
                            "fetched_at": "2026-09-29T00:00:00+00:00",
                        }
                    ],
                    "value": {
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "base_score": 9.8,
                        "score_source": "computed",
                    },
                    "created_at": "2026-09-29T00:00:00+00:00",
                }
            ]

    monkeypatch.setattr(pipeline, "poll_sources", fake_poll_sources)
    monkeypatch.setattr(pipeline, "persist_raw_items", fake_persist)
    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)
    monkeypatch.setattr(enrich_agent, "EnrichAgent", FakeEnrichAgent)


async def test_causation_chain_links_raw_to_enrich(bus, pipeline_stubs):
    fake, redis = bus
    state = new_state(trace_id="trace-chain", task="monitor_cycle")

    state = await nodes.node_collect(state)
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_triage(state)
    state = await nodes.node_enrich(state)

    envelopes = _envelopes(redis)
    by_topic = {env["topic"]: env for env in envelopes}
    assert set(by_topic) == {
        TOPIC_RAW_DOCS,
        TOPIC_INTEL_ITEMS,
        TOPIC_ENRICH_ITEMS,
        TOPIC_ENRICH_EVIDENCE,
    }

    raw, intel, enrich = (
        by_topic[TOPIC_RAW_DOCS],
        by_topic[TOPIC_INTEL_ITEMS],
        by_topic[TOPIC_ENRICH_ITEMS],
    )
    evidence = [e for e in envelopes if e["topic"] == TOPIC_ENRICH_EVIDENCE]

    # 根事件没有上游
    assert "causation_id" not in raw
    # 后一跳指向前一跳
    assert intel["causation_id"] == raw["event_id"]
    assert enrich["causation_id"] == intel["event_id"]
    # 明细事件同样挂在 intel.items 上（与交接口同源，不分叉）
    assert [e["causation_id"] for e in evidence] == [intel["event_id"]]
    # 全链同 trace
    assert {raw["trace_id"], intel["trace_id"], enrich["trace_id"]} == {"trace-chain"}


async def test_state_records_causality_for_downstream_nodes(bus, pipeline_stubs):
    """causality 存进 state，后续节点（alert/report）才能取到上游 event_id。"""

    fake, redis = bus
    state = new_state(trace_id="trace-state", task="monitor_cycle")

    state = await nodes.node_collect(state)
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)

    assert set(state["causality"]) == {"raw", "intel"}
    assert state["causality"]["intel"] == _envelopes(redis)[-1]["event_id"]


async def test_triage_event_is_caused_by_enrich(bus, pipeline_stubs):
    fake, redis = bus
    state = new_state(trace_id="trace-triage", task="monitor_cycle")
    state = await nodes.node_collect(state)
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_triage(state)
    state = await nodes.node_enrich(state)
    state["severity"] = "critical"
    state["vuln"] = {"id": "CVE-2026-10001", "cve_id": "CVE-2026-10001", "title": "t"}

    state = await nodes.node_alert(state)

    triage = [e for e in _envelopes(redis) if e["topic"] == TOPIC_ENRICH_TRIAGE]
    assert len(triage) == 1
    enrich = [e for e in _envelopes(redis) if e["topic"] == TOPIC_ENRICH_ITEMS][-1]
    assert triage[0]["causation_id"] == enrich["event_id"]
    assert state["causality"]["triage"] == triage[0]["event_id"]


async def test_replay_of_same_raw_item_yields_same_event_id(bus, pipeline_stubs):
    """幂等：同一批原始抓取重放两次，raw.docs 的 event_id 必须一致。"""

    fake, redis = bus
    for _ in range(2):
        await nodes.node_collect(new_state(trace_id="t", task="monitor_cycle"))

    raw_ids = [e["event_id"] for e in _envelopes(redis) if e["topic"] == TOPIC_RAW_DOCS]
    assert len(raw_ids) == 2
    assert raw_ids[0] == raw_ids[1], "同源重放必须得同一 event_id，否则消费者无法幂等去重"


async def test_different_items_get_different_event_ids(bus, pipeline_stubs, monkeypatch):
    from aiintel.services.ingest import pipeline

    async def two_sources(sources, mode):
        return [
            {"id": "raw-1", "source": "nvd", "cve_id": "CVE-1"},
            {"id": "raw-2", "source": "ghsa", "cve_id": "CVE-2"},
        ]

    monkeypatch.setattr(pipeline, "poll_sources", two_sources)
    fake, redis = bus
    await nodes.node_collect(new_state(trace_id="t", task="monitor_cycle"))

    raw_ids = [e["event_id"] for e in _envelopes(redis) if e["topic"] == TOPIC_RAW_DOCS]
    assert len(set(raw_ids)) == 2, "不同原始条目不能撞 ID，否则一条事件会被另一条吞掉"

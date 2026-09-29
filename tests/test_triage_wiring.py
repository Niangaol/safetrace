"""动态优先级接线测试：EPSS/KEV 必须真的走到 `node_triage`。

`tests/test_triage_policy.py` 测排序语义；这里测**数据路径**：
真实形状的 NVD payload → `normalize_item` 抽出 EPSS/KEV → `merge_items` 不丢
→ `node_triage` 据此排名并发出过契约的 `TriageOrder`。

这条路径是提案① 的真正工作量所在：EPSS/KEV 早有解析器，但**在 triage 时没人算**
（归一阶段没抽、合并阶段没带），所以旧实现只能按 CVSS 单因子排。
"""

from __future__ import annotations

import json

import pytest
from scripts.contracts import load_schema, validate
from scripts.validate_contracts import payload_schema_for

from aiintel.agents import nodes
from aiintel.agents.state import new_state
from aiintel.core.events import TOPIC_ENRICH_TRIAGE, EventBus
from aiintel.services.ingest import dedup, pipeline
from aiintel.services.ingest.pipeline import extract_epss, extract_kev

NVD_WITH_SIGNALS = {
    "cve": {
        "id": "CVE-2026-28114",
        "descriptions": [{"lang": "en", "value": "transformers from_pretrained pickle RCE"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 8.8,
                        "baseSeverity": "HIGH",
                    },
                }
            ]
        },
        "cisaExploitAdd": "2026-09-22",
        "epss": [{"epss": 0.71, "percentile": 0.98}],
    }
}


@pytest.fixture()
def bus_and_redis(monkeypatch):
    class FakeRedis:
        def __init__(self) -> None:
            self.published: list[tuple[str, str]] = []

        async def publish(self, channel: str, message: str) -> int:
            self.published.append((channel, message))
            return 1

    redis = FakeRedis()
    monkeypatch.setattr(nodes, "bus", EventBus(redis_client=redis))
    return redis


# ---------------------------------------------------------------- 抽取层


def test_extract_kev_and_epss_from_real_shaped_payload() -> None:
    assert extract_kev(NVD_WITH_SIGNALS) is True
    assert extract_epss(NVD_WITH_SIGNALS) == 0.71


def test_extract_never_invents_signals() -> None:
    """缺信号就返回 None/False；`hasKev` 是查询开关，不是本条情报的属性。"""

    assert extract_kev({}) is False
    assert extract_epss({}) is None
    assert extract_kev({"id": "x", "hasKev": True}) is False


async def test_normalize_item_carries_signals() -> None:
    """归一阶段必须把 EPSS/KEV 写进条目 —— triage 跑在富化之前，那时没有 F4 解析结果。"""

    item = {
        "id": "raw-1",
        "source": "nvd",
        "external_id": "CVE-2026-28114",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-28114",
        "title": "transformers pickle RCE",
        "content_text": "short",
        "raw": NVD_WITH_SIGNALS,
        "fetched_at": "2026-09-29T00:00:00+00:00",
    }
    normalized = await pipeline.normalize_item(item)
    assert normalized["kev"] is True
    assert normalized["epss"] == 0.71
    assert normalized["cvss_score"] == 8.8


def test_merge_keeps_signals_regardless_of_source_order() -> None:
    """跨源合并：KEV 取并集、EPSS 取更大值 —— 抓取先后不该影响风险判断。"""

    low = {
        "id": "r1",
        "source": "nvd",
        "cve_id": "CVE-2026-28114",
        "content_hash": "h1" + "0" * 62,
        "epss": 0.02,
        "kev": False,
    }
    high = {
        "id": "r2",
        "source": "ghsa",
        "cve_id": "CVE-2026-28114",
        "content_hash": "h2" + "0" * 62,
        "epss": 0.91,
        "kev": True,
    }
    for order in ((low, high), (high, low)):
        merged = dedup.merge_items([dict(x) for x in order])[0]
        assert merged["epss"] == 0.91
        assert merged["kev"] is True


# ---------------------------------------------------------------- 排序接线


async def test_triage_ranks_by_epss_not_cvss_alone(bus_and_redis, monkeypatch) -> None:
    """★ CVSS 9.8 但无利用信号 vs CVSS 8.8 + KEV/EPSS → **后者排前面**。

    这正是旧实现（`max(items, key=cvss_score)`）判反的情形。
    """

    high_cvss = {
        "id": "raw-a",
        "cve_id": "CVE-2026-31001",
        "title": "CVSS 9.8 但无在野利用信号",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss": None,
        "kev": False,
    }
    exploited = {
        "id": "raw-b",
        "cve_id": "CVE-2026-28114",
        "title": "CVSS 8.8 但已列入 KEV",
        "severity": "high",
        "cvss_score": 8.8,
        "epss": 0.71,
        "kev": True,
    }

    async def fake_normalize(items):
        return [dict(high_cvss), dict(exploited)]

    def fake_merge(items):
        return [dict(high_cvss), dict(exploited)]

    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)

    state = new_state(trace_id="t", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)

    queue = state["triage_queue"]
    assert queue[0]["vuln_id"] == "CVE-2026-28114", "被在野利用的应排第一"
    assert queue[0]["rank"] == 1
    assert queue[0]["kev"] is True
    assert queue[0]["policy_version"] == "1.0.0"
    # 队首进 vuln，供 node_enrich 做详细富化
    assert state["vuln"].get("cve_id") == "CVE-2026-28114"
    assert state["priority"] in {"urgent", "high"}


async def test_triage_queue_gets_top_n_detail_route(bus_and_redis, monkeypatch) -> None:
    """Top-N 走详细富化，其余走通用模板（修"一次只处理一条"）。"""

    from aiintel.config import get_settings

    items = [
        {
            "id": f"raw-{i}",
            "cve_id": f"CVE-2026-{i:05d}",
            "title": f"t{i}",
            "severity": "high",
            "cvss_score": 9.0 - i * 0.1,
            "epss": 0.9 - i * 0.05,
            "kev": False,
        }
        for i in range(1, 6)
    ]

    async def fake_normalize(rows):
        return [dict(x) for x in items]

    def fake_merge(rows):
        return [dict(x) for x in items]

    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)

    settings = get_settings()
    state = new_state(trace_id="t", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)

    queue = state["triage_queue"]
    assert len(queue) == 5, "排名应覆盖整批，而不是只挑一条"
    detail = [q for q in queue if q["route"] == "detail_enrich"]
    template = [q for q in queue if q["route"] == "template_enrich"]
    assert len(detail) == min(settings.triage_detail_top_n, 5)
    if template:
        assert all(q["rank"] > settings.triage_detail_top_n for q in template)


async def test_triage_event_payload_matches_contract(bus_and_redis, monkeypatch) -> None:
    """`enrich.triage` 现在发完整的 `TriageOrder`（带分数依据），不是一行 priority。"""

    item = {
        "id": "raw-b",
        "cve_id": "CVE-2026-28114",
        "title": "t",
        "severity": "critical",
        "cvss_score": 8.8,
        "epss": 0.71,
        "kev": True,
    }

    async def fake_normalize(rows):
        return [dict(item)]

    def fake_merge(rows):
        return [dict(item)]

    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)

    state = new_state(trace_id="t", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)
    state = await nodes.node_alert(state)

    envelopes = [json.loads(raw) for _, raw in bus_and_redis.published]
    triage = [e for e in envelopes if e["topic"] == TOPIC_ENRICH_TRIAGE]
    assert triage, "没发 enrich.triage"
    payload = triage[0]["payload"]
    schema = payload_schema_for("enrich.triage")
    assert schema is not None
    assert validate(schema, payload) == [], validate(schema, payload)
    assert payload["kev"] is True
    assert payload["epss"] == 0.71
    assert payload["score"] > 0
    assert payload["reasons"], "必须给出排名依据"
    assert validate(load_schema("EventEnvelope.json"), triage[0]) == []


def test_triage_order_fallback_is_still_contract_valid() -> None:
    """队列缺失时的兜底载荷也必须过契约（不能发缺字段的 TriageOrder）。"""

    state = new_state(trace_id="t", task="monitor_cycle")
    state["severity"] = "high"
    state["priority"] = "high"
    payload = nodes.triage_order_payload(state, {"cve_id": "CVE-2026-1", "cvss_score": 7.5})
    schema = payload_schema_for("enrich.triage")
    assert schema is not None
    assert validate(schema, payload) == [], validate(schema, payload)
    assert payload["rank"] == 1

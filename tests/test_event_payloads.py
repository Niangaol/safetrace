"""事件载荷门禁：**真实发布路径**产出的 payload 必须过契约。

为什么单独一个文件：P0-A 的教训是"信封对了、主题名对了，载荷却还是内部短字典"，
而 346 个测试全绿 —— 因为 `validate_contracts` 只校验 `fixtures/*.json`，
**真实发布路径的载荷一次都没被校验过**。

所以这里的载荷一律通过**运行 `agents/nodes.py` 的真实节点函数**取得：
用内存 EventBus 截获发布内容，逐条过对应主题的 payload 契约。
禁止用 fixture 冒充（fixture 已有自己的测试）。
"""

from __future__ import annotations

import json

import pytest
from scripts.contracts import load_schema, validate
from scripts.validate_contracts import payload_schema_for

from aiintel.agents import nodes
from aiintel.agents.state import new_state
from aiintel.core.events import (
    TOPIC_ALERT_RAISED,
    TOPIC_ENRICH_EVIDENCE,
    TOPIC_ENRICH_ITEMS,
    TOPIC_ENRICH_PAPERS,
    TOPIC_ENRICH_REQUESTED,
    TOPIC_ENRICH_TRIAGE,
    TOPIC_INTEL_ITEMS,
    TOPIC_RAW_DOCS,
    TOPIC_REPORT_DAILY,
    EventBus,
)

# ---------------------------------------------------------------- 测试脚手架


class RecordingBus:
    """内存事件总线：把 (topic, envelope) 全记下来。"""

    def __init__(self) -> None:
        class FakeRedis:
            def __init__(self) -> None:
                self.published: list[tuple[str, str]] = []

            async def publish(self, channel: str, message: str) -> int:
                self.published.append((channel, message))
                return 1

        self.redis = FakeRedis()
        self.bus = EventBus(redis_client=self.redis)

    @property
    def envelopes(self) -> list[dict]:
        return [json.loads(raw) for _, raw in self.redis.published]

    def by_topic(self, topic: str) -> list[dict]:
        return [env for env in self.envelopes if env["topic"] == topic]


@pytest.fixture()
def recorder(monkeypatch):
    rec = RecordingBus()
    monkeypatch.setattr(nodes, "bus", rec.bus)
    return rec


@pytest.fixture()
def stub_pipeline(monkeypatch):
    """确定性假数据，**字段齐全**（载荷要过 Schema，缺字段会直接违约）。"""

    from aiintel.services.enrich import agent as enrich_agent
    from aiintel.services.ingest import dedup, pipeline

    raw = {
        "id": "raw-1",
        "source": "nvd",
        "external_id": "CVE-2026-31001",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
        "title": "vLLM chat_template RCE",
        "content_text": "未沙箱的 Jinja2 模板渲染",
        "published_at": "2026-09-21T00:00:00+00:00",
        "fetched_at": "2026-09-21T03:20:00+00:00",
        "cve_id": "CVE-2026-31001",
    }
    merged = {
        "id": "raw-1",
        "cve_id": "CVE-2026-31001",
        "title": "vLLM 0.9.2 及更早版本模板注入 RCE",
        "description": "未沙箱的 Jinja2 环境渲染 chat_template",
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "cwe": ["CWE-1336"],
        "cpe": ["cpe:2.3:a:vllm:vllm:0.9.2:*:*:*:*:*:*:*"],
        "affected_products": ["vLLM"],
        "version_ranges": [{"fixed": "0.9.3", "source": "vendor"}],
        "published_at": "2026-09-21T00:00:00+00:00",
        "merged_raw_ids": ["raw-1"],
        "merge_type": "exact",
    }
    enrichment = {
        "dimension": "cvss",
        "confidence": 0.9,
        "source": ["nvd", "computed"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "nvd",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                "snippet": "CVSS 3.1 base score 9.8",
                "fetched_at": "2026-09-21T03:20:00+00:00",
            }
        ],
        "value": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "base_score": 9.8,
            "score_source": "computed",
            "technical_impact": "命令执行",
            "epss": 0.87,
            "kev": True,
        },
        "created_at": "2026-09-21T03:21:00+00:00",
    }

    async def fake_poll(sources, mode):
        return [dict(raw)]

    async def fake_persist(items):
        return len(items)

    async def fake_normalize(items):
        return [dict(merged)]

    def fake_merge(items):
        return [dict(merged)]

    class FakeEnrichAgent:
        async def run(self, vuln):
            return [dict(enrichment)]

    monkeypatch.setattr(pipeline, "poll_sources", fake_poll)
    monkeypatch.setattr(pipeline, "persist_raw_items", fake_persist)
    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)
    monkeypatch.setattr(enrich_agent, "EnrichAgent", FakeEnrichAgent)
    return {"raw": raw, "merged": merged, "enrichment": enrichment}


async def _run_pipeline(recorder, stub_pipeline) -> dict:
    """跑完 collect→normalize→dedup→triage→enrich（含告警），返回最终 state。"""

    state = new_state(trace_id="trace-payload", task="monitor_cycle")
    state = await nodes.node_collect(state)
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_triage(state)
    state = await nodes.node_enrich(state)
    state = await nodes.node_alert(state)
    return state


def _assert_payload_ok(env: dict) -> None:
    """单条信封：信封过 `EventEnvelope`，payload 过该主题的载荷契约。"""

    assert validate(load_schema("EventEnvelope.json"), env) == [], env
    topic = env["topic"]
    schema = payload_schema_for(topic)
    assert schema is not None, f"主题 {topic} 没有可校验的载荷契约"
    errors = validate(schema, env["payload"])
    assert errors == [], f"{topic} 载荷不合契约: {errors}"


# ---------------------------------------------------------------- 载荷门禁


@pytest.mark.parametrize(
    "topic",
    [
        TOPIC_RAW_DOCS,
        TOPIC_INTEL_ITEMS,
        TOPIC_ENRICH_ITEMS,
        TOPIC_ENRICH_EVIDENCE,
        TOPIC_ENRICH_TRIAGE,
        TOPIC_ALERT_RAISED,
    ],
)
async def test_published_payload_matches_its_contract(recorder, stub_pipeline, topic: str) -> None:
    """★ 主门禁：nodes.py 真实发布的每类载荷都必须过契约。"""

    await _run_pipeline(recorder, stub_pipeline)
    envelopes = recorder.by_topic(topic)
    assert envelopes, f"{topic} 一条都没发出来（生产者掉线？）"
    for env in envelopes:
        _assert_payload_ok(env)


async def test_raw_docs_payload_is_authoritative_rawdoc(recorder, stub_pipeline) -> None:
    """raw.docs 以前发的是 `{raw_item_id, source, vuln_id}`，与 RawDoc 7 字段匹配 0/7。"""

    await nodes.node_collect(new_state(trace_id="t", task="monitor_cycle"))
    payload = recorder.by_topic(TOPIC_RAW_DOCS)[0]["payload"]
    assert set(payload) >= {
        "source_id",
        "source_type",
        "external_id",
        "url",
        "fetched_at",
        "content_type",
        "payload_ref",
    }
    assert payload["source_id"] == "nvd"
    assert payload["source_type"] == "nvd_cve"
    assert payload["content_type"] == "json"
    # payload_ref 与 IntelItem.raw_refs 同一约定，F 线靠它回读原始 payload
    assert payload["payload_ref"] == "payload://nvd/CVE-2026-31001"


async def test_intel_items_payload_is_authoritative_intelitem(recorder, stub_pipeline) -> None:
    """intel.items 以前发的是 `{vuln_id, merged_raw_ids, merge_type}`，与 IntelItem 10 字段 0/10。"""

    await _run_pipeline(recorder, stub_pipeline)
    payload = recorder.by_topic(TOPIC_INTEL_ITEMS)[0]["payload"]
    assert payload["intel_id"].startswith("intel_")
    assert payload["cve_ids"] == ["CVE-2026-31001"]
    assert payload["raw_refs"], "raw_refs 是 F 线回读原始 payload 的唯一入口"
    assert payload["schema_version"] == "1.0"
    # entities 五件套齐全（additionalProperties:false，缺项即违约）
    assert set(payload["entities"]) == {"product", "vendor", "version_range", "cwe", "cpes"}
    assert payload["entities"]["version_range"] == ["<=0.9.3"]


async def test_intel_items_source_ids_are_strings_not_dicts(recorder, stub_pipeline) -> None:
    """回归：`source_ids` 必须是**源名字符串列表**，不能被字典列表污染。

    这是曾被 346 个测试漏掉的真实 bug：内部 `sources` 是引用字典列表，
    直接塞进权威 `source_ids` 会产出 `[{...}]`，Schema 报"期望 string 实际 dict"。
    """

    await _run_pipeline(recorder, stub_pipeline)
    payload = recorder.by_topic(TOPIC_INTEL_ITEMS)[0]["payload"]
    assert all(isinstance(s, str) for s in payload["source_ids"]), payload["source_ids"]
    assert payload["source_ids"] == ["nvd"]


async def test_enrich_items_is_one_result_per_run_with_contract_dimensions(
    recorder, stub_pipeline
) -> None:
    """enrich.items 是**一次富化一条** EnrichmentResult，不是一维一条短字典。"""

    await _run_pipeline(recorder, stub_pipeline)
    envelopes = recorder.by_topic(TOPIC_ENRICH_ITEMS)
    assert len(envelopes) == 1, "一次富化只该发一条交接口事件"
    payload = envelopes[0]["payload"]
    assert payload["intel_id"].startswith("intel_")
    assert "cvss" in payload["dimensions_completed"]
    assert payload["dimensions_failed"] == []
    # 交接口维度枚举只有权威 6 值
    assert set(payload["dimensions_completed"]) <= {
        "paper",
        "asset",
        "poc",
        "cvss",
        "remediation",
        "triage",
    }
    assert 0.0 <= payload["enrichment_score"] <= 1.0


async def test_enrich_evidence_carries_seven_dimension_detail(recorder, stub_pipeline) -> None:
    """7 维明细走扩展契约 `enrich.evidence`（权威交接口装不下）。"""

    await _run_pipeline(recorder, stub_pipeline)
    envelopes = recorder.by_topic(TOPIC_ENRICH_EVIDENCE)
    assert len(envelopes) == 1
    payload = envelopes[0]["payload"]
    assert payload["dimension"] == "cvss"
    assert payload["sources"], "每条富化必须带 source"
    assert payload["evidence"], "每条富化必须带证据"
    assert payload["evidence"][0]["url"].startswith("https://")
    assert payload["schema_version"] == "1.0"


async def test_every_published_envelope_has_declared_payload_contract(
    recorder, stub_pipeline
) -> None:
    """不许存在"发了但没有任何契约"的主题 —— 那正是 P0-A 的温床。"""

    await _run_pipeline(recorder, stub_pipeline)
    assert recorder.envelopes, "整条链路一条事件都没发"
    for env in recorder.envelopes:
        assert payload_schema_for(env["topic"]) is not None, f"{env['topic']} 缺载荷契约"
        _assert_payload_ok(env)


async def test_report_event_payload_matches_contract(recorder, stub_pipeline, monkeypatch) -> None:
    """日报载荷也要过契约（`intel.report.daily` 是扩展主题）。"""

    from aiintel.agents import report as report_module

    async def fake_report(state):
        return "# 日报\n- 无异常"

    monkeypatch.setattr(report_module, "build_daily_report", fake_report)
    state = await _run_pipeline(recorder, stub_pipeline)
    await nodes.node_report(state)

    envelopes = recorder.by_topic(TOPIC_REPORT_DAILY)
    assert envelopes
    _assert_payload_ok(envelopes[0])


async def test_enrich_requested_payload_matches_contract(recorder, stub_pipeline) -> None:
    """F 线的派发事件（扩展主题 `intel.enrich.requested`）也要过契约。"""

    from aiintel.services.enrich import s2_events

    ok = await s2_events.publish_requested(recorder.bus, "intel_x", ["cvss", "fix"])
    assert ok
    env = recorder.by_topic(TOPIC_ENRICH_REQUESTED)[0]
    _assert_payload_ok(env)


# ------------------------------------------------- enrich.papers 生产者接线


def _paper_enrichment() -> dict:
    return {
        "dimension": "paper",
        "confidence": 0.7,
        "source": ["arxiv"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "arxiv",
                "url": "https://arxiv.org/abs/2609.01234",
                "snippet": "pickle payload model serving stacks",
                "fetched_at": "2026-09-29T00:00:00+00:00",
            }
        ],
        "value": {
            "papers": [
                {
                    "paper_id": "2609.01234",
                    "arxiv_id": "2609.01234",
                    "title": "Serving Stack Vulns",
                    "source": "arxiv",
                    "year": 2026,
                    "relevance_score": 0.8,
                    "relevance": 0.8,
                    "findings": ["模型加载路径可被利用"],
                }
            ]
        },
        "created_at": "2026-09-29T00:00:00+00:00",
    }


def test_publish_papers_payload_matches_contract() -> None:
    """`enrich.papers` 的载荷是只带 `artifacts.papers` 的 EnrichmentResult。"""

    payload = nodes.publish_papers_payload("intel_x", [_paper_enrichment()])
    assert payload is not None
    schema = payload_schema_for(TOPIC_ENRICH_PAPERS)
    assert schema is not None
    assert validate(schema, payload) == [], validate(schema, payload)
    assert payload["artifacts"]["papers"][0]["paper_id"] == "2609.01234"
    assert payload["artifacts"]["papers"][0]["source"] == "arxiv"
    assert payload["artifacts"]["papers"][0]["relevance_score"] == 0.8
    assert payload["artifacts"]["papers"][0]["confidence"] == 0.7


def test_publish_papers_payload_is_none_without_papers() -> None:
    """没有论文结论就不发这条事件，而不是发一条空载荷装样子。"""

    assert nodes.publish_papers_payload("intel_x", []) is None
    no_papers = {**_paper_enrichment(), "value": {"papers": []}}
    assert nodes.publish_papers_payload("intel_x", [no_papers]) is None
    assert nodes.publish_papers_payload("intel_x", [{"dimension": "cvss", "value": {}}]) is None


async def test_enrich_papers_event_only_fires_when_papers_exist(
    recorder, stub_pipeline, monkeypatch
) -> None:
    """接线检查：有论文时真的发 `enrich.papers`，且载荷过契约。"""

    from aiintel.services.enrich import agent as enrich_agent

    class PaperAgent:
        async def run(self, vuln):
            return [_paper_enrichment()]

    monkeypatch.setattr(enrich_agent, "EnrichAgent", PaperAgent)

    state = new_state(trace_id="trace-papers", task="monitor_cycle")
    state = await nodes.node_collect(state)
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)
    await nodes.node_enrich(state)

    envelopes = recorder.by_topic(TOPIC_ENRICH_PAPERS)
    assert envelopes, "有论文结论却没有发 enrich.papers（生产者又掉线了？）"
    _assert_payload_ok(envelopes[0])
    assert envelopes[0]["causation_id"] == state["causality"]["intel"]

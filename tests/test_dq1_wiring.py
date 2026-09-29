"""DQ1 接线测试：闸门真的在图里生效，判定真的落库。

`tests/test_dq1.py` 测判定语义，这里测**接线**：节点位置、事件、落库、
以及与富化闸门（`dimensions_for_quality`）的阈值一致性。
"""

from __future__ import annotations

import datetime as dt
import json

import pytest
from scripts.contracts import load_schema, validate
from scripts.validate_contracts import payload_schema_for

from aiintel.agents import nodes
from aiintel.agents.graph import PIPELINE
from aiintel.agents.state import new_state
from aiintel.core.events import TOPIC_DQ_VERDICTS, TOPIC_INTEL_ITEMS, EventBus
from aiintel.services.enrich.dimensions import dimensions_for_quality


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


@pytest.fixture()
def clean_merged(monkeypatch):
    """一条干净情报 + 一条会被隔离的脏情报。"""

    from aiintel.services.ingest import dedup, pipeline

    clean = {
        "id": "raw-clean",
        "cve_id": "CVE-2026-31001",
        "title": "vLLM chat_template RCE",
        "description": "未沙箱的 Jinja2 环境渲染 chat_template，可逃逸到 os.popen。",
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "published_at": "2026-09-28T00:00:00+00:00",
        "fetched_at": "2026-09-28T02:00:00+00:00",
        "raw_json": {"cve": {"id": "CVE-2026-31001"}},
        "merged_raw_ids": ["raw-clean", "raw-other"],
        "merge_type": "cross_source",
    }
    dirty = {
        "id": "raw-dirty",
        "cve_id": "CVE-2026-99999",
        "title": "No description",
        "description": "No description",
        "severity": "high",
        "published_at": "2026-09-28T00:00:00",  # 无时区 → ts_no_tz
        "merged_raw_ids": ["raw-dirty"],
        "merge_type": "exact",
    }

    async def fake_poll(sources, mode):
        return []

    async def fake_normalize(items):
        return [dict(clean), dict(dirty)]

    def fake_merge(items):
        return [dict(clean), dict(dirty)]

    monkeypatch.setattr(pipeline, "poll_sources", fake_poll)
    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)
    return clean, dirty


def test_dq1_sits_between_dedup_and_triage() -> None:
    """闸门位置是硬约束：必须在 triage/enrich 之前。"""

    order = list(PIPELINE)
    assert "dq1" in order
    assert order.index("dedup") < order.index("dq1") < order.index("triage")
    assert "dq1" in nodes.NODES


async def test_dq1_writes_scores_and_emits_contract_valid_verdicts(
    bus_and_redis, clean_merged
) -> None:
    state = new_state(trace_id="trace-dq", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)

    # 分数写回条目（node_persist 靠它落库）
    assert all(item.get("quality_score") is not None for item in state["merged"])
    assert set(state["quality_verdicts"]) == {"CVE-2026-31001", "CVE-2026-99999"}

    schema = payload_schema_for(TOPIC_DQ_VERDICTS)
    assert schema is not None
    envelopes = [
        json.loads(raw) for channel, raw in bus_and_redis.published if channel == TOPIC_DQ_VERDICTS
    ]
    assert len(envelopes) == 2
    for env in envelopes:
        assert validate(load_schema("EventEnvelope.json"), env) == []
        assert validate(schema, env["payload"]) == [], env["payload"]


async def test_dq_verdict_is_caused_by_its_own_intel_item(bus_and_redis, clean_merged) -> None:
    """因果链逐条对齐：**每条** dq.verdicts 指向**它自己那条** intel.items。

    回归：旧实现把所有下游事件都挂到"最后一条" intel.items 上，
    两条情报的判定共用一个 parent —— 链看着在，实际是错的。
    """

    state = new_state(trace_id="trace-dq", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)

    envelopes = [json.loads(raw) for _, raw in bus_and_redis.published]
    intel_by_id = {
        env["payload"]["cve_ids"][0]: env["event_id"]
        for env in envelopes
        if env["topic"] == TOPIC_INTEL_ITEMS and env["payload"]["cve_ids"]
    }
    verdicts = [env for env in envelopes if env["topic"] == TOPIC_DQ_VERDICTS]
    assert len(verdicts) == 2
    assert len(intel_by_id) == 2

    for env in verdicts:
        item_id = env["payload"]["item_id"]
        assert env["causation_id"] == intel_by_id[item_id], (
            f"{item_id} 的判定挂错了上游事件（应挂自己的 intel.items）"
        )
    assert len({env["causation_id"] for env in verdicts}) == 2, "两条判定不能共用同一个 parent"
    assert state["causality"]["dq"] == verdicts[-1]["event_id"]


async def test_quarantined_item_is_not_selected_by_triage(bus_and_redis, clean_merged) -> None:
    """脏条目被隔离后，triage 不应该挑它。"""

    state = new_state(trace_id="trace-dq", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)

    verdicts = state["quality_verdicts"]
    assert verdicts["CVE-2026-99999"]["verdict"] == "quarantine"
    assert state["vuln_id"] != "raw-dirty"
    assert state["vuln"].get("cve_id") == "CVE-2026-31001"


async def test_all_quarantined_marks_degraded(bus_and_redis, monkeypatch) -> None:
    """全部被隔离时不能静默：必须标记 degraded 并留 warning。"""

    from aiintel.services.ingest import dedup, pipeline

    dirty = {
        "id": "raw-dirty",
        "cve_id": "CVE-2026-99999",
        "title": "No description",
        "description": "No description",
        "severity": "high",
        "published_at": "2026-09-28T00:00:00",
    }

    async def fake_normalize(items):
        return [dict(dirty)]

    def fake_merge(items):
        return [dict(dirty)]

    monkeypatch.setattr(pipeline, "normalize_items", fake_normalize)
    monkeypatch.setattr(dedup, "merge_items", fake_merge)

    state = new_state(trace_id="t", task="monitor_cycle")
    state = await nodes.node_normalize(state)
    state = await nodes.node_dedup(state)
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)
    assert state["degraded"] is True
    assert state["vuln_id"] == "raw-dirty"  # 退回它，但不是静默混过去


async def test_dq1_can_be_disabled(bus_and_redis, clean_merged, monkeypatch) -> None:
    """`DQ1_ENABLED=false` 时闸门不拦人（但也不偷偷打分）。"""

    from aiintel.config import get_settings

    monkeypatch.setenv("DQ1_ENABLED", "false")
    get_settings.cache_clear()
    try:
        state = new_state(trace_id="t", task="monitor_cycle")
        state = await nodes.node_normalize(state)
        state = await nodes.node_dedup(state)
        state = await nodes.node_dq1(state)
        assert state["quality_verdicts"] == {}
        assert all("quality_score" not in item for item in state["merged"])
    finally:
        get_settings.cache_clear()


def test_quality_gate_thresholds_are_single_sourced() -> None:
    """★ 富化闸门与 DQ1 判定线必须同源，不能各维护一份。

    `dimensions_for_quality` 与 `decide_verdict` 共用
    `enrich_min_quality_partial` / `enrich_min_quality_full`；
    这条测试在阈值两侧逐一比对两者结论，任何一边漂移都会红。
    """

    from aiintel.services.dq1 import decide_verdict, thresholds_for

    limits = thresholds_for()
    for score in (
        0.0,
        limits["partial"],
        limits["partial"] + 0.01,
        limits["full"],
        limits["full"] + 0.01,
        1.0,
    ):
        verdict = decide_verdict(score, [])
        dims = dimensions_for_quality({"quality_score": score})
        if verdict == "review":
            assert dims is None, f"score={score} DQ1 判 review，富化闸门却放行 {dims}"
        elif verdict == "degrade":
            assert dims is not None and set(dims) <= {"cvss", "fix", "consistency"}, (
                f"score={score} DQ1 判 degrade，富化闸门给了 {dims}"
            )
        else:
            assert dims is not None and len(dims) > 3, (
                f"score={score} DQ1 判 pass，富化闸门只给 {dims}"
            )


def test_missing_quality_score_runs_all_dimensions() -> None:
    """没有 DQ1 判定（老数据）时不拦人 —— 缺字段不等于脏数据。"""

    assert len(dimensions_for_quality({}) or []) > 3


# ------------------------------------------------- DB 时间戳的时区补全（回归）


def test_iso_utc_attaches_timezone_to_naive_values() -> None:
    """SQLite 的 `DateTime(timezone=True)` 不保留 tzinfo，读出来是 naive。

    若原样 `isoformat()`，DQ1 会如实判 `ts_no_tz` → **整库条目被隔离**。
    本库所有时间戳都以 UTC 写入，所以 naive 一律按 UTC 补全。
    """

    from aiintel.services.ingest.pipeline import _iso_utc

    naive = dt.datetime(2026, 9, 28, 0, 0, 0)
    aware = dt.datetime(2026, 9, 28, 0, 0, 0, tzinfo=dt.UTC)
    assert _iso_utc(naive) == aware.isoformat()
    assert _iso_utc(aware) == aware.isoformat()
    assert _iso_utc(None) is None
    # 字符串形态同样补全
    assert _iso_utc("2026-09-28T00:00:00") == aware.isoformat()
    assert _iso_utc("2026-09-28T00:00:00Z") == aware.isoformat()
    # 解析不了的原样返回，不抛异常（宁可留着让人看到脏值）
    assert _iso_utc("not-a-date") == "not-a-date"


def test_loaded_intel_item_from_sqlite_is_not_flagged_ts_no_tz(sqlite_sessionmaker) -> None:
    """端到端回归：SQLite 里落库再读出来，DQ1 不应因为时区假象隔离它。"""

    from aiintel.db.models import RawItem, Vuln, VulnSource
    from aiintel.services.dq1 import evaluate
    from aiintel.services.ingest.pipeline import load_intel_item

    factory = sqlite_sessionmaker
    now = dt.datetime.now(dt.UTC)
    with factory() as session:
        vuln = Vuln(
            id="v_tz",
            cve_id="CVE-2026-31001",
            title="vLLM chat_template RCE",
            description="未沙箱的 Jinja2 模板渲染",
            severity="critical",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            published_at=now,
            fetched_at=now,
        )
        raw = RawItem(
            id="raw_tz",
            source="nvd",
            external_id="CVE-2026-31001",
            url="https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
            title="t",
            content_text="c",
            content_hash="h" * 64,
            published_at=now,
            fetched_at=now,
        )
        session.add_all([vuln, raw])
        session.flush()
        session.add(VulnSource(id="vs_tz", vuln_id=vuln.id, raw_item_id=raw.id, source="nvd"))
        session.commit()

    item = load_intel_item("v_tz")
    assert item, "load_intel_item 应该装配出条目"
    assert item["published_at"].endswith("+00:00"), item["published_at"]
    assert item["sources"][0]["fetched_at"].endswith("+00:00")
    verdict = evaluate(item)
    assert "ts_no_tz" not in verdict.flags, verdict.to_payload()

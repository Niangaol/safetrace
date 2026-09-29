"""DQ1 质量闸门单测：6 类 flag、四档边界、可复算、与富化闸门对齐。

闸门是"脏数据不进知识底座"这条红线的唯一执行点，所以这里测的是**判定语义**，
不是"函数能跑"。
"""

from __future__ import annotations

import datetime as dt

import pytest
from scripts.contracts import load_schema, validate
from scripts.validate_contracts import payload_schema_for

from aiintel.services.dq1 import (
    ALL_FLAGS,
    FLAG_BOILERPLATE,
    FLAG_KEY5_MISSING,
    FLAG_MULTI_ID_MISMATCH,
    FLAG_POC_DEAD_LINK,
    FLAG_REJECT_STATUS,
    FLAG_TS_NO_TZ,
    GATE_VERSION,
    GATE_WEIGHTS,
    QualityVerdict,
    collect_flags,
    decide_verdict,
    evaluate,
    score_structure,
    score_timeliness,
    thresholds_for,
    weights_for,
)

#: 一条"干净"的情报：五件套齐全、时区正确、单源加 URL、时效新
CLEAN = {
    "id": "v1",
    "cve_id": "CVE-2026-31001",
    "title": "vLLM chat_template RCE",
    "description": "未沙箱的 Jinja2 环境渲染 chat_template，可逃逸到 os.popen。",
    "severity": "critical",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "published_at": "2026-09-28T00:00:00+00:00",
    "fetched_at": "2026-09-28T02:00:00+00:00",
    "sources": [
        {"source": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001"},
    ],
    "merged_raw_ids": ["raw-1", "raw-2"],
    "raw_json": {"cve": {"id": "CVE-2026-31001"}},
}


def _case(**overrides) -> dict:
    payload = {**CLEAN, **overrides}
    for key, value in overrides.items():
        if value is None:
            payload.pop(key, None)
    return payload


# ---------------------------------------------------------------- 6 类 flag


def test_clean_item_has_no_flags() -> None:
    assert collect_flags(CLEAN) == []


def test_flag_ts_no_tz() -> None:
    """命中：裸时间戳（无时区）。不命中：带 Z/+00:00。"""

    assert FLAG_TS_NO_TZ in collect_flags(_case(published_at="2026-09-28T00:00:00"))
    assert FLAG_TS_NO_TZ not in collect_flags(_case(published_at="2026-09-28T00:00:00Z"))
    assert FLAG_TS_NO_TZ not in collect_flags(_case(published_at="2026-09-28T00:00:00+08:00"))
    # 缺失不算"无时区"——那归 key5_missing
    assert FLAG_TS_NO_TZ not in collect_flags(_case(published_at=None))


def test_flag_reject_status() -> None:
    """命中：上游明确驳回。不命中：正常状态。"""

    assert FLAG_REJECT_STATUS in collect_flags(_case(vuln_status="Rejected"))
    assert FLAG_REJECT_STATUS in collect_flags(_case(status="disputed"))
    assert FLAG_REJECT_STATUS not in collect_flags(_case(vuln_status="Analyzed"))


def test_flag_poc_dead_link() -> None:
    """命中：exploit 类参考指向不可用地址。不命中：真实仓库。"""

    dead = _case(
        references=[{"url": "http://example.com/poc", "kind": "exploit"}],
    )
    assert FLAG_POC_DEAD_LINK in collect_flags(dead)

    alive = _case(
        references=[{"url": "https://github.com/x/y", "kind": "exploit"}],
    )
    assert FLAG_POC_DEAD_LINK not in collect_flags(alive)

    # 非 exploit 类的坏链接不该触发（advisory 指向内网不算 POC 死链）
    advisory = _case(references=[{"url": "http://localhost/advisory", "kind": "advisory"}])
    assert FLAG_POC_DEAD_LINK not in collect_flags(advisory)


def test_flag_key5_missing() -> None:
    """命中：关键五件套缺任一。不命中：齐全。"""

    for field_name in ("cve_id", "title", "description", "published_at", "severity"):
        assert FLAG_KEY5_MISSING in collect_flags(_case(**{field_name: None})), field_name
    assert FLAG_KEY5_MISSING not in collect_flags(CLEAN)


def test_flag_boilerplate() -> None:
    """命中：模板化正文 / 只有一堆链接。不命中：有实质描述。"""

    assert FLAG_BOILERPLATE in collect_flags(_case(description="No description"))
    assert FLAG_BOILERPLATE in collect_flags(
        _case(description=" ".join(f"https://x.example/{i}" for i in range(8)))
    )
    assert FLAG_BOILERPLATE in collect_flags(_case(description="暂无描述"))
    assert FLAG_BOILERPLATE not in collect_flags(CLEAN)


def test_flag_multi_id_mismatch() -> None:
    """命中：CVE 与 GHSA 并存但编号形态非法（结构性错误）。

    口径与 SafeTrace 冻结契约的 flag 语义对齐：**任一 flag ⇒ quarantine**，
    所以"可疑但不致命"的编号冲突不进 flag，只归到 consistency 分数。
    """

    bad = _case(ghsa_id="not-a-ghsa-id")
    assert FLAG_MULTI_ID_MISMATCH in collect_flags(bad)

    good = _case(ghsa_id="GHSA-7f3q-vllm-rce")  # 形态正确，不该误报
    assert FLAG_MULTI_ID_MISMATCH not in collect_flags(good)
    # 只有 CVE 没有 GHSA 属于正常情况
    assert FLAG_MULTI_ID_MISMATCH not in collect_flags(_case(ghsa_id=None))


def test_suspicious_id_pair_lowers_consistency() -> None:
    """编号形态非法时 consistency 分必须被压下去（flag 与分数各司其职）。"""

    good = evaluate(_case(ghsa_id="GHSA-7f3q-vllm-rce"))
    bad = evaluate(_case(ghsa_id="not-a-ghsa-id"))
    assert bad.dimension_scores["consistency"] < good.dimension_scores["consistency"]
    assert bad.verdict == "quarantine"


def test_no_invented_flags() -> None:
    """禁止自造 flag —— 权威枚举就 6 个。"""

    every_kind = _case(
        published_at="2026-09-28T00:00:00",
        vuln_status="rejected",
        title="",
        description="n/a",
        ghsa_id="broken",
        references=[{"url": "http://127.0.0.1/poc", "kind": "exploit"}],
    )
    flags = collect_flags(every_kind)
    assert set(flags) <= set(ALL_FLAGS)
    assert len(flags) == len(set(flags)), "flag 不许重复"


# ---------------------------------------------------------------- 四档判定


def test_verdict_boundaries_match_configured_thresholds() -> None:
    """四档边界必须与 `enrich_min_quality_*` 配置一致（回归：旧行为不能被改坏）。"""

    partial = thresholds_for()["partial"]
    full = thresholds_for()["full"]

    assert decide_verdict(0.0, []) == "review"
    assert decide_verdict(partial, []) == "review"
    assert decide_verdict(partial + 0.01, []) == "degrade"
    assert decide_verdict(full, []) == "degrade"
    assert decide_verdict(full + 0.01, []) == "pass"
    assert decide_verdict(1.0, []) == "pass"


def test_flags_force_quarantine_regardless_of_score() -> None:
    """★ flag 与分数解耦：满分也拦不住 flag。"""

    verdict = decide_verdict(1.0, [FLAG_KEY5_MISSING])
    assert verdict == "quarantine"


def test_quarantine_verdict_gets_reference() -> None:
    result = evaluate(_case(description="No description"))
    assert result.verdict == "quarantine"
    assert result.quarantine_ref and result.quarantine_ref.startswith("quarantine://")


def test_clean_item_passes() -> None:
    result = evaluate(CLEAN)
    assert result.flags == []
    assert result.verdict in {"pass", "degrade"}, result.to_payload()
    assert 0.0 <= result.quality_score <= 1.0


# ---------------------------------------------------------------- 可复算


def test_same_input_same_output() -> None:
    """同 gate_version + 同输入 ⇒ 同分数、同 flags（可复算，发布不了随机判定）。"""

    now = dt.datetime(2026, 9, 29, tzinfo=dt.UTC)
    first = evaluate(CLEAN, now=now).to_payload()
    second = evaluate(CLEAN, now=now).to_payload()
    assert first == second


def test_timeliness_is_deterministic_with_injected_now() -> None:
    now = dt.datetime(2026, 9, 29, tzinfo=dt.UTC)
    assert score_timeliness(CLEAN, now=now) == 1.0
    old = _case(published_at="2026-01-01T00:00:00+00:00", fetched_at=None)
    assert score_timeliness(old, now=now) == 0.0


def test_missing_published_at_is_neutral_not_zero() -> None:
    """ "上游没给发布时间"不是这条情报的错，给中性分而不是 0。"""

    assert score_timeliness(_case(published_at=None)) == 0.5


def test_unknown_gate_version_raises() -> None:
    from aiintel.services.dq1 import DQ1Error

    with pytest.raises(DQ1Error):
        weights_for("9.9.9")
    with pytest.raises(DQ1Error):
        evaluate(CLEAN, gate_version="9.9.9")


def test_weights_sum_to_one_per_version() -> None:
    for version, weights in GATE_WEIGHTS.items():
        assert abs(sum(weights.values()) - 1.0) < 1e-9, version


# ---------------------------------------------------------------- 载荷契约


def test_verdict_payload_matches_dq_verdicts_contract() -> None:
    """`dq.verdicts` 的载荷必须过内联 `QualityVerdict` 契约。"""

    payload = evaluate(CLEAN).to_payload()
    schema = payload_schema_for("dq.verdicts")
    assert schema is not None
    assert validate(schema, payload) == [], validate(schema, payload)
    assert payload["gate_version"] == GATE_VERSION


def test_quarantine_payload_also_matches_contract() -> None:
    payload = evaluate(_case(published_at="2026-09-28T00:00:00")).to_payload()
    schema = load_schema("LocalPayloads.json")["definitions"]["QualityVerdict"]
    assert validate(schema, payload) == []
    assert payload["verdict"] == "quarantine"
    assert FLAG_TS_NO_TZ in payload["flags"]


def test_dimension_scores_cover_all_five_axes() -> None:
    payload = evaluate(CLEAN).to_payload()
    assert set(payload["dimension_scores"]) == {
        "structure",
        "completeness",
        "consistency",
        "timeliness",
        "sourcing",
    }


def test_structure_score_rewards_parsable_payload() -> None:
    """有可解析载荷要真的加分（不能因为字段齐全就被截断抹平）。

    `_structured_ok` 认三种信号：原始 payload / CVSS 向量 / 严重性。
    所以"无载荷"的对照组必须把三者都去掉，否则它仍然算"有结构"。
    """

    with_raw = score_structure(CLEAN)
    stripped = {k: v for k, v in CLEAN.items() if k not in {"raw_json", "cvss_vector", "severity"}}
    without_any = score_structure(stripped)
    assert with_raw > without_any
    assert without_any < 1.0


def test_verdict_dataclass_is_stable_shape() -> None:
    verdict = QualityVerdict(item_id="x")
    assert verdict.item_kind == "intel"
    assert verdict.gate_version == GATE_VERSION
    assert verdict.reviewer is None and verdict.reviewed_at is None

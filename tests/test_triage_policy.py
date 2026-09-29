"""动态优先级单测：EPSS/KEV/CVSS 加权排序、可复算、KEV 安全网。

对应 `docs/路线评估-优先级与RAG.md` 提案① 的改写版：
**不新增任何数据集成**（EPSS/KEV 早在库），只重写排序逻辑。
"""

from __future__ import annotations

import pytest
from scripts.contracts import load_schema, validate
from scripts.validate_contracts import payload_schema_for

from aiintel.services.triage import (
    KEV_FLOOR,
    POLICY_VERSION,
    POLICY_WEIGHTS,
    PRIORITIES,
    ROUTE_DETAIL,
    ROUTE_TEMPLATE,
    TriagePolicyError,
    rank_items,
    score_item,
    thresholds_for,
    weights_for,
)

#: 实测风格的三条情报：高影响 / 高利用概率 / 在野利用
HIGH_CVSS = {"cve_id": "CVE-A", "cvss_score": 9.8, "epss": 0.02, "kev": False}
HIGH_EPSS = {"cve_id": "CVE-B", "cvss_score": 7.5, "epss": 0.9, "kev": False}
IN_KEV = {"cve_id": "CVE-C", "cvss_score": 5.0, "epss": 0.01, "kev": True}


# ---------------------------------------------------------------- 权重与版本


def test_weights_sum_to_one() -> None:
    for version, weights in POLICY_WEIGHTS.items():
        assert abs(sum(weights.values()) - 1.0) < 1e-9, version


def test_unknown_policy_version_raises() -> None:
    with pytest.raises(TriagePolicyError):
        weights_for("9.9.9")
    with pytest.raises(TriagePolicyError):
        thresholds_for("9.9.9")
    with pytest.raises(TriagePolicyError):
        score_item(HIGH_CVSS, policy_version="9.9.9")


def test_score_is_normalised_into_unit_range() -> None:
    """三项权重之和为 1 且各自归一，所以分数必须落在 [0,1]。"""

    everything = {"cve_id": "x", "cvss_score": 10.0, "epss": 1.0, "kev": True}
    nothing = {"cve_id": "y"}
    assert 0.0 <= score_item(nothing).score <= 1.0
    assert score_item(everything).score <= 1.0
    assert score_item(HIGH_CVSS).score <= 1.0


def test_max_signal_scores_higher_than_single_signal() -> None:
    everything = score_item({"cve_id": "x", "cvss_score": 10.0, "epss": 1.0, "kev": True})
    assert everything.score > score_item(HIGH_CVSS).score
    assert everything.score > score_item(HIGH_EPSS).score


# ---------------------------------------------------------------- 排序语义


def test_epss_outranks_cvss_at_similar_impact() -> None:
    """主信号是**被利用概率**：EPSS 0.9 的中危应排在 EPSS 0.02 的严重之前。

    这正是旧实现（单因子 CVSS）判错的地方。
    """

    ranked = rank_items([HIGH_CVSS, HIGH_EPSS])
    assert ranked[0].vuln_id == "CVE-B", "EPSS 高的应该排前面"
    assert ranked[0].epss == 0.9
    assert ranked[1].vuln_id == "CVE-A"


def test_kev_never_sinks_to_the_bottom() -> None:
    """★ KEV 是罕见但决定性的信号：命中就不许沉到队尾。"""

    ranked = rank_items([HIGH_CVSS, HIGH_EPSS, IN_KEV])
    kev_candidate = next(c for c in ranked if c.vuln_id == "CVE-C")
    assert kev_candidate.priority != "low"
    assert PRIORITIES.index(kev_candidate.priority) <= PRIORITIES.index(KEV_FLOOR)


def test_kev_item_always_gets_detail_route() -> None:
    """★ 在野利用的条目不能被降级成通用模板建议。"""

    ranked = rank_items([HIGH_CVSS, HIGH_EPSS, IN_KEV], limit=1)
    kev_candidate = next(c for c in ranked if c.vuln_id == "CVE-C")
    assert kev_candidate.rank == 3, "前提：它确实排在 Top-N 之外"
    assert kev_candidate.route == ROUTE_DETAIL


def test_top_n_gets_detail_route_and_rest_template() -> None:
    ranked = rank_items([HIGH_CVSS, HIGH_EPSS, IN_KEV], limit=2)
    assert [c.route for c in ranked] == [ROUTE_DETAIL, ROUTE_DETAIL, ROUTE_DETAIL]
    # 去掉 KEV 那条，验证"排后走模板"的常规路径
    tail = {"cve_id": "CVE-D", "cvss_score": 1.0, "epss": 0.0, "kev": False}
    ranked2 = rank_items([HIGH_CVSS, HIGH_EPSS, tail], limit=2)
    assert ranked2[-1].route == ROUTE_TEMPLATE
    assert ranked2[-1].rank == 3


def test_rank_is_total_order_and_reproducible() -> None:
    """同分时按 vuln_id 字典序 —— 全序才谈得上复算。"""

    a = {"cve_id": "CVE-B", "cvss_score": 5.0, "epss": 0.5}
    b = {"cve_id": "CVE-A", "cvss_score": 5.0, "epss": 0.5}
    first = rank_items([a, b])
    second = rank_items([b, a])
    assert [c.vuln_id for c in first] == [c.vuln_id for c in second] == ["CVE-A", "CVE-B"]
    assert [c.score for c in first] == [c.score for c in second]


def test_same_input_same_output() -> None:
    payloads = [dict(HIGH_CVSS), dict(HIGH_EPSS), dict(IN_KEV)]
    assert [c.to_order_payload() for c in rank_items(payloads, limit=2)] == [
        c.to_order_payload() for c in rank_items(payloads, limit=2)
    ]


def test_low_quality_is_downweighted() -> None:
    """DQ1 的质量分参与排序（乘性降权），但不至于把 KEV 翻下去。"""

    good = {"cve_id": "CVE-X", "cvss_score": 9.0, "epss": 0.8, "quality_score": 0.95}
    poor = {"cve_id": "CVE-Y", "cvss_score": 9.0, "epss": 0.8, "quality_score": 0.1}
    assert score_item(poor).score < score_item(good).score
    assert any("降权" in r for r in score_item(poor).reasons)


def test_missing_signals_are_reported_not_invented() -> None:
    """三项信号全缺时要如实说明，不能编一个分数理由。"""

    candidate = score_item({"cve_id": "CVE-Z"})
    assert candidate.score == 0.0
    assert candidate.epss is None
    assert candidate.kev is False
    assert any("均缺失" in r for r in candidate.reasons)


def test_epss_out_of_range_is_clamped_by_weight_not_crashing() -> None:
    """上游给了 >1 的 EPSS 也不能算出 >1 的总分（不清洗数据但也不失真）。"""

    weird = score_item({"cve_id": "CVE-W", "cvss_score": 9.0, "epss": 3.0})
    assert weird.score <= 1.0


# ---------------------------------------------------------------- 载荷契约


def test_order_payload_matches_triage_order_contract() -> None:
    schema = payload_schema_for("enrich.triage")
    assert schema is not None
    for candidate in rank_items([HIGH_CVSS, HIGH_EPSS, IN_KEV], limit=2):
        payload = candidate.to_order_payload()
        assert validate(schema, payload) == [], validate(schema, payload)
        assert payload["policy_version"] == POLICY_VERSION
        assert payload["route"] in {ROUTE_DETAIL, ROUTE_TEMPLATE}
        assert payload["priority"] in PRIORITIES


def test_priority_values_are_within_contract_enum() -> None:
    schema = load_schema("LocalPayloads.json")["definitions"]["TriageOrder"]
    for item in (HIGH_CVSS, HIGH_EPSS, IN_KEV, {"cve_id": "z"}):
        assert validate(schema, score_item(item).to_order_payload()) == []

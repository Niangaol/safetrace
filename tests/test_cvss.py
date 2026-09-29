"""CVSS 3.1 计算：向量解析、基础分、roundup、分级标签。"""

from __future__ import annotations

import pytest

from aiintel.services.enrich.cvss import (
    WEIGHTS,
    parse_vector,
    qualitative,
    risk_ratio,
    roundup,
    score_vector_31,
    severity_label,
    vector_from_components,
)

# CVSS v3.1 官方参考向量
REF_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
REF_75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"  # 7.5
REF_00 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # 0.0
SCOPE_CHANGED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0


def test_roundup_matches_spec():
    assert roundup(4.02) == 4.1
    assert roundup(4.00) == 4.0
    assert roundup(5.00) == 5.0
    assert roundup(6.02) == 6.1
    assert roundup(0.0) == 0.0
    assert roundup(0.1) == 0.1


def test_official_reference_scores():
    assert score_vector_31(REF_98) == pytest.approx(9.8)
    assert score_vector_31(REF_75) == pytest.approx(7.5)
    assert score_vector_31(REF_00) == pytest.approx(0.0)
    assert score_vector_31(SCOPE_CHANGED) == pytest.approx(10.0)


def test_scope_changed_raises_score():
    assert score_vector_31(SCOPE_CHANGED) > score_vector_31(REF_98)


def test_parse_vector():
    parsed = parse_vector(REF_98)
    assert parsed["AV"] == "N"
    assert parsed["S"] == "U"
    assert len(parsed) == 8


def test_parse_vector_handles_garbage():
    assert parse_vector("") == {}
    assert parse_vector("garbage") == {}


def test_invalid_vector_returns_none():
    assert score_vector_31("CVSS:3.1/AV:N/AC:L") is None  # 缺字段
    assert score_vector_31("") is None
    assert score_vector_31("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None  # 非法取值


def test_weights_table_complete():
    assert set(WEIGHTS) == {"AV", "AC", "PR", "UI", "C", "I", "A"}
    assert set(WEIGHTS["AV"]) == {"N", "A", "L", "P"}
    assert set(WEIGHTS["AC"]) == {"L", "H"}
    assert set(WEIGHTS["PR"]) == {"U", "C"}
    for dim in ("C", "I", "A"):
        assert set(WEIGHTS[dim]) == {"H", "L", "N"}


def test_vector_from_components_roundtrip():
    vector = vector_from_components(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H")
    assert vector == REF_98
    assert score_vector_31(vector) == pytest.approx(9.8)


def test_severity_labels_match_cvss_bands():
    assert severity_label(9.8) == "critical"
    assert severity_label(9.0) == "critical"
    assert severity_label(7.5) == "high"
    assert severity_label(7.0) == "high"
    assert severity_label(5.0) == "medium"
    assert severity_label(3.9) == "low"
    assert severity_label(None) == "unknown"


def test_qualitative_labels():
    assert qualitative(9.8) == "Critical"
    assert qualitative(7.5) == "High"
    assert qualitative(5.0) == "Medium"
    assert qualitative(2.0) == "Low"
    assert qualitative(0.0) == "None"
    assert qualitative(None) == "None"


def test_risk_ratio_monotonic_and_bounded():
    assert 0.0 <= risk_ratio(None) == 0.0
    assert risk_ratio(5.0) < risk_ratio(9.8)
    assert risk_ratio(10.0) <= 1.5

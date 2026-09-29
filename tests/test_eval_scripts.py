"""评测脚本自身的正确性（无需数据库/网络）。"""

from __future__ import annotations

from eval.collect_latency import collect_latency_stats
from eval.enrich_accuracy import score_cases


def test_collect_latency_percentiles_and_tier():
    rows = [
        {"source": "ghsa", "latency_seconds": 5.0},
        {"source": "nvd", "latency_seconds": 7200.0},
        {"source": "nvd", "latency_seconds": 57600.0},
    ]
    stats = collect_latency_stats(rows)
    assert stats["samples"] == 3
    assert stats["p50_seconds"] == 7200.0
    assert stats["sla_tier"] in {"excellent", "good", "pass", "fail"}
    assert set(stats["by_source"]) == {"ghsa", "nvd"}


def test_collect_latency_ignores_invalid_rows():
    stats = collect_latency_stats([{"latency_seconds": None}, {"latency_seconds": -1}])
    assert stats["samples"] == 0
    assert stats["p95_seconds"] is None


def test_enrich_accuracy_counts_correct_binary():
    cases = [
        {"case_id": "a", "dimension": "poc", "expected": {"poc": True}},
        {"case_id": "b", "dimension": "poc", "expected": {"poc": False}},
    ]
    actuals = {
        "a": {"dimension": "poc", "value": {"pocs": ["https://github.com/x/y"]}},
        "b": {"dimension": "poc", "value": {"pocs": []}},
    }
    result = score_cases(cases, actuals)
    assert result["overall_accuracy"] == 1.0
    assert result["meets_target"] is True


def test_enrich_accuracy_penalises_false_positive():
    cases = [{"case_id": "a", "dimension": "poc", "expected": {"poc": False}}]
    actuals = {"a": {"dimension": "poc", "value": {"pocs": ["x"]}}}
    result = score_cases(cases, actuals)
    assert result["overall_accuracy"] < 1.0

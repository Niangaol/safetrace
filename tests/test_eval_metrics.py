"""评测指标的口径回归（`eval/enrich_accuracy.py`）。

这两个 bug 都是**在建立基线时实测暴露**的，且都属于"数字看着像真的、其实是错的"：

1. `precision = 23.667` —— 数学上不可能（>1）。
   根因：把 **case 级**计数（`total`、`correct`）与 **元素级**计数（集合类维度按元素累加
   tp/fp/fn）混进同一个公式，`total - correct - hits` 会是**负数**，分母被压到 1~3。
2. `{'poc': False}` 被当成正例 —— 它是**非空 dict**，`bool()` 为 True，
   于是"正确判定为没有 POC"被记成 fp，accuracy 从 1.0 掉到 0.961。

两条都属于"不看数字合理性就发现不了"的类型，所以钉在这里。
"""

from __future__ import annotations

from eval.enrich_accuracy import _expected_positive, score_cases


def _case(case_id: str, dimension: str, expected) -> dict:
    return {"case_id": case_id, "dimension": dimension, "expected": expected}


def test_no_poc_annotation_is_not_treated_as_positive() -> None:
    """`{'poc': False}` 必须判为**负例**（非空 dict 的 bool() 是 True，这里最容易踩）。"""

    assert _expected_positive("poc", {"poc": False}) is False
    assert _expected_positive("poc", {"poc": True}) is True
    # 别的维度用单键 dict 也要取键值，而不是取 dict 本身的真值
    assert _expected_positive("fix", {"fix": False}) is False
    # 空集合是负例
    assert _expected_positive("paper", []) is False
    assert _expected_positive("paper", ["2609.01234"]) is True


def test_precision_stays_within_unit_interval() -> None:
    """回归：precision 绝不能 > 1（旧公式在集合类维度上会算出 23.667）。"""

    cases = [
        _case("c1", "paper", ["a", "b"]),
        _case("c2", "paper", ["c"]),
        _case("c3", "poc", {"poc": False}),
        _case("c4", "poc", {"poc": True}),
        _case("c5", "ai_risk", "model_serving"),
    ]
    actuals = {
        "c1": {"value": {"papers": [{"arxiv_id": "a"}, {"arxiv_id": "b"}]}},
        "c2": {"value": {"papers": [{"arxiv_id": "c"}]}},
        "c3": {"value": {"pocs": []}},
        "c4": {"value": {"pocs": [{"url": "x"}]}},
        "c5": {"value": {"category": "model_serving"}},
    }
    result = score_cases(cases, actuals)

    for key in ("micro_precision", "micro_recall", "macro_precision", "macro_recall"):
        value = result[key]
        assert 0.0 <= value <= 1.0, f"{key}={value} 超出 [0,1]"
    for dim, stats in result["dimensions"].items():
        for key in ("precision", "recall", "accuracy"):
            assert 0.0 <= stats[key] <= 1.0, f"{dim}.{key}={stats[key]} 超出 [0,1]"

    # 全部正确命中时应当满分
    assert result["overall_accuracy"] == 1.0
    assert result["micro_precision"] == 1.0
    assert result["unmatched_cases"] == 0


def test_unmatched_cases_are_reported_not_counted_as_wrong() -> None:
    """标注的 vuln_id 在库里找不到时：不做分母，但要**显式报出来**。

    否则"只测了 3 条"和"全测过了"在输出里长得一样。
    """

    cases = [
        _case("c1", "poc", {"poc": True}),
        _case("c2", "poc", {"poc": True}),
        _case("c3", "poc", {"poc": True}),
    ]
    actuals = {"c1": {"value": {"pocs": [{"url": "x"}]}}}  # c2/c3 库里没有

    result = score_cases(cases, actuals)
    assert result["matched_cases"] == 1
    assert result["unmatched_cases"] == 2
    assert result["overall_accuracy"] == 1.0, "未匹配的不该算判错"
    assert "跳过" in result.get("note", "")

"""富化准确率与召回率：基于人工标注集做字段级 precision / recall。

标注集格式（eval/datasets/enrich_cases.jsonl，每行一条）：
  {"case_id":"e001","vuln_id":"v_xxx","dimension":"poc",
   "expected":{"poc":true},"judge_by":"人工"}

对 LLM 判定的二元结论（如"是否有可用 POC"）计算准确率；
对集合类结论（论文列表）计算 precision / recall。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATASET = Path(__file__).parent / "datasets" / "enrich_cases.jsonl"
TARGET_ACCURACY = 0.90  # 良好档；优秀档 0.95


def _load_cases(path: Path = DATASET) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _actual_value(dimension: str, value: dict) -> Any:
    """把某维度的产出压成"可判定"的形式：布尔 / 标量 / 集合。

    新增维度（F2 asset / F5 fix / F6 consistency）也要在这里给出口径，
    否则评测会静默把它们算成"未命中"。
    """

    value = value or {}
    if dimension == "poc":
        return bool(value.get("pocs"))
    if dimension == "paper":
        return {(p.get("arxiv_id") or "") for p in value.get("papers", [])}
    if dimension == "ai_risk":
        return value.get("category")
    if dimension == "cvss":
        return value.get("base_score")
    if dimension == "asset":
        # 判"是否给出了受影响产品"，不评资产画像（那是 Mock）
        return {str(p.get("product") or "") for p in value.get("products", []) if p.get("product")}
    if dimension == "fix":
        # 判"是否定位到官方修复版本 + 给出了缓解动作"
        return bool(value.get("upgrade", {}).get("target_version")) or bool(value.get("immediate"))
    if dimension == "consistency":
        # 集合类：检出的冲突字段名（召回 = 该冲突有没有被检出来）
        return {str(c.get("field") or "") for c in value.get("conflicts", []) if c.get("field")}
    return None


def _is_set_case(dimension: str, expected: Any, actual: Any) -> bool:
    """集合类维度（如 paper 的论文列表）走 precision/recall 而非二元判定。"""

    return (
        dimension == "paper" or isinstance(actual, set) or isinstance(expected, (set, list, tuple))
    )


def _expected_positive(dimension: str, expected: Any) -> bool:
    """把标注集的 expected 统一成"是否为正例"。

    ⚠️ 这里有个**必须小心的坑**：`{'poc': False}` 是一个**非空 dict**，
    所以 `bool(expected)` 是 `True` —— 直接用 `bool()` 判会把"标注为没有 POC"
    误当成正例，进而把这条例算成 fp（假阳），accuracy 凭空掉下来。
    实测踩过：76 条基线里恰好有 1 条 `{'poc': False}`，accuracy 因此从 1.0 掉到 0.961。
    """

    if isinstance(expected, bool):
        return expected
    if isinstance(expected, dict):
        if dimension == "poc" and "poc" in expected:
            return bool(expected["poc"])
        values = list(expected.values())
        # 单键 dict 取该键的布尔值；多键（信息不全）按正例处理，避免漏判
        return bool(values[0]) if len(values) == 1 else True
    if isinstance(expected, (list, set, tuple)):
        return len(expected) > 0
    return bool(expected)


def score_cases(cases: list[dict], actuals: dict[str, dict]) -> dict[str, Any]:
    """actuals: {case_id: {"dimension": dim, "value": {...}}}

    统计口径（两套并存，别混用）：

    - **case 级**：判对/判错按"标注条目"计数 → `overall_accuracy` / `macro_*`
    - **元素级**：集合类维度（paper/asset/consistency）按**元素个数**累计 tp/fp/fn
      → `micro_precision` / `micro_recall`

    ⚠️ 早先的 `precision` 把两套口径混进同一个公式
    （`hits / max(hits + (total - correct - hits), 1)`），而 `total - correct - hits`
    在集合类维度上**可以是负数** → 分母被压到 1~3 → 算出 `precision = 23.667` 这种
    数学上不可能的值（实测）。现在分开算，两个指标都落在 [0,1]。
    """

    per_dimension: dict[str, dict[str, float]] = {}
    hits = misses = correct_cases = matched = 0
    fp_total = fn_total = 0

    for case in cases:
        dimension = case["dimension"]
        expected = case.get("expected", {})
        actual_entry = actuals.get(case["case_id"])
        if actual_entry is None:
            # 库里没有对应产出：**不算判错**，但也不计进分母（最后由 unmatched_cases 暴露）
            continue
        matched += 1
        actual = _actual_value(dimension, actual_entry.get("value", {}))
        bucket = per_dimension.setdefault(dimension, {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})

        if _is_set_case(dimension, expected, actual):
            exp_set = set(expected or [])
            act_set = set(actual or set())
            bucket["n"] += 1
            tp = len(exp_set & act_set)
            fp = len(act_set - exp_set)
            fn = len(exp_set - act_set)
            bucket["tp"] += tp
            bucket["fp"] += fp
            bucket["fn"] += fn
            fp_total += fp
            fn_total += fn
            hits += tp
            misses += fp + fn
            # case 级"判对" = 集合完全一致
            if exp_set == act_set:
                correct_cases += 1
            continue

        bucket["n"] += 1
        expected_positive = _expected_positive(dimension, expected)
        actual_positive = bool(actual)
        if actual_positive and expected_positive:
            bucket["tp"] += 1
            correct_cases += 1
            hits += 1
        elif actual_positive and not expected_positive:
            bucket["fp"] += 1
            fp_total += 1
            misses += 1
        elif not actual_positive and expected_positive:
            bucket["fn"] += 1
            fn_total += 1
            misses += 1
        else:
            bucket["tn"] += 1
            correct_cases += 1

    result: dict[str, Any] = {"cases": len(cases), "dimensions": {}}
    for dimension, bucket in per_dimension.items():
        # ⚠️ 三个指标都要用**同一个口径**。
        # 集合类维度的 tp/fp/fn 是按**元素个数**累加的，而 n 是**case 个数**；
        # 若 accuracy 写成 (tp+tn)/n 就会 >1（实测 paper 维度算出 1.5）。
        # 因此 accuracy 也用元素级：tp/(tp+fp+fn)，tn 不参与（集合类没有 tn 的概念）。
        precision = bucket["tp"] / max(bucket["tp"] + bucket["fp"], 1)
        recall = bucket["tp"] / max(bucket["tp"] + bucket["fn"], 1)
        elements = bucket["tp"] + bucket["fp"] + bucket["fn"]
        accuracy = (bucket["tp"] / elements) if elements else (1.0 if bucket["tn"] else 0.0)
        result["dimensions"][dimension] = {
            "n": bucket["n"],
            "tp": bucket["tp"],
            "fp": bucket["fp"],
            "fn": bucket["fn"],
            "tn": bucket["tn"],
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "accuracy": round(accuracy, 3),
        }

    result["matched_cases"] = matched
    result["correct_cases"] = correct_cases
    # 准确率 = 判对的 case 数 / **参与评测的 case 数**
    result["overall_accuracy"] = round(correct_cases / max(matched, 1), 3)
    # 宏平均：每个维度各占一票，避免"元素多的维度"主导总分
    if per_dimension:
        result["macro_accuracy"] = round(
            sum(d["accuracy"] for d in result["dimensions"].values()) / len(per_dimension), 3
        )
        result["macro_precision"] = round(
            sum(d["precision"] for d in result["dimensions"].values()) / len(per_dimension), 3
        )
        result["macro_recall"] = round(
            sum(d["recall"] for d in result["dimensions"].values()) / len(per_dimension), 3
        )
    # 微平均：把所有权重压成一个比例（元素级）
    result["micro_precision"] = round(hits / max(hits + fp_total, 1), 3)
    result["micro_recall"] = round(hits / max(hits + fn_total, 1), 3)
    result["meets_target"] = result["overall_accuracy"] >= TARGET_ACCURACY
    result["target"] = TARGET_ACCURACY
    result["unmatched_cases"] = len(cases) - matched
    if result["unmatched_cases"]:
        # 标注集的 vuln_id 在库里找不到时，这些 case 会被静默跳过。
        # 必须显式暴露出来，否则"少测了一半"看起来和"全测过了"一样。
        result["note"] = (
            f"{result['unmatched_cases']} 条标注在库中找不到对应 (vuln_id, dimension)，已跳过；"
            "这些不计入准确率分母。"
        )
    # ⚠️ 口径警告：`enrich_cases.jsonl` 的 expected 是**由当前产出固化**生成的
    # （见 `scripts/build_eval_datasets.py`），与 `load_actuals()` 读的是同一张表。
    # 因此准确率必然接近 1.0 —— 它证明的是"输出没变"，**不是"输出正确"**。
    # 真准确率请用 `eval/datasets/enrich_annotation.jsonl`（独立于系统产出，见
    # `scripts/build_enrich_annotation.py`）与 `docs/评测实测结果.md`。
    result["caveat"] = (
        "本指标是**回归基线**：expected 由当前产出固化而来，与 actual 同源，"
        "准确率恒接近 1.0。**不可读作「富化准确率」**。"
    )
    return result


def load_actuals() -> dict[str, dict]:
    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import Enrichment

    with get_sessionmaker()() as session:
        rows = session.query(Enrichment).order_by(Enrichment.version.desc()).all()
    latest: dict[tuple[str, str], dict] = {}
    for row in rows:
        latest.setdefault(
            (row.vuln_id, row.dimension), {"dimension": row.dimension, "value": row.value}
        )
    return {f"{vuln_id}|{item['dimension']}": item for (vuln_id, _), item in latest.items()}


def main() -> dict[str, Any]:
    cases = _load_cases()
    if not cases:
        return {"error": f"标注集不存在或为空: {DATASET}（Day8 前必须建好 100 条标注集）"}
    try:
        db_actuals = load_actuals()
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] 数据库不可用({exc})，仅统计标注集规模")
        return {"cases": len(cases), "error": "no actuals in database"}

    actuals: dict[str, dict] = {}
    for case in cases:
        key = f"{case['vuln_id']}|{case['dimension']}"
        if key in db_actuals:
            actuals[case["case_id"]] = db_actuals[key]
    result = score_cases(cases, actuals)
    print("[enrich] ", json.dumps(result, ensure_ascii=False))
    return result


if __name__ == "__main__":
    print(json.dumps(main(), ensure_ascii=False, indent=2))

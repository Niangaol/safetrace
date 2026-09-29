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
    """把标注集的 expected 统一成"是否为正例"。"""

    if isinstance(expected, bool):
        return expected
    if isinstance(expected, dict):
        if dimension == "poc" and "poc" in expected:
            return bool(expected["poc"])
        values = list(expected.values())
        return bool(values[0]) if len(values) == 1 else True
    return bool(expected)


def score_cases(cases: list[dict], actuals: dict[str, dict]) -> dict[str, Any]:
    """actuals: {case_id: {"dimension": dim, "value": {...}}}"""

    per_dimension: dict[str, dict[str, float]] = {}
    hits = misses = correct = 0

    for case in cases:
        dimension = case["dimension"]
        expected = case.get("expected", {})
        actual = _actual_value(dimension, actuals.get(case["case_id"], {}).get("value", {}))
        bucket = per_dimension.setdefault(dimension, {"n": 0, "tp": 0, "fp": 0, "fn": 0, "tn": 0})

        if _is_set_case(dimension, expected, actual):
            exp_set = set(expected or [])
            act_set = set(actual or set())
            bucket["n"] += 1
            bucket["tp"] += len(exp_set & act_set)
            bucket["fp"] += len(act_set - exp_set)
            bucket["fn"] += len(exp_set - act_set)
            continue

        bucket["n"] += 1
        expected_positive = _expected_positive(dimension, expected)
        actual_positive = bool(actual)
        if actual_positive and expected_positive:
            bucket["tp"] += 1
        elif actual_positive and not expected_positive:
            bucket["fp"] += 1
        elif not actual_positive and expected_positive:
            bucket["fn"] += 1
        else:
            bucket["tn"] += 1

    result: dict[str, Any] = {"cases": len(cases), "dimensions": {}}
    for dimension, bucket in per_dimension.items():
        n = max(bucket["n"], 1)
        precision = bucket["tp"] / max(bucket["tp"] + bucket["fp"], 1)
        recall = bucket["tp"] / max(bucket["tp"] + bucket["fn"], 1)
        result["dimensions"][dimension] = {
            "n": bucket["n"],
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "accuracy": round((bucket["tp"] + bucket["tn"]) / n, 3),
        }
        correct += bucket["tp"] + bucket["tn"]
        hits += bucket["tp"]
        misses += bucket["fn"] + bucket["fp"]

    total = max(len(cases), 1)
    # 准确率 = 判对数（含真负例）/ 总数；只看 tp 会把"正确地判定为无 POC"也算成错
    result["overall_accuracy"] = round(correct / total, 3)
    result["precision"] = round(hits / max(hits + (total - correct - hits), 1), 3)
    result["meets_target"] = result["overall_accuracy"] >= TARGET_ACCURACY
    result["target"] = TARGET_ACCURACY
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

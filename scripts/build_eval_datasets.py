"""生成富化标注集 `eval/datasets/enrich_cases.jsonl`。

**这里必须说清楚它是什么、不是什么**（不然报告会写错）：

- 它**不是**人工标注的准确率真值。人工标注需要领域专家逐条判定，
  本仓目前没有这个条件（台账 `E-03` 要的是 100 条人工标注 + recall@5 基线）。
- 它是**回归基线**：把当前演示库（13 条真实漏洞 × 7 个维度 = 76 条富化结论）
  的产出**固化**成期望值，用来回答一个具体问题——
  **"改了富化链路之后，输出有没有悄悄变掉？"**
  这类回归对"每次都该一样"的维度（cvss / ai_risk / asset / fix）是真有效的；
  对依赖外部检索的维度（paper / poc）只能反映当时那一次的结果。

所以：`eval/run_all.py` 报出的数字应当读作「**与基线的一致率**」，
不能读作「富化准确率」。报告里要如实区分（见 docs/交接说明.md 的已知限制）。

生成规则：对每条 `(vuln_id, dimension)`，按 `eval/enrich_accuracy.py::_actual_value`
的口径把**当前值**写成 expected，使基线自洽（一致率应为 1.0）。
若之后代码改动导致输出变化，一致率会掉下来——这正是我们要的报警。

用法::

    python -m scripts.build_eval_datasets            # 两个集都生成
    python -m scripts.build_eval_datasets --check    # 只校验现有集是否仍自洽
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "eval" / "datasets"
ENRICH_PATH = OUT_DIR / "enrich_cases.jsonl"

#: 每个维度的标注口径说明（写进 JSONL 的 note 字段，便于复核时知道"在判什么"）
DIMENSION_NOTES: dict[str, str] = {
    "poc": "是否存在可用 POC（布尔）",
    "paper": "关联到的 arXiv 编号集合（集合类，算 precision/recall）",
    "ai_risk": "AI 风险分类标签（标量）",
    "cvss": "CVSS 基础分（标量）",
    "asset": "受影响产品集合（不评资产画像，那是 Mock）",
    "fix": "是否定位到官方修复版本或给出缓解动作（布尔）",
    "consistency": "检出的冲突字段名集合（召回 = 该冲突有没有被检出来）",
}


def _expected_for(dimension: str, value: dict[str, Any]) -> Any:
    """按 enrich_accuracy._actual_value 的口径生成 expected（保持同一套定义）。"""

    value = value or {}
    if dimension == "poc":
        return {"poc": bool(value.get("pocs"))}
    if dimension == "paper":
        return sorted({(p.get("arxiv_id") or "") for p in value.get("papers", [])} - {""})
    if dimension == "ai_risk":
        return value.get("category")
    if dimension == "cvss":
        return value.get("base_score")
    if dimension == "asset":
        return sorted(
            {str(p.get("product")) for p in value.get("products", []) if p.get("product")}
        )
    if dimension == "fix":
        return {
            "fix": bool(value.get("upgrade", {}).get("target_version"))
            or bool(value.get("immediate"))
        }
    if dimension == "consistency":
        return sorted({str(c.get("field")) for c in value.get("conflicts", []) if c.get("field")})
    return None


def build(dsn: str | None = None) -> dict[str, Any]:
    import os

    if dsn:
        os.environ["POSTGRES_DSN"] = dsn

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import Enrichment, Vuln

    with get_sessionmaker()() as session:
        vulns = {v.id: v.cve_id for v in session.query(Vuln.id, Vuln.cve_id).all()}
        rows = (
            session.query(Enrichment)
            .order_by(Enrichment.vuln_id, Enrichment.dimension, Enrichment.version.desc())
            .all()
        )

    # 每条 (vuln_id, dimension) 只取版本号最大的那条（与 eval.load_actuals 一致）
    latest: dict[tuple[str, str], Enrichment] = {}
    for row in rows:
        latest.setdefault((row.vuln_id, row.dimension), row)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    for idx, ((vuln_id, dimension), row) in enumerate(sorted(latest.items()), start=1):
        cases.append(
            {
                "case_id": f"e{idx:03d}",
                "vuln_id": vuln_id,
                "cve_id": vulns.get(vuln_id),
                "dimension": dimension,
                "expected": _expected_for(dimension, row.value or {}),
                "judge_by": "基线回归（由当前产出固化，非人工标注）",
                "note": DIMENSION_NOTES.get(dimension, ""),
            }
        )

    lines = [json.dumps(c, ensure_ascii=False) for c in cases]
    ENRICH_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    by_dim: dict[str, int] = {}
    for c in cases:
        by_dim[c["dimension"]] = by_dim.get(c["dimension"], 0) + 1
    return {"path": str(ENRICH_PATH), "cases": len(cases), "by_dimension": by_dim}


def main() -> int:
    parser = argparse.ArgumentParser(description="生成/校验评测标注集")
    parser.add_argument("--dsn", default=None, help="覆盖 POSTGRES_DSN")
    parser.add_argument("--check", action="store_true", help="只校验现有集能否加载")
    args = parser.parse_args()

    if args.check:
        if not ENRICH_PATH.exists():
            print(f"[FAIL] 不存在: {ENRICH_PATH}")
            return 1
        cases = [
            json.loads(line)
            for line in ENRICH_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        print(f"OK: {ENRICH_PATH.name} 可加载，{len(cases)} 条")
        dims: dict[str, int] = {}
        for c in cases:
            dims[c["dimension"]] = dims.get(c["dimension"], 0) + 1
        print("  按维度:", dims)
        return 0

    result = build(args.dsn)
    print(f"已生成 {result['path']}")
    print(f"  条数: {result['cases']}")
    print(f"  按维度: {result['by_dimension']}")
    print()
    print("注意：这是**回归基线**（把当前产出固化成期望值），不是人工标注的准确率真值。")
    print("      run_all 报出的数字应读作「与基线的一致率」。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

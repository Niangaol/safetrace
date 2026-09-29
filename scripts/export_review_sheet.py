"""导出 13 条漏洞的富化实况 + 知识切片原文，供"独立于系统产出"的人工标注。

用途：
  1. 生成标注**审阅表**（review sheet）—— 每条给出系统产出，人对照原始证据判定对错；
  2. 导出切片原文，让判定有依据（而不是凭印象）。

⚠️ 关键设计：本脚本只打印**证据**，不生成 expected 值。
expected 必须由人（或用例作者）独立写出，否则就和
`build_eval_datasets.py` 一样陷入"expected 抄自 actual"的自我循环，一致率恒为 1.0。
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")
os.environ.setdefault("POSTGRES_DSN", "sqlite:///E:/code/ai-threat-intel-demo-v1/data/demo.db")

import json  # noqa: E402

from aiintel.db.base import get_sessionmaker  # noqa: E402
from aiintel.db.models import Chunk, Enrichment, Vuln  # noqa: E402

OUT = Path("eval/artifacts/review_sheet")
OUT.mkdir(parents=True, exist_ok=True)

with get_sessionmaker()() as s:
    vulns = s.query(Vuln).all()
    enrs = s.query(Enrichment).all()
    chunks = s.query(Chunk).all()

# 索引：vuln_id -> cve_id
vmap = {v.id: v for v in vulns}
# 切片原文按 owner_id 归组（owner_id 现在是 CVE 编号）
by_owner: dict[str, list[str]] = {}
for c in chunks:
    by_owner.setdefault(c.owner_id, []).append(c.content)

sheet: list[dict] = []
for e in enrs:
    v = vmap.get(e.vuln_id)
    row = {
        "case_id": f"{e.vuln_id[:8]}|{e.dimension}",
        "vuln_id": e.vuln_id,
        "cve_id": v.cve_id if v else None,
        "severity": v.severity if v else None,
        "dimension": e.dimension,
        "confidence": e.confidence,
        "degraded_to": e.degraded_to,
        "sources": e.source,
        "evidence": e.evidence,
        "value": e.value,
    }
    sheet.append(row)

(OUT / "enrichment_actuals.json").write_text(
    json.dumps(sheet, ensure_ascii=False, indent=2), encoding="utf-8"
)

# 切片原文单独落盘，便于对照
(OUT / "chunks_by_owner.json").write_text(
    json.dumps(by_owner, ensure_ascii=False, indent=2), encoding="utf-8"
)

print(f"富化实况 {len(sheet)} 条 -> {OUT / 'enrichment_actuals.json'}")
print(f"切片原文 {len(chunks)} 片 -> {OUT / 'chunks_by_owner.json'}")
print()
print("=== 逐维度价值预览（判定时要看的东西）===")
for dim in ("poc", "paper", "fix", "cvss", "ai_risk", "consistency", "asset"):
    rows = [r for r in sheet if r["dimension"] == dim]
    print(f"--- {dim} ({len(rows)} 条) ---")
    for r in rows[:3]:
        val = r["value"] if isinstance(r["value"], dict) else {}
        key_bits = {k: val[k] for k in list(val)[:4]}
        print(f"  {r['cve_id']}  conf={r['confidence']}  deg={r['degraded_to']}")
        print(f"     {json.dumps(key_bits, ensure_ascii=False)[:150]}")
    if len(rows) > 3:
        print(f"  …还有 {len(rows) - 3} 条")

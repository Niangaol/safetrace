"""构建漏洞主表一致性标注集（台账要求的「漏洞 30」块）。

全是**零判断**检查，不需要专家也不需要外部核查 —— 因此可以自动判定：
  1. cve_id 存在且格式合法（`^CVE-\\d{4}-\\d{4,}$`）
  2. severity 标签与 cvss_vector **独立重算**的档位一致（用 eval/cvss_reference.py）
  3. 时间戳齐全且 published_at <= fetched_at

第 2 条是硬缺陷：同一个对象里"向量说是 8.8/high、标签写 critical"是自相矛盾，
任何评审都能一眼看出。演示库实测 13 条里 3 条不合格。

产出 `eval/datasets/vuln_annotation.jsonl`。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from eval.cvss_reference import base_score as ref_score  # noqa: E402
from eval.cvss_reference import severity_label as ref_sev  # noqa: E402

OUT = ROOT / "eval" / "datasets" / "vuln_annotation.jsonl"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def build() -> dict:
    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import Vuln

    with get_sessionmaker()() as s:
        rows = s.query(Vuln).order_by(Vuln.cve_id).all()

    cases: list[dict] = []
    for i, v in enumerate(rows, start=1):
        checks: list[dict] = []

        # 1) cve_id
        if not v.cve_id:
            checks.append({"name": "cve_id_present", "ok": False, "detail": "缺 cve_id"})
        elif not CVE_RE.match(v.cve_id):
            checks.append(
                {
                    "name": "cve_id_format",
                    "ok": False,
                    "detail": f"{v.cve_id} 不符合 CVE-YYYY-NNNN 格式",
                }
            )
        else:
            checks.append({"name": "cve_id_format", "ok": True, "detail": v.cve_id})

        # 2) severity vs 向量
        truth = ref_score(v.cvss_vector) if v.cvss_vector else None
        if truth is None:
            checks.append(
                {
                    "name": "severity_matches_vector",
                    "ok": False,
                    "detail": "cvss_vector 缺失或不可解析，无法核对 severity",
                }
            )
        else:
            want = ref_sev(truth)
            got = (v.severity or "").lower()
            checks.append(
                {
                    "name": "severity_matches_vector",
                    "ok": got == want,
                    "detail": f"标签 {got}，向量 {v.cvss_vector} 独立算出 {truth}/{want}",
                }
            )

        # 3) 时间戳
        if v.published_at and v.fetched_at:
            ok = v.published_at <= v.fetched_at
            checks.append(
                {
                    "name": "timestamps_ordered",
                    "ok": ok,
                    "detail": f"published={v.published_at} fetched={v.fetched_at}",
                }
            )
        else:
            checks.append(
                {
                    "name": "timestamps_present",
                    "ok": False,
                    "detail": f"published={v.published_at} fetched={v.fetched_at}",
                }
            )

        failed = [c for c in checks if not c["ok"]]
        cases.append(
            {
                "case_id": f"v{i:03d}",
                "cve_id": v.cve_id,
                "vuln_id": v.id,
                "track": "A",
                "verdict": "correct" if not failed else "wrong",
                "rationale": "；".join(c["detail"] for c in failed) or "三项检查全部通过",
                "checks": checks,
            }
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    total = len(cases)
    correct = sum(1 for c in cases if c["verdict"] == "correct")
    return {"total": total, "correct": correct, "wrong": total - correct, "path": str(OUT)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default=None)
    args = ap.parse_args()
    if args.dsn:
        import os

        os.environ["POSTGRES_DSN"] = args.dsn

    r = build()
    print(f"漏洞条数   : {r['total']}")
    print(f"  correct  : {r['correct']}")
    print(f"  wrong    : {r['wrong']}")
    print(f"  准确率   : {r['correct'] / r['total']:.3f}")
    print(f"已写       : {r['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

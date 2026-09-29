"""对演示库里 13 条**真实漏洞**跑**真实富化链路**，产出评测用的 actuals。

为什么要这一步：
  演示库（`data/demo.db`）里的富化是把 `demo_seed.py::DIMENSIONS` 那份**模板**
  套给所有漏洞 —— 7 个维度各只有 2 个不同值，`poc` 的 11 个引用指向同一个占位仓库，
  `paper` 的 12 个引用指向同一篇论文，`cvss` 与切片里的真值 8 条错 7 条。
  用那份数据做标注，expected 只能抄 actual，一致率恒为 1.0，测不出任何东西。

  所以评测必须建立在**真实链路产出**上：`EnrichAgent.run()` 会真的去搜 arXiv/OpenAlex、
  真的从 CVSS 向量算分、在缺依据时**如实给空**（实测 `pocs: []`、`papers: []`）。

产出：`eval/artifacts/real_enrich/<cve_id>.json`，每条含 7 个维度的完整结果
（value / source / evidence / confidence / degraded_to / model）。

用法::

    python -m scripts.run_real_enrichment            # 全部 13 条
    python -m scripts.run_real_enrichment --only CVE-2026-31001
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

OUT_DIR = ROOT / "eval" / "artifacts" / "real_enrich"

#: 显式指定全部维度 —— `agent.run` 的 docstring 说明：显式传 dimensions 时
#: 不受 DQ1 质量闸门约束（回填场景），这正是我们要的（演示库的 quality_score 不足）
ALL_DIMENSIONS = ["paper", "poc", "cvss", "fix", "asset", "consistency", "ai_risk"]


def log(msg: str) -> None:
    print(msg, flush=True)


async def run_one(agent, vuln_row: dict) -> dict:
    cve = vuln_row.get("cve_id") or vuln_row["id"]
    results = await agent.run(vuln_row, ALL_DIMENSIONS)
    by_dim = {}
    for item in results or []:
        if isinstance(item, dict) and item.get("dimension"):
            by_dim[item["dimension"]] = item
    return {"cve_id": cve, "vuln_id": vuln_row["id"], "dimensions": by_dim}


async def main() -> int:
    parser = argparse.ArgumentParser(description="对真实漏洞跑真实富化")
    parser.add_argument("--only", default=None, help="只跑指定 CVE")
    parser.add_argument("--dsn", default=None, help="覆盖 POSTGRES_DSN")
    args = parser.parse_args()

    if args.dsn:
        import os

        os.environ["POSTGRES_DSN"] = args.dsn

    # 事件总线未配置时会刷大量 "事件发布失败" 日志，评测时降噪
    logging.getLogger("aiintel.services.enrich.s2_events").setLevel(logging.CRITICAL)
    logging.getLogger("aiintel.core.events").setLevel(logging.CRITICAL)

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import Vuln
    from aiintel.services.enrich.agent import EnrichAgent

    with get_sessionmaker()() as session:
        rows = session.query(Vuln).order_by(Vuln.cve_id).all()
        payloads = []
        for v in rows:
            if v.cve_id is None:
                log(f"  跳过（无 cve_id）: {v.id}  {v.title}")
                continue
            if args.only and v.cve_id != args.only:
                continue
            payloads.append(
                {
                    "id": v.id,
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "description": v.description,
                    "cpe": v.cpe or [],
                    "cvss_vector": getattr(v, "cvss_vector", None),
                    "references": v.references or [],
                    "severity": v.severity,
                }
            )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    agent = EnrichAgent()
    ok = failed = 0
    for i, payload in enumerate(payloads, start=1):
        cve = payload["cve_id"]
        log(f"[{i}/{len(payloads)}] {cve} ...")
        try:
            record = await run_one(agent, payload)
        except Exception as exc:  # noqa: BLE001
            log(f"    ✗ 整体失败 {type(exc).__name__}: {str(exc)[:160]}")
            failed += 1
            continue

        dims = record["dimensions"]
        out = OUT_DIR / f"{cve}.json"
        out.write_text(
            json.dumps({"input": payload, **record}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        ok += 1
        # 只打印每维的"是否有内容"，便于肉眼判断空产出
        bits = []
        for d in ALL_DIMENSIONS:
            if d not in dims:
                bits.append(f"{d}=缺失")
                continue
            val = dims[d].get("value") or {}
            if d == "poc":
                bits.append(f"poc={len(val.get('pocs', []))}")
            elif d == "paper":
                bits.append(f"paper={len(val.get('papers', []))}")
            elif d == "cvss":
                bits.append(f"cvss={val.get('base_score')}")
            elif d == "asset":
                bits.append(f"asset={len(val.get('products', []))}")
            elif d == "fix":
                bits.append(f"fix={'有' if (val.get('immediate') or val.get('upgrade')) else '空'}")
            elif d == "consistency":
                bits.append(f"conf={len(val.get('conflicts', []))}")
            elif d == "ai_risk":
                bits.append(f"risk={val.get('category')}")
        log("    " + "  ".join(bits))

    log("")
    log(f"完成：成功 {ok}，失败 {failed}  ->  {OUT_DIR}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

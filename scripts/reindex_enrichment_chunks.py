"""把**已有富化结论**补进检索空间。

## 为什么需要

`persist_vuln()` 会把富化结论也切成切片（`owner_type='enrichment'`），
否则 Q 线问"这个漏洞怎么修"召回不到 F5 的结论 —— 代码注释里写明了这个意图。

但**演示库的 seed 直接写 `enrichment` 表，没走这道索引**，于是：

```
enrichment 总行数      247
enrichment 类型切片     34     ← 大量结论没进检索空间
本该进但没进的          69 条   ← 实测
```

后果是**演示时最常被问的那句**"这个漏洞怎么修"会召回不到修复建议。

## 做法

对"有富化、但缺 enrichment 切片"的漏洞，用**与 `persist_vuln` 同一套口径**
（`indexer.enrichment_chunk_text`）重建切片。幂等：`index_owner` 内部先删后写。

只重建 `missing` 的，不动已有的。

用法：
    python -m scripts.reindex_enrichment_chunks --dry-run
    python -m scripts.reindex_enrichment_chunks
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time

sys.path.insert(0, "src")
sys.path.insert(0, ".")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--batch", type=int, default=50)
    ap.add_argument(
        "--all",
        action="store_true",
        help='强制重建**所有**有富化的漏洞（不只是"完全没有切片"的）',
    )
    args = ap.parse_args()

    from sqlalchemy import text

    from aiintel.db.base import get_sessionmaker
    from aiintel.services.knowledge.indexer import enrichment_chunk_text, index_owner

    with get_sessionmaker()() as s:
        # 默认只挑"完全没有 enrichment 切片"的漏洞。
        #
        # ⚠️ 但**逐段 replace 的 bug**（见下）会让一个漏洞只剩**最后 1 维**的切片
        # —— 它"有切片"所以不会被这条 SQL 选中，于是 bug 修好之后旧数据仍是残的。
        # 这种情况要用 `--all` 强制重建。
        cond = (
            "1=1"
            if args.all
            else "not exists (select 1 from chunk c "
            "where c.owner_type='enrichment' and c.owner_id = v.cve_id)"
        )
        rows = s.execute(
            text(
                "select distinct v.id, v.cve_id, v.title "
                "from enrichment e join vuln v on v.id = e.vuln_id "
                "where e.evidence is not null and e.evidence != '[]' "
                f"  and {cond} "
                "order by v.cve_id"
            )
        ).all()

    label = "所有有富化的漏洞（--all）" if args.all else "有富化但完全缺 enrichment 切片的漏洞"
    print(f"  {label}: {len(rows)} 条")
    if args.dry_run:
        for _vid, cve, title in rows[:12]:
            print(f"    {cve:18} {str(title)[:60]}")
        print("  （--dry-run：未执行）")
        return 0
    if not rows:
        print("  ✓ 无需补齐")
        return 0

    import json

    done = failed = chunks = 0
    t0 = time.perf_counter()
    for idx, (vid, cve, title) in enumerate(rows, 1):
        try:
            with get_sessionmaker()() as s:
                # 取出该漏洞全部富化（与 persist_vuln 同口径重建）
                items = s.execute(
                    text(
                        "select dimension, value, evidence from enrichment "
                        "where vuln_id = :vid and version = ("
                        "  select max(version) from enrichment e2 "
                        "  where e2.vuln_id = :vid and e2.dimension = enrichment.dimension)"
                    ),
                    {"vid": vid},
                ).all()
                total = 0
                next_no = 0
                for dim, value, evidence in items:
                    if evidence is None or evidence == "[]":
                        continue
                    val = value if isinstance(value, dict) else {}
                    if isinstance(value, str) and value:
                        try:
                            val = json.loads(value)
                        except ValueError:
                            val = {}
                    ev = evidence if isinstance(evidence, list) else []
                    if isinstance(evidence, str) and evidence:
                        try:
                            ev = json.loads(evidence)
                        except ValueError:
                            ev = []
                    text_blob = enrichment_chunk_text(str(dim or ""), val, ev, identity=cve)
                    if text_blob:
                        # ⚠️ 同一 owner 写多段：首段 replace=True 清旧数据，
                        # 之后 replace=False + 递增 offset。
                        # 逐段都用 replace=True 会互相删（实测：7 维只活下来 1 维）。
                        written = await index_owner(
                            s,
                            "enrichment",
                            cve,
                            title or "",
                            text_blob,
                            replace=(next_no == 0),
                            chunk_no_offset=next_no,
                        )
                        next_no += written
                        total += written
                s.commit()
            chunks += total
            done += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            if failed <= 5:
                print(f"    ✗ {cve}: {type(exc).__name__}: {str(exc)[:80]}", flush=True)

        if idx % args.batch == 0:
            rate = idx / max(time.perf_counter() - t0, 1e-6)
            print(f"    进度 {idx}/{len(rows)}  ({rate:.0f} 条/秒)  切片 {chunks}", flush=True)

    with get_sessionmaker()() as s:
        left = s.execute(
            text(
                "select count(*) from enrichment e join vuln v on v.id = e.vuln_id "
                "where e.evidence is not null and e.evidence != '[]' "
                "  and not exists (select 1 from chunk c "
                "                  where c.owner_type='enrichment' and c.owner_id = v.cve_id)"
            )
        ).scalar()
        n_chunk = s.execute(
            text("select count(*) from chunk where owner_type='enrichment'")
        ).scalar()

    print()
    print("  === 结果 ===")
    print(f"  补齐漏洞 {done}，失败 {failed}，新增切片 {chunks}")
    print(f"  enrichment 切片总数: {n_chunk}")
    print(f"  仍缺切的富化: {left}")
    print(f"  用时 {(time.perf_counter() - t0) / 60:.1f} 分钟")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

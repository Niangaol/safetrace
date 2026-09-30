"""重建漏洞切片，让**正文带 CVE 编号**（按编号提问才检得到它自己）。

## 修的缺陷

`index_owner` 拼的是 `title\n\ncontent`。而 NVD 来源的 `title` 是
**英文原始描述截断**（NVD 的 title 就是 description），里面**没有 CVE 编号**。

后果（实测）：问 `CVE-2026-102697 怎么修复？` 时，
关键词召回按编号匹配 → 该漏洞的 `vuln` 切片**匹配不上** →
"问某个 CVE 却检索不到这个 CVE 自己"。

`indexer.persist_vuln()` 已修（正文前置编号，且已有编号时不重复加）；
本脚本回填**已有数据**。

用法：
    python -m scripts.reindex_vuln_chunks --all       # 全部有切片的漏洞
    python -m scripts.reindex_vuln_chunks --enriched  # 只重建有富化的（快）
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
    ap.add_argument("--all", action="store_true", help="全部有切片的漏洞")
    ap.add_argument("--enriched", action="store_true", help="只重建有富化的漏洞")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--batch", type=int, default=200)
    args = ap.parse_args()

    from sqlalchemy import text

    from aiintel.db.base import get_sessionmaker
    from aiintel.services.knowledge.indexer import index_owner

    where = "1=1"
    if args.enriched and not args.all:
        where = "exists (select 1 from enrichment e where e.vuln_id = v.id)"

    with get_sessionmaker()() as s:
        rows = s.execute(
            text(
                "select v.id, v.cve_id, v.title, v.description, v.summary from vuln v "
                f"where v.cve_id is not null and {where} "
                "  and exists (select 1 from chunk c where c.owner_type='vuln' "
                "                  and c.owner_id = v.cve_id) "
                "order by v.cve_id"
            )
        ).all()

    print(f"  待重建漏洞切片: {len(rows)} 条")
    if args.dry_run:
        print("  （--dry-run：未执行）")
        return 0
    if not rows:
        return 0

    done = failed = 0
    t0 = time.perf_counter()
    for idx, (_vid, cve, title, description, summary) in enumerate(rows, 1):
        body = f"{description or ''}\n{summary or ''}"
        if title and cve not in f"{title}{body}":
            body = f"{cve} {title}\n{body}"
        try:
            with get_sessionmaker()() as s:
                await index_owner(s, "vuln", cve, title or "", body)
                s.commit()
            done += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            if failed <= 5:
                print(f"    ✗ {cve}: {type(exc).__name__}: {str(exc)[:80]}", flush=True)
        if idx % args.batch == 0:
            rate = idx / max(time.perf_counter() - t0, 1e-6)
            print(f"    进度 {idx}/{len(rows)}  ({rate:.0f} 条/秒)", flush=True)

    with get_sessionmaker()() as s:
        # 校验：有多少 vuln 切片含自己的编号
        n_ok = s.execute(
            text(
                "select count(*) from chunk c join vuln v on v.cve_id = c.owner_id "
                "where c.owner_type='vuln' and c.content like '%' || v.cve_id || '%'"
            )
        ).scalar()
        n_all = s.execute(text("select count(*) from chunk where owner_type='vuln'")).scalar()

    print()
    print(f"  重建成功 {done}，失败 {failed}")
    print(f"  vuln 切片中含自身编号: {n_ok} / {n_all}")
    print(f"  用时 {(time.perf_counter() - t0) / 60:.1f} 分钟")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

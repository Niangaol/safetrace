"""把已有 chunk 的 `owner_id` 从**主键 UUID** 换成 **CVE 编号**。

## 为什么要换

`chunk.owner_id` 会成为检索结果里的 `chunk_key`（`vuln::<owner_id>`），
并直接透到引用标题给用户看。用 UUID 时界面上显示
`vuln:81cc6cdc518a4f4fa8e45399869bc14f` —— 完全不可读。
而演示库 seed 写的是 CVE 编号，于是**库里两种形态并存**（实测：1705 个 UUID owner
+ 8 个 CVE owner）。

`indexer.persist_vuln()` 已改为用 `row.cve_id or row.id` 作 owner_id
（新建数据是对的）；本脚本负责**回填已有数据**。

## 安全性

- 检索层按 `owner_type + owner_id` 取回内容，不依赖 UUID；
- `/vulns/{id}/evidence` 同时支持主键与 cve_id；
- 唯一变化是 `chunk_key` 更可读，且与 seed 数据形态一致。

用法：
    python -m scripts.reindex_chunk_owner_ids --limit 0     # 全量
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
    ap.add_argument("--limit", type=int, default=0, help="处理前 N 条；0 = 全部")
    ap.add_argument("--batch", type=int, default=200)
    args = ap.parse_args()

    from sqlalchemy import text

    from aiintel.db.base import get_sessionmaker
    from aiintel.services.knowledge.indexer import index_owner

    with get_sessionmaker()() as s:
        # 找"有 chunk、但 owner_id 不是 CVE 编号"的 vuln
        rows = s.execute(
            text(
                "select v.id, v.cve_id, v.title, v.description, v.summary "
                "from vuln v "
                "where v.cve_id is not null "
                "  and exists (select 1 from chunk c "
                "              where c.owner_type='vuln' and c.owner_id = v.id)"
            )
        ).all()
    print(f"  待转换: {len(rows)} 条（chunk 的 owner_id 目前是主键 UUID）", flush=True)
    if not rows:
        print("  ✓ 无需转换")
        return 0

    if args.limit and args.limit > 0:
        rows = rows[: args.limit]
        print(f"  本次处理 {len(rows)} 条", flush=True)

    done = failed = 0
    t0 = time.perf_counter()
    for idx, (vid, cve, title, description, summary) in enumerate(rows, 1):
        try:
            with get_sessionmaker()() as s:
                # 先删旧 UUID 切片，再按 CVE 编号重建（index_owner 内部也是先删后写，
                # 但删的是新 owner_id，所以旧的必须显式删）
                s.execute(
                    text("delete from chunk where owner_type='vuln' and owner_id = :oid"),
                    {"oid": vid},
                )
                s.commit()
                await index_owner(
                    s,
                    "vuln",
                    cve,
                    title or "",
                    f"{description or ''}\n{summary or ''}",
                )
                s.commit()
            done += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            if failed <= 5:
                print(f"    ✗ {cve}: {type(exc).__name__}: {str(exc)[:80]}", flush=True)

        if idx % args.batch == 0:
            rate = idx / max(time.perf_counter() - t0, 1e-6)
            print(f"    进度 {idx}/{len(rows)}  ({rate:.0f} 条/秒)  成功 {done}", flush=True)

    with get_sessionmaker()() as s:
        left_uuid = s.execute(
            text(
                "select count(*) from chunk c where c.owner_type='vuln' "
                "and exists (select 1 from vuln v where v.id = c.owner_id)"
            )
        ).scalar()
        cve_owned = s.execute(
            text(
                "select count(*) from chunk c where c.owner_type='vuln' "
                "and exists (select 1 from vuln v where v.cve_id = c.owner_id)"
            )
        ).scalar()
        total = s.execute(text("select count(*) from chunk")).scalar()

    print()
    print("  === 结果 ===")
    print(f"  转换成功 {done}，失败 {failed}")
    print(f"  chunk 仍以 UUID 为 owner_id: {left_uuid}")
    print(f"  chunk 以 CVE 为 owner_id   : {cve_owned}")
    print(f"  chunk 总数                 : {total}")
    print(f"  用时 {(time.perf_counter() - t0) / 60:.1f} 分钟")
    return 0 if done else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

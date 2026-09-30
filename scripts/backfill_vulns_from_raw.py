"""把已落库的 raw_item（真实采集）补成 vuln 记录 —— 打通证据链。

## 为什么需要这一步

实测发现：`raw_item` 有 1720 条（1692 条真实 NVD），但 **`vuln` 表仍是 12 条**
（全是演示库的合成数据）。也就是说**采集到的证据没有落成底座记录**，
证据链断在"归一之后"。

根因：`persist_raw_items()` 只写 `raw_item` 表；`normalize_items()` **只做归一不写库**
（这个坑我踩过一次）；真正写 `vuln` 的是 `persist_vuln()`，而它此前只在
**带富化结果**的路径里被调用（`nodes.py` 的 enrich 节点）。所以：
**只采集不富化 ⇒ vuln 表永远是空的**。

## 本脚本做什么

读 `raw_item` 里的真实条目 → 规则归一 → `persist_vuln(vuln, enrichments=[])`。
**不调 LLM**（富化是另一件事），目的是把"采集→归一→底座"这条链打通并留下数字。
`enrichments=[]` 是合法输入：`persist_vuln` 会照常 upsert vuln 并尝试索引。

用法：
    python -m scripts.backfill_vulns_from_raw --limit 0      # 全量
    python -m scripts.backfill_vulns_from_raw --limit 50     # 抽样
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
    ap.add_argument("--source", default="nvd")
    ap.add_argument("--batch", type=int, default=200)
    args = ap.parse_args()

    from sqlalchemy import select, text

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import Vuln
    from aiintel.services.ingest.pipeline import _rule_extract  # noqa: SLF001
    from aiintel.services.knowledge.indexer import persist_vuln

    with get_sessionmaker()() as s:
        before_vuln = s.execute(select(Vuln.id)).all().__len__()
        # 只取"raw 有、vuln 没有"的，避免重复处理（幂等）
        rows = s.execute(
            text(
                "select r.external_id, r.source, r.title, r.content_text, r.url, "
                "       r.published_at, r.raw_json "
                "from raw_item r "
                "where r.external_id like 'CVE-%' "
                "  and not exists (select 1 from vuln v where v.cve_id = r.external_id) "
                "order by r.external_id"
            )
        ).all()
    print(f"  vuln 前: {before_vuln}   待补齐: {len(rows)} 条", flush=True)

    if args.limit and args.limit > 0:
        rows = rows[: args.limit]
        print(f"  本次处理前 {len(rows)} 条", flush=True)

    import json

    def _iso(value: object) -> str | None:
        """归一成 ISO 字符串。

        ⚠️ 原生 SQL 查询**绕过 SQLAlchemy 的类型转换**，SQLite 返回的是**字符串**
        而不是 datetime —— 早期版本直接 `.isoformat()` 会报
        `AttributeError: 'str' object has no attribute 'isoformat'`（实测）。
        两种形态都要能处理。
        """

        if value is None:
            return None
        if hasattr(value, "isoformat"):
            return str(value.isoformat())
        text = str(value).strip()
        return text or None

    written = failed = 0
    t0 = time.perf_counter()
    for idx, (ext, source, title, content, url, published, raw_json) in enumerate(rows, 1):
        raw = raw_json if isinstance(raw_json, dict) else {}
        if isinstance(raw_json, str) and raw_json:
            try:
                raw = json.loads(raw_json)
            except ValueError:
                raw = {}
        published_iso = _iso(published)
        item = {
            "source": source,
            "external_id": ext,
            "title": title or "",
            "content_text": content or "",
            "url": url,
            "published_at": published_iso,
            "raw": raw,
        }
        try:
            extracted = _rule_extract(item)
            vuln = {
                **extracted,
                "external_id": ext,
                "source": source,
                "title": title or ext,
                "description": content or "",
                "url": url,
                "published_at": published_iso,
                "fetched_at": published_iso,
                "references": [{"url": u} for u in (raw.get("references") or []) if u][:20],
                "cpe": raw.get("cpe") or [],
                "cwe": raw.get("cwe") or extracted.get("cwe") or [],
                "cvss_vector": raw.get("cvss_vector") or extracted.get("cvss_vector"),
                "epss": raw.get("epss"),
                "kev": bool(raw.get("kev")),
                "affected_products": extracted.get("affected_products") or [],
            }
            if raw.get("cvss_score") is not None:
                vuln["cvss_score"] = raw["cvss_score"]
            await persist_vuln(vuln, [])
            written += 1
        except Exception as exc:  # noqa: BLE001
            failed += 1
            if failed <= 5:
                print(f"    ✗ {ext}: {type(exc).__name__}: {str(exc)[:80]}", flush=True)

        if idx % args.batch == 0:
            rate = idx / max(time.perf_counter() - t0, 1e-6)
            print(f"    进度 {idx}/{len(rows)}  ({rate:.0f} 条/秒)  已写入 {written}", flush=True)

    with get_sessionmaker()() as s:
        after_vuln = s.execute(select(Vuln.id)).all().__len__()
        real = s.execute(
            text("select count(*) from vuln where cve_id not like 'CVE-2026-%'")
        ).scalar()

    print()
    print("  === 结果 ===")
    print(f"  写入成功 {written}，失败 {failed}")
    print(f"  vuln 表: {before_vuln} -> {after_vuln}  (Δ{after_vuln - before_vuln:+d})")
    print(f"  其中真实 CVE: {real}")
    print(f"  用时 {(time.perf_counter() - t0) / 60:.1f} 分钟")
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

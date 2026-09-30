"""E-02 真实采集→落库的**有界**验证。

为什么有界：`fetch(full)` 实测能取 **1698** 条，但全量落库 + 富化要几十分钟
（富化逐条走 LLM）。这里只取前 N 条真实 CVE 走**完整链路**
（`poll_sources` → `persist_raw_items` → `normalize_items`），
目的是证明链路通了并留下可复现数字；全量灌库是另一件事。

⚠️ 早先版本只调 `normalize_item()` 就以为会落库 —— **它只做归一不写库**，
所以行数 Δ0（实测踩过）。真正落库靠 `persist_raw_items()`。

用法：
    python -m scripts.real_ingest --limit 8
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
    ap.add_argument("--limit", type=int, default=8, help="只处理前 N 条真实条目")
    ap.add_argument("--source", default="nvd")
    ap.add_argument("--mode", default="full", choices=["full", "incremental"])
    args = ap.parse_args()

    from sqlalchemy import select

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import RawItem, Vuln, VulnSource
    from aiintel.services.collectors.registry import get_registry
    from aiintel.services.ingest.pipeline import (
        normalize_items,
        persist_raw_items,
    )

    def counts() -> dict[str, int]:
        with get_sessionmaker()() as s:
            return {
                "vuln": len(s.execute(select(Vuln.id)).all()),
                "raw_item": len(s.execute(select(RawItem.id)).all()),
                "vuln_source": len(s.execute(select(VulnSource.vuln_id)).all()),
            }

    before = counts()
    print(f"  采集前: {before}")

    reg = get_registry()
    collector = reg.get(args.source)
    print(f"  水位线: {collector.watermark()}")

    # ── 1. 真实抓取 ────────────────────────────────────────────────
    t0 = time.perf_counter()
    items = await collector.fetch(mode=args.mode)
    fetch_s = time.perf_counter() - t0
    print(f"  fetch({args.mode}) -> {len(items)} 条真实条目，用时 {fetch_s:.1f}s")
    if not items:
        print("  ⚠ 没取到条目，无法继续")
        return 1

    sample = [item.to_dict() for item in items[: args.limit]]

    # ── 2. 原始条目落库（证据链起点）───────────────────────────────
    t1 = time.perf_counter()
    persisted = await persist_raw_items(sample)
    persist_s = time.perf_counter() - t1
    print(f"  persist_raw_items -> 新增 {persisted} 条，用时 {persist_s:.1f}s")

    # ── 3. 归一（抽 CVE / CVSS / 严重度）───────────────────────────
    t2 = time.perf_counter()
    normalized = await normalize_items(sample)
    norm_s = time.perf_counter() - t2
    print(f"  normalize_items -> {len(normalized)} 条，用时 {norm_s:.1f}s")

    print()
    print("  === 归一结果抽样 ===")
    ok = 0
    for item in normalized:
        cve = item.get("cve_id")
        score = item.get("cvss_score")
        sev = item.get("severity")
        title = str(item.get("title") or "")[:44]
        mark = "✓" if cve else "✗"
        ok += 1 if cve else 0
        print(f"    {mark} cve={cve or '（缺）':18} score={score} sev={sev}  {title}")

    after = counts()
    print()
    print("  === 结果 ===")
    print(f"  归一出 CVE 的条数: {ok}/{len(normalized)}")
    print(f"  采集后: {after}")
    for key in before:
        print(f"    {key:12} {before[key]} -> {after[key]}  (Δ{after[key] - before[key]:+d})")

    await reg.aclose()
    return 0 if persisted else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

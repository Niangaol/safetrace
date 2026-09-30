"""E-02 真实采集 → 落库。支持**有界**（验证链路）与**全量**（灌真实语料）。

`--limit 0` = 全量。

⚠️ 三个实测踩过的坑（写在这里免得重踩）：
1. `normalize_item()` **只归一不写库**，真正落库靠 `persist_raw_items()`；
2. 全量时**不要每条都调 LLM**：`normalize_items` 按描述长度决定是否走 LLM，
   1698 条会跑很久。`--no-llm` 走纯规则（快得多）；
3. NVD 来源的 CVE 编号在 **`external_id`** 里，不在 `raw.cve_id`
   （规则抽取的兜底已修，见 `tests/test_ingest_rule_extract.py`）。

用法：
    python -m scripts.real_ingest --limit 6            # 有界验证
    python -m scripts.real_ingest --limit 0 --no-llm   # 全量、纯规则
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
    ap.add_argument("--limit", type=int, default=8, help="只处理前 N 条；0 = 全量")
    ap.add_argument("--source", default="nvd")
    ap.add_argument("--mode", default="full", choices=["full", "incremental"])
    ap.add_argument(
        "--no-llm",
        action="store_true",
        help="纯规则归一（不调 LLM）。全量灌库建议开启：1698 条走 LLM 要很久",
    )
    ap.add_argument("--batch", type=int, default=200, help="每批处理条数（便于观察进度）")
    args = ap.parse_args()

    from sqlalchemy import select

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import RawItem, Vuln, VulnSource
    from aiintel.services.collectors.registry import get_registry
    from aiintel.services.ingest import pipeline as P

    def counts() -> dict[str, int]:
        with get_sessionmaker()() as s:
            return {
                "vuln": len(s.execute(select(Vuln.id)).all()),
                "raw_item": len(s.execute(select(RawItem.id)).all()),
                "vuln_source": len(s.execute(select(VulnSource.vuln_id)).all()),
            }

    before = counts()
    print(f"  采集前: {before}", flush=True)

    reg = get_registry()
    collector = reg.get(args.source)
    print(f"  水位线: {collector.watermark()}", flush=True)

    t0 = time.perf_counter()
    items = await collector.fetch(mode=args.mode)
    print(
        f"  fetch({args.mode}) -> {len(items)} 条，用时 {time.perf_counter() - t0:.1f}s", flush=True
    )
    if not items:
        print("  ⚠ 没取到条目")
        return 1

    payloads = [i.to_dict() for i in items]
    if args.limit and args.limit > 0:
        # `--limit 0` = 全量；正数才截断
        payloads = payloads[: args.limit]
    print(f"  本次处理 {len(payloads)} 条", flush=True)

    # ── 1. 原始条目落库（幂等：source + external_id 唯一）──────────
    t1 = time.perf_counter()
    persisted = await P.persist_raw_items(payloads)
    print(
        f"  persist_raw_items -> 新增 {persisted} 条（已存在的跳过），"
        f"用时 {time.perf_counter() - t1:.1f}s",
        flush=True,
    )

    # ── 2. 归一（可选跳过 LLM）────────────────────────────────────
    if args.no_llm:
        # 走规则抽取（与 LLM 路径同一输出契约），避免 1698 次 LLM 调用
        normalized = [P._rule_extract(p) for p in payloads]  # noqa: SLF001 - 有意复用同一口径
        print(f"  规则归一 -> {len(normalized)} 条（未调 LLM）", flush=True)
    else:
        normalized = []
        t2 = time.perf_counter()
        for start in range(0, len(payloads), args.batch):
            batch = payloads[start : start + args.batch]
            normalized.extend(await P.normalize_items(batch))
            done = min(start + args.batch, len(payloads))
            rate = done / max(time.perf_counter() - t2, 1e-6)
            print(f"    归一进度 {done}/{len(payloads)}  ({rate:.1f} 条/秒)", flush=True)

    with_cve = sum(1 for n in normalized if n.get("cve_id"))
    print(f"  归一出 CVE 的条数: {with_cve}/{len(normalized)}", flush=True)

    after = counts()
    print()
    print("  === 结果 ===")
    print(f"  采集后: {after}")
    for key in before:
        print(f"    {key:12} {before[key]} -> {after[key]}  (Δ{after[key] - before[key]:+d})")
    print(f"  总用时 {(time.perf_counter() - t0) / 60:.1f} 分钟", flush=True)

    await reg.aclose()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

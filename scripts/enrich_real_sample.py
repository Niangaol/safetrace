"""给**代表性真实条目**补富化（评委看得见的那个面板）。

## 背景

真实采集的 1440 条目前**只有底座记录**（漏洞简介 + 检索切片），富化面板是空的。
演示时评委点开一个 CVE，看到的是英文原始描述 + 空白面板 —— 不好看，
而且体现不出 F 线的价值。

全量富化 1440 条要几小时、约 ¥3（单条 ~7 秒），代价不值当；
**分层抽样补一批代表性的**即可让面板有内容，其余如实标注"未富化"。

## 两个必须显式处理的开关

1. **`S1_STUB_MODE` 默认 `true`** → `store_enrichment()` 会**跳过落库**
   （实测：不关掉的话富化跑完但库里什么都没有）。本脚本显式置 `false`；
2. `load_intel_item()` 要的是 **vuln 主键 UUID**，不是 CVE 编号。

用法：
    python -m scripts.enrich_real_sample --per-product 2 --dry-run   # 先看选谁
    python -m scripts.enrich_real_sample --per-product 2             # 执行
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

sys.path.insert(0, "src")
sys.path.insert(0, ".")

#: 抽样要覆盖的产品（按 AI 相关性排序，这些是评委最可能问到的）
PRODUCTS = (
    "vllm",
    "ollama",
    "langchain",
    "llamaindex",
    "transformers",
    "huggingface",
    "pytorch",
    "tensorflow",
    "openai",
    "gradio",
    "ray dashboard",
    "mlflow",
)


def product_of(title: str, content: str) -> str:
    blob = f"{title} {content}".lower()
    for k in PRODUCTS:
        if k in blob:
            return k
    return "other"


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-product", type=int, default=2, help="每个产品抽几条")
    ap.add_argument(
        "--skip-products",
        default="",
        help="逗号分隔：跳过某些产品（如已经富化过的 vllm）",
    )
    ap.add_argument(
        "--top-recent",
        type=int,
        default=0,
        help="额外补：不分产品，直接取最近 N 条（0=不补）",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dimensions", default=None, help="逗号分隔；默认全部维度")
    ap.add_argument(
        "--min-severity",
        default="high",
        choices=["critical", "high", "medium", "low", "any"],
        help="只要该严重度及以上（默认 high：演示要挑有说服力的）",
    )
    ap.add_argument("--since", default="2023-01-01", help="只要该日期之后发布的")
    args = ap.parse_args()

    # 必须在导入 config 之前设置，否则 settings 已缓存旧值
    os.environ["S1_STUB_MODE"] = "false"

    from sqlalchemy import text

    from aiintel.config import get_settings
    from aiintel.db.base import get_sessionmaker
    from aiintel.services.enrich.s1_knowledge import s1_stub_mode

    get_settings.cache_clear()
    print(f"  S1_STUB_MODE = {s1_stub_mode()}（必须 False 才会落库）")
    if s1_stub_mode():
        print("  ⛔ 仍是桩模式，富化不会落库；请检查 S1_STUB_MODE 环境变量")
        return 1

    with get_sessionmaker()() as s:
        # 选样原则（**面向演示的说服力**，不是"随便取几条"）：
        #   1. 只要 high/critical —— 演示挑低危没有说服力；
        #   2. 只要 `--since` 之后发布的 —— 老漏洞（2004 年的）看着不像"前沿情报"；
        #   3. 排除**明显非 AI 的生态**（WordPress 插件的 "AI ChatBot" 会命中 `openai`，
        #      是同一类子串陷阱，实测混进来过）。
        sev_filter = {
            "critical": "v.severity = 'critical'",
            "high": "v.severity in ('critical','high')",
            "medium": "v.severity in ('critical','high','medium')",
            "low": "1=1",
            "any": "1=1",
        }[args.min_severity]
        rows = s.execute(
            text(
                "select v.id, v.cve_id, v.title, v.description, v.severity from vuln v "
                "where exists (select 1 from raw_item r where r.external_id = v.cve_id) "
                "  and not exists (select 1 from enrichment e where e.vuln_id = v.id) "
                f"  and ({sev_filter}) "
                "  and v.published_at >= :since "
                "  and lower(v.title) not like '%wordpress%' "
                "  and lower(v.title) not like '%plugin%' "
                "order by v.published_at desc"
            ),
            {"since": args.since},
        ).all()

    skip = {s.strip() for s in args.skip_products.split(",") if s.strip()}
    picked: dict[str, list[tuple[str, str, str]]] = {}
    for vid, cve, title, desc, _sev in rows:
        key = product_of(title or "", desc or "")
        if key in skip:
            continue
        bucket = picked.setdefault(key, [])
        if len(bucket) < args.per_product:
            bucket.append((vid, cve, str(title or "")[:64]))

    # 额外补一批"最近 N 条"：不论产品，直接取最新的 —— 演示时"近期情报"最抗问
    if args.top_recent > 0:
        chosen = {v for items in picked.values() for v, _c, _t in items}
        recent: list[tuple[str, str, str]] = []
        for vid, cve, title, _desc, _sev in rows:
            if vid in chosen:
                continue
            recent.append((vid, cve, str(title or "")[:64]))
            if len(recent) >= args.top_recent:
                break
        if recent:
            picked["_recent"] = recent

    total = sum(len(v) for v in picked.values())
    print(f"  候选（无富化 + {args.min_severity} + {args.since} 之后 + 排除插件）: {len(rows)} 条")
    print(f"  抽样结果: {total} 条，覆盖 {len(picked)} 个分组")
    for key, items in sorted(picked.items()):
        print(f"    {key:14} {len(items)} 条")
        for _vid, cve, title in items[:3]:
            print(f"        {cve:18} {title}")

    if args.dry_run:
        print()
        print("  （--dry-run：未执行）")
        return 0

    dims = args.dimensions.split(",") if args.dimensions else None
    from aiintel.services.enrich.agent import EnrichAgent

    agent = EnrichAgent()
    t0 = time.perf_counter()
    ok = fail = 0
    for idx, (vid, cve, _title) in enumerate(
        [item for items in picked.values() for item in items], 1
    ):
        t1 = time.perf_counter()
        try:
            await agent.backfill([vid], dims)
            ok += 1
            mark = "✓"
        except Exception as exc:  # noqa: BLE001
            fail += 1
            mark = "✗"
            print(f"    {mark} {cve}: {type(exc).__name__}: {str(exc)[:70]}", flush=True)
        if mark == "✓":
            print(
                f"    {mark} {idx:3} {cve:18} {time.perf_counter() - t1:5.1f}s  累计 "
                f"{(time.perf_counter() - t0) / 60:.1f} 分钟",
                flush=True,
            )

    from aiintel.core.cost import get_cost_guard

    print()
    print("  === 结果 ===")
    print(f"  成功 {ok}，失败 {fail}")
    print(f"  用时 {(time.perf_counter() - t0) / 60:.1f} 分钟")
    print(
        f"  今日累计花费 ¥{get_cost_guard().spent_today():.4f} / 预算 ¥{get_settings().cost_daily_budget_cny}"
    )

    with get_sessionmaker()() as s:
        n = s.execute(text("select count(*) from enrichment")).scalar()
        nv = s.execute(
            text(
                "select count(distinct e.vuln_id) from enrichment e join vuln v on v.id = e.vuln_id "
                "where v.cve_id not like :p"
            ),
            {"p": "CVE-2026-3%"},
        ).scalar()
        print(f"  enrichment 总行数 {n}，其中真实 CVE 覆盖 {nv} 条漏洞")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

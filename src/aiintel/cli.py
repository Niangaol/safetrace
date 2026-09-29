"""CLI：本地开发与演示的入口。

用法：
  python -m aiintel.cli collect --sources nvd,ghsa
  python -m aiintel.cli enrich --vuln-id v_xxx
  python -m aiintel.cli ask "最近影响 vLLM 的高危漏洞"
  python -m aiintel.cli cost
  python -m aiintel.cli health
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from aiintel.core.metrics import setup_logging


def _cmd_collect(args: argparse.Namespace) -> int:
    from aiintel.agents.graph import run_monitor_cycle

    sources = [s for s in (args.sources or "").split(",") if s] or None
    state = asyncio.run(run_monitor_cycle(sources=sources, mode=args.mode))
    print(
        json.dumps(
            {
                "collected": state.get("collected"),
                "merged": state.get("merged_count"),
                "enriched": state.get("enriched_count"),
                "alerts": state.get("alerts"),
                "degraded": state.get("degraded"),
                "errors": state.get("errors"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def _cmd_enrich(args: argparse.Namespace) -> int:
    from aiintel.services.enrich.agent import EnrichAgent

    dimensions = [d for d in (args.dimensions or "").split(",") if d] or None
    done = asyncio.run(EnrichAgent().backfill([args.vuln_id], dimensions))
    print(f"backfill 完成: {done}")
    return 0


def _cmd_ask(args: argparse.Namespace) -> int:
    from aiintel.services.qa.agent import QAAgent, dumps_event

    async def run() -> None:
        async for event in QAAgent().answer_stream(args.question):
            if event.get("event") == "token":
                sys.stdout.write(event["text"])
                sys.stdout.flush()
            elif event.get("event") == "citation":
                print(f"\n[{event['id']}] {event['title']}", file=sys.stderr)
            elif event.get("event") == "done":
                print(f"\n\n{dumps_event(event)}", file=sys.stderr)

    asyncio.run(run())
    return 0


def _cmd_cost(args: argparse.Namespace) -> int:
    from aiintel.core.cost import PRICES, blended_price, get_cost_guard, is_peak

    guard = get_cost_guard()
    print(f"当前时段: {'高峰' if is_peak() else '闲时'}")
    print(f"今日已用: {guard.spent_today():.4f} / {guard.daily_budget:.2f} 元")
    print(f"剩余: {guard.remaining():.4f} 元")
    for tier, periods in PRICES.items():
        idle, peak = blended_price(tier), periods["peak"]
        print(
            f"{tier:6s} 加权价(元/M) 输入未命中 {idle.input:.3f} 命中 {idle.cache_hit_input:.4f} "
            f"输出 {idle.output:.3f} | 高峰输出 {peak.output:.1f}"
        )
    breakdown = guard.breakdown()
    if breakdown:
        print("\n今日花费分布:")
        for key, value in breakdown.items():
            print(f"  {key:40s} {value:.4f} 元")
    return 0


def _cmd_health(args: argparse.Namespace) -> int:
    from aiintel.agents.watchdog import check_health

    report = asyncio.run(check_health())
    print(
        json.dumps(
            {"healthy": report.healthy, "findings": report.findings, "actions": report.actions},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if report.healthy else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aiintel", description="AI 安全知识情报系统 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect", help="执行一轮采集-去重-富化链路")
    p_collect.add_argument("--sources", help="逗号分隔的源名，默认全部")
    p_collect.add_argument("--mode", default="incremental", choices=["incremental", "full"])
    p_collect.set_defaults(func=_cmd_collect)

    p_enrich = sub.add_parser("enrich", help="对指定漏洞补富化")
    p_enrich.add_argument("--vuln-id", required=True)
    p_enrich.add_argument("--dimensions", help="paper,poc,cvss,ai_risk")
    p_enrich.set_defaults(func=_cmd_enrich)

    p_ask = sub.add_parser("ask", help="命令行问答")
    p_ask.add_argument("question")
    p_ask.set_defaults(func=_cmd_ask)

    p_cost = sub.add_parser("cost", help="查看成本与今日花费分布")
    p_cost.set_defaults(func=_cmd_cost)

    p_health = sub.add_parser("health", help="健康检查与自愈建议")
    p_health.set_defaults(func=_cmd_health)
    return parser


def main() -> int:
    setup_logging()
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

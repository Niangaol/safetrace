"""日报生成：把一轮链路结果压缩成可读的 Markdown（写报告与演示都用得上）。"""

from __future__ import annotations

from datetime import datetime

from aiintel.agents.state import IntelState
from aiintel.config import BEIJING_TZ
from aiintel.core.events import TOPIC_REPORT_DAILY, EventBus
from aiintel.core.llm import get_llm

REPORT_SYSTEM_PROMPT = (
    "你是安全情报分析助手。基于给定的采集/富化统计，输出 200 字以内的中文日报摘要，"
    "包含：今日重点、时效表现、异常与建议。不要编造统计中不存在的数字。"
)


async def build_daily_report(state: IntelState) -> str:
    now = datetime.now(BEIJING_TZ)
    stats = {
        "采集条目": state.get("collected", 0),
        "去重后漏洞": state.get("merged_count", 0),
        "富化记录": state.get("enriched_count", 0),
        "告警数": state.get("alerts", 0),
        "降级": bool(state.get("degraded")),
    }
    lines = [
        f"# AI 安全情报日报 {now:%Y-%m-%d}",
        "",
        "| 指标 | 值 |",
        "| --- | --- |",
        *[f"| {k} | {v} |" for k, v in stats.items()],
    ]
    if state.get("errors"):
        lines += ["", "## 异常", *[f"- {e}" for e in state["errors"][:5]]]

    try:
        result = await get_llm().complete(
            [
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": "\n".join(lines)},
            ],
            task="classify",
            max_tokens=400,
            node="report",
            agent="ReportAgent",
        )
        lines += ["", "## 摘要", result.text.strip()]
    except Exception as exc:  # noqa: BLE001 - 报告失败不能影响主链路
        lines += ["", f"> 摘要生成失败（已降级）：{exc}"]

    return "\n".join(lines)


async def publish_daily_report(markdown: str, trace_id: str | None = None) -> None:
    await EventBus().try_publish(TOPIC_REPORT_DAILY, {"markdown": markdown}, trace_id)

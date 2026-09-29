"""S2 · 情报总线客户端（F 线事件出口）。

F 线只发布 5 个 topic（见 `contracts/events.md` §2/§3）：3 个用权威主题
（`enrich.items` / `enrich.papers` / `fallback.events`），2 个用本仓扩展主题
（`intel.enrich.requested` / `enrich.evidence`）。

事件发布失败**不得阻断**主链路（`EventBus` 自带降级），但必须记 warning 并在返回值里体现，
避免"静默兜底"。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from aiintel.core.degrade import degrade
from aiintel.core.events import (
    TOPIC_ENRICH_EVIDENCE,
    TOPIC_ENRICH_ITEMS,
    TOPIC_ENRICH_PAPERS,
    TOPIC_ENRICH_REQUESTED,
    TOPIC_FALLBACK_EVENTS,
    EventBus,
)

logger = logging.getLogger(__name__)

# topic 常量在 core.events 里集中定义（避免拼写漂移），F 线只允许发这五个。
# `enrich.papers` / `enrich.evidence` 曾长期"已登记但无生产者"，现在接上了。
ALLOWED_TOPICS = frozenset(
    {
        TOPIC_ENRICH_REQUESTED,
        TOPIC_ENRICH_ITEMS,
        TOPIC_ENRICH_PAPERS,
        TOPIC_ENRICH_EVIDENCE,
        TOPIC_FALLBACK_EVENTS,
    }
)


@dataclass(slots=True)
class S2Result:
    published: int = 0
    failed: int = 0
    errors: list[str] | None = None


def _bus(bus: EventBus | None = None) -> EventBus:
    return bus or EventBus()


async def publish(bus: EventBus | None, topic: str, payload: dict[str, Any]) -> bool:
    """发布单个事件。topic 越界时拒绝（防止 F 线发别人的事件）。"""

    if topic not in ALLOWED_TOPICS:
        logger.error("F 线试图发布越界 topic=%s（允许：%s）", topic, sorted(ALLOWED_TOPICS))
        return False
    try:
        await _bus(bus).publish(topic, payload, payload.get("trace_id"))
    except Exception as exc:  # noqa: BLE001 - 事件总线失败不阻断富化
        logger.warning("事件发布失败 topic=%s: %s", topic, exc)
        return False
    return True


async def publish_requested(bus: EventBus | None, vuln_id: str, dimensions: list[str]) -> bool:
    return await publish(
        bus, TOPIC_ENRICH_REQUESTED, {"vuln_id": vuln_id, "dimensions": dimensions}
    )


async def publish_completed(bus: EventBus | None, vuln_id: str, item: dict[str, Any]) -> bool:
    """富化完成事件。载荷带 source / degraded_to / mock，让下游与前端能看到降级。"""

    return await publish(
        bus,
        TOPIC_ENRICH_ITEMS,
        {
            "vuln_id": vuln_id,
            "dimension": item.get("dimension"),
            "confidence": item.get("confidence"),
            "source": item.get("source") or [],
            "degraded_to": item.get("degraded_to"),
            "mock": bool(item.get("mock")),
            "trace_id": item.get("trace_id"),
        },
    )


async def publish_degraded(bus: EventBus | None, vuln_id: str, item: dict[str, Any]) -> bool:
    """FB1：降级必须显式可见，不能静默兜底。

    载荷按权威内联契约 `FallbackEvent` 投影（events.md），而不是自定义形状 ——
    `fallback.events` 的消费者是按权威契约写的。
    """

    trace_id = item.get("trace_id") or "trace_unavailable"
    channel = item.get("degraded_detail") or item.get("degraded_to") or "fixture"
    try:
        marker = degrade(
            channel,
            detail=str(item.get("dimension") or vuln_id),
            trace_id=trace_id,
            trigger=str(item.get("degraded_reason") or item.get("degraded_to") or "unknown"),
            layer="L3",
        )
    except Exception as exc:  # noqa: BLE001 - 未登记通道也要留痕，不能静默丢
        logger.error("降级通道无法投影为 FallbackEvent vuln_id=%s: %s", vuln_id, exc)
        return False

    event_bus = _bus(bus)
    # FallbackEvent 自带 event_id：先造信封、回填 payload，再发同一条信封
    env = event_bus.envelope(
        TOPIC_FALLBACK_EVENTS,
        {},
        trace_id,
        dedup_key=f"{vuln_id}:{item.get('dimension')}:{marker.contract_value}",
    )
    env["payload"] = marker.to_fallback_event(event_id=env["event_id"], trace_id=trace_id)
    try:
        await event_bus.publish_envelope(env)
    except Exception as exc:  # noqa: BLE001 - 事件总线失败不阻断富化
        logger.warning("事件发布失败 topic=%s: %s", TOPIC_FALLBACK_EVENTS, exc)
        return False
    return True


async def publish_all(
    bus: EventBus | None, vuln_id: str, results: list[dict[str, Any]]
) -> S2Result:
    """批量发布：每维一条 completed；降级的额外发一条 degraded。"""

    published = 0
    failed = 0
    for item in results:
        if await publish_completed(bus, vuln_id, item):
            published += 1
        else:
            failed += 1
        if item.get("degraded_to"):
            if await publish_degraded(bus, vuln_id, item):
                published += 1
            else:
                failed += 1
    return S2Result(published=published, failed=failed, errors=[])

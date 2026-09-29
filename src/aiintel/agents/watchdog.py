"""WatchAgent：健康检查与自愈。

自愈动作一律通过事件广播（intel.selfheal.action），既能在 API 侧流式展示，
也直接作为答辩"自愈能力"的演示素材。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from aiintel.core.cost import get_cost_guard
from aiintel.core.events import TOPIC_SELFHEAL_ACTION, EventBus
from aiintel.core.metrics import selfheal

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class HealthReport:
    healthy: bool
    findings: list[str]
    actions: list[str]


async def record_selfheal(action: str, target: str, reason: str, detail: str = "") -> None:
    selfheal.labels(action=action).inc()
    await EventBus().try_publish(
        TOPIC_SELFHEAL_ACTION,
        {"action": action, "target": target, "reason": reason, "detail": detail},
    )
    logger.warning("selfheal action=%s target=%s reason=%s", action, target, reason)


async def check_health() -> HealthReport:
    """三类检查：预算水位、LLM 连通性、采集源成功率。"""

    findings: list[str] = []
    actions: list[str] = []
    guard = get_cost_guard()

    # 1) 预算水位：超限即熔断降级（LLMRouter 内部已自动切本地模型）
    if guard.exceeded():
        findings.append(f"LLM 日预算耗尽 {guard.spent_today():.2f}/{guard.daily_budget:.2f} 元")
        actions.append("switch_to_local_model")
        await record_selfheal("switch_to_local_model", target="llm", reason="daily_budget_exceeded")
    elif guard.near_budget():
        findings.append(f"LLM 预算已用 {guard.spent_today():.2f} 元，接近上限")

    # 2) LLM 连通性
    from aiintel.config import get_settings
    from aiintel.core.llm import LLMError, get_llm

    settings = get_settings()
    if not settings.llm_api_key:
        findings.append("未配置 LLM_API_KEY")
        if settings.llm_local_enabled:
            actions.append("switch_to_local_model")
    else:
        try:
            await get_llm().complete(
                [{"role": "user", "content": "ping"}],
                task="classify",
                max_tokens=8,
                node="watchdog",
            )
        except LLMError as exc:
            findings.append(f"云端 LLM 不可用: {exc}")
            if settings.llm_local_enabled:
                actions.append("switch_to_local_model")
                await record_selfheal("switch_to_local_model", target="llm", reason=str(exc))

    # 3) 采集源最近状态
    try:
        from aiintel.db.base import get_sessionmaker
        from aiintel.db.models import SyncWatermark

        with get_sessionmaker()() as session:
            rows = session.query(SyncWatermark).all()
            failed = [r.source for r in rows if r.last_error]
            if failed:
                findings.append(f"数据源异常: {', '.join(failed)}")
                actions.append("fallback_source")
                await record_selfheal(
                    "fallback_source", target=",".join(failed), reason="last_error"
                )
    except Exception as exc:  # noqa: BLE001 - 健康检查不能因 DB 不可用而崩
        findings.append(f"数据库不可用: {exc}")

    return HealthReport(healthy=not findings, findings=findings, actions=actions)

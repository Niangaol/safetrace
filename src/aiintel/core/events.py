"""事件总线：Redis Pub/Sub，模块之间唯一解耦通道（见 docs/API契约.md 第 7 节）。

事件信封与主题以 SafeTrace `contracts/events.md` 为权威规格，本仓只允许在
`contracts/events.md` §3 登记的扩展主题上追加，不得改动权威主题名。

信封形状（权威）::

    Envelope{ event_id, topic, occurred_at, trace_id, causation_id, payload, schema_version }

三条设计约束：

1. **幂等**：生产者给出 `dedup_key` 时，`event_id` 由内容派生
   （`evt_` + `sha256(topic|dedup_key|schema_version)[:32]`），同键重放得同 ID，
   消费者据此去重。`dedup_key` 是可选的 —— 状态类事件（心跳、预算超限）本就
   不该去重，硬造一个键反而会吞掉真实事件。
2. **因果链**：`causation_id` 指向触发本事件的上游 `event_id`；根事件省略该键。
3. **降级可见**：发布失败绝不静默，`try_publish` 记 warning 后放行（FB1 红线）。
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime
from typing import Any

from aiintel.config import BEIJING_TZ, get_settings

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
EVENT_ID_PREFIX = "evt_"

# ---------------------------------------------------------------- 权威主题
# SafeTrace contracts/events.md 主题表，前 10 个，一字不改。
TOPIC_RAW_DOCS = "raw.docs"
TOPIC_INTEL_ITEMS = "intel.items"
TOPIC_DQ_VERDICTS = "dq.verdicts"
TOPIC_ENRICH_TRIAGE = "enrich.triage"
TOPIC_ENRICH_PAPERS = "enrich.papers"
TOPIC_ENRICH_ITEMS = "enrich.items"
TOPIC_QA_QUERIES = "qa.queries"
TOPIC_QA_ANSWERS = "qa.answers"
TOPIC_DECISION_REPLIES = "decision.replies"
TOPIC_FALLBACK_EVENTS = "fallback.events"

AUTHORITATIVE_TOPICS: tuple[str, ...] = (
    TOPIC_RAW_DOCS,
    TOPIC_INTEL_ITEMS,
    TOPIC_DQ_VERDICTS,
    TOPIC_ENRICH_TRIAGE,
    TOPIC_ENRICH_PAPERS,
    TOPIC_ENRICH_ITEMS,
    TOPIC_QA_QUERIES,
    TOPIC_QA_ANSWERS,
    TOPIC_DECISION_REPLIES,
    TOPIC_FALLBACK_EVENTS,
)

# ------------------------------------------------------------ 本仓扩展主题
# 权威 10 主题覆盖不到本仓能力，在 contracts/events.md §3 登记后追加。
TOPIC_ENRICH_REQUESTED = "intel.enrich.requested"
TOPIC_ENRICH_EVIDENCE = "enrich.evidence"
TOPIC_ALERT_RAISED = "intel.alert.raised"
TOPIC_REPORT_DAILY = "intel.report.daily"
TOPIC_BUDGET_EXCEEDED = "intel.budget.exceeded"
TOPIC_SELFHEAL_ACTION = "intel.selfheal.action"

EXTENSION_TOPICS: tuple[str, ...] = (
    TOPIC_ENRICH_REQUESTED,
    TOPIC_ENRICH_EVIDENCE,
    TOPIC_ALERT_RAISED,
    TOPIC_REPORT_DAILY,
    TOPIC_BUDGET_EXCEEDED,
    TOPIC_SELFHEAL_ACTION,
)

ALL_TOPICS: tuple[str, ...] = AUTHORITATIVE_TOPICS + EXTENSION_TOPICS

# 旧主题 -> 权威主题。保留是为了让存量消费者/文档迁移期不炸；
# 新代码禁止再用左边的名字（normalize_topic 会打 warning）。
LEGACY_TOPIC_ALIASES: dict[str, str] = {
    "intel.raw.collected": TOPIC_RAW_DOCS,
    "intel.dedup.merged": TOPIC_INTEL_ITEMS,
    "intel.enrich.completed": TOPIC_ENRICH_ITEMS,
    "intel.enrich.degraded": TOPIC_FALLBACK_EVENTS,
    "intel.risk.triaged": TOPIC_ENRICH_TRIAGE,
    "intel.qa.asked": TOPIC_QA_QUERIES,
}

Handler = Callable[[dict], Awaitable[None]]


class EventBusUnavailable(RuntimeError):
    """Redis 不可用（连接失败或处于熔断窗口内）。事件发布失败不阻断主链路。"""


class UnknownTopicError(ValueError):
    """主题既不在权威清单也不在扩展清单里。宁可炸掉也不要往总线上发野主题。"""


class EventBus:
    # Redis 挂掉后的熔断窗口。一轮富化要发十几条事件，没有熔断就是十几轮连接超时。
    _REDIS_DOWN_UNTIL: float = 0.0
    _REDIS_DOWN_COOLDOWN: float = 5.0

    def __init__(self, redis_client: Any | None = None) -> None:
        self.settings = get_settings()
        self._redis = redis_client
        # 注入了 client（测试/替代实现）就不参与熔断，否则假 client 会被误伤
        self._injected = redis_client is not None
        self._unavailable_until = 0.0

    @property
    def redis_enabled(self) -> bool:
        """空 REDIS_URL 视为"显式禁用事件总线"，不是配置错误。"""

        return bool((self.settings.redis_url or "").strip())

    @property
    def redis(self) -> Any:
        if not self.redis_enabled:
            raise EventBusUnavailable("未配置 REDIS_URL，事件总线已禁用")
        if self._redis is None:
            from redis.asyncio import Redis  # 惰性导入，便于无 Redis 环境跑单测

            timeout = self.settings.redis_socket_timeout_seconds
            self._redis = Redis.from_url(
                self.settings.redis_url,
                decode_responses=True,
                # 不给超时时连接失败要等 ~4s；事件是"锦上添花"，不能让它拖住主链路
                socket_connect_timeout=timeout,
                socket_timeout=timeout,
                retry_on_timeout=False,
            )
        return self._redis

    # ------------------------------------------------------------ 信封构造

    @staticmethod
    def normalize_topic(topic: str) -> str:
        """把旧主题名映射到权威主题名；未知主题直接拒绝。"""

        if topic in ALL_TOPICS:
            return topic
        if topic in LEGACY_TOPIC_ALIASES:
            mapped = LEGACY_TOPIC_ALIASES[topic]
            logger.warning("主题已迁移到权威契约: %s -> %s", topic, mapped)
            return mapped
        raise UnknownTopicError(
            f"未知主题 {topic!r}：权威 {len(AUTHORITATIVE_TOPICS)} 个 + "
            f"扩展 {len(EXTENSION_TOPICS)} 个，新主题须先在 contracts/events.md 登记"
        )

    @staticmethod
    def make_event_id(topic: str, dedup_key: str, schema_version: str = SCHEMA_VERSION) -> str:
        """内容派生的确定性 event_id：同 (topic, dedup_key, version) 必得同 ID。"""

        material = f"{topic}|{dedup_key}|{schema_version}".encode()
        return f"{EVENT_ID_PREFIX}{hashlib.sha256(material).hexdigest()[:32]}"

    @classmethod
    def envelope(
        cls,
        topic: str,
        payload: dict,
        trace_id: str | None = None,
        *,
        causation_id: str | None = None,
        dedup_key: str | None = None,
        occurred_at: str | None = None,
        schema_version: str = SCHEMA_VERSION,
    ) -> dict:
        """构造权威信封。

        `dedup_key` 给了就走确定性 ID（可重放去重）；没给就退化为随机 ID ——
        心跳、预算超限这类状态事件本就不该被去重。
        """

        topic = cls.normalize_topic(topic)
        if dedup_key is not None:
            event_id = cls.make_event_id(topic, dedup_key, schema_version)
        else:
            event_id = f"{EVENT_ID_PREFIX}{uuid.uuid4().hex}"

        env: dict[str, Any] = {
            "event_id": event_id,
            "topic": topic,
            "occurred_at": occurred_at or datetime.now(BEIJING_TZ).isoformat(),
            "trace_id": trace_id or uuid.uuid4().hex,
            "payload": payload,
            "schema_version": schema_version,
        }
        if causation_id:
            # 根事件省略此键，而不是写 null —— 省一个字段，也避免消费者判空。
            env["causation_id"] = causation_id
        return env

    def _redis_down(self) -> bool:
        if self._injected:
            return False
        until = max(EventBus._REDIS_DOWN_UNTIL, self._unavailable_until)
        return time.monotonic() < until

    def _mark_redis_down(self) -> None:
        if self._injected:
            return
        EventBus._REDIS_DOWN_UNTIL = time.monotonic() + EventBus._REDIS_DOWN_COOLDOWN
        self._unavailable_until = EventBus._REDIS_DOWN_UNTIL

    @staticmethod
    def reset_availability() -> None:
        """手动清掉熔断状态（进程重启、Redis 恢复后由 self-heal 调用）。"""

        EventBus._REDIS_DOWN_UNTIL = 0.0

    async def publish(
        self,
        topic: str,
        payload: dict,
        trace_id: str | None = None,
        *,
        causation_id: str | None = None,
        dedup_key: str | None = None,
    ) -> str:
        env = self.envelope(
            topic, payload, trace_id, causation_id=causation_id, dedup_key=dedup_key
        )
        return await self.publish_envelope(env)

    async def publish_envelope(self, env: dict) -> str:
        """发布已构造好的信封。

        需要"payload 自带 event_id"的权威内联契约（如 `FallbackEvent`）时走这里：
        先造信封拿到 `event_id`，回填 payload，再发同一条信封 —— 保证
        `payload.event_id == envelope.event_id`，消费者两边去重都能命中。
        """

        topic = self.normalize_topic(env["topic"])
        if self._redis_down():
            raise EventBusUnavailable(f"Redis 熔断中，跳过发布 topic={topic}")
        try:
            await self.redis.publish(topic, json.dumps(env, ensure_ascii=False))
        except Exception as exc:
            self._mark_redis_down()
            raise EventBusUnavailable(f"事件发布失败 topic={topic}: {exc}") from exc
        logger.info("event published topic=%s event_id=%s", topic, env["event_id"])
        return env["event_id"]

    async def try_publish(
        self,
        topic: str,
        payload: dict,
        trace_id: str | None = None,
        *,
        causation_id: str | None = None,
        dedup_key: str | None = None,
    ) -> str | None:
        """发布事件但绝不抛异常（Redis 故障场景）。

        用于"事件挂了也不能影响主链路"的场景：失败仍然记 warning（FB1 禁止静默兜底），
        但调用方继续干活，而不是把整个请求打成 500。

        注意：主题非法属于**契约错误**而非基础设施故障，直接抛出 ——
        契约错误被 warning 吞掉就等于契约形同虚设。
        """

        topic = self.normalize_topic(topic)
        try:
            return await self.publish(
                topic, payload, trace_id, causation_id=causation_id, dedup_key=dedup_key
            )
        except EventBusUnavailable as exc:
            logger.warning("事件发布降级 topic=%s: %s", topic, exc)
            return None
        except Exception:  # noqa: BLE001 - 兜底也不能让主链路挂掉
            logger.exception("事件发布异常 topic=%s", topic)
            return None

    async def subscribe(self, topics: tuple[str, ...], handler: Handler) -> None:
        resolved = tuple(self.normalize_topic(t) for t in topics)
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(*resolved)
        logger.info("subscribed: %s", ", ".join(resolved))
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                env = json.loads(message["data"])
            except json.JSONDecodeError:
                continue
            try:
                await handler(env)
            except Exception:
                logger.exception("事件处理失败 topic=%s", env.get("topic"))


async def stream_topics(bus: EventBus, topics: tuple[str, ...]) -> AsyncIterator[dict]:
    """供 API SSE 转发内部事件（问答页展示 Agent 阶段）。"""

    resolved = tuple(bus.normalize_topic(t) for t in topics)
    pubsub = bus.redis.pubsub()
    await pubsub.subscribe(*resolved)
    try:
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                yield json.loads(message["data"])
            except json.JSONDecodeError:
                continue
    finally:
        await pubsub.unsubscribe(*resolved)
        await pubsub.aclose()

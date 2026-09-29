"""事件总线与告警：横切能力。

事件信封与主题以 SafeTrace `contracts/events.md` 为权威规格，本文件是它的自动化落点：
信封形状、主题白名单、确定性 event_id、causation_id 因果链都必须被 CI 拦下。
"""

from __future__ import annotations

import json
import time

import pytest
from scripts.contracts import load_schema, validate

from aiintel.core.alerts import AlertManager
from aiintel.core.events import (
    ALL_TOPICS,
    AUTHORITATIVE_TOPICS,
    EVENT_ID_PREFIX,
    EXTENSION_TOPICS,
    LEGACY_TOPIC_ALIASES,
    SCHEMA_VERSION,
    TOPIC_ALERT_RAISED,
    TOPIC_ENRICH_ITEMS,
    TOPIC_FALLBACK_EVENTS,
    TOPIC_INTEL_ITEMS,
    TOPIC_QA_QUERIES,
    TOPIC_RAW_DOCS,
    EventBus,
    EventBusUnavailable,
    UnknownTopicError,
)


# 熔断状态挂在 EventBus 类上，测试间必须清干净，否则会互相污染
@pytest.fixture(autouse=True)
def _reset_event_bus_availability():
    EventBus.reset_availability()
    yield
    EventBus.reset_availability()


async def test_publish_wraps_payload_in_envelope(fake_bus):
    bus, redis = fake_bus
    event_id = await bus.publish(TOPIC_ALERT_RAISED, {"level": "HIGH"}, "trace-1")

    assert event_id
    channel, raw = redis.published[-1]
    assert channel == TOPIC_ALERT_RAISED
    env = json.loads(raw)
    # 权威信封字段集，additionalProperties:false 下多一个键就是违约
    assert set(env) == {
        "event_id",
        "topic",
        "occurred_at",
        "trace_id",
        "payload",
        "schema_version",
    }
    assert env["trace_id"] == "trace-1"
    assert env["payload"]["level"] == "HIGH"
    assert env["schema_version"] == SCHEMA_VERSION
    # 根事件省略 causation_id，而不是写 null
    assert "causation_id" not in env


async def test_envelope_conforms_to_event_envelope_contract(fake_bus):
    """信封必须真的过 JSON Schema，不能只是"看起来像"。"""

    bus, redis = fake_bus
    await bus.publish(TOPIC_RAW_DOCS, {"raw_item_id": "r1"}, "trace-1", dedup_key="nvd:r1")

    env = json.loads(redis.published[-1][1])
    assert validate(load_schema("EventEnvelope.json"), env) == []


async def test_envelope_with_causation_id_conforms_to_contract(fake_bus):
    bus, redis = fake_bus
    await bus.publish(
        TOPIC_INTEL_ITEMS, {"vuln_id": "v1"}, "t1", causation_id=f"{EVENT_ID_PREFIX}{'a' * 32}"
    )

    env = json.loads(redis.published[-1][1])
    assert validate(load_schema("EventEnvelope.json"), env) == []


async def test_publish_generates_trace_id_when_missing(fake_bus):
    bus, redis = fake_bus
    await bus.publish(TOPIC_ALERT_RAISED, {"level": "LOW"})
    env = json.loads(redis.published[-1][1])
    assert env["trace_id"]


async def test_publish_uses_chinese_keys_unescaped(fake_bus):
    bus, redis = fake_bus
    await bus.publish(TOPIC_ALERT_RAISED, {"title": "模型投毒告警"})
    assert "模型投毒告警" in redis.published[-1][1]


# ------------------------------------------------------------------ 主题治理


def test_all_topics_are_unique():
    assert len(ALL_TOPICS) == len(set(ALL_TOPICS))


def test_authoritative_topics_match_safetrace_verbatim():
    """权威 10 主题一字不改。这是"以他的为主"的底线，改名即违约。"""

    assert AUTHORITATIVE_TOPICS == (
        "raw.docs",
        "intel.items",
        "dq.verdicts",
        "enrich.triage",
        "enrich.papers",
        "enrich.items",
        "qa.queries",
        "qa.answers",
        "decision.replies",
        "fallback.events",
    )


def test_every_topic_is_declared_in_the_envelope_schema():
    """总线里能发的主题，必须都在 EventEnvelope 的枚举里登记。"""

    schema = load_schema("EventEnvelope.json")
    declared = set(schema["properties"]["topic"]["enum"])
    assert set(ALL_TOPICS) <= declared, f"未在契约登记的主题: {set(ALL_TOPICS) - declared}"
    assert declared == set(ALL_TOPICS), f"契约里多出的僵尸主题: {declared - set(ALL_TOPICS)}"


def test_extension_topics_are_disjoint_from_authoritative():
    assert not set(AUTHORITATIVE_TOPICS) & set(EXTENSION_TOPICS)


def test_envelope_structure():
    env = EventBus.envelope(TOPIC_QA_QUERIES, {"a": 1}, "t1")
    assert env["topic"] == TOPIC_QA_QUERIES
    assert env["payload"] == {"a": 1}


def test_unknown_topic_is_rejected():
    """未知主题必须炸掉 —— 往权威总线上发野主题等于绕过契约。"""

    with pytest.raises(UnknownTopicError, match="contracts/events.md"):
        EventBus.envelope("intel.made_up", {}, "t1")


def test_legacy_topic_names_are_translated_not_accepted():
    """存量主题名仍能发，但会被改写成权威主题并打 warning。"""

    assert EventBus.normalize_topic("intel.enrich.completed") == TOPIC_ENRICH_ITEMS
    for legacy, canonical in LEGACY_TOPIC_ALIASES.items():
        assert legacy not in ALL_TOPICS, f"{legacy} 已迁移，不该留在白名单里"
        assert EventBus.normalize_topic(legacy) == canonical


# ------------------------------------------------- 确定性 event_id / 幂等


def test_dedup_key_yields_stable_event_id():
    """同 (topic, dedup_key) 必得同 event_id —— 消费者据此幂等去重。"""

    a = EventBus.envelope(TOPIC_RAW_DOCS, {"x": 1}, "t1", dedup_key="nvd:CVE-1")
    b = EventBus.envelope(TOPIC_RAW_DOCS, {"x": 999}, "t2", dedup_key="nvd:CVE-1")
    assert a["event_id"] == b["event_id"]


def test_event_id_differs_per_topic_and_key():
    base = EventBus.make_event_id(TOPIC_RAW_DOCS, "k1")
    assert base != EventBus.make_event_id(TOPIC_INTEL_ITEMS, "k1")
    assert base != EventBus.make_event_id(TOPIC_RAW_DOCS, "k2")


def test_event_id_matches_contract_pattern():
    env = EventBus.envelope(TOPIC_RAW_DOCS, {}, "t1", dedup_key="k")
    assert env["event_id"].startswith(EVENT_ID_PREFIX)
    assert validate(load_schema("EventEnvelope.json"), env) == []


def test_random_event_id_when_no_dedup_key():
    """状态类事件（心跳/预算超限）不该被去重，没给 dedup_key 就得是随机 ID。"""

    a = EventBus.envelope("intel.budget.exceeded", {}, "t1")
    b = EventBus.envelope("intel.budget.exceeded", {}, "t1")
    assert a["event_id"] != b["event_id"]
    assert validate(load_schema("EventEnvelope.json"), a) == []


def test_schema_version_takes_part_in_the_dedup_hash():
    """契约版本变了就是另一种形状，ID 必须跟着变，否则重放会命中旧消费者。"""

    v1 = EventBus.make_event_id(TOPIC_RAW_DOCS, "k", "1.0")
    v2 = EventBus.make_event_id(TOPIC_RAW_DOCS, "k", "1.1")
    assert v1 != v2


# ------------------------------------------------------------ 降级事件出口


async def test_degraded_event_uses_authoritative_fallback_topic_and_shape(fake_bus):
    """降级走权威 `fallback.events`，载荷是权威内联契约 FallbackEvent。"""

    from aiintel.services.enrich import s2_events

    bus, redis = fake_bus
    ok = await s2_events.publish_degraded(
        bus,
        "v1",
        {
            "dimension": "cvss",
            "degraded_to": "fixture",
            "degraded_reason": "NVD 不可达",
            "trace_id": "trace-9",
        },
    )

    assert ok
    channel, raw = redis.published[-1]
    assert channel == TOPIC_FALLBACK_EVENTS
    env = json.loads(raw)
    assert validate(load_schema("EventEnvelope.json"), env) == []
    payload = env["payload"]
    assert payload["layer"] in {"L1", "L2", "L3", "L4"}
    assert payload["user_visible"] is True
    assert payload["degraded_state"]["label"]
    assert payload["degraded_state"]["since"]
    # FallbackEvent 自带的 event_id 必须与信封一致，否则消费者两边去重对不上
    assert payload["event_id"] == env["event_id"]
    assert payload["trace_id"] == "trace-9"


async def test_alert_publishes_event_and_no_webhook_when_unset(fake_bus):
    bus, redis = fake_bus
    manager = AlertManager(bus=bus)
    await manager.raise_alert(
        level="HIGH", title="CVE-2026-0001", message="CVSS 9.8", vuln_id="v1", trace_id="t2"
    )
    channel, raw = redis.published[-1]
    assert channel == TOPIC_ALERT_RAISED
    payload = json.loads(raw)["payload"]
    assert payload["level"] == "HIGH"
    assert payload["vuln_id"] == "v1"


async def test_alert_test_reports_delivery_flag(fake_bus):
    bus, _ = fake_bus
    result = await AlertManager(bus=bus).test()
    assert set(result) == {"delivered"}
    assert isinstance(result["delivered"], bool)


async def test_alert_webhook_failure_does_not_raise(fake_bus, monkeypatch):
    import httpx

    bus, _ = fake_bus
    manager = AlertManager(bus=bus)

    class FailingClient:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            raise httpx.ConnectError("webhook 不可达")

    monkeypatch.setattr(httpx, "AsyncClient", FailingClient)
    monkeypatch.setattr(
        manager.settings, "alert_webhook_url", "https://hook.invalid/x", raising=False
    )
    await manager.raise_alert(level="LOW", title="t", message="m")  # 不抛错即通过


async def _dead_redis_bus(monkeypatch) -> EventBus:
    """指向一个没人监听的端口，模拟"Redis 没起"。"""

    bus = EventBus()
    monkeypatch.setattr(bus.settings, "redis_url", "redis://127.0.0.1:1/0", raising=False)
    monkeypatch.setattr(bus.settings, "redis_socket_timeout_seconds", 0.05, raising=False)
    return bus


def _dead_redis_bus_sync() -> EventBus:
    """同 _dead_redis_bus，但用完即还原（不依赖 monkeypatch 的同步场景）。"""

    bus = EventBus()
    bus.settings.redis_url = "redis://127.0.0.1:1/0"
    bus.settings.redis_socket_timeout_seconds = 0.05
    return bus


async def test_publish_fails_fast_when_redis_unreachable(monkeypatch):
    """Redis 不可用必须快速失败：没有超时时 redis-py 要等约 4s，
    一轮富化十几条事件就会把事件循环拖死（曾经单测要 45s/条）。"""

    bus = await _dead_redis_bus(monkeypatch)

    started = time.perf_counter()
    with pytest.raises(EventBusUnavailable):
        await bus.publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})
    elapsed = time.perf_counter() - started

    assert elapsed < 2.0, f"Redis 不可用时发布耗时 {elapsed:.2f}s，太慢了"


async def test_publish_short_circuits_while_redis_is_down(monkeypatch):
    """熔断：Redis 挂掉后，后续事件不应该每条都再付一次连接超时。"""

    bus = await _dead_redis_bus(monkeypatch)
    with pytest.raises(EventBusUnavailable):
        await bus.publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})

    started = time.perf_counter()
    for _ in range(20):
        with pytest.raises(EventBusUnavailable, match="熔断"):
            await bus.publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})
    elapsed = time.perf_counter() - started

    assert elapsed < 0.5, f"熔断后 20 次发布仍耗时 {elapsed:.2f}s，说明没短路"


async def test_injected_client_is_never_short_circuited(fake_bus):
    """注入了 client 的总线（测试/替代实现）不能被真实 Redis 的熔断状态误伤。"""

    EventBus._REDIS_DOWN_UNTIL = time.monotonic() + 60
    bus, redis = fake_bus

    event_id = await bus.publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})

    assert event_id
    assert redis.published[-1][0] == TOPIC_ALERT_RAISED


async def test_blank_redis_url_means_bus_disabled(fake_bus, monkeypatch):
    """空 REDIS_URL 是"显式禁用"，不是配置错误 —— demo 模式就靠它跑。"""

    bus, _ = fake_bus
    bus._injected = False
    monkeypatch.setattr(bus.settings, "redis_url", "", raising=False)

    assert bus.redis_enabled is False
    with pytest.raises(EventBusUnavailable, match="已禁用"):
        await bus.publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})


async def test_try_publish_never_raises_and_reports_failure(monkeypatch):
    """主链路用 try_publish：Redis 挂了只降级记 warning，不能把请求打成 500。"""

    bus = await _dead_redis_bus(monkeypatch)

    event_id = await bus.try_publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})

    assert event_id is None


async def test_try_publish_succeeds_when_redis_works(fake_bus):
    bus, redis = fake_bus

    event_id = await bus.try_publish(TOPIC_ALERT_RAISED, {"level": "HIGH"})

    assert event_id
    assert redis.published[-1][0] == TOPIC_ALERT_RAISED


async def test_try_publish_survives_unexpected_exception(fake_bus, monkeypatch):
    """连 EventBus 之外的意外异常也不能影响主链路。"""

    bus, _ = fake_bus

    async def boom(*a, **k):
        raise ZeroDivisionError("unexpected")

    monkeypatch.setattr(bus, "publish", boom)

    assert await bus.try_publish(TOPIC_ALERT_RAISED, {"level": "HIGH"}) is None


async def test_qa_request_succeeds_without_redis(monkeypatch):
    """回归：事件发布失败曾经让整个问答请求返回 QA_FAILED。"""

    from aiintel.core.llm import get_llm
    from aiintel.services.qa.agent import QAAgent

    agent = QAAgent(bus=_dead_redis_bus_sync())
    # 注意要改 router 自己的 settings：get_settings() 被别的用例 cache_clear 过，
    # 拿到的可能是另一个 Settings 实例，改了不生效
    llm_settings = get_llm().settings
    monkeypatch.setattr(llm_settings, "llm_api_key", "", raising=False)
    monkeypatch.setattr(llm_settings, "demo_mode", True, raising=False)
    monkeypatch.setattr(llm_settings, "llm_local_enabled", False, raising=False)

    frames = [f async for f in agent.answer_stream("CVE-2026-31001 影响哪些产品？")]
    kinds = {f.get("event") for f in frames}

    assert "error" not in kinds, (
        f"问答因事件总线失败：{[f for f in frames if f.get('event') == 'error']}"
    )
    assert "done" in kinds


async def test_reset_availability_allows_publish_again(fake_bus, monkeypatch):
    EventBus._REDIS_DOWN_UNTIL = time.monotonic() + 60
    EventBus.reset_availability()
    bus, redis = fake_bus

    await bus.publish(TOPIC_ALERT_RAISED, {"level": "LOW"})

    assert redis.published[-1][0] == TOPIC_ALERT_RAISED


async def test_event_publish_failure_never_blocks_enrichment():
    """F 线铁律：事件发布失败不阻断富化主链路。"""

    from aiintel.services.enrich import s2_events

    results = [{"dimension": "cvss", "source": ["nvd"], "degraded_to": None, "mock": False}]
    out = await s2_events.publish_all(None, "v1", results)

    assert out.published + out.failed == len(results)

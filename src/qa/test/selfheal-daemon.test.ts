/**
 * A-06 尾项回归：常驻自愈（服务进程订阅 + 周期 drain/healthcheck）。
 * 口径：与演练/冒烟共用同一 SelfHealAgent；每拍显式交出报告（禁静默自愈）；
 * start 订阅 fallback.events 保持兜底透明率 100%，stop 退净订阅；拍串行禁并发。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { DecisionReply, FallbackEvent } from "@safetrace/shared";
import { SelfHealDaemon } from "../src/orchestrator/selfheal-daemon.js";

function fallbackEvent(traceId: string, degradedOf: string): FallbackEvent {
  return {
    event_id: "fb_" + degradedOf + "_" + traceId,
    layer: "L3",
    trigger: "daemon test degrade",
    action_taken: "degraded to memory index",
    degraded_of: degradedOf,
    user_visible: true,
    degraded_state: { label: "测试降级", since: "2026-10-10T00:00:00.000Z", detail_ref: "tr:" + traceId },
    recovery_hint: "恢复后重试",
    trace_id: traceId,
  };
}

/** 造 3 条死信（消费者坏 + maxRetries=1），返回可切换消费者的闭包。 */
function brokenConsumerSetup(): { store: MemoryEventStore; bus: EventBus; setBroken: (v: boolean) => void } {
  const store = new MemoryEventStore();
  let broken = true;
  let agent: SelfHealDaemon | undefined;
  const bus = new EventBus({
    store,
    maxRetries: 1,
    onDeadLetter: (eventId, reason) => agent?.agent.noteDeadLetter(eventId, reason),
  });
  bus.subscribe("decision.replies", async () => {
    if (broken) throw new Error("daemon test: consumer broken");
  });
  return { store, bus, setBroken: (v: boolean) => { broken = v; } };
}

async function seedDeadLetters(bus: EventBus, traceId: string, count: number): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    const reply: DecisionReply = {
      decision_id: "dec_daemon_" + i,
      kind: "q1_route",
      decision: { choice: "impact_range" },
      calibrated_prob: 0.9,
      decided_by: "rule_fallback",
      schema_version: "1.0",
    };
    await bus.publish("decision.replies", reply, { trace_id: traceId });
  }
}

test("A-06 常驻：单拍 drain + healthcheck，报告经 onTick 显式交出", async () => {
  const { store, bus } = brokenConsumerSetup();
  await seedDeadLetters(bus, "tr_daemon_dl", 3);
  assert.equal((await store.deadLetters()).length, 3, "消费失败 3 条进死信");
  const ticks: unknown[] = [];
  const daemon = new SelfHealDaemon({
    bus, store,
    backoff: { baseMs: 1000, maxMs: 60_000, maxAttempts: 8 },
    onTick: (report) => { ticks.push(report); },
  });
  const first = await daemon.tick();
  assert.equal(ticks.length, 1, "每拍报告必须经 onTick 显式交出（禁静默自愈）");
  assert.equal(first.drain.retried, 3, "首拍重投 3 条（消费者仍坏）");
  assert.equal(first.drain.recovered, 0);
  assert.equal(first.health.dead_letters, 3);
  assert.equal(first.health.retry_scheduled, 3, "失败排入退避队列");
  assert.equal(daemon.ticks, 1);
  const windowTick = await daemon.tick();
  assert.equal(windowTick.drain.retried, 0, "指数退避窗口内不重投");
  assert.equal(ticks.length, 2);
});

test("A-06 常驻：修复消费者后到拍重投全部恢复，healthcheck 归零", async () => {
  const { store, bus, setBroken } = brokenConsumerSetup();
  await seedDeadLetters(bus, "tr_daemon_recover", 3);
  let now = 1_800_000_000_000;
  const daemon = new SelfHealDaemon({
    bus, store, now: () => now,
    backoff: { baseMs: 1000, maxMs: 60_000, maxAttempts: 8 },
  });
  const first = await daemon.tick();
  assert.equal(first.drain.recovered, 0);
  now += 1500; // 越过 baseMs 退避窗口
  setBroken(false);
  const recovered = await daemon.tick();
  assert.equal(recovered.drain.recovered, 3, "到拍重投 3 条全部恢复");
  assert.equal(recovered.health.dead_letters, 0, "恢复后死信清零");
  assert.equal(recovered.health.retry_scheduled, 0, "退避队列清空");
  assert.equal((await store.deadLetters()).length, 0);
});

test("A-06 常驻：start 订阅 fallback.events（兜底透明率 100%）+ stop 退净", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const daemon = new SelfHealDaemon({ bus, store, intervalMs: 100_000 });
  daemon.start();
  await bus.publish("fallback.events", fallbackEvent("tr_daemon_sub", "qdrant"), { trace_id: "tr_daemon_sub" });
  assert.equal(daemon.agent.registeredFallbackEvents.length, 1, "常驻订阅必须登记降级事件");
  assert.ok(daemon.agent.registeredFallbackEvents.every((e) => e.user_visible), "登记事件全部用户可见");
  const lineage = await store.readLineage("tr_daemon_sub");
  assert.ok(lineage.some((r) => r.stage === "selfheal.fallback_registration"), "登记必须落 lineage");
  daemon.stop();
  await bus.publish("fallback.events", fallbackEvent("tr_daemon_sub2", "qdrant"), { trace_id: "tr_daemon_sub2" });
  assert.equal(daemon.agent.registeredFallbackEvents.length, 1, "stop 后不再登记（订阅已退净）");
  // start 幂等
  daemon.start();
  daemon.start();
  daemon.stop();
});

test("A-06 常驻：并发拍串行（禁并发 drain）", async () => {
  const { store, bus } = brokenConsumerSetup();
  const daemon = new SelfHealDaemon({ bus, store });
  const first = daemon.tick();
  await assert.rejects(daemon.tick(), /上一拍尚未结束/);
  await first;
  assert.equal(daemon.ticks, 1);
});

test("A-06 常驻：周期拍按间隔触发（start → 等两拍 → stop）", async () => {
  const { store, bus } = brokenConsumerSetup();
  let tickCount = 0;
  const daemon = new SelfHealDaemon({ bus, store, intervalMs: 20, onTick: () => { tickCount += 1; } });
  daemon.start();
  await new Promise((resolve) => setTimeout(resolve, 120));
  daemon.stop();
  assert.ok(tickCount >= 2, "周期拍应按间隔触发（实际 " + tickCount + " 拍）");
  const afterStop = tickCount;
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(tickCount, afterStop, "stop 后不再触发新拍");
});
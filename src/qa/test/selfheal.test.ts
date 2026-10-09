/**
 * A-06 · 自愈 Agent 单测（roles.ts selfheal 三角色的实现验收）。
 * 覆盖：工具白名单边界、fallback 登记（兜底透明率 100%）、死信指数退避重投与销档、
 *       replay、healthcheck 聚合、drill 全链路、Trace 外发桩。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore, LangfuseTraceSink, degrade } from "@safetrace/shared";
import type { DecisionReply, Envelope, FallbackEvent } from "@safetrace/shared";
import { AGENT_ROLES } from "../src/orchestrator/roles.js";
import {
  SELFHEAL_TOOL_PERMISSIONS,
  SelfHealAgent,
  assertSelfhealTool,
  type CircuitSnapshot,
} from "../src/orchestrator/selfheal.js";

function setup(opts: { backoff?: { baseMs?: number; maxMs?: number; maxAttempts?: number }; circuits?: () => CircuitSnapshot[] } = {}) {
  const store = new MemoryEventStore();
  let agent: SelfHealAgent;
  const bus = new EventBus({
    store,
    maxRetries: 1,
    onDeadLetter: (eventId, reason) => agent?.noteDeadLetter(eventId, reason),
  });
  agent = new SelfHealAgent({ bus, store, ...opts });
  return { store, bus, agent };
}

function drillReply(): DecisionReply {
  return {
    decision_id: "dec_selfheal_test",
    kind: "q1_route",
    decision: { choice: "impact_range" },
    calibrated_prob: 0.9,
    decided_by: "rule_fallback",
    schema_version: "1.0",
  };
}

test("A-06 工具边界：白名单与角色声明一致，越权工具抛错", () => {
  assert.deepEqual(Object.keys(SELFHEAL_TOOL_PERMISSIONS).sort(), [...AGENT_ROLES.selfheal.tools].sort(),
    "roles.ts selfheal 白名单与实现必须一致（防声明漂移）");
  for (const [name, permissions] of Object.entries(SELFHEAL_TOOL_PERMISSIONS)) {
    assert.equal(permissions.network, false, name + " 不得联网");
    assert.equal(permissions.filesystem, "none", name + " 不得碰文件系统");
    assert.equal(permissions.exec, false, name + " 不得执行进程");
  }
  assert.throws(() => assertSelfhealTool("http_fetch"), /selfheal 角色无权使用工具/);
  assertSelfhealTool("replay");
  assertSelfhealTool("dead_letter_drain");
  assertSelfhealTool("healthcheck");
});

test("A-06 fallback 登记：订阅后全部降级事件入账并外发 Trace", async () => {
  const sentBatches: unknown[] = [];
  const sink = new LangfuseTraceSink({
    url: "http://127.0.0.1:3000", publicKey: "pk", secretKey: "sk",
    fetchImpl: (async (_i: string | URL | Request, init?: RequestInit) => {
      sentBatches.push(JSON.parse(String(init?.body ?? "{}")) as unknown);
      return new Response("{}", { status: 200 });
    }) as typeof fetch,
  });
  const { store, bus, agent } = setup();
  const detach = agent.subscribeFallbackEvents();
  await degrade({
    layer: "L3", trigger: "test degrade", degradedOf: "test:degrade", traceId: "tr_sh_1",
    label: "测试降级", emit: async (e) => { await bus.publish("fallback.events", e, { trace_id: e.trace_id }); },
  });
  await degrade({
    layer: "L1", trigger: "test degrade 2", degradedOf: "test:degrade2", traceId: "tr_sh_2",
    label: "测试降级 2", emit: async (e) => { await bus.publish("fallback.events", e, { trace_id: e.trace_id }); },
  });
  assert.equal(agent.registeredFallbackEvents.length, 2, "两条降级全部登记（兜底透明率 100%）");
  const stored = await store.read<FallbackEvent>("fallback.events");
  assert.equal(stored.length, 2);
  const lineage = await bus.readLineage("tr_sh_1");
  assert.ok(lineage.some((r) => r.stage === "selfheal.fallback_registration"), "登记动作落 lineage");
  await sink.flush();
  assert.equal(sentBatches.length, 0, "未接入 sink 的 agent 不外发（不替调用方决定）");
  detach();
});

test("A-06 死信重投：指数退避窗口内不重投，到拍重投成功即销档", async () => {
  const { store, bus, agent } = setup({ backoff: { baseMs: 1000, maxMs: 60_000, maxAttempts: 3 } });
  agent.subscribeFallbackEvents();
  let broken = true;
  bus.subscribe("decision.replies", async () => {
    if (broken) throw new Error("consumer broken");
  });
  const env = await bus.publish("decision.replies", drillReply(), { trace_id: "tr_sh_dl" });
  assert.equal((await store.deadLetters()).length, 1, "一次失败即死信（maxRetries=1）");

  // 首次 drain：消费者仍坏 → 重投失败并按退避排下一拍
  const now = 1_000_000;
  const first = await agent.dead_letter_drain({ now });
  assert.equal(first.retried, 1);
  assert.equal(first.recovered, 0);
  assert.equal(first.details[0]?.attempt, 1);

  // 同一拍号再 drain：退避窗口内不重投
  const second = await agent.dead_letter_drain({ now });
  assert.equal(second.retried, 0, "退避窗口内不得重投");
  assert.equal(second.deferred, 1);

  // 到拍 + 消费者修复 → 重投成功并销档
  broken = false;
  const third = await agent.dead_letter_drain({ now: now + 1001 });
  assert.equal(third.recovered, 1);
  assert.equal((await store.deadLetters()).length, 0, "恢复后死信销档");
  assert.equal((await store.read("decision.replies")).length, 1, "事件不重复入库（幂等）");
  assert.ok(env.event_id.length > 0);
});

test("A-06 死信重投：超过 maxAttempts 仍失败 → still_failed 并保留死信转人工", async () => {
  const { store, agent } = setup({ backoff: { baseMs: 10, maxMs: 20, maxAttempts: 2 } });
  const bus = (agent as unknown as { opts: { bus: EventBus } }).opts.bus;
  bus.subscribe("decision.replies", async () => { throw new Error("always broken"); });
  await bus.publish("decision.replies", drillReply(), { trace_id: "tr_sh_dl2" });
  let now = 0;
  for (let i = 0; i < 3; i += 1) {
    now += 1000;
    await agent.dead_letter_drain({ now });
  }
  const report = await agent.dead_letter_drain({ now: now + 1000 });
  assert.equal(report.still_failed, 1, "超过重投上限后显式记 still_failed（转人工，不无限重试）");
  assert.equal((await store.deadLetters()).length, 1, "仍保留死信供人工处理");
});

test("A-06 replay 工具：按主题重读重投且留 lineage", async () => {
  const { store, bus, agent } = setup();
  let seen = 0;
  bus.subscribe("decision.replies", async () => { seen += 1; });
  await bus.publish("decision.replies", drillReply(), { trace_id: "tr_sh_rp" });
  assert.equal(seen, 1);
  const result = await agent.replay("decision.replies", { traceId: "tr_sh_rp" });
  assert.equal(result.replayed, 1);
  assert.equal(seen, 2, "replay 重新投递给订阅者");
  const lineage = await store.readLineage("tr_sh_rp");
  assert.ok(lineage.some((r) => r.stage === "selfheal.replay"), "replay 落 lineage");
});

test("A-06 healthcheck：聚合死信/退避/fallback/熔断/Trace，缺探针时显式注明", async () => {
  const { store, bus, agent } = setup({
    circuits: () => [{ key: "deepseek", status: "open", opened_at: "2026-10-09T00:00:00Z", consecutive_failures: 5, reason: "failure_threshold_exceeded" }],
  });
  agent.subscribeFallbackEvents();
  await degrade({
    layer: "L4", trigger: "breaker open", degradedOf: "provider:deepseek", traceId: "tr_sh_hc",
    label: "熔断打开", emit: async (e) => { await bus.publish("fallback.events", e, { trace_id: e.trace_id }); },
  });
  bus.subscribe("decision.replies", async () => { throw new Error("broken"); });
  await bus.publish("decision.replies", drillReply(), { trace_id: "tr_sh_hc2" });
  const health = await agent.healthcheck();
  assert.equal(health.status, "degraded", "有死信 + 开路熔断 → degraded");
  assert.equal(health.dead_letters, 1);
  assert.equal(health.fallback_events.total, 1);
  assert.equal(health.fallback_events.by_layer.L4, 1);
  assert.equal(health.circuits_observed, true);
  assert.equal(health.circuits[0]?.status, "open");
  assert.ok(health.notes.some((n) => n.includes("未配置 Trace 外发")), "未配置 Trace 必须显式注明");

  const bare = setup();
  const bareHealth = await bare.agent.healthcheck();
  assert.equal(bareHealth.circuits_observed, false);
  assert.ok(bareHealth.notes.some((n) => n.includes("未注入熔断探针")), "缺探针不得冒充健康");
});

test("A-06 drill：检测→降级→故障→重投失败→退避→恢复→重放→验证 全链路", async () => {
  const sentBatches: unknown[] = [];
  const sink = new LangfuseTraceSink({
    url: "http://127.0.0.1:3000", publicKey: "pk", secretKey: "sk",
    fetchImpl: (async (_i: string | URL | Request, init?: RequestInit) => {
      sentBatches.push(JSON.parse(String(init?.body ?? "{}")) as unknown);
      return new Response("{}", { status: 200 });
    }) as typeof fetch,
  });
  const store = new MemoryEventStore();
  let agent: SelfHealAgent;
  const bus = new EventBus({ store, maxRetries: 1, onDeadLetter: (id, reason) => agent?.noteDeadLetter(id, reason) });
  agent = new SelfHealAgent({ bus, store, traceSink: sink, backoff: { baseMs: 1000, maxMs: 60_000 } });
  agent.subscribeFallbackEvents();
  const replayed: Envelope[] = [];
  const report = await agent.drill({
    breakConsumer: () => bus.subscribe("decision.replies", async () => { throw new Error("drill broken"); }),
    fixConsumer: () => bus.subscribe("decision.replies", async (_payload, env) => { replayed.push(env as Envelope); }),
    publishDrillEvent: async () => bus.publish("decision.replies", drillReply(), { trace_id: "tr_sh_drill" }),
  });
  assert.equal(report.ok, true, "演练全链路必须通过：" + JSON.stringify(report.steps));
  assert.equal(report.steps.map((s) => s.step).join(">"),
    "detect>degrade>inject-failure>retry-fails>backoff>recover>verify");
  assert.equal(replayed.length, 1, "恢复后的消费者实际处理了重放事件");
  assert.equal(report.health.dead_letters, 0);
  assert.ok(sentBatches.length >= 1, "Trace 外发批次已产生");
  assert.equal(sink.stats().failed, 0);
  assert.ok(agent.deadLetterNotifications.length >= 1, "死信通知到达 selfheal");
});

test("A-06 Trace 外发：未配置即禁用；失败只计数不外溢", async () => {
  assert.equal(LangfuseTraceSink.fromEnv({}), null, "未配置 host/keys → null（禁静默外发）");
  const disabled = new LangfuseTraceSink({});
  assert.equal(disabled.enabled, false);
  disabled.recordFallbackEvent({ event_id: "fb_x", layer: "L1", trigger: "t", action_taken: "a", degraded_of: "d", user_visible: true, degraded_state: { label: "l", since: "2026-10-09T00:00:00Z", detail_ref: "tr" }, trace_id: "tr" });
  assert.equal((await disabled.flush()).queued, 0, "禁用态不入队");

  const failing = new LangfuseTraceSink({
    url: "http://127.0.0.1:3000/", publicKey: "pk", secretKey: "sk",
    fetchImpl: (async () => { throw new Error("transport down"); }) as typeof fetch,
  });
  failing.recordFallbackEvent({ event_id: "fb_y", layer: "L2", trigger: "t", action_taken: "a", degraded_of: "d", user_visible: true, degraded_state: { label: "l", since: "2026-10-09T00:00:00Z", detail_ref: "tr" }, trace_id: "tr" });
  const stats = await failing.flush();
  assert.equal(stats.failed, 1, "外发失败如实计数");
  assert.equal(stats.last_error, "transport");
  assert.equal(stats.queued, 0, "失败批次出队（不无限重试堆积）");
});

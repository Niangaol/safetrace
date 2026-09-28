import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus } from "../src/bus.js";
import { MemoryEventStore, SqliteEventStore } from "../src/store.js";
import { makeEnvelope } from "../src/envelope.js";
import { degrade } from "../src/degrade.js";
import { lagSeconds, parseLoose, nextId } from "../src/time.js";
import { validateInstance, assertIntelItemBasics } from "../src/schema.js";

test("envelope：默认生成 event_id/trace_id 与 UTC 时间", () => {
  const env = makeEnvelope("raw.docs", { source_id: "kev" });
  assert.ok(env.event_id.startsWith("ev_"));
  assert.ok(env.trace_id.startsWith("tr_"));
  assert.match(env.occurred_at, /^\d{4}-\d{2}-\d{2}T.*Z$/);
  assert.equal(env.schema_version, "1.0");
});

test("bus：发布-订阅-重放闭环", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const got: number[] = [];
  bus.subscribe<number>("intel.items", (p) => { got.push(p); });
  await bus.publish("intel.items", 1, { trace_id: "tr_x" });
  await bus.publish("intel.items", 2, { trace_id: "tr_x" });
  assert.deepEqual(got, [1, 2]);
  const replayed = await bus.replay<number>("intel.items");
  assert.equal(replayed, 2);
  assert.deepEqual(got, [1, 2, 1, 2]); // 重放重复投递（死信修复场景）
});

test("bus：重复 event_id 幂等去重", async () => {
  const store = new MemoryEventStore();
  const env = makeEnvelope("raw.docs", { a: 1 });
  assert.equal(await store.append(env), true);
  assert.equal(await store.append(env), false);
});

test("bus：处理失败 3 次进死信", async () => {
  const store = new MemoryEventStore();
  const dead: string[] = [];
  const bus = new EventBus({ store, maxRetries: 3, onDeadLetter: (id) => dead.push(id) });
  bus.subscribe("qa.queries", () => { throw new Error("boom"); });
  const env = await bus.publish("qa.queries", { text: "q" });
  await bus.replay("qa.queries"); // 1
  await bus.replay("qa.queries"); // 2 -> 达到 3 次
  const dls = await store.deadLetters();
  assert.equal(dls.length, 1);
  assert.equal(dls[0]!.event_id, env.event_id);
  assert.equal(dls[0]!.reason, "boom");
  assert.equal(dead.length, 1);
});

test("sqlite store：幂等 + 顺序读", async () => {
  const store = new SqliteEventStore(":memory:");
  const a = makeEnvelope("enrich.items", { n: 1 });
  const b = makeEnvelope("enrich.items", { n: 2 });
  assert.equal(await store.append(a), true);
  assert.equal(await store.append(a), false);
  assert.equal(await store.append(b), true);
  const rows = await store.read<{ n: number }>("enrich.items");
  assert.deepEqual(rows.map((r) => r.payload.n), [1, 2]);
  store.close();
});

test("degrade：必须产出 FallbackEvent 与响应标记", async () => {
  const events: unknown[] = [];
  const res = await degrade({
    layer: "L3",
    trigger: "provider 全链熔断",
    degradedOf: "cache",
    traceId: "tr_d1",
    label: "模型服务降级中，以下为缓存答案",
    emit: (e) => { events.push(e); },
  });
  assert.equal(events.length, 1);
  assert.equal(res.degraded_to, "cache");
  assert.equal(res.degraded_state.label, "模型服务降级中，以下为缓存答案");
  assert.ok(res.degraded_state.detail_ref === "tr_d1");
});

test("time：lag 口径与脏时间容忍", () => {
  assert.equal(lagSeconds("2026-09-01T00:00:00Z", "2026-09-01T02:00:00Z"), 7200);
  // 无时区按 UTC 解析（parseWarnings 由调用方登记）
  assert.equal(parseLoose("2026-09-01T00:00:00"), Date.parse("2026-09-01T00:00:00Z"));
  assert.equal(parseLoose("not-a-time"), null);
  assert.notEqual(nextId("x"), nextId("x"));
});

test("schema：运行期校验捕获缺字段/枚举/格式", () => {
  const schema = {
    type: "object",
    required: ["verdict"],
    properties: {
      verdict: { enum: ["pass", "degrade", "review", "quarantine"] },
      when: { type: "string", format: "date-time" },
    },
    additionalProperties: false,
  };
  assert.deepEqual(validateInstance({ verdict: "pass", when: "2026-09-28T10:00:00Z" }, schema), []);
  assert.ok(validateInstance({}, schema).length >= 1);
  assert.ok(validateInstance({ verdict: "maybe" }, schema).length === 1);
  assert.ok(validateInstance({ verdict: "pass", extra: 1 }, schema).some((e) => e.includes("additionalProperties")));
  assert.ok(validateInstance({ verdict: "pass", when: "昨天" }, schema).some((e) => e.includes("date-time")));
  assert.ok(assertIntelItemBasics({ intel_id: "x" }).length >= 1);
});

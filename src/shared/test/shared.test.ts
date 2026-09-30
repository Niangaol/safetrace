import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus } from "../src/bus.js";
import { MemoryEventStore, SqliteEventStore } from "../src/store.js";
import { makeEnvelope } from "../src/envelope.js";
import { degrade } from "../src/degrade.js";
import { lagSeconds, parseLoose, nextId } from "../src/time.js";
import { validateInstance, assertIntelItemBasics } from "../src/schema.js";
import { recordLineage, sha256, sha256Json } from "../src/lineage.js";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

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

test("lineage：canonical SHA-256 ignores object key order", () => {
  assert.equal(sha256Json({ b: 2, a: 1 }), sha256Json({ a: 1, b: 2 }));
  assert.notEqual(sha256Json({ a: 1 }), sha256Json({ a: 2 }));
});

test("lineage：MemoryEventStore records parent, input/output hashes and filters trace", async () => {
  const store = new MemoryEventStore();
  const parent = await recordLineage(store, {
    trace_id: "tr_lineage_a", stage: "fetch", operation_version: "ingest.fetch.v1", status: "success",
    output_refs: [{ kind: "RawDoc", id: "raw:nvd:CVE-2026-1234", sha256: sha256Json({ raw: 1 }) }],
  });
  const child = await recordLineage(store, {
    trace_id: "tr_lineage_a", parent_lineage_ids: [parent.lineage_id], causation_id: "ev_raw_1",
    stage: "parse", operation_version: "ingest.parse.nvd.v1", status: "success",
    input_refs: [{ kind: "RawDoc", id: "raw:nvd:CVE-2026-1234", sha256: sha256Json({ raw: 1 }) }],
    output_refs: [{ kind: "IntelItem", id: "intel_1", sha256: sha256Json({ title: "advisory" }) }],
    source: { source_id: "nvd_cve", url: "https://nvd.example/CVE-2026-1234" },
  });
  await recordLineage(store, { trace_id: "tr_lineage_b", stage: "retrieve", operation_version: "qa.retrieve.v1", status: "success" });
  const rows = await store.readLineage("tr_lineage_a");
  assert.deepEqual(rows.map((row) => row.lineage_id), [parent.lineage_id, child.lineage_id]);
  assert.deepEqual(rows[1]!.parent_lineage_ids, [parent.lineage_id]);
  assert.equal(rows[1]!.causation_id, "ev_raw_1");
  assert.equal(rows[1]!.output_refs[0]!.kind, "IntelItem");
  assert.ok(rows.every((row) => !("raw_text" in row)));
});

test("lineage：SQLite records survive close/reopen and remain append-only", async () => {
  const dir = join(process.cwd(), "tmp", "lineage-test-" + process.pid + "-" + Date.now());
  await mkdir(dir, { recursive: true });
  const path = join(dir, "events.sqlite");
  try {
    const store = new SqliteEventStore(path);
    const first = await recordLineage(store, {
      trace_id: "tr_persist", stage: "embed", operation_version: "q2.embed.v1", status: "success",
      execution: { provider: "vllm", model_id: "test-model", model_version: "v1" },
    });
    store.close();
    const reopened = new SqliteEventStore(path);
    const rows = await reopened.readLineage("tr_persist");
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.lineage_id, first.lineage_id);
    assert.equal(rows[0]!.execution?.model_id, "test-model");
    assert.equal(await reopened.appendLineage(rows[0]!), false, "重复 lineage_id 应幂等去重");
    reopened.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("last-good pages：SQLite persists SHA-verified snapshots and rejects stale overwrites", async () => {
  const path = join(process.cwd(), "tmp", "last-good-" + process.pid + "-" + Date.now() + ".sqlite");
  await mkdir(join(process.cwd(), "tmp"), { recursive: true });
  const text = "A verified public security page snapshot.";
  const snapshot = {
    source_url: "https://vendor.example/advisory/1",
    final_url: "https://vendor.example/advisory/1",
    title: "Security advisory",
    text,
    fetched_at: "2026-09-30T00:00:00.000Z",
    provider: "direct" as const,
    content_sha256: sha256(text),
    lineage_ids: ["ln_fetch"],
  };
  const first = new SqliteEventStore(path);
  assert.equal(await first.saveLastGoodPageSnapshot(snapshot), true);
  first.close();
  const second = new SqliteEventStore(path);
  try {
    assert.deepEqual(await second.getLastGoodPageSnapshot(snapshot.source_url), snapshot);
    assert.equal(await second.saveLastGoodPageSnapshot({ ...snapshot, fetched_at: "2026-09-29T00:00:00.000Z", text: "older" , content_sha256: sha256("older") }), false);
    assert.equal((await second.getLastGoodPageSnapshot(snapshot.source_url))?.content_sha256, snapshot.content_sha256);
    await assert.rejects(second.saveLastGoodPageSnapshot({ ...snapshot, content_sha256: "0".repeat(64) }), /invalid SHA-256/);
  } finally {
    second.close();
    for (const suffix of ["", "-wal", "-shm"]) await rm(path + suffix, { force: true });
  }
});

test("review queue：SQLite pending case 与人工决定跨重启保留", async () => {
  const path = join(process.cwd(), "tmp", "review-queue-" + process.pid + "-" + Date.now() + ".sqlite");
  await mkdir(join(process.cwd(), "tmp"), { recursive: true });
  const store = new SqliteEventStore(path);
  const review = {
    review_id: "rv_test_1",
    trace_id: "tr_review_test",
    source_url: "https://vendor.example/advisory",
    page_sha256: "a".repeat(64),
    title: "Vendor advisory",
    reason: "rules incomplete and LLM safety gate unavailable",
    lineage_id: "ln_review_case",
    created_at: "2026-09-30T00:00:00.000Z",
  };
  try {
    assert.equal(await store.enqueueReviewCase(review), true);
    assert.equal(await store.enqueueReviewCase(review), false);
    assert.equal((await store.listPendingReviewCases()).length, 1);
    assert.equal(await store.appendReviewCaseDecision({ review_id: review.review_id, trace_id: review.trace_id, action: "accepted", reviewer_id: "local-human", rationale: "verified against vendor page", lineage_id: "ln_human_decision", recorded_at: "2026-09-30T00:01:00.000Z" }), true);
  } finally {
    store.close();
  }
  const reopened = new SqliteEventStore(path);
  try {
    assert.equal((await reopened.listPendingReviewCases()).length, 0);
    const resolved = await reopened.getReviewCase(review.review_id);
    assert.equal(resolved?.status, "accepted");
    assert.equal(resolved?.reviewer_id, "local-human");
    assert.equal(resolved?.decision_lineage_id, "ln_human_decision");
  } finally {
    reopened.close();
    for (const suffix of ["", "-wal", "-shm"]) await rm(path + suffix, { force: true });
  }
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

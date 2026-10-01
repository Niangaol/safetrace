import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore, MemoryLlmContextStore } from "@safetrace/shared";
import type { FallbackEvent, LineageRecord } from "@safetrace/shared";
import { ModelGateway } from "../src/index.js";

const TASK_KEY = "qa.q1.intent";

function contextStore(): MemoryLlmContextStore {
  const store = new MemoryLlmContextStore(false);
  store.register({
    context_id: "safetrace.public.core", task_key: "*", role: "*", data_domain: "public", priority: 0,
    description: "shared public rules", source: "builtin",
    blocks: [{ block_id: "shared", position: 0, stability: "stable", content: "SHARED_STABLE_RULE_SENTINEL" }],
  });
  store.register({
    context_id: "test.q1.context", task_key: TASK_KEY, role: "planner", data_domain: "public", priority: 10,
    description: "Q1 task context", source: "operator",
    blocks: [
      { block_id: "task-rule", position: 0, stability: "stable", content: "TASK_STABLE_RULE_SENTINEL" },
      { block_id: "live-facts", position: 0, stability: "volatile", content: "VOLATILE_DB_FACTS_SENTINEL", max_age_seconds: 3600 },
    ],
  });
  return store;
}

interface Captured { messages: Array<{ role: string; content: string }> }

function stubFetch(captured: Captured[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: string, init?: { body?: unknown }) => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) as Captured : { messages: [] };
    captured.push({ messages: body.messages ?? [] });
    return new Response(JSON.stringify({ choices: [{ message: { content: "pong" } }], usage: { prompt_tokens: 3, completion_tokens: 1 } }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return () => { globalThis.fetch = original; };
}

test("Gateway injects database context as a stable system prefix before dynamic request data", async () => {
  const captured: Captured[] = [];
  const restore = stubFetch(captured);
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  try {
    const gw = new ModelGateway({ forceProvider: "deepseek", bus, contextStore: contextStore() });
    await gw.chat("planner", [{ role: "user", content: "FIRST_DYNAMIC_QUESTION" }], {}, "tr_ctx_first", "public", TASK_KEY);
    await gw.chat("planner", [{ role: "user", content: "SECOND_DYNAMIC_QUESTION" }], {}, "tr_ctx_second", "public", TASK_KEY);
  } finally {
    restore();
  }
  assert.equal(captured.length, 2, "两次调用都应真正发到 provider");
  const firstSystem = captured[0]!.messages[0]!;
  const secondSystem = captured[1]!.messages[0]!;
  assert.equal(firstSystem.role, "system");
  assert.equal(firstSystem.content, secondSystem.content, "稳定前缀在变化请求之间必须逐字节一致，才能命中 prompt-prefix 缓存");
  const system = firstSystem.content;
  assert.ok(system.includes("SHARED_STABLE_RULE_SENTINEL"));
  assert.ok(system.includes("TASK_STABLE_RULE_SENTINEL"));
  assert.ok(system.indexOf("SHARED_STABLE_RULE_SENTINEL") < system.indexOf("TASK_STABLE_RULE_SENTINEL"), "通用规则必须先于任务规则");
  assert.ok(system.indexOf("TASK_STABLE_RULE_SENTINEL") < system.indexOf("VOLATILE_DB_FACTS_SENTINEL"), "变化快的数据库事实必须排在稳定指令之后");
  assert.equal(captured[0]!.messages.at(-1)?.content, "FIRST_DYNAMIC_QUESTION");
  assert.equal(captured[1]!.messages.at(-1)?.content, "SECOND_DYNAMIC_QUESTION");
  assert.equal(captured[0]!.messages.some((message) => message.content.includes("SECOND_DYNAMIC_QUESTION")), false);
});

test("Gateway records context refs in model lineage and never stores prompt text", async () => {
  const captured: Captured[] = [];
  const restore = stubFetch(captured);
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  try {
    const gw = new ModelGateway({ forceProvider: "deepseek", bus, contextStore: contextStore() });
    await gw.chat("planner", [{ role: "user", content: "LINEAGE_DYNAMIC_SENTINEL" }], {}, "tr_ctx_lineage", "public", TASK_KEY);
  } finally {
    restore();
  }
  const rows: LineageRecord[] = await store.readLineage("tr_ctx_lineage");
  const chat = rows.find((row) => row.stage === "mg1.chat" && row.status === "success");
  assert.ok(chat, "成功调用必须有 mg1.chat lineage");
  const kinds = chat.input_refs.map((ref) => ref.kind);
  assert.ok(kinds.includes("LlmContextSet"), "lineage 必须给出关联的 context 版本");
  assert.ok(kinds.includes("LlmPromptStablePrefix"), "lineage 必须记录稳定前缀 hash");
  assert.ok(kinds.includes("LlmContextSnapshot"));
  assert.ok(chat.input_refs.some((ref) => ref.id.startsWith("test.q1.context@")));
  assert.equal(JSON.stringify(rows).includes("LINEAGE_DYNAMIC_SENTINEL"), false, "lineage 只存 hash，不复制提示词正文");
  assert.equal(JSON.stringify(rows).includes("TASK_STABLE_RULE_SENTINEL"), false, "lineage 只存 hash，不复制 ctx 正文");
});

test("Gateway fails closed and skips the provider when an explicit task context is missing", async () => {
  const captured: Captured[] = [];
  const restore = stubFetch(captured);
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  try {
    const gw = new ModelGateway({ forceProvider: "deepseek", bus, contextStore: contextStore() });
    await assert.rejects(
      () => gw.chat("planner", [{ role: "user", content: "SHOULD_NOT_LEAVE" }], {}, "tr_ctx_missing", "public", "qa.unknown.task"),
      /LLM context unavailable/,
    );
  } finally {
    restore();
  }
  assert.equal(captured.length, 0, "缺少 ctx 时禁止发起 provider 请求");
  const fallbacks = await store.read<FallbackEvent>("fallback.events");
  assert.ok(fallbacks.some((event) => event.payload.degraded_of === "llm-context:unavailable"), "必须留下用户可见的降级事件");
  const rows = await store.readLineage("tr_ctx_missing");
  const gate = rows.find((row) => row.stage === "mg1.context_gate");
  assert.equal(gate?.status, "rejected");
  assert.equal(rows.some((row) => row.stage === "mg1.chat"), false, "未解析 ctx 时不得写入模型调用 lineage");
});

test("Gateway never injects private context into a public model call", async () => {
  const captured: Captured[] = [];
  const restore = stubFetch(captured);
  const contexts = contextStore();
  contexts.register({
    context_id: "test.q1.private", task_key: TASK_KEY, role: "planner", data_domain: "private", priority: 5,
    description: "private-only task context", source: "operator",
    blocks: [{ block_id: "private-rule", position: 0, stability: "stable", content: "PRIVATE_CONTEXT_SENTINEL" }],
  });
  try {
    const gw = new ModelGateway({ forceProvider: "deepseek", contextStore: contexts });
    await gw.chat("planner", [{ role: "user", content: "PUBLIC_CALL" }], {}, "tr_ctx_public", "public", TASK_KEY);
  } finally {
    restore();
  }
  assert.equal(JSON.stringify(captured).includes("PRIVATE_CONTEXT_SENTINEL"), false, "public 调用必须过滤 private ctx");
});

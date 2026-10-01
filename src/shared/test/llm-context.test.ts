import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { assembleLlmContextMessages, MemoryLlmContextStore, SqliteLlmContextStore } from "../src/index.js";
import type { LlmContextDefinition } from "../src/index.js";

function definition(overrides: Partial<LlmContextDefinition> = {}): LlmContextDefinition {
  return {
    context_id: "test.q1.context", task_key: "qa.q1.intent", role: "planner", data_domain: "public",
    description: "test Q1 context", source: "operator",
    blocks: [{ block_id: "stable", position: 0, stability: "stable", content: "STABLE_CONTEXT_SENTINEL" }],
    ...overrides,
  };
}

test("context assembly keeps stable instructions first, volatile blocks later, and request data last", () => {
  const store = new MemoryLlmContextStore(false);
  store.register(definition({ blocks: [
    { block_id: "volatile", position: 0, stability: "volatile", content: "VOLATILE_FACTS_SENTINEL" },
    { block_id: "stable-b", position: 2, stability: "stable", content: "STABLE_B_SENTINEL" },
    { block_id: "stable-a", position: 1, stability: "stable", content: "STABLE_A_SENTINEL" },
  ] }));
  const context = store.resolve({ context_key: "qa.q1.intent", role: "planner", data_domain: "public" });
  const first = assembleLlmContextMessages([
    { role: "system", content: "TASK_SYSTEM_SENTINEL" },
    { role: "user", content: "DYNAMIC_QUERY_ONE" },
  ], context);
  const second = assembleLlmContextMessages([
    { role: "system", content: "TASK_SYSTEM_SENTINEL" },
    { role: "user", content: "DYNAMIC_QUERY_TWO" },
  ], context);
  const system = first.messages[0]?.content ?? "";
  assert.ok(system.indexOf("STABLE_A_SENTINEL") < system.indexOf("STABLE_B_SENTINEL"));
  assert.ok(system.indexOf("STABLE_B_SENTINEL") < system.indexOf("TASK_SYSTEM_SENTINEL"));
  assert.ok(system.indexOf("TASK_SYSTEM_SENTINEL") < system.indexOf("VOLATILE_FACTS_SENTINEL"));
  assert.equal(first.messages.at(-1)?.content, "DYNAMIC_QUERY_ONE");
  assert.equal(second.messages.at(-1)?.content, "DYNAMIC_QUERY_TWO");
  assert.equal(first.stable_prefix_sha256, second.stable_prefix_sha256, "stable prefix remains reusable across changing queries");
  assert.notEqual(first.prompt_sha256, second.prompt_sha256, "full-prompt response cache key changes with dynamic input");
  assert.ok(first.context_refs.some((ref) => ref.kind === "LlmPromptStablePrefix"));
});

test("context resolution never exposes private context to public model calls", () => {
  const store = new MemoryLlmContextStore(false);
  store.register(definition());
  store.register(definition({
    context_id: "test.q1.private", data_domain: "private", description: "private context",
    blocks: [{ block_id: "secret", position: 0, stability: "stable", content: "PRIVATE_CONTEXT_SENTINEL" }],
  }));
  const publicContext = store.resolve({ context_key: "qa.q1.intent", role: "planner", data_domain: "public" });
  const privateContext = store.resolve({ context_key: "qa.q1.intent", role: "planner", data_domain: "private" });
  assert.equal(publicContext.blocks.some((block) => block.content.includes("PRIVATE_CONTEXT_SENTINEL")), false);
  assert.equal(privateContext.blocks.some((block) => block.content.includes("PRIVATE_CONTEXT_SENTINEL")), true);
  assert.equal(publicContext.task_context_found, true);
});

test("volatile context expires while the active task context remains identifiable", () => {
  const store = new MemoryLlmContextStore(false);
  store.register(definition({ blocks: [{ block_id: "fresh", position: 0, stability: "volatile", content: "FRESH_SENTINEL", max_age_seconds: 1 }] }));
  const context = store.resolve({ context_key: "qa.q1.intent", role: "planner", data_domain: "public", now: new Date(Date.now() + 5000) });
  assert.equal(context.expired_block_count, 1);
  assert.equal(context.blocks.length, 0);
  assert.equal(context.task_context_found, true);
});

test("SQLite contexts persist immutable versions, active selection, and rollback", () => {
  const root = mkdtempSync(join(tmpdir(), "safetrace-llm-context-"));
  const path = join(root, "contexts.sqlite");
  const taskKey = "test.custom.task";
  let store: SqliteLlmContextStore | undefined;
  let reopened: SqliteLlmContextStore | undefined;
  try {
    store = new SqliteLlmContextStore(path);
    const first = store.register(definition({ task_key: taskKey }));
    const second = store.register(definition({ task_key: taskKey, blocks: [{ block_id: "stable", position: 0, stability: "stable", content: "NEW_STABLE_CONTEXT_SENTINEL" }] }));
    assert.equal(first.version, 1);
    assert.equal(second.version, 2);
    assert.equal(store.get("test.q1.context", 1)?.active, false);
    assert.equal(store.get("test.q1.context")?.version, 2);
    store.activate("test.q1.context", 1);
    store.close();
    store = undefined;

    reopened = new SqliteLlmContextStore(path);
    const active = reopened.resolve({ context_key: taskKey, role: "planner", data_domain: "public" });
    assert.equal(reopened.get("test.q1.context")?.version, 1);
    assert.ok(active.blocks.some((block) => block.content.includes("STABLE_CONTEXT_SENTINEL")));
    assert.equal(active.blocks.some((block) => block.content.includes("NEW_STABLE_CONTEXT_SENTINEL")), false);
    assert.equal(active.task_context_found, true);
    reopened.deactivate("test.q1.context");
    assert.equal(reopened.resolve({ context_key: taskKey, role: "planner", data_domain: "public" }).task_context_found, false);
  } finally {
    reopened?.close();
    store?.close();
    rmSync(root, { recursive: true, force: true });
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { loadModelsConfig } from "../src/profiles.js";
import { ModelGateway } from "../src/index.js";
import { EventBus, MemoryEventStore } from "@safetrace/shared";

test("real profile is explicitly selectable and default embedder remains cache", () => {
  assert.equal(loadModelsConfig("config/models.yml").roles.embedder.provider, "cache");
  const live = loadModelsConfig("config/models.tokendance.yml");
  assert.equal(live.roles.embedder.provider, "tokendance");
  assert.equal(live.roles.embedder.model_id, "qwen3.7-text-embedding");
  assert.equal(live.roles.embedder.capability_flags.dim, 1024);
  assert.equal(live.providers.tokendance?.api_key_env, "TOKENDANCE_API_KEY");
  assert.equal(live.roles.embedder.model_version, "unversioned-api");
});

test("MG1 real-profile protocol and lineage tested with injected response, not a cloud call", async () => {
  const original = globalThis.fetch;
  const previousKey = process.env.TOKENDANCE_API_KEY;
  const previousBase = process.env.TOKENDANCE_BASE_URL;
  process.env.TOKENDANCE_API_KEY = "test-only-not-a-real-secret";
  process.env.TOKENDANCE_BASE_URL = "https://tokendance.space/gateway/v1";
  const store = new MemoryEventStore(); const bus = new EventBus({ store });
  let calls = 0;
  globalThis.fetch = (async (input, init) => {
    calls++;
    assert.equal(String(input), "https://tokendance.space/gateway/v1/embeddings");
    assert.equal(init?.redirect, "error");
    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, "qwen3.7-text-embedding");
    return new Response(JSON.stringify({ model: body.model, data: [{ index: 0, embedding: Array.from({ length: 1024 }, (_, i) => i === 0 ? 0.5 : 0) }] }), { status: 200 });
  }) as typeof fetch;
  try {
    const gateway = new ModelGateway({ configPath: "config/models.tokendance.yml", bus });
    const result = await gateway.embed("embedder", ["synthetic protocol test"], "tr_profile_test");
    assert.equal(calls, 1);
    assert.equal(result.provider, "tokendance");
    assert.equal(result.vectors[0]?.length, 1024);
    assert.equal(result.degraded_to, "");
    const rows = await bus.readLineage("tr_profile_test");
    assert.ok(rows.some(r => r.stage === "mg1.embed" && r.status === "success" && r.execution?.provider === "tokendance"));
    assert.ok(!JSON.stringify(rows).includes("test-only-not-a-real-secret"));
    assert.ok(!JSON.stringify(rows).includes("synthetic protocol test"));
  } finally {
    globalThis.fetch = original;
    if (previousKey === undefined) delete process.env.TOKENDANCE_API_KEY; else process.env.TOKENDANCE_API_KEY = previousKey;
    if (previousBase === undefined) delete process.env.TOKENDANCE_BASE_URL; else process.env.TOKENDANCE_BASE_URL = previousBase;
  }
});

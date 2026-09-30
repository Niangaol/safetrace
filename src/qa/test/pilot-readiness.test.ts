import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPilotReadiness } from "../src/pilot-readiness.js";
import type { PilotReadinessOptions } from "../src/pilot-readiness.js";

function options(): PilotReadinessOptions {
  return { qdrant_url: "http://127.0.0.1:6333", collection: "sources", embedding_url: "http://127.0.0.1:8000/v1", profile: { provider: "vllm", model_id: "bge-m3", model_version: "v1", dimension: 1024 } };
}
function response(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status }); }

test("doctor only uses local GET endpoints, never claims actual inference", async () => {
  const o = options(); const calls: string[] = [];
  o.fetch_impl = (async (input, init) => {
    const url = String(input); calls.push(url);
    assert.equal(init?.method, "GET"); assert.equal(init?.redirect, "error");
    assert.equal(init?.headers, undefined, "no credentials sent");
    if (url.endsWith("/models")) return response({ data: [{ id: "bge-m3" }] });
    if (url.endsWith("/collections")) return response({ result: { collections: [] } });
    return response({}, 404);
  }) as typeof fetch;
  const result = await checkPilotReadiness(o);
  assert.equal(result.prerequisites_ready, true);
  assert.equal(result.embedding_inference_verified, false);
  assert.equal(result.vector_persistence_verified, false);
  assert.equal(calls.length, 3);
});

test("doctor refuses remote, credential and query-bearing URLs without probing", async () => {
  for (const url of ["https://cloud.example/v1", "http://user:secret@localhost:8000/v1", "http://localhost:8000/v1?api_key=secret"]) {
    let calls = 0;
    const o = { ...options(), qdrant_url: url, embedding_url: url, fetch_impl: (async () => { calls++; throw new Error("must not probe"); }) as typeof fetch };
    const result = await checkPilotReadiness(o);
    assert.equal(result.prerequisites_ready, false); assert.equal(calls, 0);
    assert.ok(!JSON.stringify(result).includes("secret"));
  }
});

test("doctor cache configuration and incompatible collection remain unready", async () => {
  const o = options();
  o.fetch_impl = (async input => String(input).endsWith("/collections") ? response({ result: { collections: [] } }) : String(input).endsWith("/models") ? response({ data: [{ id: "bge-m3" }] }) : response({ result: { config: { params: { vectors: { dense: { size: 256, distance: "Cosine" } } } } } })) as typeof fetch;
  const mismatch = await checkPilotReadiness(o);
  assert.equal(mismatch.prerequisites_ready, false);
  assert.ok(mismatch.checks.some(c => c.name === "collection" && c.status === "missing"));
  o.profile = { provider: "cache", model_id: "hash-256", model_version: "v0", dimension: 256 };
  const cache = await checkPilotReadiness(o);
  assert.equal(cache.prerequisites_ready, false);
  assert.ok(cache.checks.some(c => c.name === "embedding_service" && c.status === "skipped"));
});

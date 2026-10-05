import { test } from "node:test";
import assert from "node:assert/strict";
import { ModelGateway } from "../src/index.js";

test("Gateway fetchImpl is used for chat and embedding, isolated per gateway", async () => {
  const requests: Array<{ url: string; body: Record<string, unknown>; signal: AbortSignal | null | undefined }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    requests.push({ url: String(input), body, signal: init?.signal });
    assert.equal(init?.redirect, "error");
    const response = String(input).endsWith("/embeddings")
      ? { data: [{ index: 0, embedding: new Array(256).fill(0.1) }] }
      : { choices: [{ message: { content: "injected success" } }], usage: { prompt_tokens: 3, completion_tokens: 2 } };
    return new Response(JSON.stringify(response), { status: 200 });
  };
  const gateway = new ModelGateway({ forceProvider: "deepseek", fetchImpl });
  const reply = await gateway.chat("answerer", [{ role: "user", content: "test" }]);
  const vectors = await gateway.embed("embedder", ["test"]);
  assert.equal(reply.provider, "deepseek");
  assert.equal(reply.text, "injected success");
  assert.equal(vectors.provider, "deepseek");
  assert.equal(vectors.vectors[0]!.length, 256);
  assert.equal(requests.length, 2);
  assert.ok(requests[0]!.url.endsWith("/chat/completions"));
  assert.ok(requests[1]!.url.endsWith("/embeddings"));
  assert.deepEqual(requests[1]!.body.input, ["test"]);
  assert.ok(requests.every((request) => request.signal instanceof AbortSignal));
  let failures = 0;
  const other = new ModelGateway({ forceProvider: "deepseek", fetchImpl: async () => { failures++; throw new Error("separate transport"); } });
  const degraded = await other.chat("answerer", [{ role: "user", content: "test" }]);
  assert.equal(degraded.provider, "cache");
  assert.equal(failures, 1);
  assert.equal(requests.length, 2, "one gateway must not mutate another gateway's fetch");
});

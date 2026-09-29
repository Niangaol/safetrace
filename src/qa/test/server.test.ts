import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createServer } from "../src/server.js";
import { MemoryIndex, readFixtureChunks } from "../src/q2-retrieval.js";

let server: Server;
let base: string;

before(async () => {
  const engine = new MemoryIndex();
  engine.upsert(readFixtureChunks());
  server = createServer(engine);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  base = "http://127.0.0.1:" + addr.port;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

test("GET /healthz → {status:ok} 且无降级标记", async () => {
  const res = await fetch(base + "/healthz");
  assert.equal(res.status, 200);
  const body = (await res.json()) as { status: string; degraded_to?: string };
  assert.equal(body.status, "ok");
  assert.equal(body.degraded_to, undefined);
});

test("POST /v1/retrieve → RetrievalResponse 契约形状", async () => {
  const res = await fetch(base + "/v1/retrieve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      query_id: "q_http",
      query_text: "Log4Shell 影响哪些版本？",
      top_k: 3,
      trace_id: "tr_http",
      schema_version: "1.0",
    }),
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as {
    query_id: string;
    chunks: Array<{ chunk_id: string; doc_type: string; text: string; score_dense?: number; score_sparse?: number; score_rerank?: number; provenance: { url: string; section: string } }>;
    retrieval_ms: number;
    embedder_model_id: string;
    trace_id: string;
    schema_version: string;
    degraded_to?: string;
  };
  assert.equal(body.query_id, "q_http");
  assert.equal(body.chunks.length, 3);
  for (const c of body.chunks) {
    assert.ok(c.chunk_id.length > 0);
    assert.ok(c.text.length > 0);
    assert.ok(typeof c.score_sparse === "number" || typeof c.score_dense === "number" || typeof c.score_rerank === "number");
    assert.match(c.provenance.url, /^https:\/\//);
    assert.ok(c.provenance.section.length > 0);
  }
  assert.equal(body.embedder_model_id, "bm25-lite-v1");
  assert.ok(Number.isInteger(body.retrieval_ms) && body.retrieval_ms >= 0);
  assert.equal(body.trace_id, "tr_http");
  assert.equal(body.schema_version, "1.0");
  assert.equal(body.degraded_to, undefined);
});

test("POST /v1/retrieve：非法请求体 → 400 + errors", async () => {
  const res = await fetch(base + "/v1/retrieve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query_text: "x" }),
  });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error: string; errors: string[] };
  assert.equal(body.error, "invalid_request");
  assert.ok(Array.isArray(body.errors) && body.errors.length >= 1);
});

test("POST /v1/retrieve：doc_types 非法枚举 → 400", async () => {
  const res = await fetch(base + "/v1/retrieve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      query_id: "q_bad",
      query_text: "Log4Shell",
      top_k: 3,
      doc_types: ["not_a_doc_type"],
      trace_id: "tr_bad",
      schema_version: "1.0",
    }),
  });
  assert.equal(res.status, 400);
});

test("POST /v1/retrieve：非 JSON / 空体 → 400；未知路由 → 404", async () => {
  const notJson = await fetch(base + "/v1/retrieve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "not-json",
  });
  assert.equal(notJson.status, 400);

  const empty = await fetch(base + "/v1/retrieve", { method: "POST" });
  assert.equal(empty.status, 400);

  const notFound = await fetch(base + "/nope");
  assert.equal(notFound.status, 404);
});

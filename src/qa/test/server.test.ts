import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore, sha256, SqliteEventStore } from "@safetrace/shared";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { createServer, startServer } from "../src/server.js";
import { MemoryIndex, readFixtureChunks } from "../src/q2-retrieval.js";

let server: Server;
let base: string;
let store: MemoryEventStore;
let bus: EventBus;

before(async () => {
  store = new MemoryEventStore();
  bus = new EventBus({ store });
  const engine = new MemoryIndex({ bus });
  await engine.upsert(readFixtureChunks(), { trace_id: "tr_http_seed" });
  server = createServer(engine, bus);
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
  const lineage = await bus.readLineage("tr_http");
  const validation = lineage.find((record) => record.stage === "qa.http_validate");
  const retrieval = lineage.find((record) => record.stage === "q2.bm25_search");
  const responseRecord = lineage.find((record) => record.stage === "qa.http_response");
  assert.ok(validation && retrieval && responseRecord);
  assert.ok(retrieval.parent_lineage_ids.includes(validation.lineage_id));
  assert.ok(responseRecord.parent_lineage_ids.includes(retrieval.lineage_id));
  assert.ok(!JSON.stringify(lineage).includes("Log4Shell 影响哪些版本"), "lineage stores query hashes, not raw query text");

});

test("startServer：请求/检索/响应 lineage 在 SQLite 重启后仍可查询", async () => {
  const dbPath = join(process.cwd(), "tmp", "server-lineage-" + process.pid + "-" + Date.now() + ".sqlite");
  await mkdir(join(process.cwd(), "tmp"), { recursive: true });
  const oldSqlite = process.env.SQLITE_PATH;
  const oldQdrant = process.env.QDRANT_URL;
  const oldOffline = process.env.OFFLINE_FIXTURES;
  process.env.SQLITE_PATH = dbPath;
  delete process.env.QDRANT_URL;
  process.env.OFFLINE_FIXTURES = "true";
  let persistent: SqliteEventStore | undefined;
  let app: Server | undefined;
  try {
    app = await startServer({ port: 0 });
    const addr = app.address() as AddressInfo;
    const response = await fetch("http://127.0.0.1:" + addr.port + "/v1/retrieve", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ query_id: "q_persist", query_text: "Log4Shell 影响哪些版本？", top_k: 3, trace_id: "tr_persist", schema_version: "1.0" }),
    });
    assert.equal(response.status, 200);
    await new Promise<void>((resolve) => app!.close(() => resolve()));
    app = undefined;
    persistent = new SqliteEventStore(dbPath);
    const records = await persistent.readLineage("tr_persist");
    assert.ok(records.some((record) => record.stage === "qa.http_validate"));
    assert.ok(records.some((record) => record.stage === "q2.bm25_search"));
    assert.ok(records.some((record) => record.stage === "qa.http_response"));
  } finally {
    if (app) await new Promise<void>((resolve) => app!.close(() => resolve()));
    persistent?.close();
    if (oldSqlite === undefined) delete process.env.SQLITE_PATH;
    else process.env.SQLITE_PATH = oldSqlite;
    if (oldQdrant === undefined) delete process.env.QDRANT_URL;
    else process.env.QDRANT_URL = oldQdrant;
    if (oldOffline === undefined) delete process.env.OFFLINE_FIXTURES;
    else process.env.OFFLINE_FIXTURES = oldOffline;
    for (const suffix of ["", "-wal", "-shm"]) await rm(dbPath + suffix, { force: true });
  }
});

test("POST /v1/retrieve：非法请求体 → 400 + errors", async () => {
  const invalidBody = JSON.stringify({ query_text: "x" });
  const res = await fetch(base + "/v1/retrieve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: invalidBody,
  });
  assert.equal(res.status, 400);
  const body = (await res.json()) as { error: string; errors: string[] };
  assert.equal(body.error, "invalid_request");
  assert.ok(Array.isArray(body.errors) && body.errors.length >= 1);
  const rejectedTrace = "tr_rejected_" + sha256(invalidBody).slice(0, 16);
  const rejectedLineage = await bus.readLineage(rejectedTrace);
  assert.ok(rejectedLineage.some((record) => record.stage === "qa.http_validate" && record.status === "rejected"));
  assert.ok(!JSON.stringify(rejectedLineage).includes("query_text"));
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

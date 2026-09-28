import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { EvidenceChunk, RetrievalRequest } from "@safetrace/shared";
import {
  MemoryIndex,
  QdrantEngine,
  indexChunks,
  readFixtureChunks,
} from "../src/q2-retrieval.js";

function seedIndex(): MemoryIndex {
  const idx = new MemoryIndex();
  idx.upsert(readFixtureChunks());
  return idx;
}

function req(over: Partial<RetrievalRequest> = {}): RetrievalRequest {
  return {
    query_id: "q_t",
    query_text: "Log4Shell 影响哪些版本？",
    top_k: 3,
    trace_id: "tr_t",
    schema_version: "1.0",
    ...over,
  };
}

/** 低质量脏 chunk（模拟 DQ1 未通过的转述），用于 min_quality 过滤验证。 */
const DIRTY_CHUNK: EvidenceChunk = {
  chunk_id: "chunk_dirty_lowq_log4shell",
  doc_type: "vuln_advisory",
  text: "Log4Shell 影响版本 修复 的未校验二手转述，未经 DQ1 质量门。",
  quality_score: 0.3,
  provenance: { url: "https://example.com/unverified-log4shell", section: "body" },
};

test("readFixtureChunks：种子覆盖 CVE-2021-44228 的多类型 chunk 与 NVD provenance", () => {
  const chunks = readFixtureChunks();
  assert.ok(chunks.length >= 5);
  assert.ok(chunks.some((c) => c.doc_type === "vuln_advisory" && c.text.includes("CVE-2021-44228")));
  assert.ok(chunks.some((c) => c.doc_type === "enrichment"));
  assert.ok(chunks.some((c) => c.doc_type === "paper"));
  assert.ok(chunks.some((c) => c.provenance.url === "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
  for (const c of chunks) {
    assert.ok(c.chunk_id.length > 0);
    assert.ok(c.text.length > 0);
    assert.match(c.provenance.url, /^https:\/\//);
    assert.ok(typeof c.provenance.sha256 === "string" && c.provenance.sha256.length === 64);
    assert.ok(typeof c.quality_score === "number");
  }
});

test("MemoryIndex：recall@3 命中 Log4Shell 文档且分数归一降序", async () => {
  const idx = seedIndex();
  const res = await idx.search(req({}));
  assert.equal(res.chunks.length, 3);
  for (const c of res.chunks) {
    assert.ok(/Log4Shell|CVE-2021-44228/.test(c.text), "top3 应全部命中 Log4Shell 文档");
    assert.ok(typeof c.score_rerank === "number" && c.score_rerank > 0);
  }
  assert.ok(
    res.chunks.some((c) => c.chunk_id === "chunk_nvd_cve_2021_44228_desc"),
    "NVD 漏洞通告应进入 top3",
  );
  assert.ok(res.chunks.some((c) => c.doc_type === "vuln_advisory"));
  const scores = res.chunks.map((c) => c.score_rerank ?? 0);
  assert.ok(Math.abs(scores[0]! - 1) < 1e-9, "榜首归一为 1");
  for (let i = 1; i < scores.length; i += 1) assert.ok(scores[i]! <= scores[i - 1]!);
  assert.equal(res.embedder_model_id, "hash-256");
  assert.ok(Number.isInteger(res.retrieval_ms) && res.retrieval_ms >= 0);
  assert.equal(res.trace_id, "tr_t");
  // 确定性：重复检索顺序一致
  const again = await idx.search(req({}));
  assert.deepEqual(again.chunks.map((c) => c.chunk_id), res.chunks.map((c) => c.chunk_id));
});

test("MemoryIndex：min_quality 过滤生效（脏 chunk 不过关）", async () => {
  const idx = seedIndex();
  idx.upsert([DIRTY_CHUNK]);
  const unfiltered = await idx.search(req({ query_text: "Log4Shell 影响版本 修复" }));
  assert.ok(unfiltered.chunks.some((c) => c.chunk_id === DIRTY_CHUNK.chunk_id), "无过滤时应可见");
  const filtered = await idx.search(req({ query_text: "Log4Shell 影响版本 修复", min_quality: 0.7 }));
  assert.ok(!filtered.chunks.some((c) => c.chunk_id === DIRTY_CHUNK.chunk_id), "min_quality=0.7 应滤掉 0.3 脏 chunk");
  assert.ok(filtered.chunks.every((c) => (c.quality_score ?? 0) >= 0.7));
  assert.ok(filtered.chunks.length > 0, "干净种子 chunk 应保留");
});

test("MemoryIndex：doc_types / cve_ids 过滤", async () => {
  const idx = seedIndex();
  const onlyPaper = await idx.search(req({ query_text: "Log4Shell 论文", doc_types: ["paper"] }));
  assert.ok(onlyPaper.chunks.length > 0);
  assert.ok(onlyPaper.chunks.every((c) => c.doc_type === "paper"));
  const byCve = await idx.search(req({ query_text: "Log4Shell", cve_ids: ["CVE-2021-44228"] }));
  assert.ok(byCve.chunks.length > 0);
  assert.ok(byCve.chunks.every((c) => c.text.includes("CVE-2021-44228")));
});

test("MemoryIndex：无答案问题 → 空结果（abstain 链路上游）", async () => {
  const idx = seedIndex();
  const res = await idx.search(
    req({ query_text: "CVE-2099-4321 应该怎么修复？", cve_ids: ["CVE-2099-4321"] }),
  );
  assert.deepEqual(res.chunks, []);
  assert.equal(res.degraded_to, undefined, "正常路径不得出现降级标记");
});

test("QdrantEngine：URL 未配 → degrade 到 MemoryIndex（degraded_to=memory_index + FallbackEvent）", async () => {
  const savedUrl = process.env.QDRANT_URL;
  const savedOffline = process.env.OFFLINE_FIXTURES;
  delete process.env.QDRANT_URL;
  delete process.env.OFFLINE_FIXTURES;
  try {
    const store = new MemoryEventStore();
    const bus = new EventBus({ store });
    const engine = new QdrantEngine({ bus });
    const res = await engine.search(req({}));
    assert.equal(res.degraded_to, "memory_index");
    assert.ok(res.chunks.length > 0, "降级后仍应有 fixtures 种子结果");
    const events = await store.read<{ layer: string; degraded_of: string; user_visible: boolean }>("fallback.events");
    assert.equal(events.length, 1);
    assert.equal(events[0]!.payload.layer, "L3");
    assert.equal(events[0]!.payload.degraded_of, "memory_index");
    assert.equal(events[0]!.payload.user_visible, true);
    assert.equal(engine.lastDegradedTo, "memory_index");
  } finally {
    if (savedUrl !== undefined) process.env.QDRANT_URL = savedUrl;
    if (savedOffline !== undefined) process.env.OFFLINE_FIXTURES = savedOffline;
  }
});

test("QdrantEngine：OFFLINE_FIXTURES=true → fixture 回放（degraded_to=fixture，绝不发外网请求）", async () => {
  const savedUrl = process.env.QDRANT_URL;
  const savedOffline = process.env.OFFLINE_FIXTURES;
  process.env.OFFLINE_FIXTURES = "true";
  const explodingFetch = ((): Promise<Response> => {
    throw new Error("离线模式不应发起外网请求");
  }) as unknown as typeof fetch;
  try {
    const engine = new QdrantEngine({ url: "http://127.0.0.1:6333", fetch_impl: explodingFetch });
    const res = await engine.search(req({}));
    assert.equal(res.degraded_to, "fixture");
    assert.ok(res.chunks.length > 0);
    assert.ok(res.chunks.some((c) => c.chunk_id === "chunk_nvd_cve_2021_44228_desc"));
  } finally {
    if (savedUrl !== undefined) process.env.QDRANT_URL = savedUrl;
    else delete process.env.QDRANT_URL;
    if (savedOffline !== undefined) process.env.OFFLINE_FIXTURES = savedOffline;
    else delete process.env.OFFLINE_FIXTURES;
  }
});

test("QdrantEngine：fetch 失败 → degrade 到 MemoryIndex", async () => {
  const savedUrl = process.env.QDRANT_URL;
  const savedOffline = process.env.OFFLINE_FIXTURES;
  delete process.env.QDRANT_URL;
  delete process.env.OFFLINE_FIXTURES;
  const failingFetch = ((): Promise<Response> => {
    throw new Error("connect ECONNREFUSED 127.0.0.1:6333");
  }) as unknown as typeof fetch;
  try {
    const engine = new QdrantEngine({ url: "http://127.0.0.1:6333", fetch_impl: failingFetch });
    const res = await engine.search(req({}));
    assert.equal(res.degraded_to, "memory_index");
    assert.ok(res.chunks.length > 0);
  } finally {
    if (savedUrl !== undefined) process.env.QDRANT_URL = savedUrl;
    if (savedOffline !== undefined) process.env.OFFLINE_FIXTURES = savedOffline;
  }
});

test("QdrantEngine：正常路径打 REST（POST .../points/search，named vector dense）", async () => {
  const savedUrl = process.env.QDRANT_URL;
  const savedOffline = process.env.OFFLINE_FIXTURES;
  delete process.env.QDRANT_URL;
  delete process.env.OFFLINE_FIXTURES;
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  const stubFetch = (async (input: string, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null });
    return new Response(
      JSON.stringify({
        result: [
          {
            id: 1,
            score: 0.87,
            payload: {
              chunk_id: "chunk_qdrant_1",
              doc_type: "vuln_advisory",
              text: "CVE-2021-44228 Log4Shell Qdrant 回放 chunk",
              quality_score: 0.9,
              provenance: { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", section: "description" },
              cve_ids: ["CVE-2021-44228"],
            },
          },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
  try {
    const engine = new QdrantEngine({ url: "http://127.0.0.1:6333", collection: "c1", fetch_impl: stubFetch });
    const res = await engine.search(req({ query_text: "Log4Shell", top_k: 3 }));
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "http://127.0.0.1:6333/collections/c1/points/search");
    assert.equal(calls[0]!.method, "POST");
    const body = calls[0]!.body as { vector: { name: string }; limit: number; with_payload: boolean };
    assert.equal(body.vector.name, "dense");
    assert.equal(body.limit, 3);
    assert.equal(body.with_payload, true);
    assert.equal(res.chunks.length, 1);
    assert.equal(res.chunks[0]!.chunk_id, "chunk_qdrant_1");
    assert.ok((res.chunks[0]!.score_rerank ?? 0) > 0);
    assert.equal(res.degraded_to, undefined, "正常路径不得出现降级标记");
  } finally {
    if (savedUrl !== undefined) process.env.QDRANT_URL = savedUrl;
    if (savedOffline !== undefined) process.env.OFFLINE_FIXTURES = savedOffline;
  }
});

test("indexChunks：S3 绑定登记 + 模型冲突抛错（禁止静默混用）", async () => {
  const idx = new MemoryIndex();
  const meta = await indexChunks(idx, readFixtureChunks(), {
    collection_name: "c_p0",
    model_id: "hash-256",
    dim: 256,
    metric: "cosine",
  });
  assert.equal(meta.collection_name, "c_p0");
  assert.deepEqual(idx.boundCollections().map((m) => m.collection_name), ["c_p0"]);
  assert.equal(idx.size, readFixtureChunks().length);
  await assert.rejects(
    indexChunks(new MemoryIndex({ model_id: "other-64" }), [], {
      collection_name: "c_x",
      model_id: "hash-256",
      dim: 256,
      metric: "cosine",
    }),
    /绑定冲突/,
  );
});

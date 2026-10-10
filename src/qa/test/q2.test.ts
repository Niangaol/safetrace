import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { EvidenceChunk, RetrievalRequest } from "@safetrace/shared";
import {
  MemoryIndex,
  QdrantEngine,
  fuseHybrid,
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
    assert.ok(typeof c.score_sparse === "number" && c.score_sparse > 0);
  }
  assert.ok(
    res.chunks.some((c) => c.chunk_id === "chunk_nvd_cve_2021_44228_desc"),
    "NVD 漏洞通告应进入 top3",
  );
  assert.ok(res.chunks.some((c) => c.doc_type === "vuln_advisory"));
  const scores = res.chunks.map((c) => c.score_sparse ?? 0);
  assert.ok(Math.abs(scores[0]! - 1) < 1e-9, "榜首归一为 1");
  for (let i = 1; i < scores.length; i += 1) assert.ok(scores[i]! <= scores[i - 1]!);
  assert.equal(res.embedder_model_id, "bm25-lite-v1");
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

test("MemoryIndex：published_after 时效过滤真实生效（A-05）", async () => {
  const idx = new MemoryIndex();
  const base = {
    doc_type: "vuln_advisory",
    text: "Log4Shell 影响版本 修复 CVE-2021-4428",
    provenance: { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", section: "body" },
  } as const;
  await idx.upsert([
    { ...base, chunk_id: "chunk_time_fresh", published_at: "2026-09-01T00:00:00.000Z" },
    { ...base, chunk_id: "chunk_time_stale", published_at: "2021-12-10T00:00:00.000Z" },
    { ...base, chunk_id: "chunk_time_unknown" }, // 无 published_at = 时效未知
  ]);
  const fresh = await idx.search(req({ published_after: "2026-01-01T00:00:00Z" }));
  assert.deepEqual(fresh.chunks.map((c) => c.chunk_id), ["chunk_time_fresh"], "只有窗口内的新鲜 chunk 应召回");
  const wide = await idx.search(req({ published_after: "2020-01-01T00:00:00Z" }));
  assert.ok(wide.chunks.some((c) => c.chunk_id === "chunk_time_stale"), "窗口足够宽时旧 chunk 应召回");
  assert.ok(!wide.chunks.some((c) => c.chunk_id === "chunk_time_unknown"), "时效未知按最不新鲜处理：时间窗内一律滤除");
  const future = await idx.search(req({ published_after: "2027-01-01T00:00:00Z" }));
  assert.deepEqual(future.chunks, [], "窗口在未来 → 空结果（abstain 链路上游）");
  const unfiltered = await idx.search(req({}));
  assert.equal(unfiltered.chunks.length, 3, "未指定 published_after 时不做时效过滤（兼容既有行为）");
});

test("MemoryIndex：published_after 不可解析 → 抛错（A-05 fail-closed，不静默放过）", async () => {
  const idx = seedIndex();
  await assert.rejects(idx.search(req({ published_after: "昨天" })), /published_after/);
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
    const engine = new QdrantEngine({
      url: "http://127.0.0.1:6333",
      model_id: "test-embed-v1",
      embedding_dim: 2,
      embedder: async (texts) => ({ vectors: texts.map(() => [1, 0]), model_id: "test-embed-v1", provider: "vllm", degraded_to: "" }),
      fetch_impl: failingFetch,
    });
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
              provenance: { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", section: "description", page: 3, sha256: "a".repeat(64) },
              cve_ids: ["CVE-2021-44228"],
            },
          },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
  try {
    const engine = new QdrantEngine({
      url: "http://127.0.0.1:6333",
      collection: "configured_elsewhere",
      model_id: "test-embed-v1",
      embedding_dim: 2,
      embedder: async (texts) => ({ vectors: texts.map(() => [0.25, 0.75]), model_id: "test-embed-v1", provider: "vllm", degraded_to: "" }),
      fetch_impl: stubFetch,
    });
    engine.bindCollection({ collection_name: "c1", model_id: "test-embed-v1", dim: 2, metric: "cosine" });
    const res = await engine.search(req({ query_text: "Log4Shell", top_k: 3 }));
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "http://127.0.0.1:6333/collections/c1/points/search");
    assert.equal(calls[0]!.method, "POST");
    const body = calls[0]!.body as { vector: { name: string; vector: number[] }; limit: number; with_payload: boolean; filter: { must: Array<{ key: string }> } };
    assert.equal(body.vector.name, "dense");
    assert.deepEqual(body.vector.vector, [0.25, 0.75]);
    assert.ok(body.filter.must.some((clause) => clause.key === "embedding_model_id"));
    assert.equal(body.limit, 3);
    assert.equal(body.with_payload, true);
    assert.equal(res.chunks.length, 1);
    assert.equal(res.chunks[0]!.chunk_id, "chunk_qdrant_1");
    assert.equal(res.chunks[0]!.provenance.page, 3);
    assert.equal(res.chunks[0]!.provenance.sha256, "a".repeat(64));
    assert.ok((res.chunks[0]!.score_dense ?? 0) > 0);
    assert.equal(res.degraded_to, undefined, "正常路径不得出现降级标记");
  } finally {
    if (savedUrl !== undefined) process.env.QDRANT_URL = savedUrl;
    if (savedOffline !== undefined) process.env.OFFLINE_FIXTURES = savedOffline;
  }
});


test("QdrantEngine：cache embedding 不写假向量，查询显式降级为 BM25", async () => {
  const savedOffline = process.env.OFFLINE_FIXTURES;
  delete process.env.OFFLINE_FIXTURES;
  let requests = 0;
  const fetchImpl = (async (): Promise<Response> => {
    requests += 1;
    return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200 });
  }) as unknown as typeof fetch;
  try {
    const engine = new QdrantEngine({
      url: "http://127.0.0.1:6333",
      model_id: "hash-256",
      embedding_dim: 256,
      embedder: async (texts) => ({ vectors: texts.map(() => new Array(256).fill(0)), model_id: "hash-256", provider: "cache", degraded_to: "" }),
      fetch_impl: fetchImpl,
    });
    const res = await engine.search(req({}));
    assert.equal(res.degraded_to, "memory_index");
    assert.ok(res.chunks.length > 0);
    assert.equal(requests, 0, "cache hash 不得请求语义 Qdrant 集合");
  } finally {
    if (savedOffline !== undefined) process.env.OFFLINE_FIXTURES = savedOffline;
    else delete process.env.OFFLINE_FIXTURES;
  }
});

test("QdrantEngine：hash-256 ID 即使伪报 provider 也不能写入", async () => {
  let requests = 0;
  const fetchImpl = (async () => { requests += 1; return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200 }); }) as unknown as typeof fetch;
  const engine = new QdrantEngine({
    url: "http://127.0.0.1:6333",
    model_id: "hash-256",
    embedding_dim: 256,
    embedder: async (texts) => ({ vectors: texts.map(() => new Array(256).fill(0.1)), model_id: "hash-256", provider: "vllm", degraded_to: "" }),
    fetch_impl: fetchImpl,
  });
  await assert.rejects(engine.upsert([DIRTY_CHUNK]), /hash-256/);
  assert.equal(requests, 0);
});

test("QdrantEngine：upsert 使用 MG1 原向量并写入 model_id", async () => {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  const fetchImpl = (async (input: string, init?: RequestInit): Promise<Response> => {
    calls.push({ url: input, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null });
    return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const chunk: EvidenceChunk = { ...DIRTY_CHUNK, chunk_id: "chunk_embed_upsert" };
  const engine = new QdrantEngine({
    url: "http://127.0.0.1:6333",
    collection: "c_embed",
    model_id: "bge-m3",
    model_version: "v2026.09",
    embedding_dim: 2,
    embedder: async (texts) => ({ vectors: texts.map(() => [0.1, 0.9]), model_id: "bge-m3", model_version: "v2026.09", provider: "vllm", degraded_to: "" }),
    fetch_impl: fetchImpl,
  });
  engine.bindCollection({ collection_name: "c_embed", model_id: "bge-m3", model_version: "v2026.09", dim: 2, metric: "cosine" });
  await engine.upsert([chunk]);
  assert.equal(calls.length, 2);
  const points = calls[1]!.body as { points: Array<{ vector: { dense: number[] }; payload: { embedding_model_id: string; embedding_model_version?: string } }> };
  assert.deepEqual(points.points[0]!.vector.dense, [0.1, 0.9]);
  assert.equal(points.points[0]!.payload.embedding_model_id, "bge-m3");
  assert.equal(points.points[0]!.payload.embedding_model_version, "v2026.09");
});

test("QdrantEngine：BM25 和 dense 以 RRF 融合并分别保留分数", () => {
  const dense = [{ ...DIRTY_CHUNK, chunk_id: "shared", score_dense: 0.8 }, { ...DIRTY_CHUNK, chunk_id: "dense-only", score_dense: 0.7 }];
  const sparse = [{ ...DIRTY_CHUNK, chunk_id: "shared", score_sparse: 1 }, { ...DIRTY_CHUNK, chunk_id: "sparse-only", score_sparse: 0.7 }];
  const fused = fuseHybrid(dense, sparse, 3);
  assert.equal(fused.length, 3);
  assert.ok(fused[0]!.score_dense !== undefined && fused[0]!.score_sparse !== undefined);
  assert.equal(fused[0]!.chunk_id, "shared");
  assert.equal(fused[0]!.score_rerank, undefined, "RRF 不得伪装成 reranker 分数");
});
test("QdrantEngine：index、dense、BM25 与 RRF 每一步都落 lineage", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const payloadChunk: EvidenceChunk = {
    ...DIRTY_CHUNK,
    chunk_id: "chunk_lineage_q2",
    provenance: { url: "https://vendor.example/advisory", section: "body", sha256: "c".repeat(64) },
  };
  const requests: Array<{ url: string; body: any }> = [];
  const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    requests.push({ url: String(_input), body: init?.body ? JSON.parse(String(init.body)) : null });
    if (init?.method === "POST") {
      return new Response(JSON.stringify({ result: [{ id: 1, score: 0.88, payload: {
        chunk_id: payloadChunk.chunk_id,
        doc_type: payloadChunk.doc_type,
        text: payloadChunk.text,
        quality_score: payloadChunk.quality_score,
        provenance: payloadChunk.provenance,
      } }] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const engine = new QdrantEngine({
    url: "http://127.0.0.1:6333", collection: "c_lineage", model_id: "bge-m3", model_version: "v2026.09", embedding_dim: 2,
    embedder: async (texts) => ({ vectors: texts.map(() => [0.2, 0.8]), model_id: "bge-m3", model_version: "v2026.09", provider: "vllm", degraded_to: "" }),
    fetch_impl: fetchImpl, bus,
  });
  const context = { trace_id: "tr_q2_lineage", parent_lineage_ids: ["ln_dq_parent"], causation_id: "ev_dq_parent" };
  await indexChunks(engine, [payloadChunk], { collection_name: "c_lineage", model_id: "bge-m3", model_version: "v2026.09", dim: 2, metric: "cosine" }, context);
  await engine.search(req({ query_text: "Log4Shell 影响版本", trace_id: context.trace_id }));
  const records = await bus.readLineage(context.trace_id);
  const stages = records.map((record) => record.stage);
  assert.ok(stages.includes("q2.bm25_index"));
  assert.ok(stages.includes("q2.qdrant_index"));
  assert.ok(stages.includes("q2.qdrant_search"));
  assert.ok(stages.includes("q2.bm25_search"));
  assert.ok(stages.includes("q2.hybrid_fusion"));
  const vectorIndex = records.find((record) => record.stage === "q2.qdrant_index")!;
  assert.ok(vectorIndex.output_refs.some((ref) => ref.kind === "QdrantPoint" && ref.sha256?.length === 64));
  const fusion = records.find((record) => record.stage === "q2.hybrid_fusion")!;
  assert.equal(fusion.parent_lineage_ids.length, 2);
  assert.equal(vectorIndex.execution?.model_id, "bge-m3");
  assert.equal(vectorIndex.execution?.model_version, "v2026.09");
  const searchBody = requests[2]!.body as { filter: { must: Array<{ key: string; match?: { value?: string } }> } };
  assert.ok(searchBody.filter.must.some((clause) => clause.key === "embedding_model_version" && clause.match?.value === "v2026.09"));
});

test("QdrantEngine：published_after 下推服务端范围过滤（A-05）", async () => {
  const requests: Array<{ url: string; body: any }> = [];
  const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    requests.push({ url: String(_input), body: init?.body ? JSON.parse(String(init.body)) : null });
    if (init?.method === "POST") {
      return new Response(JSON.stringify({ result: [] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ result: { status: "completed" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const engine = new QdrantEngine({
    url: "http://127.0.0.1:6333", collection: "c_time", model_id: "bge-m3", model_version: "v2026.09", embedding_dim: 2,
    embedder: async (texts) => ({ vectors: texts.map(() => [0.2, 0.8]), model_id: "bge-m3", model_version: "v2026.09", provider: "vllm", degraded_to: "" }),
    fetch_impl: fetchImpl,
  });
  await engine.search(req({ published_after: "2026-09-01T00:00:00Z" }));
  const searchCall = requests.find((r) => r.url.includes("/points/search"));
  assert.ok(searchCall, "应有一次 Qdrant points/search 请求");
  const must = (searchCall!.body as { filter: { must: Array<{ key: string; range?: { gte?: string } }> } }).filter.must;
  const clause = must.find((c) => c.key === "published_at");
  assert.ok(clause, "published_after 必须下推为 Qdrant 范围过滤（双引擎同口径）");
  assert.equal(clause!.range!.gte, "2026-09-01T00:00:00.000Z", "归一为 ISO-8601 UTC，字典序即时间序");
  const noWindow = await engine.search(req({}));
  assert.ok(noWindow.chunks.length === 0);
  const lastMust = (requests.at(-1)!.body as { filter: { must: Array<{ key: string }> } }).filter.must;
  assert.ok(!lastMust.some((c) => c.key === "published_at"), "未指定 published_after 时不得注入时间过滤");
});

test("indexChunks：S3 绑定登记 + 模型冲突抛错（禁止静默混用）", async () => {
  const idx = new MemoryIndex();
  const meta = await indexChunks(idx, readFixtureChunks(), {
    collection_name: "c_p0",
    model_id: "bm25-lite-v1",
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

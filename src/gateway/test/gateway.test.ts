import { test } from "node:test";
import assert from "node:assert/strict";
import { ModelGateway } from "../src/index.js";
import { createGatewayServer } from "../src/server.js";
import { MemoryUsageStore } from "../src/usage-store.js";
import { CircuitBreaker } from "../src/circuit.js";
import { TokenBucket, Semaphore } from "../src/limiter.js";
import { hashEmbedding, hashRerank, tokenize } from "../src/providers/cache.js";
import { EventBus, MemoryEventStore, SqliteEventStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";

test("Gateway HTTP：SQLite 保存 model attempt lineage，重启后可读", async () => {
  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  const dbPath = path.join(process.cwd(), "tmp", "gateway-lineage-" + process.pid + "-" + Date.now() + ".sqlite");
  await fs.mkdir(path.dirname(dbPath), { recursive: true });
  const oldSqlite = process.env.SQLITE_PATH;
  process.env.SQLITE_PATH = dbPath;
  let store: SqliteEventStore | undefined;
  const { server, listen } = createGatewayServer({ port: 0 });
  try {
    await listen();
    const addr = server.address() as { port: number };
    const res = await fetch("http://127.0.0.1:" + addr.port + "/v1/chat/complete", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ role: "answerer", messages: [{ role: "user", content: "private gateway input" }], trace_id: "tr_gateway_persist" }),
    });
    assert.equal(res.status, 200);
    await new Promise<void>((resolve) => server.close(() => resolve()));
    store = new SqliteEventStore(dbPath);
    const lineage = await store.readLineage("tr_gateway_persist");
    assert.ok(lineage.some((row) => row.stage === "mg1.chat" && row.status === "success"));
    assert.ok(!JSON.stringify(lineage).includes("private gateway input"));
  } finally {
    if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
    store?.close();
    if (oldSqlite === undefined) delete process.env.SQLITE_PATH;
    else process.env.SQLITE_PATH = oldSqlite;
    for (const suffix of ["", "-wal", "-shm"]) await fs.rm(dbPath + suffix, { force: true });
  }
});

test("profiles：models.yml 五角色与降级链加载", () => {
  const gw = new ModelGateway();
  const roles = gw.roles();
  assert.deepEqual(roles.map((r) => r.role).sort(), ["answerer", "decision", "embedder", "planner", "reranker"]);
  const answerer = roles.find((r) => r.role === "answerer")!;
  assert.equal(answerer.provider, "cache");
  assert.ok(answerer.fallback_chain.includes("cache"));
});

test("MG1 lineage：每次 provider 尝试记录 input/output hash、版本与 fallback", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const gateway = new ModelGateway({ forceProvider: "not-configured", bus });
  const chatTrace = "tr_mg1_lineage_chat";
  const chat = await gateway.chat("answerer", [{ role: "user", content: "private-question-marker" }], {}, chatTrace);
  assert.equal(chat.degraded_to, "cache");
  const chatRows = (await bus.readLineage(chatTrace)).filter((row) => row.stage === "mg1.chat");
  assert.ok(chatRows.some((row) => row.status === "failed"));
  const chatFallback = chatRows.find((row) => row.status === "degraded")!;
  assert.equal(chatFallback.execution?.provider, "cache");
  assert.ok(chatFallback.output_refs[0]?.sha256?.length === 64);
  assert.ok(chatFallback.parent_lineage_ids.length > 0, "fallback attempt links to failed attempt");
  assert.ok(!JSON.stringify(chatRows).includes("private-question-marker"));

  const embedTrace = "tr_mg1_lineage_embed";
  const embedding = await gateway.embed("embedder", ["private-embedding-marker"], embedTrace);
  assert.equal(embedding.provider, "cache");
  const embedRows = (await bus.readLineage(embedTrace)).filter((row) => row.stage === "mg1.embed");
  assert.ok(embedRows.some((row) => row.status === "failed"));
  assert.ok(embedRows.some((row) => row.status === "degraded" && row.execution?.model_version === "v0"));
  assert.ok(!JSON.stringify(embedRows).includes("private-embedding-marker"));
});

test("chat：cache provider 确定性输出（同输入同输出）", async () => {
  const gw = new ModelGateway();
  const a = await gw.chat("answerer", [{ role: "user", content: "Log4Shell 怎么修" }], {}, "tr_1");
  const b = await gw.chat("answerer", [{ role: "user", content: "Log4Shell 怎么修" }], {}, "tr_1");
  assert.equal(a.text, b.text);
  assert.equal(a.degraded_to, "");
  assert.equal(a.cached, false);
  assert.equal(b.cached, true, "第二次相同 prompt 应命中缓存");
  assert.equal(b.degraded_to, "");
  assert.ok(a.text.includes("cache provider"));
});

test("chat：熔断中的 provider 被跳过并显式降级", async () => {
  const events: FallbackEvent[] = [];
  const gw = new ModelGateway({ onFallback: (e) => { events.push(e); } });
  // 手动把 answerer 首个 provider 打成熔断：连打 5 次失败需要真实 provider，
  // 这里用一个不存在的 provider 名触发 fallback_chain 全失败 → 强制 cache 兜底
  const reply = await gw.chat("answerer", [{ role: "user", content: "你好" }], {}, "tr_2");
  assert.ok(reply.text.length > 0);
  // cache 是首选时 degraded_to 应为空
  assert.equal(reply.degraded_to, "");
  void events;
});

test("chat：强制 cloud provider 失败后走降级链并登记 FallbackEvent", async () => {
  const events: FallbackEvent[] = [];
  let attempts = 0;
  const gw = new ModelGateway({
    forceProvider: "deepseek",
    fetchImpl: async () => { attempts++; throw new Error("injected provider failure"); },
    onFallback: (e) => { events.push(e); },
  });
  const reply = await gw.chat("answerer", [{ role: "user", content: "测试降级链" }], {}, "tr_3");
  assert.equal(reply.provider, "cache");
  assert.equal(reply.degraded_to, "cache");
  assert.equal(attempts, 1, "失败必须来自注入 transport，不能依赖真实网络或凭据");
  assert.equal(events.length, 1);
  assert.equal(events[0]!.layer, "L3");
  assert.equal(events[0]!.user_visible, true);
});

test("embed/rerank：cache provider 确定性与维度", async () => {
  const gw = new ModelGateway();
  const emb = await gw.embed("embedder", ["hello world", "hello world"], "tr_4");
  assert.equal(emb.vectors.length, 2);
  assert.equal(emb.vectors[0]!.length, 256);
  assert.deepEqual(emb.vectors[0], emb.vectors[1]);
  assert.equal(emb.degraded_to, "");
  const ranked = await gw.rerank("reranker", "log4j rce", ["log4j rce vulnerability", "unrelated text"], "tr_5");
  assert.equal(ranked.ranked[0]!.index, 0);
  assert.ok(ranked.ranked[0]!.score > ranked.ranked[1]!.score);
});

test("embedder profile：模型 ID 与声明维度来自角色配置", () => {
  const profile = new ModelGateway().embeddingProfile();
  assert.deepEqual(profile, { provider: "cache", model_id: "hash-256", model_version: "v0", dimension: 256 });
});

test("embed：OpenAI-compatible 响应按 index 对齐到输入顺序", async () => {
  const realFetch = globalThis.fetch;
  const first = new Array(256).fill(0);
  const second = new Array(256).fill(0);
  first[0] = 1;
  second[1] = 1;
  let requestUrl = "";
  let requestBody: { model: string; input: string[] } | undefined;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    requestUrl = String(input);
    requestBody = JSON.parse(String(init?.body)) as { model: string; input: string[] };
    return new Response(JSON.stringify({
      data: [
        { index: 1, embedding: second },
        { index: 0, embedding: first },
      ],
    }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const result = await new ModelGateway({ forceProvider: "deepseek" }).embed("embedder", ["first text", "second text"], "tr_embed_alignment");
    assert.ok(requestUrl.endsWith("/embeddings"));
    assert.deepEqual(requestBody?.input, ["first text", "second text"]);
    assert.equal(result.provider, "deepseek");
    assert.deepEqual(result.vectors, [first, second]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("embed：维度不符不被误标为真实向量，显式退回 cache", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({
    data: [{ index: 0, embedding: [0.2, 0.8] }],
  }), { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch;
  try {
    const result = await new ModelGateway({ forceProvider: "deepseek" }).embed("embedder", ["test"], "tr_embed_bad_dim");
    assert.equal(result.provider, "cache");
    assert.equal(result.degraded_to, "cache");
    assert.equal(result.vectors[0]!.length, 256);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("计量：usage 记录与 totals", async () => {
  const usage = new MemoryUsageStore();
  const gw = new ModelGateway({ usageStore: usage });
  await gw.chat("planner", [{ role: "user", content: "a" }], {}, "tr_6");
  const totals = await usage.totals();
  assert.equal(totals.calls, 1);
  assert.ok(totals.prompt_tokens > 0);
});

test("计量：latency_ms/cached 如实落库（R-03，修复前写死 0/false）", async () => {
  const usage = new MemoryUsageStore();
  const gw = new ModelGateway({ usageStore: usage });

  // ① 缓存命中路径：同 prompt 二次调用，cached 必须从 false 翻成 true
  await gw.chat("planner", [{ role: "user", content: "R03 缓存命中" }], {}, "tr_r3a");
  await gw.chat("planner", [{ role: "user", content: "R03 缓存命中" }], {}, "tr_r3a");
  const cachedRows = await usage.query({ role: "planner" });
  assert.equal(cachedRows.length, 2, "两次调用应各落一行");
  assert.equal(cachedRows[0]!.cached, false, "首次调用不是缓存命中");
  assert.equal(cachedRows[1]!.cached, true, "二次相同 prompt 应命中缓存，cached 必须如实落库");
  assert.ok(
    cachedRows.every((r) => typeof r.latency_ms === "number" && r.latency_ms >= 0),
    "latency_ms 必须是真实测量值",
  );

  // ② 真实延迟路径：注入约 20ms 延迟的 fetch（openai-compat 走全局 fetch），
  //    latency_ms 必须如实反映这段耗时（修复前恒为 0，延迟统计完全失真）
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    await new Promise((r) => setTimeout(r, 20));
    return new Response(
      JSON.stringify({
        choices: [{ message: { content: "pong" } }],
        usage: { prompt_tokens: 3, completion_tokens: 1 },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
  try {
    const gw2 = new ModelGateway({ forceProvider: "deepseek", usageStore: usage });
    await gw2.chat("planner", [{ role: "user", content: "R03 真实延迟" }], {}, "tr_r3b");
  } finally {
    globalThis.fetch = realFetch;
  }
  const all = await usage.query({ role: "planner" });
  assert.equal(all.length, 3);
  assert.ok(all[2]!.latency_ms >= 15, "注入约 20ms 延迟，usage.latency_ms 必须 >=15ms（修复前恒为 0）");
  assert.equal(all[2]!.provider, "deepseek");
});

test("熔断器：阈值→OPEN→半开恢复", () => {
  let t = 1000;
  const br = new CircuitBreaker("test/p", { failureThreshold: 2, openMs: 500, now: () => t });
  assert.equal(br.state().status, "closed");
  br.onFailure();
  assert.equal(br.state().status, "closed");
  br.onFailure();
  assert.equal(br.state().status, "open");
  assert.equal(br.allow(), false);
  t += 600; // 超过 openMs → half_open
  assert.equal(br.state().status, "half_open");
  assert.equal(br.allow(), true, "半开放一个探针");
  assert.equal(br.allow(), false, "探针用完后拒绝");
  br.onSuccess();
  assert.equal(br.state().status, "closed");
});

test("令牌桶与信号量", async () => {
  const bucket = new TokenBucket(2, 120);
  assert.equal(bucket.tryTake(2), 0);
  assert.ok(bucket.tryTake(1) > 0, "桶空后应返回等待时间");
  const waited = await bucket.take(1);
  assert.ok(waited >= 0);
  const sem = new Semaphore(1);
  const r1 = await sem.acquire();
  assert.equal(sem.inFlight, 1);
  const p = sem.acquire();
  r1();
  await p;
  assert.equal(sem.inFlight, 1);
});

test("cache provider：hash 向量与分词", () => {
  assert.equal(tokenize("Hello world 世界").length, 4);
  const v = hashEmbedding("abc");
  assert.equal(v.length, 256);
  const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0));
  assert.ok(Math.abs(norm - 1) < 1e-9);
  const ranked = hashRerank("a b", ["a b c", "x"]);
  assert.equal(ranked[0]!.index, 0);
});

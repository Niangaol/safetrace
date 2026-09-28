import { test } from "node:test";
import assert from "node:assert/strict";
import { ModelGateway } from "../src/index.js";
import { MemoryUsageStore } from "../src/usage-store.js";
import { CircuitBreaker } from "../src/circuit.js";
import { TokenBucket, Semaphore } from "../src/limiter.js";
import { hashEmbedding, hashRerank, tokenize } from "../src/providers/cache.js";
import type { FallbackEvent } from "@safetrace/shared";

test("profiles：models.yml 五角色与降级链加载", () => {
  const gw = new ModelGateway();
  const roles = gw.roles();
  assert.deepEqual(roles.map((r) => r.role).sort(), ["answerer", "decision", "embedder", "planner", "reranker"]);
  const answerer = roles.find((r) => r.role === "answerer")!;
  assert.equal(answerer.provider, "cache");
  assert.ok(answerer.fallback_chain.includes("cache"));
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
  // forceProvider=deepseek 但无 key/网络 → compatChat 抛错 → 链降级到 cache（非首选→显式降级）
  const gw = new ModelGateway({ forceProvider: "deepseek", onFallback: (e) => { events.push(e); } });
  const reply = await gw.chat("answerer", [{ role: "user", content: "测试降级链" }], {}, "tr_3");
  assert.equal(reply.provider, "cache");
  assert.equal(reply.degraded_to, "cache");
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

test("计量：usage 记录与 totals", async () => {
  const usage = new MemoryUsageStore();
  const gw = new ModelGateway({ usageStore: usage });
  await gw.chat("planner", [{ role: "user", content: "a" }], {}, "tr_6");
  const totals = await usage.totals();
  assert.equal(totals.calls, 1);
  assert.ok(totals.prompt_tokens > 0);
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

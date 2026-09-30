/**
 * C-05 回归：数据隔离闸门。
 * 验收口径：private 数据 + cloud provider → 硬拒 + FallbackEvent；
 * 不降级改投云端；无 local provider 时显式失败；profiles 解析结果符合声明。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { ModelGateway, loadModelsConfig } from "../src/index.js";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function baseConfig(): string {
  return [
    "version: 1",
    "providers:",
    "  cache:",
    "    type: cache",
    "  fakelocal:",
    "    type: openai_compat",
    "    trust_boundary: local",
    "    base_url_default: http://127.0.0.1:9/v1",
    "  fakecloud:",
    "    type: openai_compat",
    "    trust_boundary: cloud",
    "    base_url_default: http://127.0.0.1:9/v1",
    "roles:",
    "  planner:",
    "    provider: fakecloud",
    "    model_id: cloud-model",
    "    data_domain: private",
    "    fallback_chain: [cache]",
    "  answerer:",
    "    provider: fakecloud",
    "    model_id: cloud-model",
    "    data_domain: public",
    "    fallback_chain: [cache]",
    "  embedder:",
    "    provider: fakelocal",
    "    model_id: local-model",
    "    data_domain: public",
    "    fallback_chain: [cache]",
    "    capability_flags: { dim: 4 }",
    "  reranker:",
    "    provider: cache",
    "    model_id: cache-reranker",
    "  decision:",
    "    provider: cache",
    "    model_id: cache-decision",
  ].join("\n");
}

test("profiles 解析 trust_boundary / data_domain，未声明时按 type 推断", () => {
  const cfg = loadModelsConfig("config/models.yml");
  assert.equal(cfg.providers.cache?.trust_boundary, "cache", "cache provider 推断为 cache 边界");
  assert.equal(cfg.providers.deepseek?.trust_boundary, "cloud", "openai_compat 默认 cloud");
  assert.equal(cfg.providers.vllm?.trust_boundary, "local", "vLLM 显式声明 local");
  assert.equal(cfg.roles.decision?.data_domain, "private", "decision 角色声明 private");
  assert.equal(cfg.roles.embedder?.data_domain, "public");
});

test("private + cloud → 硬拒并登记 FallbackEvent，绝不改投云端", async () => {
  const events: FallbackEvent[] = [];
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const dir = mkdtempSync(join(tmpdir(), "c05-"));
  const path = join(dir, "models.yml");
  writeFileSync(path, baseConfig(), "utf8");
  const gw = new ModelGateway({ configPath: path, bus, onFallback: (e) => { events.push(e); } });
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = (async () => { calls++; throw new Error("must not reach network"); }) as typeof fetch;
  try {
    await gw.chat("planner", [{ role: "user", content: "private question" }], {}, "tr_iso");
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(calls, 0, "private 数据不得发出任何网络请求");
  assert.ok(events.some((e) => e.degraded_of === "isolation:private->cloud"), "必须登记隔离 FallbackEvent");
  const rows = await bus.readLineage("tr_iso");
  assert.ok(rows.some((r) => r.stage === "mg1.isolation_gate" && r.status === "rejected"), "隔离拒绝必须落 lineage");
  const usedProviders = rows.filter((r) => r.stage === "mg1.chat").map((r) => r.execution?.provider);
  assert.ok(!usedProviders.includes("fakecloud"), "拒绝后不得仍由 cloud provider 产出结果");
  assert.ok(!JSON.stringify(rows).includes("private question"), "lineage 不复制请求内容");
});

test("private 数据在 local provider 上可正常通过（闸门不误伤）", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const dir = mkdtempSync(join(tmpdir(), "c05-"));
  const path = join(dir, "models.yml");
  writeFileSync(path, baseConfig(), "utf8");
  const original = globalThis.fetch;
  globalThis.fetch = (async () => new Response(JSON.stringify({ data: [{ index: 0, embedding: [0.5, 0.5, 0.5, 0.5] }] }), { status: 200 })) as typeof fetch;
  try {
    const gw = new ModelGateway({ configPath: path, bus });
    const res = await gw.embed("embedder", ["hello"], "tr_iso_ok");
    assert.equal(res.provider, "fakelocal", "local provider 应正常服务 private 数据");
    const rows = await bus.readLineage("tr_iso_ok");
    assert.ok(!rows.some((r) => r.stage === "mg1.isolation_gate"), "local 通道不应触发隔离拒绝");
  } finally {
    globalThis.fetch = original;
  }
});

test("显式 private 请求参数会触发闸门（覆盖角色默认 public）", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const dir = mkdtempSync(join(tmpdir(), "c05-"));
  const path = join(dir, "models.yml");
  // answerer 默认 data_domain=public；显式传 private 后即使 role 默认是 public 也必须拦截
  const cfg = baseConfig().replace('  answerer:\n    provider: fakecloud\n    model_id: cloud-model\n    data_domain: public', '  answerer:\n    provider: fakecloud\n    model_id: cloud-model\n    data_domain: public');
  writeFileSync(path, cfg, "utf8");
  const events: FallbackEvent[] = [];
  const gw = new ModelGateway({ configPath: path, bus, onFallback: (e) => { events.push(e); } });
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = (async () => { calls++; throw new Error("must not reach network"); }) as typeof fetch;
  try {
    await gw.chat("answerer", [{ role: "user", content: "sensitive" }], {}, "tr_domain_param", "private");
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(calls, 0, "显式 private 不得发出网络请求");
  assert.ok(events.some((e) => e.degraded_of === "isolation:private->cloud"), "必须登记隔离事件");
  assert.ok(!JSON.stringify(await bus.readLineage("tr_domain_param")).includes("sensitive"));
});

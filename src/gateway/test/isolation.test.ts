/**
 * C-05 回归：数据隔离闸门。
 * 验收口径：private 数据 + cloud provider → 硬拒 + FallbackEvent；
 * 不降级改投云端；无 local provider 时显式失败；profiles 解析结果符合声明。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { IsolationError, ModelGateway, ScopeViolationError, loadModelsConfig } from "../src/index.js";
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

/** A-03：带第二道闸门测试所需 provider/role 的配置（含两家 cloud 以验证"不改投下一家"）。 */
function a03Config(): string {
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
    "  fakecloudb:",
    "    type: openai_compat",
    "    trust_boundary: cloud",
    "    base_url_default: http://127.0.0.1:9/v1",
    "roles:",
    // 测试 A：整条链都是 cloud（两家），data_domain 仍为 public —— 拒绝必须由"载荷私域标记"触发
    "  planner:",
    "    provider: fakecloud",
    "    model_id: cloud-model",
    "    data_domain: public",
    "    fallback_chain: [fakecloudb]",
    // 测试 B：private 数据 + 降级链只有 cloud，全链无本机通道
    "  answerer:",
    "    provider: fakecloud",
    "    model_id: cloud-model",
    "    data_domain: private",
    "    fallback_chain: []",
    "  embedder:",
    "    provider: cache",
    "    model_id: cache-embedder",
    "    data_domain: public",
    "    fallback_chain: [cache]",
    "    capability_flags: { dim: 4 }",
    "  reranker:",
    "    provider: cache",
    "    model_id: cache-reranker",
    "    data_domain: public",
    "    fallback_chain: [cache]",
    "  decision:",
    "    provider: cache",
    "    model_id: cache-decision",
    "    data_domain: private",
    "    fallback_chain: [cache]",
  ].join("\n");
}

/** 测试 C 专用：planner 直接指向 local provider，验证闸门不误伤本机通道。 */
function a03LocalConfig(): string {
  return a03Config()
    .replace('  planner:\n    provider: fakecloud\n    model_id: cloud-model\n    data_domain: public\n    fallback_chain: [fakecloudb]',
      '  planner:\n    provider: fakelocal\n    model_id: local-model\n    data_domain: private\n    fallback_chain: []');
}

function writeA03Config(text = a03Config()): string {
  const dir = mkdtempSync(join(tmpdir(), "a03-"));
  const path = join(dir, "models.yml");
  writeFileSync(path, text, "utf8");
  return path;
}

test("A-03 第二道闸门：出网载荷含私域标记 → 硬拒并终止降级链，零网络请求", async () => {
  const events: FallbackEvent[] = [];
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const gw = new ModelGateway({ configPath: writeA03Config(), bus, onFallback: (e) => { events.push(e); } });
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = (async () => { calls++; return new Response("{}", { status: 200 }); }) as typeof fetch;
  let error: unknown;
  try {
    await gw.chat("planner", [{ role: "user", content: "asset_id=A-1024 内网主机 internal_host=db01，请总结" }], {}, "tr_marker");
  } catch (err) {
    error = err;
  } finally {
    globalThis.fetch = original;
  }
  assert.ok(error instanceof ScopeViolationError, "含私域标记的载荷必须抛 ScopeViolationError，实际：" + String(error));
  assert.equal(calls, 0, "含私域标记的载荷不得发出任何网络请求（含降级链下一家 cloud provider）");
  const msg = (error as Error).message;
  assert.ok(!msg.includes("A-1024") && !msg.includes("db01"), "错误只报标记与路径，不回显命中内容");
  assert.ok(events.some((e) => e.degraded_of === "isolation:private-marker"), "必须登记 isolation:private-marker FallbackEvent");
  const rows = await bus.readLineage("tr_marker");
  assert.ok(rows.some((r) => r.stage === "mg1.isolation_gate" && r.status === "rejected"), "拒绝必须落 lineage");
  assert.ok(!rows.some((r) => r.stage === "mg1.chat" && r.status === "success"), "被拒后不得仍产出成功结果");
  assert.ok(!JSON.stringify(rows).includes("A-1024"), "lineage 不复制请求内容");
});

test("A-03：全链无本机通道时 private 显式失败，不以 cache 模板冒充回答", async () => {
  const events: FallbackEvent[] = [];
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const gw = new ModelGateway({ configPath: writeA03Config(), bus, onFallback: (e) => { events.push(e); } });
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = (async () => { calls++; return new Response("{}", { status: 200 }); }) as typeof fetch;
  let error: unknown;
  try {
    await gw.chat("answerer", [{ role: "user", content: "private question" }], {}, "tr_nolocal");
  } catch (err) {
    error = err;
  } finally {
    globalThis.fetch = original;
  }
  assert.ok(error instanceof IsolationError, "必须先于任何 provider 尝试显式失败，实际：" + String(error));
  assert.match((error as Error).message, /本机通道/, "错误信息必须说明缺的是本机通道");
  assert.equal(calls, 0, "无本机通道时不得发出任何网络请求");
  assert.ok(events.some((e) => e.degraded_of === "isolation:no-local-provider"), "必须登记 isolation:no-local-provider FallbackEvent");
  const rows = await bus.readLineage("tr_nolocal");
  assert.ok(rows.some((r) => r.stage === "mg1.isolation_gate" && r.status === "rejected"), "显式失败必须落 lineage");
  assert.ok(!rows.some((r) => r.stage === "mg1.chat" && r.status === "success"), "不得以 cache 模板冒充成功结果");
  assert.ok(!JSON.stringify(rows).includes("private question"), "lineage 不复制请求内容");
});

test("A-03：private 数据 + local provider 正常放行（含私域标记也不误伤）", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const gw = new ModelGateway({ configPath: writeA03Config(a03LocalConfig()), bus });
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = (async () => {
    calls++;
    return new Response(JSON.stringify({ choices: [{ message: { content: "local-ok" } }], usage: { prompt_tokens: 3, completion_tokens: 2 } }), { status: 200 });
  }) as typeof fetch;
  try {
    const res = await gw.chat("planner", [{ role: "user", content: "asset_id=A-7 internal_host=db01" }], {}, "tr_local_private");
    assert.equal(res.provider, "fakelocal", "local 是 private 数据的合法目的地");
    assert.equal(calls, 1, "local 通道必须真被调用（闸门不得误伤本机通道）");
  } finally {
    globalThis.fetch = original;
  }
  const rows = await bus.readLineage("tr_local_private");
  assert.ok(!rows.some((r) => r.stage === "mg1.isolation_gate"), "本机通道不得触发隔离拒绝");
});

test("A-03：默认 config/models.yml 的 decision 角色（private + cache 本机通道）不被误伤", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const gw = new ModelGateway({ configPath: "config/models.yml", bus });
  const res = await gw.chat("decision", [{ role: "user", content: "y5 triage" }], {}, "tr_decision_private");
  assert.equal(res.provider, "cache", "cache 属本机通道，private 角色应正常服务");
  const rows = await bus.readLineage("tr_decision_private");
  assert.ok(!rows.some((r) => r.stage === "mg1.isolation_gate"), "合法本机通道不得被闸门拦截");
});

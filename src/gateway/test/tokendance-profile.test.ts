import { test } from "node:test";
import assert from "node:assert/strict";
import { loadModelsConfig } from "../src/profiles.js";
import { ModelGateway } from "../src/index.js";
import { EventBus, MemoryEventStore } from "@safetrace/shared";

test("real profile is explicitly selectable and default embedder remains cache", () => {
  assert.equal(loadModelsConfig("config/models.yml").roles.embedder.provider, "cache");
  const live = loadModelsConfig("config/models.cloud.yml");
  assert.equal(live.roles.embedder.provider, "tokendance");
  assert.equal(live.roles.embedder.model_id, "qwen3.7-text-embedding");
  assert.equal(live.roles.embedder.capability_flags.dim, 1024);
  assert.equal(live.providers.tokendance?.api_key_env, "TOKENDANCE_API_KEY");
  assert.equal(live.roles.embedder.model_version, "unversioned-api");
  assert.equal(live.roles.decision.data_domain, "private", "arbitrary decision.state must default private even in cloud profiles");
  assert.equal(loadModelsConfig("config/models.yml").roles.decision.data_domain, "private");
});

test("local stack profile switches embedder to bge-m3 with trust_boundary local", () => {
  // 本地栈（无 Docker）：embedder 指向 llama-server :8081，A-03 隔离闸门必须收到 local 边界
  const local = loadModelsConfig("config/models.tokendance.yml");
  assert.equal(local.roles.embedder.provider, "local_embed");
  assert.equal(local.roles.embedder.model_id, "bge-m3");
  assert.equal(local.roles.embedder.capability_flags.dim, 1024, "本地 bge-m3 与云端同维度，集合元数据可复用");
  // data_domain 必须是 public：A-03 隔离闸门规定 private 数据不得流向 cloud provider，
  // 若这里是 private，fallback_chain 里的云端 Tokendance 会被直接拦掉，
  // "本地没模型就转云端"这条用户可见的回退路径就失效了。
  // 公开漏洞情报（CVE/USN/KEV）本身可出网，原云端配置亦为 public，与此一致。
  assert.equal(local.roles.embedder.data_domain, "public");
  assert.equal(local.providers.local_embed?.trust_boundary, "local", "未标 local 会被 A-03 当出云请求拦掉");
  assert.equal(local.providers.local_llm?.trust_boundary, "local");
  assert.equal(local.providers.local_embed?.base_url_default, "http://127.0.0.1:8081/v1");
  assert.equal(local.providers.local_llm?.base_url_default, "http://127.0.0.1:8080/v1");
  // 云端 provider 定义仍在（切回时改 role 即可，不用重写文件）
  assert.equal(local.providers.tokendance?.api_key_env, "TOKENDANCE_API_KEY");
  assert.equal(local.roles.decision.data_domain, "private", "decision.state is arbitrary and defaults private");
});

test("StepPlan model profile uses the local OpenAI-compatible endpoint", () => {
  const profile = loadModelsConfig("config/models.tokendance.yml");
  assert.equal(profile.providers.stepplan?.base_url_default, "https://api.stepfun.com/step_plan/v1");
  assert.equal(profile.providers.stepplan?.api_key_env, "STEP_PLAN_API_KEY");
  assert.equal(profile.roles.answerer.provider, "stepplan");
  assert.equal(profile.roles.answerer.model_id, "step-3.7-flash");
  assert.equal(profile.roles.answerer.capability_flags.reasoning_effort, "low");
  assert.deepEqual(profile.roles.answerer.fallback_chain, ["cache"]);
  assert.equal(profile.roles.planner.provider, "stepplan");
  assert.equal(profile.roles.planner.model_id, "step-3.7-flash");
  assert.equal(profile.roles.planner.capability_flags.reasoning_effort, "low");
  assert.deepEqual(profile.roles.planner.fallback_chain, ["cache"]);
  assert.equal(profile.roles.decision.data_domain, "private", "arbitrary DecisionRequest.state must not inherit public by default");
});

test("StepPlan: OpenAI-compatible chat uses configured role and records model lineage", async () => {
  const original = globalThis.fetch;
  const previousKey = process.env.STEP_PLAN_API_KEY;
  const previousBase = process.env.STEPPLAN_BASE_URL;
  process.env.STEP_PLAN_API_KEY = "test-only-not-a-real-secret";
  process.env.STEPPLAN_BASE_URL = "https://api.stepfun.com/step_plan/v1";
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  globalThis.fetch = (async (input, init) => {
    assert.equal(String(input), "https://api.stepfun.com/step_plan/v1/chat/completions");
    assert.equal(new Headers(init?.headers).get("authorization"), "Bearer test-only-not-a-real-secret");
    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, "step-3.7-flash");
    assert.equal(body.reasoning_effort, "low");
    return new Response(JSON.stringify({ model: body.model, choices: [{ message: { content: "由给定证据生成的测试结论。" } }], usage: { prompt_tokens: 12, completion_tokens: 9 } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const gateway = new ModelGateway({ configPath: "config/models.tokendance.yml", bus });
    const reply = await gateway.chat("answerer", [{ role: "user", content: "public vulnerability question" }], { temperature: 0.2, max_tokens: 100 }, "tr_stepfun_profile", "public");
    assert.equal(reply.provider, "stepplan");
    assert.equal(reply.model_id, "step-3.7-flash");
    assert.equal(reply.text, "由给定证据生成的测试结论。");
    assert.equal(reply.degraded_to, "");
    const lineage = await bus.readLineage("tr_stepfun_profile");
    assert.ok(lineage.some((row) => row.stage === "mg1.chat" && row.execution?.provider === "stepplan" && row.execution.model_id === "step-3.7-flash"));
    assert.ok(!JSON.stringify(lineage).includes("test-only-not-a-real-secret"));
    assert.ok(!JSON.stringify(lineage).includes("public vulnerability question"));
  } finally {
    globalThis.fetch = original;
    if (previousKey === undefined) delete process.env.STEP_PLAN_API_KEY; else process.env.STEP_PLAN_API_KEY = previousKey;
    if (previousBase === undefined) delete process.env.STEPPLAN_BASE_URL; else process.env.STEPPLAN_BASE_URL = previousBase;
  }
});

test("MG1 real-profile protocol and lineage tested with injected response, not a cloud call", async () => {
  const original = globalThis.fetch;
  const previousKey = process.env.TOKENDANCE_API_KEY;
  const previousBase = process.env.TOKENDANCE_BASE_URL;
  process.env.TOKENDANCE_API_KEY = "test-only-not-a-real-secret";
  process.env.TOKENDANCE_BASE_URL = "https://tokendance.space/gateway/v1";
  const store = new MemoryEventStore(); const bus = new EventBus({ store });
  let calls = 0;
  globalThis.fetch = (async (input, init) => {
    calls++;
    assert.equal(String(input), "https://tokendance.space/gateway/v1/embeddings");
    assert.equal(init?.redirect, "error");
    const body = JSON.parse(String(init?.body));
    assert.equal(body.model, "qwen3.7-text-embedding");
    return new Response(JSON.stringify({ model: body.model, data: [{ index: 0, embedding: Array.from({ length: 1024 }, (_, i) => i === 0 ? 0.5 : 0) }] }), { status: 200 });
  }) as typeof fetch;
  try {
    // 用云端配置验协议路径；embedder 现役配置是本地栈（config/models.tokendance.yml）
    const gateway = new ModelGateway({ configPath: "config/models.cloud.yml", bus });
    const result = await gateway.embed("embedder", ["synthetic protocol test"], "tr_profile_test");
    assert.equal(calls, 1);
    assert.equal(result.provider, "tokendance");
    assert.equal(result.vectors[0]?.length, 1024);
    assert.equal(result.degraded_to, "");
    const rows = await bus.readLineage("tr_profile_test");
    assert.ok(rows.some(r => r.stage === "mg1.embed" && r.status === "success" && r.execution?.provider === "tokendance"));
    assert.ok(!JSON.stringify(rows).includes("test-only-not-a-real-secret"));
    assert.ok(!JSON.stringify(rows).includes("synthetic protocol test"));
  } finally {
    globalThis.fetch = original;
    if (previousKey === undefined) delete process.env.TOKENDANCE_API_KEY; else process.env.TOKENDANCE_API_KEY = previousKey;
    if (previousBase === undefined) delete process.env.TOKENDANCE_BASE_URL; else process.env.TOKENDANCE_BASE_URL = previousBase;
  }
});

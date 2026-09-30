
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { ModelGateway, type CloudFallbackRequest } from "../src/index.js";

/** 构造一个"本地已挂、云端可用"的场景：forceProvider 让首选必失败，再降级到 cloud。 */
function scenario(opts: { confirm?: (r: CloudFallbackRequest) => Promise<boolean> | boolean; forceProvider?: string } = {}) {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const seen: CloudFallbackRequest[] = [];
  const confirm = opts.confirm ? ((r: CloudFallbackRequest) => { seen.push(r); return opts.confirm!(r); }) : undefined;
  const gw = new ModelGateway({
    bus,
    // 必须指向本地栈配置：默认 config/models.yml 里只有 cache 占位，没有 local_embed/tokendance
    configPath: "config/models.tokendance.yml",
    forceProvider: opts.forceProvider,
    ...(confirm ? { confirmCloudFallback: confirm } : {}),
  });
  return { gw, bus, store, seen };
}

/**
 * 让本地 provider 必败的场景：注入 fetch，非 tokendance 请求一律抛错。
 * 不这样做的话，只要本机 llama-server 起着，首选就成功、根本不会降级，
 * 云端关卡的用例会全数假绿（2026-09-30 实测踩到）。
 */
async function scenarioWithLocalDown(opts: { confirm?: (r: CloudFallbackRequest) => Promise<boolean> | boolean } = {}) {
  const orig = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    if (String(input).includes("tokendance.space")) return orig(input);
    throw new Error("local channel down (injected)");
  }) as typeof fetch;
  const built = scenario({ confirm: opts.confirm });
  return {
    ...built,
    async restore() { globalThis.fetch = orig; },
  };
}

test("no confirmCloudFallback injected: cloud fallback is refused and never goes online", async () => {
  // fail closed：无人点头就不出网。本地(local_embed)挂 → 云端被拒 → 退 cache。
  // 注意：必须让本地必败，否则本地可用时根本不降级、到不了云端那一跳。
  const sc = await scenarioWithLocalDown();
  try {
    const r = await sc.gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_absent");
    assert.equal(r.provider, "cache", "未注入钩子时不得出网，应退到 cache");
    assert.equal(r.degraded_to, "cache");
  } finally {
    await sc.restore();
  }
});

test("human declines: cloud provider is skipped, no network call, degrade is user-visible", async () => {
  const calls: CloudFallbackRequest[] = [];
  // 首选 local_llm 指向未监听的端口，确保本地必失败、才会触发降级到云端
  const { gw, bus, store } = scenario({ forceProvider: "local_llm", confirm: (r) => { calls.push(r); return false; } });
  const r = await gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_denied");
  assert.equal(calls.length, 1, "必须询问一次人工");
  assert.equal(calls[0]!.toProvider, "tokendance");
  assert.equal(calls[0]!.trustBoundary, "cloud");
  assert.equal(r.provider, "cache");
  // 拒绝必须留痕：lineage 记 rejected + 原因含人工关卡字样，且 user_visible
  const rows = await bus.readLineage("tr_gate_denied");
  const rejected = rows.filter((x) => x.stage === "mg1.embed" && x.status === "rejected");
  assert.ok(rejected.length >= 1, "云端被拒必须落 lineage");
  assert.ok(
    rejected.some((x) => (x.decision?.reason ?? "").includes("cloud fallback denied by human gate")),
    "拒绝原因必须点名是人工关卡拦的，实际：" + JSON.stringify(rejected.map((x) => x.decision?.reason)),
  );
  // FallbackEvent（user_visible 出口）也必须登记，degradedOf 指向本关卡
  const events = (await store.read<FallbackEvent>("fallback.events")).map((e) => e.payload);
  assert.ok(
    events.some((e) => e.degraded_of === "isolation:cloud-needs-human" && e.user_visible === true),
    "拒绝必须产生 user_visible 的 FallbackEvent，实际 " + events.length + " 条",
  );
});

test("human approves: cloud fallback proceeds and records degraded_to", async (t) => {
  // 注入 fetch：凡是非 tokendance 一律当本地通道故障，只有 tokendance 放行到真实网络，
  // 这样"人工同意后这一跳必须真的发生"才可断言。
  // npm test 不带 --env-file，没有云端 key 时跳过（其余三条路径不依赖云端，照常断言）。
  if (!process.env.TOKENDANCE_API_KEY) {
    t.skip("未设置 TOKENDANCE_API_KEY，跳过真实云端一跳（关卡逻辑由其余用例覆盖）");
    return;
  }
  const prevKey = process.env.TOKENDANCE_API_KEY;
  const prevBase = process.env.TOKENDANCE_BASE_URL;
  const orig = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const url = String(input);
    if (url.includes("tokendance.space")) return orig(input);
    throw new Error("local channel down (injected)");
  }) as typeof fetch;
  try {
    const { gw } = scenario({ forceProvider: "local_llm", confirm: () => true });
    const r = await gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_allowed");
    assert.equal(r.provider, "tokendance", "人工同意后应真的走云端");
    assert.equal(r.degraded_to, "tokendance");
  } finally {
    globalThis.fetch = orig;
    if (prevKey === undefined) delete process.env.TOKENDANCE_API_KEY; else process.env.TOKENDANCE_API_KEY = prevKey;
    if (prevBase === undefined) delete process.env.TOKENDANCE_BASE_URL; else process.env.TOKENDANCE_BASE_URL = prevBase;
  }
});

test("confirm hook throwing is treated as refusal, not as approval", async () => {
  const sc = await scenarioWithLocalDown({ confirm: () => { throw new Error("审批服务不可用"); } });
  try {
    const r = await sc.gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_throw");
    assert.equal(r.provider, "cache", "钩子异常必须按拒绝处理，绝不能当同意");
  } finally {
    await sc.restore();
  }
});

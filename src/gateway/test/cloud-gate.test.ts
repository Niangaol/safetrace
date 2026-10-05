import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import type { FallbackEvent } from "@safetrace/shared";
import { ModelGateway, type CloudFallbackRequest } from "../src/index.js";

/** Local transport always fails; cloud transport is an in-memory response, never a real request. */
function scenario(confirm?: (r: CloudFallbackRequest) => Promise<boolean> | boolean) {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const seen: CloudFallbackRequest[] = [];
  let localCalls = 0;
  let cloudCalls = 0;
  const gw = new ModelGateway({
    bus,
    configPath: "config/models.tokendance.yml",
    fetchImpl: async (input, init) => {
      // Identify the intended cloud model rather than rely on ambient base-url variables.
      const body = JSON.parse(String(init?.body)) as { model: string; input: string[] };
      if (body.model !== "qwen3.7-text-embedding") {
        localCalls++;
        throw new Error("local channel down (injected)");
      }
      cloudCalls++;
      assert.ok(String(input).endsWith("/embeddings"));
      return new Response(JSON.stringify({ data: body.input.map((_, index) => ({ index, embedding: new Array(1024).fill(0.1) })) }), { status: 200 });
    },
    ...(confirm ? { confirmCloudFallback: (r: CloudFallbackRequest) => { seen.push(r); return confirm(r); } } : {}),
  });
  return { gw, bus, store, seen, counts: () => ({ localCalls, cloudCalls }) };
}

test("no confirmCloudFallback injected: cloud fallback is refused and never goes online", async () => {
  const sc = scenario();
  const r = await sc.gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_absent");
  assert.equal(r.provider, "cache");
  assert.equal(r.degraded_to, "cache");
  assert.deepEqual(sc.counts(), { localCalls: 1, cloudCalls: 0 });
});

test("human declines: cloud provider is skipped, no network call, degrade is user-visible", async () => {
  const sc = scenario(() => false);
  const r = await sc.gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_denied");
  assert.equal(sc.seen.length, 1);
  assert.equal(sc.seen[0]!.toProvider, "tokendance");
  assert.equal(sc.seen[0]!.trustBoundary, "cloud");
  assert.equal(r.provider, "cache");
  assert.deepEqual(sc.counts(), { localCalls: 1, cloudCalls: 0 });
  const rejected = (await sc.bus.readLineage("tr_gate_denied")).filter((x) => x.stage === "mg1.embed" && x.status === "rejected");
  assert.ok(rejected.some((x) => (x.decision?.reason ?? "").includes("cloud fallback denied by human gate")));
  const events = (await sc.store.read<FallbackEvent>("fallback.events")).map((e) => e.payload);
  assert.ok(events.some((e) => e.degraded_of === "isolation:cloud-needs-human" && e.user_visible === true));
});

test("human approves: injected cloud fallback proceeds and records degraded_to without network", async () => {
  const sc = scenario(() => true);
  const r = await sc.gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_allowed");
  assert.equal(sc.seen.length, 1);
  assert.equal(r.provider, "tokendance");
  assert.equal(r.degraded_to, "tokendance");
  assert.deepEqual(sc.counts(), { localCalls: 1, cloudCalls: 1 });
  const rows = await sc.bus.readLineage("tr_gate_allowed");
  assert.ok(rows.some((x) => x.status === "degraded" && x.execution?.provider === "tokendance"));
});

test("confirm hook throwing is treated as refusal, not as approval", async () => {
  const sc = scenario(() => { throw new Error("审批服务不可用"); });
  const r = await sc.gw.embed("embedder", ["CVE-2021-44228"], "tr_gate_throw");
  assert.equal(sc.seen.length, 1);
  assert.equal(r.provider, "cache");
  assert.deepEqual(sc.counts(), { localCalls: 1, cloudCalls: 0 });
});

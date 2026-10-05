// Explicit opt-in only: npm run test:live. Never matches the default *.test.ts glob.
// No env file is loaded here; caller supplies credentials after authorizing a billable request.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ModelGateway } from "../src/index.js";

test("LIVE: approved cloud embedding fallback", async () => {
  assert.ok(process.env.TOKENDANCE_API_KEY, "test:live requires explicit TOKENDANCE_API_KEY");
  const realFetch = globalThis.fetch;
  let cloudCalls = 0;
  const gateway = new ModelGateway({
    configPath: "config/models.tokendance.yml",
    confirmCloudFallback: () => true,
    fetchImpl: async (input, init) => {
      const body = JSON.parse(String(init?.body)) as { model: string };
      if (body.model !== "qwen3.7-text-embedding") throw new Error("local down (injected)");
      cloudCalls++;
      return realFetch(input, init);
    },
  });
  const result = await gateway.embed("embedder", ["CVE-2021-44228"], "tr_live_gate_allowed");
  assert.equal(cloudCalls, 1);
  assert.equal(result.provider, "tokendance");
  assert.equal(result.degraded_to, "tokendance");
});

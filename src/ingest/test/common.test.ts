import { test } from "node:test";
import assert from "node:assert/strict";
import { fetchJsonWithRetry } from "../src/common.js";

test("fetchJsonWithRetry：404 无记录不做无意义重试", async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => { calls++; return new Response("{}", { status: 404 }); }) as typeof fetch;
  try {
    const result = await fetchJsonWithRetry("https://source.example/CVE-1");
    assert.equal(result.ok, false);
    assert.equal(calls, 1);
    if (!result.ok) assert.match(result.reason, /HTTP 404/);
  } finally { globalThis.fetch = original; }
});

test("fetchJsonWithRetry：429 Retry-After 为 0 后重试并成功", async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return calls === 1
      ? new Response("{}", { status: 429, headers: { "retry-after": "0" } })
      : new Response("{\"ok\":true}", { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const result = await fetchJsonWithRetry("https://source.example/query");
    assert.equal(result.ok, true);
    assert.equal(calls, 2);
  } finally { globalThis.fetch = original; }
});
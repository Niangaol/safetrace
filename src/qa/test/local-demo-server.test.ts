import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createLocalDemoServer, loadDataset } from "../../../scripts/local-demo-server.js";

let server: Server;
let base: string;

before(async () => {
  const dataset = await loadDataset();
  server = createLocalDemoServer(dataset);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test("本地演示 API：健康状态标明 fixture 和实际索引计数", async () => {
  const response = await fetch(base + "/api/v1/health");
  assert.equal(response.status, 200);
  const payload = await response.json() as { status: string; data_mode: string; intel_count: number; chunk_count: number };
  assert.equal(payload.status, "ok");
  assert.equal(payload.data_mode, "fixture");
  assert.ok(payload.intel_count > 0);
  assert.ok(payload.chunk_count > 0);
});

test("本地演示 API：漏洞列表、详情由离线采集与富化流水线提供", async () => {
  const listResponse = await fetch(base + "/api/v1/vulns?page=1&page_size=100");
  assert.equal(listResponse.status, 200);
  const page = await listResponse.json() as { items: Array<{ id: string; enriched: boolean; data_mode: string }>; total: number };
  assert.ok(page.total > 0);
  assert.ok(page.items.some((item) => item.enriched));
  const first = page.items[0]!;
  const detailResponse = await fetch(base + "/api/v1/vulns/" + encodeURIComponent(first.id));
  assert.equal(detailResponse.status, 200);
  const detail = await detailResponse.json() as { id: string; data_mode: string };
  assert.equal(detail.id, first.id);
  assert.equal(detail.data_mode, "fixture");
  const evidenceResponse = await fetch(base + "/api/v1/vulns/" + encodeURIComponent(first.id) + "/evidence");
  assert.equal(evidenceResponse.status, 200);
  const evidence = await evidenceResponse.json() as { enrichments: unknown[]; data_mode: string };
  assert.equal(evidence.data_mode, "fixture");
  assert.ok(evidence.enrichments.length > 0);
});

test("本地演示 API：问答执行 Q1→Q2→Q4 并流出证据引用", async () => {
  const response = await fetch(base + "/api/v1/qa/chat", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ question: "Log4Shell 影响哪些版本？怎么修复？", stream: true }),
  });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /text\/event-stream/);
  const text = await response.text();
  assert.match(text, /"event":"stage","stage":"plan"/);
  assert.match(text, /"event":"stage","stage":"retrieve"/);
  assert.match(text, /"event":"citation"/);
  assert.match(text, /CVE-2021-44228/);
  assert.match(text, /"data_mode":"fixture"/);
});

test("本地演示 API：索引外 CVE 明确拒答且无引用", async () => {
  const response = await fetch(base + "/api/v1/qa/chat", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ question: "CVE-2099-4321 影响哪些版本？" }),
  });
  const text = await response.text();
  assert.match(text, /"abstained":true/);
  assert.doesNotMatch(text, /"event":"citation"/);
});

test("本地演示 API：拒绝空问题和未知路由", async () => {
  const invalid = await fetch(base + "/api/v1/qa/chat", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ question: " " }),
  });
  assert.equal(invalid.status, 400);
  const missing = await fetch(base + "/api/v1/no-such-route");
  assert.equal(missing.status, 404);
});

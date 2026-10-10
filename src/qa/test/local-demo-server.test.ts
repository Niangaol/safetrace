import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createLocalDemoServer, loadDataset } from "../../../scripts/local-demo-server.js";

let server: Server;
let base: string;
let previousModelsConfig: string | undefined;
let previousStepPlanKey: string | undefined;

before(async () => {
  previousModelsConfig = process.env.MODELS_CONFIG_PATH;
  previousStepPlanKey = process.env.STEP_PLAN_API_KEY;
  process.env.MODELS_CONFIG_PATH = "config/models.yml";
  delete process.env.STEP_PLAN_API_KEY;
  const dataset = await loadDataset();
  const absentDb = "tmp/absent-ingest-diagnostics-" + process.pid + ".sqlite";
  server = createLocalDemoServer(dataset, { diagnosticsDbPath: absentDb });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (previousModelsConfig === undefined) delete process.env.MODELS_CONFIG_PATH; else process.env.MODELS_CONFIG_PATH = previousModelsConfig;
  if (previousStepPlanKey === undefined) delete process.env.STEP_PLAN_API_KEY; else process.env.STEP_PLAN_API_KEY = previousStepPlanKey;
});

test("本地演示 API：健康状态标明 fixture 和实际索引计数", async () => {
  const response = await fetch(base + "/api/v1/health");
  assert.equal(response.status, 200);
  const payload = await response.json() as { status: string; data_mode: string; intel_count: number; chunk_count: number; qa_mode: string; qa_model: string; qa_planner_mode: string };
  assert.equal(payload.status, "ok");
  assert.equal(payload.data_mode, "fixture");
  assert.equal(payload.qa_mode, "template");
  assert.equal(payload.qa_model, "q4-template");
  assert.equal(payload.qa_planner_mode, "rules_only");
  assert.ok(payload.intel_count > 0);
  assert.ok(payload.chunk_count > 0);
});

test("本地演示 API：费用未计量时返回 null 而不是伪造 0", async () => {
  const response = await fetch(base + "/api/v1/metrics/overview");
  const payload = await response.json() as { cost: { total_cny: number | null; daily_budget_cny: number | null; degraded: boolean } };
  assert.equal(payload.cost.total_cny, null);
  assert.equal(payload.cost.daily_budget_cny, null);
  assert.equal(payload.cost.degraded, true);
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
  assert.match(text, /"answer_mode":"template"/);
  assert.ok(text.includes("\"llm_layers\":[]"));
  assert.ok(text.includes("\"layer_fallbacks\":[]"));
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

test("本地演示 API：P-05 多源分值冲突显式进问答答案（不压成单一结论）", async () => {
  const dataset = await loadDataset();
  const target = dataset.intel.find((item) => item.cve_ids.includes("CVE-2021-44228"));
  assert.ok(target, "fixture 语料应含 Log4Shell 情报");
  const outcome = dataset.enrichments.get(target!.intel_id);
  assert.ok(outcome, "fixture 富化应产出 outcome（内存侧带 conflicts 审计字段）");
  // 注入一条多源冲突（真实多源富化才产出；fixture 单源不产，故测试显式注入验证接线）
  outcome!.conflicts = [{
    field: "cvss_v3_base",
    values: [{ source: "nvd", score: 7.5 }, { source: "cna", score: 8.8 }],
    resolved: true,
    rationale: "测试注入：采用 nvd 的 7.5 分；差异源仅作旁证，不改写分值",
  }];
  const conflictServer = createLocalDemoServer(dataset, { diagnosticsDbPath: "tmp/absent-ingest-diagnostics-" + process.pid + ".sqlite" });
  await new Promise<void>((resolve) => conflictServer.listen(0, "127.0.0.1", resolve));
  const conflictBase = "http://127.0.0.1:" + (conflictServer.address() as AddressInfo).port;
  try {
    const response = await fetch(conflictBase + "/api/v1/qa/chat", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ question: "Log4Shell 影响哪些版本？", stream: true }),
    });
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.match(text, /## 来源冲突/, "答案正文必须展示来源冲突段落");
    assert.ok(text.includes("nvd 7.5 vs cna 8.8"), "分歧数值必须对用户可见");
    assert.ok(text.includes("测试注入"), "仲裁理由必须可见");
    assert.match(text, /P-05 冲突保留/, "推理链须记录冲突保留");
  } finally {
    await new Promise<void>((resolve, reject) => conflictServer.close((error) => error ? reject(error) : resolve()));
  }
});

test("本地演示 API：P-03 版本影响结构化查询（确定性规则，非相似度/模型）", async () => {
  const affected = await fetch(base + "/api/v1/qa/version-impact", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ product: "log4j", version: "2.14.1", cve_id: "CVE-2021-44228" }),
  });
  assert.equal(affected.status, 200);
  const hit = await affected.json() as { status: string; rule: string; matched_ranges: string[]; reason: string; vendor_unverified: boolean; data_mode: string };
  assert.equal(hit.data_mode, "fixture");
  assert.equal(hit.status, "affected");
  assert.deepEqual(hit.matched_ranges, ["<=2.14.1"]);
  assert.ok(hit.rule.includes("<=2.14.1"));
  assert.equal(hit.vendor_unverified, true);
  const outside = await fetch(base + "/api/v1/qa/version-impact", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ product: "Spring Framework", version: "5.3.20" }),
  });
  const miss = await outside.json() as { status: string };
  assert.equal(miss.status, "unknown", "fixture 无 Spring 情报 → 无法判定（不等于安全）");
  const bad = await fetch(base + "/api/v1/qa/version-impact", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ product: "log4j" }),
  });
  assert.equal(bad.status, 400, "version 必填");
});

test("本地演示 API：P-03 问答链路带产品+版本槽位时答案含确定性版本判定", async () => {
  const response = await fetch(base + "/api/v1/qa/chat", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ question: "Log4Shell 2.14.1 是否受 CVE-2021-44228 影响？", stream: true }),
  });
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.match(text, /## 版本影响判定（确定性规则）/, "答案必须含确定性版本判定段");
  assert.ok(text.includes("**受影响**"), "判定结论必须显式");
  assert.ok(text.includes("<=2.14.1"), "命中区间必须可见");
  assert.match(text, /P-03 版本影响判定/, "推理链须记录判定来自确定性规则");
});

test("采集诊断 API：无持久化 SQLite 时明确说明 fixture 不是真采集", async () => {
  const response = await fetch(base + "/api/v1/ingest/diagnostics");
  assert.equal(response.status, 200);
  const payload = await response.json() as { database_available: boolean; latest_run: unknown; note?: string };
  assert.equal(payload.database_available, false);
  assert.equal(payload.latest_run, null);
  assert.match(payload.note ?? "", /fixture 演示不等于真实联网采集/);
});

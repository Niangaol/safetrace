import { createHash } from "node:crypto";
import { EventBus, MemoryEventStore, sha256Json, SqliteEventStore } from "@safetrace/shared";
import { test } from "node:test";
import assert from "node:assert/strict";
import { ControlledFetchError, UnsafePageUrlError, fetchPageWithFallback, htmlToText } from "../src/firecrawl.js";
import { extractAdvisoryWithFallback } from "../src/extraction-fallback.js";
import type { PageFetchResult, PageSnapshot } from "../src/firecrawl.js";

function fetchPageNoRobots(url: string, options: Parameters<typeof fetchPageWithFallback>[1]) {
  return fetchPageWithFallback(url, { ...options, respect_robots: false });
}

const allowed = ["vendor.example"];
function response(body: string, status = 200, headers: Record<string, string> = { "content-type": "text/html" }): Response {
  return new Response(body, { status, headers });
}
function page(text: string, title = ""): PageFetchResult {
  const url = "https://vendor.example/advisory/1";
  return {
    source_url: url,
    final_url: url,
    title,
    text,
    fetched_at: "2026-09-29T00:00:00.000Z",
    provider: "direct",
    content_sha256: "a".repeat(64),
    fetched_via: "direct",
    stale: false,
    fallback_reasons: [],
    trace_id: "tr_test",
    lineage_ids: [],
  };
}

 test("allowlist：拒绝未知 host、HTTP 和 IP，且拒绝前不发请求", async () => {
  let called = false;
  const fetchImpl = (async () => { called = true; return response("irrelevant"); }) as unknown as typeof fetch;
  await assert.rejects(fetchPageNoRobots("https://evil.example/a", { enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl }), UnsafePageUrlError);
  await assert.rejects(fetchPageNoRobots("http://vendor.example/a", { enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl }), UnsafePageUrlError);
  await assert.rejects(fetchPageNoRobots("https://127.0.0.1/a", { enabled: true, allowed_hosts: ["127.0.0.1"], fetch_impl: fetchImpl }), UnsafePageUrlError);
  await assert.rejects(fetchPageNoRobots("https://vendor.example/a?api_key=do-not-log", { enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl }), UnsafePageUrlError);
  assert.equal(called, false);
});

test("robots.txt：Disallow 的路径不会进入 direct 或 Firecrawl", async () => {
  const urls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    urls.push(url);
    if (url.endsWith("/robots.txt")) return new Response("User-agent: *\nDisallow: /private\n", { status: 200, headers: { "content-type": "text/plain" } });
    return response("this page should never be requested".repeat(10));
  }) as typeof fetch;
  await assert.rejects(fetchPageWithFallback("https://vendor.example/private/advisory", { enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, firecrawl_api_key: "test-only-key" }), UnsafePageUrlError);
  assert.deepEqual(urls, ["https://vendor.example/robots.txt"]);
});

test("默认关闭：未显式 enabled 时不访问页面", async () => {
  let called = false;
  const fetchImpl = (async () => { called = true; return response("body"); }) as unknown as typeof fetch;
  await assert.rejects(fetchPageNoRobots("https://vendor.example/a", { allowed_hosts: allowed, fetch_impl: fetchImpl }), ControlledFetchError);
  assert.equal(called, false);
});

test("直连：429/5xx 按配置重试后解析 HTML，去除脚本和保留标题", async () => {
  let calls = 0;
  const fetchImpl = (async () => {
    calls += 1;
    if (calls === 1) return response("busy", 503);
    return response("<html><head><title>Security bulletin</title></head><body><script>ignore me</script><h1>Important fix</h1><p>This advisory contains enough text to pass the configured minimum length and names CVE-2024-12345.</p></body></html>");
  }) as unknown as typeof fetch;
  const result = await fetchPageNoRobots("https://vendor.example/advisory/1", {
    enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, direct_retries: 1, retry_delay_ms: 0,
    min_text_chars: 40, now: () => new Date("2026-09-29T00:00:00Z"),
  });
  assert.equal(calls, 2);
  assert.equal(result.fetched_via, "direct");
  assert.equal(result.title, "Security bulletin");
  assert.ok(result.text.includes("CVE-2024-12345"));
  assert.ok(!result.text.includes("ignore me"));
  assert.equal(result.stale, false);
  assert.equal(result.content_sha256.length, 64);
});

test("redirect：在请求重定向目标前检查 host allowlist", async () => {
  let calls = 0;
  const fetchImpl = (async () => {
    calls += 1;
    return new Response(null, { status: 302, headers: { location: "https://evil.example/next" } });
  }) as unknown as typeof fetch;
  await assert.rejects(fetchPageNoRobots("https://vendor.example/advisory/1", {
    enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl,
  }), UnsafePageUrlError);
  assert.equal(calls, 1);
});

test("Firecrawl：直连只拿到 JS 壳时走官方单页 API 并显式标降级", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const markdown = "# Vendor advisory\n\nCVE-2024-12345 affects the managed product. The vendor has released an update with a clear mitigation path for administrators.";
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    if (url === "https://vendor.example/advisory/1") return response("<html><title>Loading</title><body><div>Loading application...</div></body></html>");
    return new Response(JSON.stringify({ success: true, data: { markdown, metadata: { title: "Vendor advisory", sourceURL: "https://vendor.example/advisory/1" } } }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  const result = await fetchPageNoRobots("https://vendor.example/advisory/1", {
    enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, firecrawl_api_key: "test-only-key", min_text_chars: 50,
    bus, trace_id: "tr_crawl_firecrawl",
  });
  assert.equal(calls.length, 2);
  assert.equal(result.fetched_via, "firecrawl");
  assert.equal(result.degraded_to, "firecrawl");
  assert.ok(result.fallback_reasons.some((failure) => failure.stage === "direct"));
  assert.equal((calls[1]!.init?.headers as Record<string, string>).authorization, "Bearer test-only-key");
  assert.deepEqual(JSON.parse(String(calls[1]!.init?.body)), { url: "https://vendor.example/advisory/1", formats: ["markdown"], onlyMainContent: true });
  assert.equal(result.trace_id, "tr_crawl_firecrawl");
  const lineage = await bus.readLineage("tr_crawl_firecrawl");
  assert.ok(!lineage.some((row) => row.stage === "crawler.robots_check"), "test isolates fetch fallback with robots disabled");
  assert.ok(lineage.some((row) => row.stage === "crawler.direct_fetch" && row.status === "degraded"));
  assert.ok(lineage.some((row) => row.stage === "crawler.firecrawl" && row.status === "success"));
  assert.ok(!JSON.stringify(lineage).includes("CVE-2024-12345 affects"), "lineage stores hashes, not page text");
});

test("last-good snapshot：SQLite 跨进程重启供 crawler 显式 stale 回退", async () => {
  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  const dbPath = path.join(process.cwd(), "tmp", "crawler-last-good-" + process.pid + "-" + Date.now() + ".sqlite");
  await fs.mkdir(path.dirname(dbPath), { recursive: true });
  const pageText = "Vendor advisory CVE-2024-34567 affects releases before the fixed version. Administrators should upgrade immediately.";
  const firstStore = new SqliteEventStore(dbPath);
  const firstBus = new EventBus({ store: firstStore });
  const firstFetch = (async () => response("<html><title>Vendor advisory</title><body><p>" + pageText + "</p></body></html>")) as typeof fetch;
  const fresh = await fetchPageNoRobots("https://vendor.example/advisory/1", {
    enabled: true, allowed_hosts: allowed, fetch_impl: firstFetch, min_text_chars: 60, bus: firstBus, trace_id: "tr_snapshot_first",
  });
  assert.equal(fresh.fetched_via, "direct");
  firstStore.close();

  const secondStore = new SqliteEventStore(dbPath);
  const secondBus = new EventBus({ store: secondStore });
  try {
    const failFetch = (async () => response("unavailable", 503)) as typeof fetch;
    const stale = await fetchPageNoRobots("https://vendor.example/advisory/1", {
      enabled: true, allowed_hosts: allowed, fetch_impl: failFetch, direct_retries: 0, min_text_chars: 60, bus: secondBus, trace_id: "tr_snapshot_second",
    });
    assert.equal(stale.fetched_via, "last_good");
    assert.equal(stale.stale, true);
    assert.equal(stale.content_sha256, fresh.content_sha256);
    const records = await secondBus.readLineage("tr_snapshot_second");
    const lookup = records.find((record) => record.stage === "crawler.snapshot_lookup");
    const fallback = records.find((record) => record.stage === "crawler.last_good");
    assert.ok(lookup && fallback);
    assert.ok(fallback.parent_lineage_ids.some((id) => fresh.lineage_ids.includes(id)), "stale fallback links to the original successful fetch lineage");
  } finally {
    secondStore.close();
    for (const suffix of ["", "-wal", "-shm"]) await fs.rm(dbPath + suffix, { force: true });
  }
});

test("最后成功快照：Firecrawl 未配置时显式 stale 回退，不回放 fixture", async () => {
  const lastGood: PageSnapshot = {
    source_url: "https://vendor.example/advisory/1",
    final_url: "https://vendor.example/advisory/1",
    title: "Old security advisory",
    text: "A previously saved page with enough text for the stale last-good snapshot fallback path.",
    fetched_at: "2026-09-28T00:00:00.000Z",
    provider: "direct",
    content_sha256: createHash("sha256").update("A previously saved page with enough text for the stale last-good snapshot fallback path.").digest("hex"),
  };
  const fetchImpl = (async () => response("<html><body>Loading</body></html>")) as unknown as typeof fetch;
  const result = await fetchPageNoRobots(lastGood.source_url, {
    enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, min_text_chars: 50, last_good: lastGood,
  });
  assert.equal(result.fetched_via, "last_good");
  assert.equal(result.stale, true);
  assert.equal(result.degraded_to, "last_good_snapshot");
  assert.ok(result.fallback_reasons.some((failure) => failure.stage === "firecrawl"));
});

test("last-good：SHA-256 不匹配时不返回损坏快照", async () => {
  const text = "A previously saved page with enough text for the stale last-good snapshot fallback path.";
  const lastGood: PageSnapshot = {
    source_url: "https://vendor.example/advisory/1", final_url: "https://vendor.example/advisory/1",
    title: "Old", text, fetched_at: "2026-09-28T00:00:00.000Z", provider: "direct", content_sha256: "0".repeat(64),
  };
  const fetchImpl = (async () => response("<div>Loading</div>")) as unknown as typeof fetch;
  await assert.rejects(fetchPageNoRobots(lastGood.source_url, { enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, min_text_chars: 50, last_good: lastGood }), ControlledFetchError);
});

test("Firecrawl：返回跨域 canonical URL 时 fail-closed", async () => {
  const fetchImpl = (async (input: string | URL | Request) => {
    if (String(input) === "https://vendor.example/advisory/1") return response("<div>Loading</div>");
    return new Response(JSON.stringify({ success: true, data: { markdown: "x".repeat(100), metadata: { sourceURL: "https://evil.example/redirected" } } }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  await assert.rejects(fetchPageNoRobots("https://vendor.example/advisory/1", {
    enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, firecrawl_api_key: "test-only-key", min_text_chars: 50,
  }), UnsafePageUrlError);
});

test("Firecrawl API：未允许的 API host 不得接收 token", async () => {
  let calls = 0;
  const fetchImpl = (async () => { calls += 1; return response("<div>Loading</div>"); }) as unknown as typeof fetch;
  await assert.rejects(fetchPageNoRobots("https://vendor.example/advisory/1", {
    enabled: true,
    allowed_hosts: allowed,
    fetch_impl: fetchImpl,
    firecrawl_api_key: "test-only-key",
    firecrawl_base_url: "https://evil.example/v2/scrape",
  }), UnsafePageUrlError);
  assert.equal(calls, 1, "只允许直连；未向未知 API host 发送密钥");
});

test("HTML 规则抽取：完整 CVE 证据返回待 DQ1 candidate", async () => {
  const source = page("CVE-2024-12345 allows remote code execution in affected releases. Administrators should upgrade to version 4.2.0.", "Vendor security bulletin");
  const result = await extractAdvisoryWithFallback(source, { llm: async () => { throw new Error("rules should win"); } });
  assert.equal(result.status, "candidate");
  if (result.status !== "candidate") return;
  assert.equal(result.extracted_by, "rules");
  assert.equal(result.next_step, "DQ1");
  assert.deepEqual(result.candidate.cve_ids, ["CVE-2024-12345"]);
  assert.ok(source.text.includes(result.candidate.summary));
});

test("LLM fallback：没有 A-03/A-04 安全门时不调用模型，转人工态", async () => {
  let calls = 0;
  const source = page("The vendor has published a security update with details for administrators.");
  const result = await extractAdvisoryWithFallback(source, { llm: async () => { calls += 1; return {}; } });
  assert.equal(result.status, "needs_human_review");
  assert.equal(calls, 0);
});

test("LLM fallback：gate 拒绝时不调用模型", async () => {
  let calls = 0;
  const source = page("CVE-2024-98765 was reported. The vendor advisory describes remote code execution in product X.");
  const result = await extractAdvisoryWithFallback(source, {
    safety_gate: async () => false,
    llm: async () => { calls += 1; return {}; },
  });
  assert.equal(result.status, "needs_human_review");
  assert.equal(calls, 0);
});

test("LLM fallback：输出必须是原文可验证证据，否则进入人工复核", async () => {
  const text = "CVE-2024-98765 was reported. The vendor advisory describes remote code execution in product X.";
  const source = page(text);
  const llm = async () => ({
    title: "remote code execution in product X",
    summary: "The vendor advisory describes remote code execution in product X.",
    cve_ids: ["CVE-2024-98765"],
    confidence: 0.93,
    evidence_quotes: ["The vendor advisory describes remote code execution in product X."],
  });
  const accepted = await extractAdvisoryWithFallback(source, { safety_gate: async () => true, llm });
  assert.equal(accepted.status, "candidate");
  if (accepted.status === "candidate") assert.equal(accepted.extracted_by, "llm");
  const fabricated = await extractAdvisoryWithFallback(source, {
    safety_gate: async () => true,
    llm: async () => ({ title: "Made up title", summary: "Made up fact", cve_ids: ["CVE-2024-98765"], confidence: 0.99, evidence_quotes: ["Made up fact"] }),
  });
  assert.equal(fabricated.status, "needs_human_review");
});

test("crawler→snapshot→rules→human queue：SQLite restart keeps page, case and decision lineage", async () => {
  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  const dbPath = path.join(process.cwd(), "tmp", "crawl-review-chain-" + process.pid + "-" + Date.now() + ".sqlite");
  await fs.mkdir(path.dirname(dbPath), { recursive: true });
  const text = "The vendor announced a security update and recommends administrators install the latest release immediately.";
  const fetchImpl = (async () => response("<html><title>Security update</title><body>" + text + "</body></html>")) as typeof fetch;
  const traceId = "tr_crawl_review_chain";
  let store: SqliteEventStore | undefined = new SqliteEventStore(dbPath);
  let reopened: SqliteEventStore | undefined;
  try {
    const bus = new EventBus({ store });
    const fetched = await fetchPageNoRobots("https://vendor.example/advisory/queue", {
      enabled: true, allowed_hosts: allowed, fetch_impl: fetchImpl, min_text_chars: 50, bus, trace_id: traceId,
    });
    const extraction = await extractAdvisoryWithFallback(fetched, { bus, trace_id: traceId });
    assert.equal(extraction.status, "needs_human_review");
    assert.ok(extraction.review_id);
    assert.equal((await bus.listPendingReviewCases()).length, 1);
    store.close();
    store = undefined;

    reopened = new SqliteEventStore(dbPath);
    const reopenedBus = new EventBus({ store: reopened });
    const pending = await reopenedBus.listPendingReviewCases();
    assert.equal(pending[0]?.review_id, extraction.review_id);
    const snapshot = await reopenedBus.getLastGoodPageSnapshotByHash(fetched.content_sha256);
    assert.equal(snapshot?.content_sha256, fetched.content_sha256);
    assert.ok(snapshot?.text.includes("recommends administrators"));
    const records = await reopenedBus.readLineage(traceId);
    const stages = new Set(records.map((record) => record.stage));
    for (const stage of ["crawler.snapshot_persist", "extract.rules", "extract.review_required", "extract.review_case_queued"]) assert.ok(stages.has(stage));
    const review = pending[0]!;
    const decision = { action: "accepted" as const, reviewer_id: "test-reviewer", rationale: "verified against the saved vendor page" };
    const decisionLineage = await reopenedBus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: [review.lineage_id],
      stage: "human.review_decision",
      operation_version: "human-review-cli.v1",
      status: "success",
      input_refs: [{ kind: "ReviewCase", id: review.review_id, sha256: sha256Json({ review_id: review.review_id, page_sha256: review.page_sha256 }) }],
      output_refs: [{ kind: "ReviewDecision", id: review.review_id, sha256: sha256Json(decision) }],
      decision: { reason: decision.rationale },
    });
    assert.equal(await reopenedBus.appendReviewCaseDecision({
      review_id: review.review_id, trace_id: traceId, ...decision, lineage_id: decisionLineage.lineage_id, recorded_at: new Date().toISOString(),
    }), true);
    assert.equal((await reopenedBus.getReviewCase(review.review_id))?.status, "accepted");
    assert.equal((await reopenedBus.listPendingReviewCases()).length, 0);
  } finally {
    store?.close();
    reopened?.close();
    for (const suffix of ["", "-wal", "-shm"]) await fs.rm(dbPath + suffix, { force: true });
  }
});

test("extraction lineage：规则转人工状态只存原文哈希和原因", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const source = page("The vendor published details for a security update with recommended actions.");
  const result = await extractAdvisoryWithFallback(source, { bus, trace_id: "tr_extract_review" });
  assert.equal(result.status, "needs_human_review");
  const records = await bus.readLineage("tr_extract_review");
  assert.deepEqual(records.map((row) => row.stage), ["extract.rules", "extract.review_required", "extract.review_case_queued"]);
  assert.ok(result.status === "needs_human_review" && result.review_id);
  const pending = await bus.listPendingReviewCases();
  assert.equal(pending.length, 1);
  assert.equal(pending[0]!.review_id, result.review_id);
  assert.equal(pending[0]!.page_sha256, source.content_sha256);
  assert.ok(records[0]!.input_refs.some((ref) => ref.sha256 === source.content_sha256));
  assert.ok(!JSON.stringify(records).includes("recommended actions"));
});

test("extraction lineage：通过 gate 的 LLM 输出记录 provider/hash 并经引用验证", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const source = page("CVE-2024-98765 was reported. The vendor advisory describes remote code execution in product X.");
  const summary = "The vendor advisory describes remote code execution in product X.";
  const result = await extractAdvisoryWithFallback(source, {
    bus,
    trace_id: "tr_extract_llm",
    safety_gate: async () => true,
    llm_execution: { provider: "test", model_id: "mock-extractor", model_version: "v1", prompt_sha256: "d".repeat(64) },
    llm: async () => ({ title: "remote code execution in product X", summary, cve_ids: ["CVE-2024-98765"], confidence: 0.93, evidence_quotes: [summary] }),
  });
  assert.equal(result.status, "candidate");
  const records = await bus.readLineage("tr_extract_llm");
  const llm = records.find((row) => row.stage === "extract.llm");
  assert.equal(llm?.execution?.model_id, "mock-extractor");
  assert.equal(llm?.execution?.prompt_sha256, "d".repeat(64));
  assert.ok(records.some((row) => row.stage === "extract.validate" && row.status === "success"));
  assert.ok(!JSON.stringify(records).includes(summary));
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import { runControlledPage } from "../src/controlled-page.js";

const url = "https://vendor.example/advisory";
function metadata() {
  return { source: { source_id: "registered_vendor", source_type: "vendor_advisory", url, status: "active", poll_interval_s: 3600, rate_per_min: 5, requires_api_key: false }, published_at: "2026-09-28T00:00:00Z", source_reliability: 0.9 };
}
function options(text = "CVE-2024-12345 affects the vendor product and administrators should install the fixed release.") {
  const store = new MemoryEventStore(); const bus = new EventBus({ store }); const calls: string[] = [];
  const fetcher = (async input => {
    const target = String(input); calls.push(target);
    return new Response(target.endsWith("/robots.txt") ? "User-agent: *\nAllow: /" : "<html><title>Vendor advisory</title><body>" + text + "</body></html>", { status: 200, headers: { "content-type": target.endsWith("/robots.txt") ? "text/plain" : "text/html" } });
  }) as typeof fetch;
  return { store, bus, calls, opts: { enabled: true, allowed_hosts: ["vendor.example"], respect_robots: true, fetch_impl: fetcher, bus, trace_id: "tr_controlled", min_text_chars: 40 } };
}

test("enabled ingestion rejects missing or mismatched metadata before robots/page requests", async () => {
  for (const value of [undefined, { ...metadata(), published_at: "" }, { ...metadata(), source_reliability: 2 }, { ...metadata(), source: { ...metadata().source, url: "https://other.example/advisory" } }]) {
    const o = options();
    await assert.rejects(runControlledPage(url, { ...o.opts, ingest_enabled: true, metadata: value }));
    assert.equal(o.calls.length, 0);
    assert.equal((await o.store.read("raw.docs")).length, 0);
    assert.ok((await o.bus.readLineage(o.opts.trace_id)).some(r => r.stage === "crawler.page_metadata" && r.status === "rejected"));
  }
});

test("controlled robots → fetch → rules → DQ1 → source evidence shares lineage", async () => {
  const o = options();
  const run = await runControlledPage(url, { ...o.opts, ingest_enabled: true, metadata: metadata() });
  assert.equal(run.admission?.status, "accepted");
  assert.equal(run.evidence?.chunks.length, 1);
  assert.deepEqual(o.calls, ["https://vendor.example/robots.txt", url]);
  assert.equal((await o.store.read("intel.items")).length, 1);
  const rows = await o.bus.readLineage(o.opts.trace_id);
  const meta = rows.find(r => r.stage === "crawler.page_metadata")!;
  assert.ok(rows.find(r => r.stage === "crawler.allowlist")!.parent_lineage_ids.includes(meta.lineage_id));
  for (const stage of ["crawler.robots_check", "crawler.direct_fetch", "extract.rules", "ingest.page_dq1", "ingest.evidence_chunks"]) assert.ok(rows.some(r => r.stage === stage));
});

test("default remains preview-only and incomplete rule output stays in human queue", async () => {
  const preview = options();
  const result = await runControlledPage(url, { ...preview.opts, metadata: metadata() });
  assert.equal(result.admission, undefined);
  assert.equal((await preview.store.read("intel.items")).length, 0);
  const o = options("The vendor published a security update; administrators should upgrade to the newest release.");
  const run = await runControlledPage(url, { ...o.opts, ingest_enabled: true, metadata: metadata() });
  assert.equal(run.extraction.status, "needs_human_review");
  assert.equal(run.admission?.status, "rejected");
  assert.equal((await o.store.read("intel.items")).length, 0);
  assert.equal((await o.bus.listPendingReviewCases()).length, 1);
});

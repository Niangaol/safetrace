import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, MemoryEventStore, SqliteEnrichmentStateStore, enrichmentInputHash } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { runEnrichment, EnrichmentCommitRejected, type EnrichmentCommitCheck } from "../src/index.js";

const item: IntelItem = { intel_id: "intel_guard", title: "Log4Shell remote code execution", cve_ids: ["CVE-2021-44228"], source_ids: ["nvd_cve"], published_at: "2021-12-10T00:00:00Z", first_seen_at: "2026-10-01T00:00:00Z", raw_refs: [], source_reliability: 0.9, schema_version: "1.0", entities: { product: "log4j", vendor: "apache", version_range: [], cwe: [], cpes: [] } };
const scoreSources = [{ source_of_score: "nvd" as const, cvss_v3_base: 10, cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }];
const now = new Date("2026-10-04T00:00:00Z");
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; };
const epssResponse = { ok: true, status: 200, text: async () => "", json: async () => ({ data: [{ cve: "CVE-2021-44228", epss: "0.42", percentile: "0.85", date: "2026-10-04" }] }) };

for (const mode of ["false", "throw"] as const) test("publish guard " + mode + " preserves last-good and state, with no success event", async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  const events = new MemoryEventStore(); const bus = new EventBus({ store: events });
  try {
    await runEnrichment([item], { stateStore, bus, now, offline: true, scoreSources });
    const cvss = stateStore.get(item.intel_id, "cvss")!;
    stateStore.put({ ...cvss, status: "failed", retry_after: null });
    const before = stateStore.list(); assert.ok(stateStore.get(item.intel_id, "cvss")!.last_good);
    const count = (await events.read("enrich.items")).length;
    await assert.rejects(runEnrichment([item], { stateStore, bus, now, scoreSources, dimensions: ["cvss"], beforeCommit: async check => {
      if (check.phase === "publish") { if (mode === "throw") throw new Error("read unavailable"); return false; }
      return true;
    } }), EnrichmentCommitRejected);
    assert.deepEqual(stateStore.list(), before);
    assert.equal((await events.read("enrich.items")).length, count);
  } finally { stateStore.close(); }
});

test("version or quarantine change during await prevents old F6 publication", async () => {
  for (const reason of ["update", "quarantine"] as const) {
    const stateStore = new SqliteEnrichmentStateStore(":memory:");
    const events = new MemoryEventStore(); const bus = new EventBus({ store: events });
    let current = "event_old", accepted = true; const entered = deferred(), release = deferred();
    const guard = async (check: EnrichmentCommitCheck) => check.intel_event_id === current && accepted;
    try {
      const work = runEnrichment([item], { stateStore, bus, now, dimensions: ["epss"], causation_by_intel_id: { [item.intel_id]: "event_old" }, beforeCommit: guard,
        fetchImpl: async () => { entered.resolve(); await release.promise; return epssResponse; } });
      const rejected = assert.rejects(work, EnrichmentCommitRejected);
      await entered.promise;
      if (reason === "update") current = "event_new"; else accepted = false;
      release.resolve(); await rejected;
      assert.deepEqual(stateStore.list(), []); assert.equal((await events.read("enrich.items")).length, 0);
    } finally { stateStore.close(); }
  }
});

test("new in-flight version commits while late old work cannot overwrite it", async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  const events = new MemoryEventStore(); const bus = new EventBus({ store: events });
  const entered = deferred(), release = deferred(); let current = "old";
  const guard = async (check: EnrichmentCommitCheck) => check.intel_event_id === current;
  try {
    const old = runEnrichment([item], { stateStore, bus, now, dimensions: ["epss"], beforeCommit: guard, causation_by_intel_id: { [item.intel_id]: "old" }, fetchImpl: async () => { entered.resolve(); await release.promise; return epssResponse; } });
    const rejected = assert.rejects(old, EnrichmentCommitRejected);
    await entered.promise; current = "new";
    const updated = { ...item, title: "Updated Log4Shell facts" };
    await runEnrichment([updated], { stateStore, bus, now, offline: true, dimensions: ["cvss"], scoreSources, beforeCommit: guard, causation_by_intel_id: { [item.intel_id]: "new" } });
    const good = stateStore.list(); release.resolve(); await rejected;
    assert.deepEqual(stateStore.list(), good);
    assert.equal(stateStore.get(item.intel_id, "cvss")!.input_hash, enrichmentInputHash(updated));
    assert.equal((await events.read("enrich.items")).length, 1);
  } finally { stateStore.close(); }
});

test("slow model advisory cannot publish old F6 artifacts after a new item version", { timeout: 3000 }, async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  const events = new MemoryEventStore(); const bus = new EventBus({ store: events });
  const entered = deferred(), release = deferred(); let current = "old";
  const atom = '<feed xmlns="http://www.w3.org/2005/Atom">' + ["2609.10001", "2609.10002"].map(id => '<entry><id>http://arxiv.org/abs/' + id + '</id><published>2026-09-01T00:00:00Z</published><title>Log4Shell remote code execution study</title><summary>Log4j CVE-2021-44228 remote code execution security research.</summary></entry>').join("") + '</feed>';
  try {
    const work = runEnrichment([item], { stateStore, bus, now, dimensions: ["paper"], causation_by_intel_id: { [item.intel_id]: "old" }, beforeCommit: async check => check.intel_event_id === current,
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => atom, json: async () => ({}) }),
      paperReviewer: async () => { entered.resolve(); await release.promise; return { status: "abstained", reason: "mock advisory only" }; } });
    const rejected = assert.rejects(work, EnrichmentCommitRejected);
    await entered.promise; current = "new"; release.resolve(); await rejected;
    // The earlier papers event is append-only history, not a committed current enrichment.
    assert.equal((await events.read("enrich.papers")).length, 1);
    assert.equal((await events.read("enrich.items")).length, 0); assert.deepEqual(stateStore.list(), []);
  } finally { release.resolve(); stateStore.close(); }
});

test("state fence rejects post-publication version change without mutating sidecars", async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  const events = new MemoryEventStore(); const bus = new EventBus({ store: events });
  try {
    await runEnrichment([item], { stateStore, now, offline: true, scoreSources, dimensions: ["cvss"] });
    const before = stateStore.list();
    await assert.rejects(runEnrichment([{ ...item, title: "changed" }], { stateStore, bus, now, offline: true, scoreSources, dimensions: ["cvss"], beforeCommit: async check => check.phase !== "states" }), EnrichmentCommitRejected);
    assert.deepEqual(stateStore.list(), before);
    // Events and sidecars are not one transaction. Projection/version verification is required.
    assert.equal((await events.read("enrich.items")).length, 1);
  } finally { stateStore.close(); }
});

test("two-item batch pins facts before awaits and independently fences second item", async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  const items = [structuredClone(item), { ...structuredClone(item), intel_id: "intel_second" }];
  const entered = deferred(), release = deferred(); const expectedSecondHash = enrichmentInputHash(items[1]!);
  let secondCurrentHash = expectedSecondHash;
  try {
    const work = runEnrichment(items, { stateStore, now, dimensions: ["epss"], beforeCommit: async check => check.item.intel_id !== "intel_second" || check.input_hash === secondCurrentHash,
      fetchImpl: async () => { entered.resolve(); await release.promise; return epssResponse; } });
    const rejected = assert.rejects(work, EnrichmentCommitRejected);
    await entered.promise; items[1]!.title = "mutated outside running batch"; secondCurrentHash = enrichmentInputHash(items[1]!); release.resolve(); await rejected;
    assert.ok(stateStore.get(item.intel_id, "epss")); assert.equal(stateStore.get("intel_second", "epss"), undefined);
  } finally { stateStore.close(); }
});

test("captured source byte update during work is fenced before F6 publish", async () => {
  const dir = mkdtempSync(join(tmpdir(), "enrich-guard-")); const raw = join(dir, "source.json");
  writeFileSync(raw, JSON.stringify({ revision: 1 }));
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  const events = new MemoryEventStore(); const bus = new EventBus({ store: events });
  const recordLineage = bus.recordLineage.bind(bus);
  bus.recordLineage = async input => {
    const receipt = await recordLineage(input);
    if (input.stage === "enrich.f4") writeFileSync(raw, JSON.stringify({ revision: 2 }));
    return receipt;
  };
  try {
    await assert.rejects(runEnrichment([{ ...item, raw_refs: [raw] }], { stateStore, bus, now, dimensions: ["cvss"] }), EnrichmentCommitRejected);
    assert.deepEqual(stateStore.list(), []); assert.equal((await events.read("enrich.items")).length, 0);
  } finally { stateStore.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("changed score dependency stays historical during EPS-only retry", async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  try {
    await runEnrichment([item], { stateStore, now, offline: true, scoreSources, dimensions: ["cvss"] });
    const old = stateStore.get(item.intel_id, "cvss");
    const result = await runEnrichment([item], { stateStore, now, scoreSources: [], dimensions: ["epss"], fetchImpl: async () => epssResponse });
    assert.deepEqual(stateStore.get(item.intel_id, "cvss"), old);
    assert.equal(result[0]!.artifacts.score_assessment, undefined);
    assert.equal(stateStore.get(item.intel_id, "epss")!.status, "live");
  } finally { stateStore.close(); }
});

test("EPS-only scope never runs missing CVSS or paper and does not rebind old-version states", async () => {
  const stateStore = new SqliteEnrichmentStateStore(":memory:");
  try {
    await runEnrichment([item], { stateStore, now, offline: true, scoreSources, dimensions: ["cvss"] });
    const old = stateStore.get(item.intel_id, "cvss");
    await runEnrichment([{ ...item, title: "new version" }], { stateStore, now, dimensions: ["epss"], fetchImpl: async url => { assert.match(url, /epss/); return epssResponse; } });
    assert.deepEqual(stateStore.get(item.intel_id, "cvss"), old);
    assert.equal(stateStore.get(item.intel_id, "paper"), undefined);
  } finally { stateStore.close(); }
});

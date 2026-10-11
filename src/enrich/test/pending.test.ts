import { test } from "node:test";
import assert from "node:assert/strict";
import { enrichmentInputHash, sha256Json } from "@safetrace/shared";
import type { IntelItem, EnrichmentResult, QualityVerdict, EnrichmentDimensionState } from "@safetrace/shared";
import { nextArxivFailureStreak, planPendingEnrichment } from "../src/pending.js";
const item = (id: string, title = id): IntelItem => ({
  intel_id: id, title, cve_ids: [], source_ids: [], published_at: "2026-10-01T00:00:00Z",
  first_seen_at: "2026-10-01T00:00:00Z", raw_refs: [], source_reliability: 0.8, schema_version: "1.0",
  entities: { product: "test", vendor: "test", version_range: [], cwe: [], cpes: [] },
});
const verdict = (id: string, value: QualityVerdict["verdict"]): QualityVerdict => ({
  item_id: id, item_kind: "intel", quality_score: 0.8,
  dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 },
  flags: [], verdict: value, gate_version: "test.v1",
});
const state = (intel: IntelItem, dimension: EnrichmentDimensionState["dimension"], patch: Partial<EnrichmentDimensionState> = {}): EnrichmentDimensionState => ({
  intel_id: intel.intel_id, dimension, status: "live", input_hash: enrichmentInputHash(intel), result_hash: sha256Json(null), artifact: null,
  enrich_event_id: "receipt", intel_event_id: "current", retry_after: null, attempts: 1, reason: "test", updated_at: "2026-10-04T00:00:00Z", ...patch,
});
const enrichment = (id: string): EnrichmentResult => ({
  intel_id: id, dimensions_completed: [], dimensions_failed: ["paper", "cvss"], artifacts: {},
  enrichment_score: 0, completed_at: "2026-10-03T00:00:00Z", schema_version: "1.0",
});
test("arXiv cutoff counts consecutive fallback items, not retry attempts or EPSS failures", () => {
  let streak = 0;
  for (let i = 0; i < 3; i++) streak = nextArxivFailureStreak(streak, [{ trigger: "arxiv_http_429" }, { trigger: "arxiv_fetch_failed" }]);
  assert.equal(streak, 3);
  assert.equal(nextArxivFailureStreak(streak, []), 0);
  assert.equal(nextArxivFailureStreak(streak, [{ trigger: "epss_fetch_failed" }]), 0);
});

test("resumption respects the latest quarantine even after a historical pass", () => {
  const plan = planPendingEnrichment([item("a")], [verdict("a", "pass"), verdict("a", "quarantine")], []);
  assert.equal(plan.accepted_ids, 0);
  assert.deepEqual(plan.pending, []);
});
test("resumption selects latest unique intel and retries unknown recorded dimensions", () => {
  const plan = planPendingEnrichment([item("a", "old"), item("b"), item("a", "new")], [verdict("a", "pass"), verdict("b", "degrade")], [enrichment("b"), enrichment("b")]);
  assert.equal(plan.unique_intel_ids, 2);
  assert.equal(plan.already_enriched, 1);
  assert.equal(plan.recorded_with_failed_dimensions, 1);
  assert.equal(plan.pending[0]!.title, "new");
  assert.deepEqual(plan.pending.map(row => row.intel_id), ["a", "b"]);
});
test("resumption refuses unknown DQ and honors a later release", () => {
  const plan = planPendingEnrichment([item("a"), item("unknown")], [verdict("a", "quarantine"), verdict("a", "pass")], []);
  assert.deepEqual(plan.pending.map(row => row.intel_id), ["a"]);
});

test("only due failed dimensions enter selective retry; fresh dimensions remain untouched", () => {
  const a = item("a");
  const states = [state(a, "paper", { status: "failed", retry_after: "2026-10-04T00:05:00Z" }), state(a, "cvss"), state(a, "epss", { status: "failed", retry_after: "2026-10-04T01:00:00Z" })];
  const plan = planPendingEnrichment([a], [verdict("a", "pass")], [enrichment("a")], { states, now: new Date("2026-10-04T00:06:00Z") });
  assert.deepEqual(plan.pending_dimensions.get("a"), ["paper"]);
  assert.equal(plan.pending.length, 1);
});

test("new facts/source bindings precede historical failed backlogs and latest versions are unique", () => {
  const backlog = item("backlog"), old = item("updated", "old"), updated = item("updated", "new"), newItem = item("new");
  const states = [state(backlog, "cvss", { status: "failed" }), state(old, "cvss")];
  const plan = planPendingEnrichment([backlog, old, newItem, updated], [verdict("backlog", "pass"), verdict("updated", "pass"), verdict("new", "pass")], [], { states, dimensions: ["cvss"], now: new Date("2026-10-04T00:06:00Z") });
  assert.deepEqual(plan.pending.map(i => i.intel_id), ["updated", "new", "backlog"]);
  assert.equal(plan.pending[0]!.title, "new");
  const sourceUpdated = planPendingEnrichment([backlog, old], [verdict("backlog", "pass"), verdict("updated", "pass")], [], { states, dimensions: ["cvss"], currentIntelEventIds: new Map([["backlog", "current"], ["updated", "new-source-event"]]), now: new Date("2026-10-04T00:06:00Z") });
  assert.deepEqual(sourceUpdated.pending.map(i => i.intel_id), ["updated", "backlog"]);
});

test("changed captured source dependency is due before TTL without forcing paper/EPSS", () => {
  const a = item("a");
  const states = [state(a, "paper"), state(a, "cvss", { dependency_hash: "old" }), state(a, "epss")];
  const plan = planPendingEnrichment([a], [verdict("a", "pass")], [], { states, cvssDependencyHashes: new Map([["a", "new"]]), now: new Date("2026-10-04T00:06:00Z") });
  assert.deepEqual(plan.pending_dimensions.get("a"), ["cvss"]);
});

test("current non-live states without matching receipts respect future retry backoff", () => {
  const a = item("a"), now = new Date("2026-10-04T00:06:00Z");
  for (const status of ["failed", "empty", "degraded", "unknown"] as const) {
    for (const enrich_event_id of [null, "old-receipt"] as const) {
      const states = [state(a, "cvss", { status, enrich_event_id, retry_after: "2026-10-04T01:00:00Z", dependency_hash: "same" })];
      const options = { states, now, dimensions: ["cvss"] as const, currentIntelEventIds: new Map([["a", "current"]]), cvssDependencyHashes: new Map([["a", "same"]]), publishedEnrichments: [] };
      const plan = planPendingEnrichment([a], [verdict("a", "pass")], [], options);
      assert.deepEqual(plan.pending_dimensions.get("a"), [], status + ": " + enrich_event_id);
      assert.deepEqual(plan.pending, []);
      const due = planPendingEnrichment([a], [verdict("a", "pass")], [], { ...options, now: new Date("2026-10-04T01:00:00Z") });
      assert.deepEqual(due.pending_dimensions.get("a"), ["cvss"]);
    }
  }
});

test("new source event, changed facts and changed dependency override current non-live backoff", () => {
  const a = item("a"), now = new Date("2026-10-04T00:06:00Z");
  for (const status of ["failed", "empty", "degraded"] as const) {
    const states = [state(a, "cvss", { status, enrich_event_id: null, retry_after: "2026-10-04T01:00:00Z", dependency_hash: "same" })];
    const options = { states, now, dimensions: ["cvss"] as const, currentIntelEventIds: new Map([["a", "current"]]), cvssDependencyHashes: new Map([["a", "same"]]), publishedEnrichments: [] };
    const newEvent = planPendingEnrichment([a], [verdict("a", "pass")], [], { ...options, currentIntelEventIds: new Map([["a", "new-source-event"]]) });
    const newFacts = planPendingEnrichment([{ ...a, title: "changed source facts" }], [verdict("a", "pass")], [], options);
    const newDependency = planPendingEnrichment([a], [verdict("a", "pass")], [], { ...options, cvssDependencyHashes: new Map([["a", "changed"]]) });
    for (const plan of [newEvent, newFacts, newDependency]) assert.deepEqual(plan.pending_dimensions.get("a"), ["cvss"], status);
  }
});

test("live states still force repair for absent or mismatched published receipts before TTL", () => {
  const a = item("a");
  for (const enrich_event_id of [null, "old-receipt"] as const) {
    const plan = planPendingEnrichment([a], [verdict("a", "pass")], [], { states: [state(a, "cvss", { enrich_event_id })], dimensions: ["cvss"], now: new Date("2026-10-04T00:06:00Z"), currentIntelEventIds: new Map([["a", "current"]]), publishedEnrichments: [] });
    assert.deepEqual(plan.pending_dimensions.get("a"), ["cvss"]);
  }
});

test("non-intel DQ cannot override an active intel quarantine", () => {
  const plan = planPendingEnrichment([item("a")], [verdict("a", "quarantine"), { ...verdict("a", "pass"), item_kind: "enriched" }], []);
  assert.deepEqual(plan.pending, []);
});

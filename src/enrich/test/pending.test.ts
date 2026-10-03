import { test } from "node:test";
import assert from "node:assert/strict";
import type { IntelItem, EnrichmentResult, QualityVerdict } from "@safetrace/shared";
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
test("resumption selects latest unique intel and does not repeat recorded items", () => {
  const plan = planPendingEnrichment([item("a", "old"), item("b"), item("a", "new")], [verdict("a", "pass"), verdict("b", "degrade")], [enrichment("b"), enrichment("b")]);
  assert.equal(plan.unique_intel_ids, 2);
  assert.equal(plan.already_enriched, 1);
  assert.equal(plan.recorded_with_failed_dimensions, 1);
  assert.equal(plan.pending[0]!.title, "new");
});
test("resumption refuses unknown DQ and honors a later release", () => {
  const plan = planPendingEnrichment([item("a"), item("unknown")], [verdict("a", "quarantine"), verdict("a", "pass")], []);
  assert.deepEqual(plan.pending.map(row => row.intel_id), ["a"]);
});

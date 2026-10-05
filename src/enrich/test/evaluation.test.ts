import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { evaluatePaperPredictions, loadEvaluationReference, ratio, runEnrichmentEvaluation, summarizeChecks } from "../src/evaluation.js";

const cases = [
  { id: "positive", query: "suffix attack", relevant_ids: ["paper-a", "paper-b"], rationale: "synthetic" },
  { id: "negative", query: "unrelated", relevant_ids: [], rationale: "synthetic" },
];
test("precision/recall@5 use labels, cap rank and retain explicit denominators", () => {
  const result = evaluatePaperPredictions(cases, { positive: ["paper-a", "wrong", "paper-a", "x", "y", "paper-b"], negative: ["wrong"] });
  assert.deepEqual(result.precision_at_5, ratio(1, 10));
  assert.deepEqual(result.recall_at_5, ratio(1, 2));
  assert.deepEqual(result.returned_precision, ratio(1, 6));
  assert.deepEqual(result.negative_false_positive_rate, ratio(1, 1));
  assert.equal(result.badcases.length, 2);
  assert.equal(result.cases[0]!.duplicates, 1);
  assert.deepEqual(result.cases[0]!.false_negatives, ["paper-b"]);
});
test("missing/abstain negative outputs cannot be credited as correct", () => {
  for (const predictions of [{}, { positive: null, negative: null }]) {
    const result = evaluatePaperPredictions(cases, predictions);
    assert.deepEqual(result.exact_case_accuracy, ratio(0, 2));
    assert.deepEqual(result.negative_correct, ratio(0, 1));
    assert.deepEqual(result.recall_at_5, ratio(0, 2));
    assert.equal(result.badcases.length, 2);
  }
  assert.deepEqual(evaluatePaperPredictions([cases[1]!], { negative: [] }).negative_correct, ratio(1, 1));
  assert.deepEqual(ratio(0, 0), { numerator: 0, denominator: 0, value: null });
});
test("synthetic correctness cannot hide missing or abstain denominators", () => {
  const report = summarizeChecks([
    { id: "a", expected: 1, actual: 1, status: "correct" },
    { id: "b", expected: 1, actual: null, status: "missing" },
    { id: "c", expected: 1, actual: null, status: "abstain" },
  ]);
  assert.deepEqual(report.accuracy, ratio(1, 3));
  assert.equal(report.badcases.length, 2);
});
test("official metadata and proposed labels are independent of Log4Shell fixture", async () => {
  const reference = await loadEvaluationReference();
  assert.equal(reference.label_status, "agent-proposed");
  assert.equal(reference.review_status, "待人工复核");
  assert.equal(reference.blind_test, false);
  assert.equal(reference.papers.length, 3);
  assert.ok(reference.papers.every(p => p.source_url.startsWith("https://arxiv.org/abs/") && p.fetched_at === "2026-10-04"));
  assert.ok(!JSON.stringify(reference).includes("Log4Shell"));
  assert.ok(reference.paper_cases.some(c => c.relevant_ids.length === 0));
});
test("offline evaluation separates real metadata replay from synthetic algorithm checks", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = process.env.OFFLINE_FIXTURES;
  process.env.OFFLINE_FIXTURES = "true";
  const dir = await mkdtemp(join(tmpdir(), "safetrace-evaluation-report-"));
  try {
    const report = await runEnrichmentEvaluation();
    assert.deepEqual(report.safety, { model_calls: 0, live_requests: 0, unexpected_fetch_attempts: 0, production_writes: 0 });
    assert.equal(report.paper_association.live_cases, 0);
    assert.deepEqual(report.paper_association.precision_at_5, ratio(3, 20));
    assert.deepEqual(report.paper_association.recall_at_5, ratio(3, 3));
    assert.equal(report.candidate_ranking_baseline.badcases.length, 4); // ranking-only intentionally retains candidates
    assert.deepEqual(report.paper_association.returned_precision, ratio(3, 3));
    assert.equal(report.paper_association.badcases.length, 0); // actual entity/topic publication policy is measured separately
    assert.deepEqual(report.paper_association.negative_false_positive_rate, ratio(0, 1));
    const synthetic = report.synthetic_regressions;
    assert.deepEqual(synthetic.cvss_specification.accuracy, ratio(9, 9));
    assert.deepEqual(synthetic.cvss_identity.accuracy, ratio(5, 5));
    assert.deepEqual(synthetic.epss_validation_and_degradation.accuracy, ratio(12, 12));
    assert.equal(synthetic.epss_validation_and_degradation.fixture_is_live, false);
    const output = join(dir, "report.json");
    await writeFile(output, JSON.stringify(report));
    assert.equal(JSON.parse(await readFile(output, "utf8")).blind_test, false);
    assert.equal(globalThis.fetch, originalFetch);
    assert.equal(process.env.OFFLINE_FIXTURES, "true");
  } finally {
    if (originalEnv === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = originalEnv;
    await rm(dir, { recursive: true, force: true });
  }
});
test("CLI import has no execution, environment changes or stdout output", async () => {
  const before = globalThis.fetch;
  const env = process.env.OFFLINE_FIXTURES;
  const imported = await import("../../../scripts/enrich-evaluate.js");
  assert.equal(typeof imported.main, "function");
  assert.equal(globalThis.fetch, before);
  assert.equal(process.env.OFFLINE_FIXTURES, env);
});
test("reference loader rejects fabricated official evidence and unknown labels", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-reference-"));
  try {
    const reference = await loadEvaluationReference();
    reference.papers[0]!.source_url = "";
    const path = join(dir, "bad-reference.json");
    await writeFile(path, JSON.stringify(reference));
    await assert.rejects(loadEvaluationReference(path), /URL and fetch date/);
    reference.papers[0]!.metadata_status = "synthetic";
    reference.paper_cases[0]!.relevant_ids = ["invented-paper"];
    await writeFile(path, JSON.stringify(reference));
    await assert.rejects(loadEvaluationReference(path), /Invalid evaluation case/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

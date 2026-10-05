/** Offline quality evaluation. No provider, collector, event store or production database imports. */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IntelItem } from "@safetrace/shared";
import { parseArxivAtom, anchoredPapers, arxivPaperRecords } from "./f1-papers.js";
import { loadScoreSourcesFromRawRefs, lookupEpss, parseCvssV31Vector, type HttpFetcher } from "./f4-cvss.js";

export interface ReferencePaper {
  paper_id: string; title: string; summary: string; published_at: string;
  authors: string[]; source_url: string; fetched_at: string;
  metadata_status: "official-metadata-verified" | "synthetic";
}
export interface PaperCase { id: string; query: string; relevant_ids: string[]; rationale: string }
export interface EvaluationReference {
  schema_version: "1.0"; label_status: "agent-proposed"; review_status: "待人工复核";
  blind_test: false; scope: string; papers: ReferencePaper[]; paper_cases: PaperCase[];
}
export interface Ratio { numerator: number; denominator: number; value: number | null }
export const ratio = (numerator: number, denominator: number): Ratio => ({
  numerator, denominator, value: denominator ? numerator / denominator : null,
});
export interface CheckCase {
  id: string; expected: unknown; actual: unknown;
  status: "correct" | "incorrect" | "missing" | "abstain"; reason?: string;
}
export function summarizeChecks(cases: CheckCase[]) {
  return { accuracy: ratio(cases.filter(c => c.status === "correct").length, cases.length),
    missing: cases.filter(c => c.status === "missing").length,
    abstain: cases.filter(c => c.status === "abstain").length, cases,
    badcases: cases.filter(c => c.status !== "correct") };
}
/** Missing prediction is not an explicit negative prediction. Duplicates cannot earn extra hits. */
export function evaluatePaperPredictions(cases: PaperCase[], predictions: Record<string, string[] | null | undefined>) {
  const details = cases.map(c => {
    const raw = predictions[c.id];
    const missing = !Array.isArray(raw);
    const top = missing ? [] : raw.slice(0, 5);
    const unique = [...new Set(top)];
    const relevant = new Set(c.relevant_ids);
    const hits = unique.filter(id => relevant.has(id));
    const falsePositives = unique.filter(id => !relevant.has(id));
    const falseNegatives = [...relevant].filter(id => !unique.includes(id));
    const duplicates = top.length - unique.length;
    const status = missing ? (raw === null ? "abstain" : "missing")
      : falsePositives.length || falseNegatives.length || duplicates ? "incorrect" : "correct";
    return { id: c.id, query: c.query, status, expected: c.relevant_ids, actual: top,
      precision_at_5: ratio(hits.length, 5), recall_at_5: ratio(hits.length, relevant.size),
      hits: hits.length, false_positives: falsePositives, false_negatives: falseNegatives, duplicates };
  });
  const hits = details.reduce((n, c) => n + c.hits, 0);
  const negatives = details.filter(c => c.expected.length === 0);
  return { precision_at_5: ratio(hits, cases.length * 5),
    recall_at_5: ratio(hits, cases.reduce((n, c) => n + new Set(c.relevant_ids).size, 0)),
    returned_precision: ratio(hits, details.reduce((n, c) => n + c.actual.length, 0)),
    exact_case_accuracy: ratio(details.filter(c => c.status === "correct").length, cases.length),
    negative_false_positive_rate: ratio(negatives.filter(c => c.actual.length > 0).length, negatives.length),
    negative_correct: ratio(negatives.filter(c => c.status === "correct").length, negatives.length),
    missing: details.filter(c => c.status === "missing").length,
    abstain: details.filter(c => c.status === "abstain").length, cases: details,
    badcases: details.filter(c => c.status !== "correct") };
}
export async function loadEvaluationReference(path: string | URL = new URL("../../../fixtures/enrich/evaluation.reference.v1.json", import.meta.url)): Promise<EvaluationReference> {
  const data = JSON.parse(await readFile(path, "utf8")) as EvaluationReference;
  if (data.schema_version !== "1.0" || data.label_status !== "agent-proposed" || data.review_status !== "待人工复核" || data.blind_test !== false || !Array.isArray(data.papers) || !Array.isArray(data.paper_cases)) throw new Error("Invalid evaluation reference or misleading label status");
  const ids = new Set<string>();
  for (const p of data.papers) {
    if (!p.paper_id || ids.has(p.paper_id) || typeof p.title !== "string" || typeof p.summary !== "string" || typeof p.published_at !== "string" || !Array.isArray(p.authors)) throw new Error("Invalid/duplicate reference paper");
    ids.add(p.paper_id);
    if (p.metadata_status !== "synthetic" && (p.metadata_status !== "official-metadata-verified" || !/^https:\/\//.test(p.source_url) || !/^\d{4}-\d{2}-\d{2}$/.test(p.fetched_at))) throw new Error("Official metadata requires URL and fetch date");
  }
  const caseIds = new Set<string>();
  for (const c of data.paper_cases) {
    if (!c.id || caseIds.has(c.id) || typeof c.query !== "string" || !c.query.trim() || !Array.isArray(c.relevant_ids) || c.relevant_ids.some(id => !ids.has(id))) throw new Error("Invalid evaluation case");
    caseIds.add(c.id);
  }
  return data;
}
function xml(value: string) { return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }
/** Official metadata is replayed as bounded Atom input; this is NOT a live arXiv search. */
export function referenceAtom(papers: ReferencePaper[]): string {
  return "<feed>" + papers.map(p => "<entry><id>https://arxiv.org/abs/" + xml(p.paper_id.replace(/^arXiv:/, "")) + "</id><title>" + xml(p.title) + "</title><summary>" + xml(p.summary) + "</summary><published>" + xml(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(p.published_at) ? p.published_at + "T00:00:00Z" : p.published_at) + "</published></entry>").join("") + "</feed>";
}
const VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N";
const TARGET = "CVE-2099-10001"; // synthetic identity, not an assertion of a real CVE
function item(ref: string): IntelItem {
  return { intel_id: "evaluation-synthetic", cve_ids: [TARGET], source_ids: ["nvd_cve"], title: "Synthetic identity regression",
    published_at: "2026-10-04T00:00:00Z", first_seen_at: "2026-10-04T00:00:00Z",
    entities: { product: "synthetic", vendor: "synthetic", version_range: [], cwe: [], cpes: [] },
    raw_refs: [ref], source_reliability: 0.9, schema_version: "1.0" };
}
const nvd = (id: string | undefined, vector: string, base: number) => ({ cve: {
  ...(id ? { id } : {}), metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { vectorString: vector, baseScore: base } }] },
} });
function check(id: string, expected: unknown, actual: unknown): CheckCase {
  return { id, expected, actual, status: actual === undefined ? "missing" : JSON.stringify(actual) === JSON.stringify(expected) ? "correct" : "incorrect" };
}
let evaluationRunning = false;
export async function runEnrichmentEvaluation(input?: EvaluationReference) {
  const reference = input ?? await loadEvaluationReference();
  if (evaluationRunning) throw new Error("Evaluation must run in a dedicated process, not concurrently");
  const guardUrl = new URL("../../../scripts/test-network-guard.mjs", import.meta.url).href;
  await import(guardUrl);
  if (evaluationRunning) throw new Error("Evaluation must run in a dedicated process, not concurrently");
  evaluationRunning = true;
  let unexpectedFetchAttempts = 0;
  const fetchBefore = globalThis.fetch;
  const offlineBefore = process.env.OFFLINE_FIXTURES;
  // API parser regressions use injected in-memory responses, never the global transport.
  process.env.OFFLINE_FIXTURES = "false";
  globalThis.fetch = async () => { unexpectedFetchAttempts++; throw new Error("EVALUATION_NETWORK_FORBIDDEN"); };
  let dir: string | undefined;
  try {
    dir = await mkdtemp(join(tmpdir(), "safetrace-evaluation-"));
    const raw = join(dir, "synthetic-raw.json");
    const atom = referenceAtom(reference.papers);
    const rankingPredictions = Object.fromEntries(reference.paper_cases.map(c => [c.id, parseArxivAtom(atom, c.query).map(p => p.paper_id)]));
    const records = arxivPaperRecords(atom);
    const predictions = Object.fromEntries(reference.paper_cases.map(c => [c.id, anchoredPapers({ title: c.query, cve_ids: [], entities: { product: null, vendor: null, version_range: [], cwe: [], cpes: [] } }, parseArxivAtom(atom, c.query), records).map(p => p.paper_id)]));
    const cvss: CheckCase[] = [];
    const vectors: Array<[string, string, number | "reject"]> = [
      ["network-critical", VECTOR, 9.8], ["network-low", LOW, 3.7],
      ["scope-changed-low-privilege", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9],
      ["scope-unchanged-low-privilege", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8],
      ["zero-impact", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0],
      ["missing-metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "reject"],
      ["duplicate-metric", VECTOR + "/AV:N", "reject"],
      ["invalid-value", VECTOR.replace("AV:N", "AV:X"), "reject"],
      ["wrong-version", VECTOR.replace("3.1", "3.0"), "reject"],
    ];
    for (const [id, vector, expected] of vectors) {
      let actual: unknown; try { actual = parseCvssV31Vector(vector).baseScore; } catch { actual = "reject"; }
      cvss.push(check(id, expected, actual));
    }
    const identity: CheckCase[] = [];
    const fixtures: Array<[string, unknown, unknown]> = [
      ["batch-target-not-first", { vulnerabilities: [nvd("CVE-2099-10002", VECTOR, 9.8), nvd(TARGET, LOW, 3.7)] }, [LOW]],
      ["unrelated-cve", { vulnerabilities: [nvd("CVE-2099-10002", VECTOR, 9.8)] }, []],
      ["unbound-identity", { vulnerabilities: [nvd(undefined, VECTOR, 9.8)] }, []],
      ["osv-alias", { results: [{ vulns: [{ id: "GHSA-synthetic", aliases: [TARGET], severity: [{ type: "CVSS_V3", score: LOW }] }] }] }, [LOW]],
      ["cna-identity", { cveMetadata: { cveId: TARGET }, containers: { cna: { metrics: [{ cvssV3_1: { vectorString: LOW, baseScore: 3.7 } }] } } }, [LOW]],
    ];
    for (const [id, doc, expected] of fixtures) {
      await writeFile(raw, JSON.stringify(doc));
      const role = id === "osv-alias" ? "ghsa" : id === "cna-identity" ? "cna" : "nvd";
      const expectedBound = (expected as string[]).map(vector => ({ cve_id: TARGET, source: role, vector }));
      const actualBound = (await loadScoreSourcesFromRawRefs(item(raw))).map(s => ({ cve_id: s.cve_id, source: s.source_of_score, vector: s.cvss_v3_vector }));
      identity.push(check(id, expectedBound, actualBound));
    }
    const epss: CheckCase[] = [];
    const invalidCases: Array<[string, unknown]> = [
      ["negative", { cve: TARGET, epss: -0.1, percentile: 0.5 }],
      ["over-one", { cve: TARGET, epss: 1.1, percentile: 0.5 }],
      ["blank", { cve: TARGET, epss: "", percentile: 0.5 }],
      ["boolean", { cve: TARGET, epss: true, percentile: 0.5 }],
      ["null", { cve: TARGET, epss: null, percentile: 0.5 }],
      ["not-finite", { cve: TARGET, epss: "NaN", percentile: 0.5 }],
      ["invalid-percentile", { cve: TARGET, epss: 0.1, percentile: 2 }],
      ["wrong-cve", { cve: "CVE-2099-10002", epss: 0.1, percentile: 0.5 }],
    ];
    const mock: (payload: unknown) => HttpFetcher = payload => async () => ({ ok: true, status: 200, text: async () => "", json: async () => payload });
    for (const [id, row] of invalidCases) {
      const result = await lookupEpss(TARGET, { offline: false, fetchImpl: mock({ data: [row] }) });
      epss.push(check(id, { score: null, percentile: null, degraded: "fixture" }, { score: result.epss_score, percentile: result.epss_percentile, degraded: result.degraded_to }));
    }
    const duplicate = await lookupEpss(TARGET, { offline: false, fetchImpl: mock({ data: [{ cve: TARGET, epss: 0.2, percentile: 0.5 }, { cve: TARGET, epss: 0.3, percentile: 0.6 }] }) });
    epss.push(check("duplicate-cve", { score: null, degraded: "fixture" }, { score: duplicate.epss_score, degraded: duplicate.degraded_to }));
    const offline = await lookupEpss(TARGET, { offline: true, fetchImpl: async () => { throw new Error("offline must not call mock"); } });
    epss.push(check("offline-degradation", { score: null, degraded: "fixture" }, { score: offline.epss_score, degraded: offline.degraded_to }));
    const failure = await lookupEpss(TARGET, { offline: false, fetchImpl: async () => { throw new Error("synthetic timeout"); } });
    epss.push(check("transport-degradation", { score: null, degraded: "fixture" }, { score: failure.epss_score, degraded: failure.degraded_to }));
    const valid = await lookupEpss(TARGET, { offline: false, fetchImpl: mock({ data: [{ cve: TARGET, epss: "0.25", percentile: "0.75", date: "2026-10-04" }] }) });
    epss.push(check("valid-mock-values", { score: 0.25, percentile: 0.75, receiptCve: TARGET }, { score: valid.epss_score, percentile: valid.epss_percentile, receiptCve: valid.receipt?.cve_id }));
    if (unexpectedFetchAttempts) throw new Error("Evaluation attempted global network transport");
    return { schema_version: "1.0", label_status: "agent-proposed", review_status: "待人工复核", blind_test: false,
      warning: "非盲测；提议标签未人工复核；不代表赛题准确率或线上覆盖率", mode: "offline-reference-replay",
      safety: { model_calls: 0, live_requests: 0, unexpected_fetch_attempts: unexpectedFetchAttempts, production_writes: 0 },
      reference_metadata: { official_papers: reference.papers.filter(p => p.metadata_status === "official-metadata-verified").length,
        synthetic_papers: reference.papers.filter(p => p.metadata_status === "synthetic").length,
        sources: reference.papers.map(p => ({ paper_id: p.paper_id, url: p.source_url, fetched_at: p.fetched_at })) },
      candidate_ranking_baseline: { dataset: "reference-metadata-replay", policy: "ranking-only; not published association", ...evaluatePaperPredictions(reference.paper_cases, rankingPredictions) },
      paper_association: { dataset: "reference-metadata-replay", policy: "actual entity-and-topic publication filter", live_cases: 0, ...evaluatePaperPredictions(reference.paper_cases, predictions) },
      synthetic_regressions: { cvss_specification: summarizeChecks(cvss),
        cvss_calculation: summarizeChecks(cvss.filter(c => typeof c.expected === "number")),
        cvss_invalid_vector_rejection: summarizeChecks(cvss.filter(c => c.expected === "reject")),
        cvss_identity: summarizeChecks(identity),
        epss_invalid_value_rejection: summarizeChecks(epss.filter(c => invalidCases.some(([id]) => id === c.id) || c.id === "duplicate-cve")),
        epss_degradation_recognition: summarizeChecks(epss.filter(c => ["offline-degradation", "transport-degradation"].includes(c.id))),
        epss_validation_and_degradation: { live_cases: 0, fixture_is_live: false, ...summarizeChecks(epss) } } };
  } finally {
    globalThis.fetch = fetchBefore;
    evaluationRunning = false;
    if (offlineBefore === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = offlineBefore;
    if (dir) await rm(dir, { recursive: true, force: true });
  }
}

import { test } from "node:test";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { parseNvd } from "../../ingest/src/adapters/nvd.js";
import assert from "node:assert/strict";
import { sha256, sha256Json } from "@safetrace/shared";
import type { EnrichmentResult, IntelItem, LineageRecord, QualityVerdict, RawDoc } from "@safetrace/shared";
import { projectKnowledgeEvidence } from "../src/knowledge-projection.js";
import type { KnowledgeProjectionInput, KnowledgeEvent, KnowledgeEnrichmentState } from "../src/knowledge-projection.js";
import { MemoryIndex } from "../src/q2-retrieval.js";
import { classifyIntent } from "../src/q1-intent.js";
import { synthesizeAnswer } from "../src/q4-answer.js";

const date = "2026-10-03T00:00:00Z", cve = "CVE-2024-12345";
const description = "Actual original vendor vulnerability description. Separate-record-only evidence.";
const paperTitle = "Quantum Marmalade Vulnerability Correlation";
const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
function line(id: string, patch: Partial<LineageRecord>): LineageRecord {
  return { lineage_id: id, trace_id: "tr_test", parent_lineage_ids: [], causation_id: null, stage: "test", operation_version: "test.v1", status: "success", started_at: date, completed_at: date, recorded_at: date, input_refs: [], output_refs: [], ...patch };
}
function setup() {
  const payload = { vulnerabilities: [{ cve: { id: cve, published: date, descriptions: [{ lang: "en", value: description }], metrics: { cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { vectorString: vector, baseScore: 9.8 } }] } } }, { cve: { id: "CVE-2024-99999", published: date, descriptions: [{ lang: "en", value: "Alien unrelated record must not leak" }], metrics: {} } }] };
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const raw: RawDoc = { source_id: "src_nvd", source_type: "nvd_cve", external_id: "batch", url: "https://services.nvd.nist.gov/rest/json/cves/2.0", fetched_at: date, content_type: "json", payload_ref: "tmp/live-nvd.json" };
  const item: IntelItem = { intel_id: "intel_n07", title: "Merged Intel Title", summary: "Old merged synthetic summary must never appear as raw text", cve_ids: [cve], source_ids: [raw.source_id], raw_refs: [raw.payload_ref], published_at: date, first_seen_at: date, source_reliability: 0.9, entities: { vendor: null, product: null, version_range: [], cwe: [], cpes: [] }, schema_version: "1.0" };
  const dq: QualityVerdict = { item_id: item.intel_id, item_kind: "intel", quality_score: 0.95, dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 }, flags: [], verdict: "pass", gate_version: "dq1.v1" };
  const result: EnrichmentResult = { intel_id: item.intel_id, dimensions_completed: ["paper", "cvss"], dimensions_failed: [], artifacts: { papers: [{ paper_id: "2601.01234", source: "arxiv", title: paperTitle, year: 2026, relevance_score: 0.9, confidence: 0.95 }], score_assessment: { cvss_v3_vector: vector, cvss_v3_base: 9.8, source_of_score: "nvd" } }, enrichment_score: 0.95, completed_at: date, schema_version: "1.0" };
  const event = (seq: number, topic: KnowledgeEvent["topic"], payload: unknown, cause: string | null): KnowledgeEvent => ({ seq, event_id: "ev_" + seq, trace_id: "tr_test", causation_id: cause, topic, payload });
  const events = [event(1, "raw.docs", raw, null), event(2, "intel.items", item, "ev_1"), event(3, "dq.verdicts", dq, "ev_2"), event(4, "enrich.items", result, "ev_2")];
  const rawId = "raw:" + raw.source_id + ":" + raw.external_id;
  const lineage = [line("ln_raw", { stage: "ingest.fetch", source: { source_id: raw.source_id, source_type: raw.source_type, url: raw.url }, output_refs: [{ kind: "RawDoc", id: rawId, sha256: sha256Json(raw) }, { kind: "RawPayload", id: "payload:" + rawId, sha256: sha256(bytes) }] }), line("ln_dq", { causation_id: "ev_3", input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }], output_refs: [{ kind: "QualityVerdict", id: "dq:" + item.intel_id, sha256: sha256Json(dq) }] }), line("ln_enrich", { causation_id: "ev_4", parent_lineage_ids: ["ln_dq"], input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }], output_refs: [{ kind: "EnrichmentResult", id: item.intel_id, sha256: sha256Json(result) }] })];
  const state: KnowledgeEnrichmentState = { intel_id: item.intel_id, mode: "live", status: "success", inputHash: sha256Json(item), resultHash: sha256Json(result), enrich_event_id: "ev_4", lineage_ids: ["ln_enrich"], artifacts: [{ key: "paper:2601.01234", artifactHash: sha256Json(result.artifacts.papers![0]), url: "https://arxiv.org/abs/2601.01234", published_at: date, trust: "trusted" }, { key: "cvss", artifactHash: sha256Json(result.artifacts.score_assessment), url: raw.url, published_at: date, trust: "trusted", raw_ref: raw.payload_ref, cve_id: cve }] };
  const input: KnowledgeProjectionInput = { events, lineage, enrichment_states: [state], read_raw_payload: async r => { assert.equal(r.payload_ref, raw.payload_ref); return bytes; }, read_page_snapshot: async () => undefined };
  return { input, item, raw, dq, result, state, events, lineage, bytes, payload, event };
}

test("N07 actual raw record and CVSS ground the projection; original and derived hashes stay separate", async () => {
  const s = setup(), projected = await projectKnowledgeEvidence(s.input);
  assert.equal(projected.chunks.length, 3, JSON.stringify(projected.rejected));
  const source = projected.evidence.find(e => e.kind === "source")!;
  const actual = JSON.parse(new TextDecoder().decode(s.bytes)).vulnerabilities[0].cve;
  assert.equal(source.chunk.text, cve + "\n" + actual.descriptions[0].value);
  assert.equal(source.original_sha256, sha256(s.bytes));
  assert.equal(source.text_sha256, sha256(source.chunk.text));
  assert.notEqual(source.text_sha256, source.original_sha256);
  assert.equal(source.chunk.trust, "untrusted");
  assert.ok(projected.chunks.every(c => !c.text.includes(s.item.summary!) && !c.text.includes("Alien unrelated")));
  const score = projected.evidence.find(e => e.kind === "cvss")!;
  assert.ok(score.chunk.text.includes(String(actual.metrics.cvssMetricV31[0].cvssData.baseScore)));
  assert.ok(score.chunk.text.includes(actual.id));
  assert.ok(score.parent_lineage_ids.includes("ln_raw") && score.parent_lineage_ids.includes("ln_enrich"));
});

test("N07 artifact-only facts are recalled by MemoryIndex and cited by Q4 with a model mock", async () => {
  const projected = await projectKnowledgeEvidence(setup().input), index = new MemoryIndex();
  await index.upsert(projected.chunks);
  for (const [query, doc_type] of [[paperTitle, "paper"], ["9.8 CVSS", "enrichment"]] as const) {
    assert.ok(!projected.chunks.find(c => c.doc_type === "vuln_advisory")!.text.includes(query));
    const recalled = await index.search({ query_id: "q_n07", query_text: query, top_k: 1, trace_id: "tr_qa", schema_version: "1.0" });
    assert.equal(recalled.chunks[0]!.doc_type, doc_type);
    let calls = 0;
    const question = doc_type === "paper" ? "这篇论文讲了什么？" : "CVE-2024-12345 的影响是什么？";
    const plan = classifyIntent({ session_id: "s", turn_id: "t", text: question });
    const answer = await synthesizeAnswer(question, { ...plan, needs_clarify: false }, recalled, { now: new Date(date), synth: { synthesize: (_q, _p, evidence) => {
      calls++; assert.equal(evidence.chunks[0]!.chunk_id, recalled.chunks[0]!.chunk_id);
      return { session_id: "s", turn_id: "t", text_md: evidence.chunks[0]!.text + " [1]", citations: evidence.chunks.map(c => ({ chunk_id: c.chunk_id, url: c.provenance.url, quote: c.text })), reasoning_chain: [], confidence: 0.95, abstained: false };
    } }, synthesizer: { provider: "mock", model_id: "mock" } });
    assert.equal(calls, 1); assert.equal(answer.abstained, false);
    assert.equal(answer.citations[0]!.chunk_id, recalled.chunks[0]!.chunk_id);
    assert.equal(answer.citations[0]!.url, recalled.chunks[0]!.provenance.url);
    assert.ok(answer.text_md.includes(query.split(" ")[0]!));
  }
});

test("N07 latest quarantine/review and stale DQ revoke all chunks before readers run", async () => {
  for (const verdict of ["quarantine", "review"] as const) {
    const s = setup(); s.events.push(s.event(5, "dq.verdicts", { ...s.dq, verdict }, "ev_2"));
    s.input.read_raw_payload = async () => { throw new Error("must not read revoked raw"); };
    const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 0); assert.match(p.rejected[0]!.reason, /not released/);
  }
  const s = setup(); s.events.push(s.event(5, "intel.items", { ...s.item, title: "new version" }, "ev_1"));
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 0);
});

test("N07 fixture, unknown, missing hashes, event rebinding and bad lineage never release enrichment", async () => {
  for (const patch of [{ mode: "fixture" }, { mode: "unknown" }, { inputHash: "" }, { resultHash: "" }, { status: "review" }, { enrich_event_id: "ev_99" }, { lineage_ids: [] }] as Partial<KnowledgeEnrichmentState>[]) {
    const s = setup(); Object.assign(s.state, patch);
    const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 1); assert.ok(p.rejected.some(r => r.scope === "enrichment"));
  }
  const s = setup(); s.lineage[2]!.status = "degraded";
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 1);
});

test("N07 accepted input version update still excludes old artifact result", async () => {
  const s = setup(), changed = { ...s.item, title: "Changed input" };
  s.events.push(s.event(5, "intel.items", changed, "ev_1"), s.event(6, "dq.verdicts", s.dq, "ev_5"));
  s.lineage.push(line("ln_dq_new", { causation_id: "ev_6", input_refs: [{ kind: "IntelItem", id: changed.intel_id, sha256: sha256Json(changed) }], output_refs: [{ kind: "QualityVerdict", id: changed.intel_id, sha256: sha256Json(s.dq) }] }));
  const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 1); assert.ok(p.rejected.some(r => /binding/.test(r.reason)));
});

test("N07 raw SHA, URL, source identity, missing ref, record CVE and fixture are individually verified", async () => {
  for (const mutation of [
    (s: ReturnType<typeof setup>) => { s.input.read_raw_payload = async () => new TextEncoder().encode(JSON.stringify({ ...s.payload, extra: true })); },
    (s: ReturnType<typeof setup>) => { s.raw.url = "https://wrong.example/data"; },
    (s: ReturnType<typeof setup>) => { s.raw.source_id = "wrong_source"; },
    (s: ReturnType<typeof setup>) => { s.raw.payload_ref = "tmp/unrelated.json"; },
    (s: ReturnType<typeof setup>) => { s.payload.vulnerabilities[0]!.cve.id = "CVE-2024-77777"; s.input.read_raw_payload = async () => new TextEncoder().encode(JSON.stringify(s.payload)); },
    (s: ReturnType<typeof setup>) => { s.lineage[0]!.decision = { fallback_to: "fixture" }; },
  ]) { const s = setup(); mutation(s); const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 0, JSON.stringify(p.rejected)); }
});

test("N07 CVSS cannot borrow an unrelated record score even with consistent result hashes", async () => {
  for (const [field, value] of [["cvss_v3_base", 10], ["cvss_v3_vector", "CVSS:3.1/AV:L"], ["source_of_score", "cna"]] as const) {
    const s = setup(); Object.assign(s.result.artifacts.score_assessment!, { [field]: value });
    s.state.resultHash = sha256Json(s.result); s.lineage[2]!.output_refs[0]!.sha256 = s.state.resultHash;
    s.state.artifacts[1]!.artifactHash = sha256Json(s.result.artifacts.score_assessment);
    const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 2); assert.ok(p.rejected.some(r => /actual raw payload/.test(r.reason)));
  }
  const s = setup(); s.state.artifacts[1]!.cve_id = "CVE-2024-99999";
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 2);
});

test("N07 NVD bulk 报文原文收录的 CNA 评分：内容逐字比对成立即放行（1908 条误拒修复）", async () => {
  const s = setup(), cna = "cna@example.com";
  // NVD bulk 报文里除 NIST 主评分外，原文收录 CNA（sourceIdentifier）提交的评分
  const record = s.payload.vulnerabilities[0]!.cve as unknown as { sourceIdentifier?: string; metrics: { cvssMetricV31: { source: string; cvssData: { baseScore: number } }[] } };
  record.sourceIdentifier = cna;
  record.metrics.cvssMetricV31[0]!.source = cna;
  const bytes = new TextEncoder().encode(JSON.stringify(s.payload));
  s.input.read_raw_payload = async () => bytes;
  s.lineage[0]!.output_refs[1]!.sha256 = sha256(bytes); // 报文变了，RawPayload 血缘哈希同步
  Object.assign(s.result.artifacts.score_assessment!, { source_of_score: "cna" });
  s.state.resultHash = sha256Json(s.result);
  s.lineage[2]!.output_refs[0]!.sha256 = s.state.resultHash;
  s.state.artifacts[1]!.artifactHash = sha256Json(s.result.artifacts.score_assessment);
  const p = await projectKnowledgeEvidence(s.input);
  assert.equal(p.chunks.length, 3, JSON.stringify(p.rejected));
  const score = p.evidence.find(e => e.kind === "cvss")!;
  assert.ok(score.chunk.text.includes(String(record.metrics.cvssMetricV31[0]!.cvssData.baseScore)));
  assert.ok(score.chunk.text.includes('"source_of_score":"cna"'), score.chunk.text);
  assert.equal(score.raw_ref, s.raw.payload_ref);
});

test("N07 配对放行不放宽内容比对：CNA 评分与报文数值不一致仍拒绝", async () => {
  const s = setup(), cna = "cna@example.com";
  const record = s.payload.vulnerabilities[0]!.cve as unknown as { sourceIdentifier?: string; metrics: { cvssMetricV31: { source: string; cvssData: { baseScore: number } }[] } };
  record.sourceIdentifier = cna;
  record.metrics.cvssMetricV31[0]!.source = cna;
  record.metrics.cvssMetricV31[0]!.cvssData.baseScore = 4.2;
  const bytes = new TextEncoder().encode(JSON.stringify(s.payload));
  s.input.read_raw_payload = async () => bytes;
  s.lineage[0]!.output_refs[1]!.sha256 = sha256(bytes);
  Object.assign(s.result.artifacts.score_assessment!, { source_of_score: "cna" });
  s.state.resultHash = sha256Json(s.result);
  s.lineage[2]!.output_refs[0]!.sha256 = s.state.resultHash;
  s.state.artifacts[1]!.artifactHash = sha256Json(s.result.artifacts.score_assessment);
  const p = await projectKnowledgeEvidence(s.input);
  assert.equal(p.chunks.length, 2, JSON.stringify(p.rejected));
  assert.ok(p.rejected.some(r => /actual raw payload/.test(r.reason)));
});

test("N07 artifact metadata is not guessed, including trust, URL, date and hash", async () => {
  for (const patch of [{ trust: undefined }, { published_at: "2026-10-03" }, { artifactHash: "" }, { url: "https://evil.example/paper" }]) {
    const s = setup(); Object.assign(s.state.artifacts[0]!, patch);
    const p = await projectKnowledgeEvidence(s.input); assert.ok(!p.chunks.some(c => c.doc_type === "paper"));
  }
});

test("N07 controlled page reads Snapshot, honors reverse DQ causation, rejects altered snapshot", async () => {
  const s = setup(), text = "Vendor original page " + cve + " fixes available", hash = sha256(text);
  s.raw.source_type = "vendor_advisory"; s.raw.payload_ref = "sqlite-page:" + hash; s.raw.external_id = hash; s.raw.content_type = "text"; s.raw.url = "https://vendor.example/advisory";
  s.item.raw_refs = [s.raw.payload_ref]; s.item.intel_id = "intel_page_n07"; s.dq.item_id = s.item.intel_id;
  s.input.events = [s.event(1, "raw.docs", s.raw, null), s.event(2, "dq.verdicts", s.dq, "ev_1"), s.event(3, "intel.items", s.item, "ev_2")];
  s.input.lineage = [line("ln_page", { source: { source_id: s.raw.source_id, source_type: s.raw.source_type, url: s.raw.url }, output_refs: [{ kind: "RawPageSnapshot", id: s.raw.payload_ref, sha256: hash }] }), line("ln_page_dq", { causation_id: "ev_2", input_refs: [{ kind: "IntelItem", id: s.item.intel_id, sha256: sha256Json(s.item) }], output_refs: [{ kind: "QualityVerdict", id: s.item.intel_id, sha256: sha256Json(s.dq) }] })];
  const page = { source_url: s.raw.url, final_url: s.raw.url, title: "Vendor", text, fetched_at: date, provider: "direct" as const, content_sha256: hash, lineage_ids: ["ln_page"] };
  s.input.read_page_snapshot = async h => { assert.equal(h, hash); return page; };
  s.input.read_raw_payload = async () => { throw new Error("page must not use filesystem raw reader"); };
  const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 1, JSON.stringify(p.rejected)); assert.equal(p.chunks[0]!.text, text); assert.equal(p.chunks[0]!.doc_type, "vendor_advisory");
  page.text += " tampered"; assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 0);
});

test("N07 existing NVD adapter and temp raw bytes independently agree on source description/CVE", async () => {
  const s = setup(), dir = await mkdtemp(path.join(tmpdir(), "n07-raw-"));
  const file = path.join(dir, "payload.json");
  try {
    await writeFile(file, s.bytes);
    const parsed = await parseNvd({ ...s.raw, payload_ref: file });
    const record = parsed.items.find(i => i.cve_ids.includes(cve))!;
    assert.equal(record.summary, description);
    s.input.read_raw_payload = async () => await readFile(file);
    const projected = await projectKnowledgeEvidence(s.input);
    const source = projected.chunks.find(c => c.doc_type === "vuln_advisory")!;
    assert.ok(source.text.includes(record.summary!) && source.text.includes(record.cve_ids[0]!));
    assert.ok(!source.text.includes(s.item.summary!));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("N07 enriched review/quarantine revokes artifacts without poisoning intel DQ", async () => {
  for (const verdict of ["review", "quarantine"] as const) {
    const s = setup(); s.events.push(s.event(5, "dq.verdicts", { ...s.dq, item_kind: "enriched", verdict }, "ev_4"));
    const p = await projectKnowledgeEvidence(s.input);
    assert.equal(p.chunks.length, 1); assert.match(p.rejected[0]!.reason, /enriched DQ/);
  }
});

test("N07 actual page producer source-less snapshot chain is verified via RawDoc hash", async () => {
  const s = setup(), text = "Original page " + cve, hash = sha256(text);
  Object.assign(s.raw, { source_type: "vendor_advisory", payload_ref: "sqlite-page:" + hash, external_id: hash, content_type: "text", url: "https://vendor.example/advisory" });
  s.item.raw_refs = [s.raw.payload_ref];
  s.input.events = [s.event(1, "raw.docs", s.raw, null), s.event(2, "dq.verdicts", s.dq, "ev_1"), s.event(3, "intel.items", s.item, "ev_2")];
  s.input.lineage = [line("ln_snapshot", { stage: "ingest.page_snapshot", output_refs: [{ kind: "RawPageSnapshot", id: s.raw.payload_ref, sha256: hash }] }), line("ln_raw_publish", { stage: "ingest.page_raw_publish", parent_lineage_ids: ["ln_snapshot"], causation_id: "ev_1", input_refs: [{ kind: "RawPageSnapshot", id: s.raw.payload_ref, sha256: hash }], output_refs: [{ kind: "RawDoc", id: "ev_1", sha256: sha256Json(s.raw) }] }), line("ln_dq", { causation_id: "ev_2", input_refs: [{ kind: "IntelItem", id: s.item.intel_id, sha256: sha256Json(s.item) }], output_refs: [{ kind: "QualityVerdict", id: s.item.intel_id, sha256: sha256Json(s.dq) }] })];
  s.input.read_page_snapshot = async () => ({ source_url: s.raw.url, final_url: s.raw.url, title: "Original", text, fetched_at: date, provider: "direct", content_sha256: hash, lineage_ids: ["ln_snapshot"] });
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 1);
  s.raw.source_id = "spoofed_source"; s.item.source_ids = [s.raw.source_id];
  s.input.lineage[2]!.input_refs[0]!.sha256 = sha256Json(s.item);
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 0);
});

test("N07 each merged source retains its own original text and hash, never shared summary", async () => {
  const s = setup(), secondRaw = { ...s.raw, source_id: "src_nvd_second", payload_ref: "tmp/second-live.json", url: "https://nvd.nist.gov/second-source" };
  const payload = structuredClone(s.payload); payload.vulnerabilities[0]!.cve.descriptions[0]!.value = "Independent second source original prose";
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  s.item.source_ids.push(secondRaw.source_id); s.item.raw_refs.push(secondRaw.payload_ref);
  s.input.events = [s.event(1, "raw.docs", s.raw, null), s.event(2, "raw.docs", secondRaw, null), s.event(3, "intel.items", s.item, "ev_1"), s.event(4, "dq.verdicts", s.dq, "ev_3")];
  const rawId = "raw:" + secondRaw.source_id + ":" + secondRaw.external_id;
  s.input.lineage = [s.lineage[0]!, line("ln_second", { source: { source_id: secondRaw.source_id, source_type: secondRaw.source_type, url: secondRaw.url }, output_refs: [{ kind: "RawDoc", id: rawId, sha256: sha256Json(secondRaw) }, { kind: "RawPayload", id: "payload:" + rawId, sha256: sha256(bytes) }] }), line("ln_dq", { causation_id: "ev_4", input_refs: [{ kind: "IntelItem", id: s.item.intel_id, sha256: sha256Json(s.item) }], output_refs: [{ kind: "QualityVerdict", id: s.item.intel_id, sha256: sha256Json(s.dq) }] })];
  s.input.read_raw_payload = async r => r.payload_ref === secondRaw.payload_ref ? bytes : s.bytes;
  const p = await projectKnowledgeEvidence(s.input); assert.equal(p.chunks.length, 2, JSON.stringify(p.rejected));
  assert.equal(p.chunks.find(c => c.provenance.url === secondRaw.url)!.text, cve + "\nIndependent second source original prose");
  assert.equal(p.chunks.find(c => c.provenance.url === s.raw.url)!.text, cve + "\n" + description);
  assert.notEqual(p.chunks[0]!.provenance.sha256, p.chunks[1]!.provenance.sha256);
});

test("N07 quarantine and fixture replacement indexes cannot recall former artifact-only facts", async () => {
  for (const kind of ["quarantine", "fixture", "updated"] as const) {
    const s = setup();
    if (kind === "quarantine") s.events.push(s.event(5, "dq.verdicts", { ...s.dq, verdict: "quarantine" }, "ev_2"));
    else if (kind === "fixture") s.state.mode = "fixture";
    else { s.events.push(s.event(5, "intel.items", { ...s.item, title: "new version" }, "ev_1")); }
    const index = new MemoryIndex(); await index.upsert((await projectKnowledgeEvidence(s.input)).chunks);
    const response = await index.search({ query_id: "q_revoked", query_text: "Quantum Marmalade", top_k: 5, trace_id: "tr_revoked", schema_version: "1.0" });
    assert.deepEqual(response.chunks, []);
    let calls = 0; const question = "相关论文有哪些？";
    const plan = classifyIntent({ session_id: "s", turn_id: "t", text: question });
    const answer = await synthesizeAnswer(question, { ...plan, needs_clarify: false }, response, { synth: { synthesize: () => { calls++; throw new Error("revoked artifact must not reach model"); } } });
    assert.equal(answer.abstained, true); assert.equal(calls, 0); assert.deepEqual(answer.citations, []);
  }
});

test("N07 valid degraded DQ remains eligible without treating fixture fallback as live", async () => {
  const s = setup(); s.dq.verdict = "degrade"; s.lineage[1]!.status = "degraded";
  s.lineage[1]!.output_refs[0]!.sha256 = sha256Json(s.dq);
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 3);
  s.lineage[1]!.decision = { fallback_to: "fixture" };
  assert.equal((await projectKnowledgeEvidence(s.input)).chunks.length, 0);
});

test("N07 unsorted or duplicate event identities are not implicit latest ordering", async () => {
  const s = setup(); s.input.events = [...s.events].reverse(); await assert.rejects(projectKnowledgeEvidence(s.input), /strictly ordered/);
  s.input.events = [...s.events, { ...s.events[3]!, seq: 5 }]; await assert.rejects(projectKnowledgeEvidence(s.input), /unique identities/);
});

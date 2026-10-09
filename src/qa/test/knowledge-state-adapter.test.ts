import { test } from "node:test";
import assert from "node:assert/strict";
import { enrichmentInputHash, sha256Json } from "@safetrace/shared";
import type { EnrichmentDimensionState, EnrichmentResult, IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import { knowledgeStatesFromDimensions } from "../src/knowledge-state-adapter.js";
import type { KnowledgeEvent } from "../src/knowledge-projection.js";

/**
 * 适配器是投影验证的第一道门：它不产出 cvss artifact，投影再严也看不到。
 * 2026-10-09 实测误拒 1908 条"从 NVD bulk 报文取 CNA 评分"的条目，根因就是这里的
 * source_type 配对规则；内容逐字比对（source/vector/base）才是来源判据。
 */
const date = "2026-10-03T00:00:00Z", cve = "CVE-2024-12345";
const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

function fixture(opts: { scoreSource: "nvd" | "cna"; payloadSource: string; payloadBase: number; scoreBase: number }) {
  const payload = { vulnerabilities: [{ cve: { id: cve, published: date, sourceIdentifier: opts.payloadSource, descriptions: [{ lang: "en", value: "original vendor description" }], metrics: { cvssMetricV31: [{ source: opts.payloadSource, type: "Primary", cvssData: { vectorString: vector, baseScore: opts.payloadBase } }] } } }] };
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const raw: RawDoc = { source_id: "src_nvd", source_type: "nvd_cve", external_id: "batch", url: "https://services.nvd.nist.gov/rest/json/cves/2.0", fetched_at: date, content_type: "json", payload_ref: "tmp/live-nvd.json" };
  const item: IntelItem = { intel_id: "intel_adapter", title: "t", summary: "s", cve_ids: [cve], source_ids: [raw.source_id], raw_refs: [raw.payload_ref], published_at: date, first_seen_at: date, source_reliability: 0.9, entities: { vendor: null, product: null, version_range: [], cwe: [], cpes: [] }, schema_version: "1.0" };
  const dq: QualityVerdict = { item_id: item.intel_id, item_kind: "intel", quality_score: 0.95, dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 }, flags: [], verdict: "pass", gate_version: "dq1.v1" };
  const score = { cvss_v3_vector: vector, cvss_v3_base: opts.scoreBase, source_of_score: opts.scoreSource };
  const result: EnrichmentResult = { intel_id: item.intel_id, dimensions_completed: ["cvss"], dimensions_failed: [], artifacts: { score_assessment: score }, enrichment_score: 0.9, completed_at: date, schema_version: "1.0" };
  const event = (seq: number, topic: KnowledgeEvent["topic"], payload: unknown, cause: string | null): KnowledgeEvent => ({ seq, event_id: "ev_" + seq, trace_id: "tr_test", causation_id: cause, topic, payload });
  const events = [event(1, "raw.docs", raw, null), event(2, "intel.items", item, "ev_1"), event(3, "dq.verdicts", dq, "ev_2"), event(4, "enrich.items", result, "ev_2")];
  const state: EnrichmentDimensionState = { intel_id: item.intel_id, dimension: "cvss", status: "live", input_hash: enrichmentInputHash(item), result_hash: sha256Json(score), enrich_event_id: "ev_4", intel_event_id: "ev_2", retry_after: null, reason: "r", attempts: 1, updated_at: date, artifact: score };
  return { events, states: [state], bytes, cve };
}

test("适配器：NVD bulk 报文中 CNA（sourceIdentifier）提交的评分按内容比对放行", async () => {
  const f = fixture({ scoreSource: "cna", payloadSource: "cna@example.com", payloadBase: 7.5, scoreBase: 7.5 });
  const out = await knowledgeStatesFromDimensions({ events: f.events, lineage: [], states: f.states, readRaw: async () => f.bytes });
  assert.equal(out.length, 1, JSON.stringify(out));
  const cvss = out[0]!.artifacts.filter(a => a.key === "cvss");
  assert.equal(cvss.length, 1, JSON.stringify(out[0]!.artifacts));
  assert.equal(cvss[0]!.cve_id, f.cve);
  assert.equal(cvss[0]!.raw_ref, "tmp/live-nvd.json");
});

test("适配器：NIST 主评分通路不受影响", async () => {
  const f = fixture({ scoreSource: "nvd", payloadSource: "nvd@nist.gov", payloadBase: 9.8, scoreBase: 9.8 });
  const out = await knowledgeStatesFromDimensions({ events: f.events, lineage: [], states: f.states, readRaw: async () => f.bytes });
  assert.equal(out[0]!.artifacts.filter(a => a.key === "cvss").length, 1);
});

test("适配器：内容比对不因配对放行而放松——来源或数值不一致都不产出证据", async () => {
  for (const opts of [
    { scoreSource: "cna" as const, payloadSource: "nvd@nist.gov", payloadBase: 9.8, scoreBase: 9.8 }, // 评分称 cna，报文只有 NIST 主分
    { scoreSource: "cna" as const, payloadSource: "cna@example.com", payloadBase: 7.5, scoreBase: 9.8 }, // 来源对但 base 不符
    { scoreSource: "nvd" as const, payloadSource: "cna@example.com", payloadBase: 7.5, scoreBase: 7.5 }, // 评分称 nvd，报文只有 CNA 分
  ]) {
    const f = fixture(opts);
    const out = await knowledgeStatesFromDimensions({ events: f.events, lineage: [], states: f.states, readRaw: async () => f.bytes });
    assert.equal(out.length, 0, JSON.stringify({ opts, artifacts: out[0]?.artifacts }));
  }
});

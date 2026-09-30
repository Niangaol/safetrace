/**
 * C-02 生产者回归：证据块的 published_at 必须来自真实来源、trust 必须按来源类型判定，
 * 且缺失时留空而不是猜测。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore, parseLoose } from "@safetrace/shared";
import type { IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import { buildSourceEvidenceChunks } from "../src/evidence-chunks.js";

function item(over: Partial<IntelItem> = {}): IntelItem {
  return {
    intel_id: "intel_meta_1",
    cve_ids: ["CVE-2021-44228"],
    source_ids: ["nvd_cve"],
    title: "Log4Shell critical remote code execution",
    summary: "JNDI lookups allow remote code execution.",
    published_at: "2021-12-10T10:15:08.540Z",
    first_seen_at: "2026-09-30T00:00:00.000Z",
    entities: { product: "Log4j", vendor: "Apache", version_range: [], cwe: [], cpes: [] },
    raw_refs: ["fixtures/sources/nvd.sample.json"],
    source_reliability: 0.9,
    schema_version: "1.0",
    ...over,
  };
}
function raw(over: Partial<RawDoc> = {}): RawDoc {
  return { source_id: "nvd_cve", source_type: "nvd_cve", external_id: "CVE-2021-44228", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", fetched_at: "2026-09-30T00:00:00.000Z", content_type: "json", payload_ref: "fixtures/sources/nvd.sample.json", ...over };
}
function verdict(id: string): QualityVerdict {
  return { item_id: id, item_kind: "intel", quality_score: 0.98, dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 }, flags: [], verdict: "pass", gate_version: "1.0.0" };
}
async function build(i: IntelItem, r: RawDoc) {
  const bus = new EventBus({ store: new MemoryEventStore() });
  return buildSourceEvidenceChunks([i], [r], [i], [verdict(i.intel_id)], { [i.intel_id]: "ln_dq" }, { bus, trace_id: "tr_meta" });
}

test("结构化权威源：published_at 取解析后的 IntelItem 时间，trust=trusted", async () => {
  const i = item();
  const out = await build(i, raw());
  assert.equal(out.chunks.length, 1);
  const chunk = out.chunks[0]!;
  assert.equal(chunk.published_at, i.published_at, "必须沿用适配器归一化后的时间，不做二次解释");
  assert.equal(chunk.trust, "trusted");
  assert.ok(parseLoose(chunk.published_at!) !== null, "时间必须可解析");
});

test("网页/文档类来源：trust=untrusted，但仍带真实上游时间", async () => {
  const i = item({ source_ids: ["blog_x"], raw_refs: ["fixtures/sources/kev.sample.json"] });
  const r = raw({ source_id: "blog_x", source_type: "security_blog", payload_ref: "fixtures/sources/kev.sample.json", url: "https://blog.example/log4shell" });
  const out = await build(i, r);
  assert.equal(out.chunks.length, 1);
  assert.equal(out.chunks[0]!.trust, "untrusted", "外部网页文本不得标为 trusted");
  assert.equal(out.chunks[0]!.published_at, i.published_at);
});

test("缺少上游时间：字段留空而不是用抓取时间顶替", async () => {
  const i = item({ published_at: "" });
  const out = await build(i, raw());
  assert.equal(out.chunks.length, 1);
  assert.equal(out.chunks[0]!.published_at, undefined, "缺失即未知，禁止猜测");
  assert.ok(!("published_at" in out.chunks[0]!), "不应写入空字符串字段");
  assert.equal(out.chunks[0]!.trust, "trusted", "时间缺失不影响来源信任级判定");
});

test("种子证据块：日期来自 fixture、信任级为 trusted，且不早于 1999", async () => {
  const { readFixtureChunks } = await import("../../qa/src/q2-retrieval.js");
  const seed = readFixtureChunks();
  assert.equal(seed.length, 6);
  for (const chunk of seed) {
    assert.equal(chunk.trust, "trusted", chunk.chunk_id + " 来自结构化权威源或系统派生");
    assert.ok(chunk.published_at, chunk.chunk_id + " 应带上游发布时间");
    const ms = parseLoose(chunk.published_at!);
    assert.ok(ms !== null && ms > Date.parse("1999-01-01T00:00:00Z"), chunk.chunk_id + " 时间须可解析且在有意义区间");
  }
  const nvd = seed.find(c => c.chunk_id === "chunk_nvd_cve_2021_44228_desc")!;
  assert.equal(nvd.published_at, new Date(Date.parse("2021-12-10T10:15:08.540Z")).toISOString(), "NVD 块时间须与 fixture 的 published 一致（无时区按 UTC）");
  const paper = seed.find(c => c.chunk_id === "chunk_paper_arxiv_2112_00507")!;
  assert.equal(paper.published_at, "2021-12-06T00:00:00.000Z", "论文时间须取自 arXiv fixture 的 <published>");
});

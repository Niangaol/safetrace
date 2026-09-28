import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { EventBus, MemoryEventStore, validateInstance } from "@safetrace/shared";
import type { IntelItem, PaperLink, ScoreAssessment } from "@safetrace/shared";
import { runEnrichment } from "../src/index.js";
import {
  buildConflicts,
  computeEnrichmentScore,
  computeEvidenceRatio,
  REQUIRED_DIMENSIONS,
  summarizeEnrichment,
  type ScoreConflict,
  type ScoreSourceInput,
} from "../src/f6-verify.js";
import type { HttpFetcher } from "../src/f4-cvss.js";

const NVD_SCORE: ScoreSourceInput = {
  source_of_score: "nvd",
  cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  cvss_v3_base: 10.0,
};
const CNA_SCORE: ScoreSourceInput = {
  source_of_score: "cna",
  cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  cvss_v3_base: 9.0,
};
const GHSA_SCORE: ScoreSourceInput = {
  source_of_score: "ghsa",
  cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  cvss_v3_base: 8.8,
};

function makePapers(n: number, withEvidence = true): PaperLink[] {
  return Array.from({ length: n }, (_, i) => ({
    paper_id: "arXiv:2112.0000" + i,
    source: "arxiv" as const,
    title: "Paper " + i,
    year: 2021,
    venue: "arXiv",
    relevance_score: 0.8,
    confidence: 0.8,
    ...(withEvidence ? { evidence_terms: ["log4shell"] } : {}),
  }));
}

function makeItem(overrides: Partial<IntelItem> = {}): IntelItem {
  return {
    intel_id: "intel_test_002",
    cve_ids: ["CVE-2021-44228"],
    source_ids: ["nvd_cve"],
    title: "Log4Shell 测试条目",
    published_at: "2021-12-10T10:00:00Z",
    first_seen_at: "2026-09-28T12:00:00Z",
    entities: { product: "log4j-core", vendor: "apache", version_range: [], cwe: [], cpes: [] },
    raw_refs: ["fixtures/sources/nvd.sample.json"],
    source_reliability: 0.99,
    schema_version: "1.0",
    ...overrides,
  };
}

/* ---------- computeEnrichmentScore 纯函数 ---------- */

test("computeEnrichmentScore：维度完整度*0.6 + 证据覆盖率*0.4", () => {
  assert.equal(computeEnrichmentScore(2, 1), 1);
  assert.equal(computeEnrichmentScore(2, 0.8), 0.92);
  assert.equal(computeEnrichmentScore(1, 0.5), 0.5);
  assert.equal(computeEnrichmentScore(1, 0), 0.3);
  assert.equal(computeEnrichmentScore(0, 1), 0.4);
  assert.equal(computeEnrichmentScore(0, 0), 0);
});

test("computeEnrichmentScore：越界输入被夹到 0-1", () => {
  assert.equal(computeEnrichmentScore(5, 3), 1);
  assert.equal(computeEnrichmentScore(-1, -2), 0);
});

test("computeEvidenceRatio：论文带证据词占比与分值来源数各半", () => {
  const score: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
  };
  // 无论文 -> 论文证据 0；无来源 -> 分值证据 0
  assert.equal(computeEvidenceRatio(makePapers(1), null, []), 0.5);
  // 有论文有证据词(1) + 单源(0.6)
  assert.equal(computeEvidenceRatio(makePapers(1), score, [NVD_SCORE]), 0.8);
  // 有论文有证据词(1) + 多源旁证(1)
  assert.equal(computeEvidenceRatio(makePapers(1), score, [NVD_SCORE, GHSA_SCORE]), 1);
  // 无论文(0) + 单源(0.6)
  assert.equal(computeEvidenceRatio([], score, [NVD_SCORE]), 0.3);
  // 论文无证据词(0) + 无来源(0)
  assert.equal(computeEvidenceRatio(makePapers(1, false), score, []), 0);
});

/* ---------- summarizeEnrichment 维度枚举 ---------- */

test("summarizeEnrichment：paper/cvss 必做且按实际产出枚举", () => {
  const out = summarizeEnrichment(makeItem(), { papers: makePapers(2), otherScores: [NVD_SCORE] });
  assert.deepEqual(out.dimensions_completed, ["paper"]);
  assert.deepEqual(out.dimensions_failed, ["cvss"]);
  assert.equal(out.artifacts.papers !== undefined && out.artifacts.papers.length, 2);
  assert.equal(out.artifacts.score_assessment, undefined);
  assert.equal(out.intel_id, "intel_test_002");
  assert.equal(out.schema_version, "1.0");
});

test("summarizeEnrichment：无论文且无分值 → 两个维度都失败且 score=0", () => {
  const out = summarizeEnrichment(makeItem(), {});
  assert.deepEqual(out.dimensions_completed, []);
  assert.deepEqual(out.dimensions_failed, ["paper", "cvss"]);
  assert.equal(out.enrichment_score, 0);
  assert.equal(Object.keys(out.artifacts).length, 0);
});

test("summarizeEnrichment：论文无证据词 → 覆盖率减半（1 -> 0.8）", () => {
  const score: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
  };
  const out = summarizeEnrichment(makeItem(), { papers: makePapers(1, false), scoreAssessment: score, otherScores: [NVD_SCORE, GHSA_SCORE] });
  assert.equal(out.enrichment_score, 0.8);
});
test("summarizeEnrichment：论文有 evidence_terms 与多源分 → enrichment_score=1", () => {
  const score: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
  };
  const out = summarizeEnrichment(makeItem(), { papers: makePapers(1), scoreAssessment: score, otherScores: [NVD_SCORE, GHSA_SCORE] });
  assert.deepEqual(out.dimensions_completed, ["paper", "cvss"]);
  assert.equal(out.enrichment_score, 1);
});

test("summarizeEnrichment：仅 cvss 完成（无论文）→ 维度减半、覆盖率 0.5 => 0.5", () => {
  const score: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
  };
  const out = summarizeEnrichment(makeItem(), { papers: [], scoreAssessment: score, otherScores: [NVD_SCORE, GHSA_SCORE] });
  assert.deepEqual(out.dimensions_completed, ["cvss"]);
  assert.deepEqual(out.dimensions_failed, ["paper"]);
  assert.equal(out.enrichment_score, 0.5);
});

/* ---------- buildConflicts 冲突仲裁 ---------- */

test("buildConflicts：多源分值不一致 → resolved=true 且 rationale 写明采用源", () => {
  const score: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
  };
  const conflicts = buildConflicts(score, [CNA_SCORE, GHSA_SCORE]);
  assert.equal(conflicts.length, 1);
  const c = conflicts[0];
  assert.ok(c !== undefined);
  assert.equal(c.field, "cvss_v3_base");
  assert.equal(c.resolved, true);
  assert.ok(c.rationale !== undefined && c.rationale.includes("nvd"));
  assert.ok(c.rationale.includes("10"));
  assert.deepEqual(
    c.values.map((v) => v.source + ":" + v.score).sort(),
    ["cna:9", "ghsa:8.8", "nvd:10"],
  );
});

test("buildConflicts：system_derived 采纳时 rationale 写明派生理由", () => {
  const score: ScoreAssessment = {
    cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    cvss_v3_base: 10.0,
    source_of_score: "system_derived",
    derived_reason: "由上游向量重算",
  };
  const conflicts = buildConflicts(score, [GHSA_SCORE]);
  assert.equal(conflicts.length, 1);
  assert.ok(conflicts[0]!.rationale !== undefined && conflicts[0]!.rationale.includes("系统派生"));
  assert.ok(conflicts[0]!.rationale.includes("由上游向量重算"));
});

test("buildConflicts：分值一致 / 单源 / 无分 → 无冲突", () => {
  const same: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
  };
  assert.deepEqual(buildConflicts(same, []), []);
  assert.deepEqual(
    buildConflicts(same, [{ source_of_score: "ghsa", cvss_v3_vector: NVD_SCORE.cvss_v3_vector, cvss_v3_base: 10.0 }]),
    [],
  );
});

test("buildConflicts：未产出最终评分 → resolved=false", () => {
  const conflicts = buildConflicts(null, [NVD_SCORE, CNA_SCORE]);
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0]!.resolved, false);
  assert.ok(conflicts[0]!.values.length >= 2);
});

/* ---------- 契约纯净性：EnrichmentResult.json 运行时校验 ---------- */

test("summarizeEnrichment：产出通过 EnrichmentResult.json 运行时校验（additionalProperties:false）", async () => {
  const schema = JSON.parse(
    await readFile(new URL("../../../contracts/schemas/EnrichmentResult.json", import.meta.url), "utf8"),
  );
  const score: ScoreAssessment = {
    cvss_v3_vector: NVD_SCORE.cvss_v3_vector,
    cvss_v3_base: 10.0,
    source_of_score: "nvd",
    kev_flag: true,
    epss_score: 0.97401,
    epss_percentile: 0.99963,
    exploit_maturity: "high",
    confidence: 0.95,
  };
  const out = summarizeEnrichment(makeItem(), { papers: makePapers(1), scoreAssessment: score, otherScores: [NVD_SCORE] });
  const { conflicts, ...contractPayload } = out;
  void conflicts;
  const errors = validateInstance(contractPayload, schema);
  assert.deepEqual(errors, []);
});

/* ---------- runEnrichment 集成（离线全 fixture） ---------- */

const LOG4SHELL_ITEM: IntelItem = {
  intel_id: "intel_lz3k9x_cve_2021_44228",
  cve_ids: ["CVE-2021-44228"],
  ghsa_ids: ["GHSA-jfh8-c2jp-5v3q"],
  aliases: ["Log4Shell"],
  source_ids: ["cisa_kev", "nvd_cve"],
  title: "Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints (Log4Shell)",
  summary: "Apache Log4j2 <=2.14.1 JNDI 特性无法防御攻击者控制的 LDAP 端点，可致远程代码执行。",
  published_at: "2021-12-10T10:00:00Z",
  first_seen_at: "2026-09-28T12:00:01Z",
  entities: {
    product: "log4j-core",
    vendor: "apache",
    version_range: ["<=2.14.1"],
    cwe: ["CWE-917", "CWE-502"],
    cpes: ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
  },
  raw_refs: ["fixtures/sources/kev.sample.json", "fixtures/sources/nvd.sample.json"],
  source_reliability: 0.99,
  schema_version: "1.0",
};

test("runEnrichment：离线全 fixture 跑通 F1+F4+F6 并上总线", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const conflicts: ScoreConflict[] = [];
  const fallbacks: string[] = [];

  const results = await runEnrichment([LOG4SHELL_ITEM], {
    offline: true,
    bus,
    onConflict: (c) => {
      conflicts.push(c);
    },
    onDegrade: (e) => {
      fallbacks.push(e.degraded_of);
    },
  });

  assert.equal(results.length, 1);
  const r = results[0];
  assert.ok(r !== undefined);
  assert.equal(r.intel_id, "intel_lz3k9x_cve_2021_44228");
  assert.deepEqual(r.dimensions_completed, ["paper", "cvss"]);
  assert.deepEqual(r.dimensions_failed, []);

  // F4：从 raw_refs 的 nvd fixture 取分，KEV 命中，EPSS fixture 回放
  const sa = r.artifacts.score_assessment;
  assert.ok(sa !== undefined);
  assert.equal(sa.source_of_score, "nvd");
  assert.equal(sa.cvss_v3_base, 10.0);
  assert.equal(sa.kev_flag, true);
  assert.equal(sa.epss_score, 0.97401);
  assert.equal(sa.epss_percentile, 0.99963);
  assert.equal(sa.confidence, 0.95);

  // F1：fixture 论文按相关性降序，带证据词
  const papers = r.artifacts.papers;
  assert.ok(papers !== undefined && papers.length === 2);
  assert.equal(papers[0]!.paper_id, "arXiv:2112.00507");
  assert.ok(papers[0]!.relevance_score > papers[1]!.relevance_score);
  assert.ok(papers[0]!.relevance_score > 0.4);
  assert.ok(papers[0]!.evidence_terms !== undefined && papers[0]!.evidence_terms.includes("log4shell"));

  // F6：论文证据 1 + 单源 0.6 -> 覆盖率 0.8 -> 0.92；同分无冲突
  assert.equal(r.enrichment_score, 0.92);
  assert.deepEqual(conflicts, []);

  // 总线：enrich.papers / enrich.items / fallback.events（arXiv + EPSS 两次 fixture 降级）
  assert.equal((await store.read("enrich.papers")).length, 1);
  assert.equal((await store.read("enrich.items")).length, 1);
  assert.deepEqual(fallbacks, ["fixture", "fixture"]);
  const fbEvents = await store.read("fallback.events");
  assert.equal(fbEvents.length, 2);
  assert.equal((fbEvents[0]!.payload as { layer: string }).layer, "L3");
});

test("runEnrichment：无评分来源 → cvss 维度记失败（不造假分）", async () => {
  const results = await runEnrichment([makeItem({ raw_refs: ["fixtures/sources/kev.sample.json"] })], { offline: true });
  const r = results[0];
  assert.ok(r !== undefined);
  assert.equal(r.artifacts.score_assessment, undefined);
  assert.deepEqual(r.dimensions_failed, ["cvss"]);
  assert.deepEqual(r.dimensions_completed, ["paper"]);
});

test("runEnrichment：在线路径（注入 fetchImpl，零外网）跑通并取实时 EPSS", async () => {
  const atom = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<feed xmlns="http://www.w3.org/2005/Atom">',
    '  <entry>',
    '    <id>http://arxiv.org/abs/2112.00507v1</id>',
    '    <published>2021-12-06T00:00:00Z</published>',
    '    <title>Log4Shell analysis</title>',
    '    <summary>Log4Shell JNDI remote code execution</summary>',
    '  </entry>',
    '</feed>',
  ].join("\n");
  const fetcher: HttpFetcher = (url) => {
    if (url.includes("arxiv.org")) {
      return Promise.resolve({ ok: true, status: 200, text: async () => atom, json: async () => ({}) });
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      text: async () => "",
      json: async () => ({ data: [{ cve: "CVE-2021-44228", epss: "0.5", percentile: "0.9" }] }),
    });
  };
  const results = await runEnrichment([LOG4SHELL_ITEM], { fetchImpl: fetcher });
  const r = results[0];
  assert.ok(r !== undefined);
  assert.ok(r.artifacts.score_assessment !== undefined);
  assert.ok(r.artifacts.papers !== undefined);
  assert.equal(r.artifacts.score_assessment.epss_score, 0.5);
  assert.equal(r.artifacts.score_assessment.epss_percentile, 0.9);
  assert.equal(r.artifacts.papers.length, 1);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import type { IntelItem } from "@safetrace/shared";
import {
  assessScore,
  EPSS_FIXTURES,
  loadScoreSourcesFromRawRefs,
  lookupEpss,
  parseCvssV31Vector,
  type HttpFetcher,
} from "../src/f4-cvss.js";

/* ---------- 表驱动 CVSS v3.1 基准分（FIRST 规范） ---------- */

const VECTOR_CASES: Array<{ name: string; vector: string; expected: string }> = [
  { name: "Log4Shell（S:C 满分）", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", expected: "10.0" },
  { name: "C/I/A 全 N（规范规定为 0）", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", expected: "0.0" },
  { name: "本地+低权+高影响", vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", expected: "7.8" },
  { name: "网络+高复杂度+低机密", vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", expected: "3.7" },
  { name: "范围变更+用户交互", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L", expected: "7.1" },
  { name: "范围变更+仅机密性", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", expected: "8.6" },
  { name: "物理+高复杂度+高权", vector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:L/A:L", expected: "6.0" },
  { name: "本地+高复杂度（S:U）", vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:L", expected: "5.1" },
];

test("parseCvssV31Vector：表驱动基准分（保留 1 位小数）", () => {
  for (const c of VECTOR_CASES) {
    const parsed = parseCvssV31Vector(c.vector);
    assert.equal(parsed.baseScore.toFixed(1), c.expected, c.name + ": " + c.vector);
    assert.equal(parsed.vector, c.vector);
  }
});

test("parseCvssV31Vector：结构体八个度量字段齐全", () => {
  const parsed = parseCvssV31Vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  assert.equal(parsed.AV, "L");
  assert.equal(parsed.AC, "L");
  assert.equal(parsed.PR, "L");
  assert.equal(parsed.UI, "N");
  assert.equal(parsed.S, "U");
  assert.equal(parsed.C, "H");
  assert.equal(parsed.I, "H");
  assert.equal(parsed.A, "H");
  assert.equal(parsed.baseScore, 7.8);
});

test("parseCvssV31Vector：非法向量抛错且消息指明原因", () => {
  assert.throws(() => parseCvssV31Vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), /CVSS:3[.]1/);
  assert.throws(() => parseCvssV31Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"), /缺失/);
  assert.throws(() => parseCvssV31Vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), /AV/);
  assert.throws(() => parseCvssV31Vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/AV:L"), /重复/);
});

/* ---------- EPSS ---------- */

test("lookupEpss：注入 fetchImpl 正常解析实时数据（无降级标记）", async () => {
  const seen: string[] = [];
  const fetcher: HttpFetcher = (url) => {
    seen.push(url);
    return Promise.resolve({
      ok: true,
      status: 200,
      json: async () => ({ data: [{ cve: "CVE-2021-44228", epss: "0.87310", percentile: "0.97420" }] }),
      text: async () => "",
    });
  };
  const r = await lookupEpss("CVE-2021-44228", { fetchImpl: fetcher });
  assert.equal(r.epss_score, 0.8731);
  assert.equal(r.epss_percentile, 0.9742);
  assert.equal(r.degraded_to, undefined);
  assert.equal(seen[0], "https://api.first.org/data/v1/epss?cve=CVE-2021-44228");
});

test("lookupEpss：offline 回放 fixture 且带 degraded_to=fixture", async () => {
  const events: string[] = [];
  const r = await lookupEpss("CVE-2021-44228", {
    offline: true,
    emit: async (e) => {
      events.push(e.layer + "/" + e.degraded_of);
    },
  });
  assert.equal(r.degraded_to, "fixture");
  assert.equal(r.epss_score, EPSS_FIXTURES["CVE-2021-44228"]!.epss_score);
  assert.equal(r.epss_percentile, EPSS_FIXTURES["CVE-2021-44228"]!.epss_percentile);
  assert.deepEqual(events, ["L3/fixture"]);
});

test("lookupEpss：fetch 抛错 → fixture 降级（禁止静默兜底）", async () => {
  const r = await lookupEpss("CVE-2021-44228", {
    fetchImpl: async () => {
      throw new Error("network down");
    },
  });
  assert.equal(r.degraded_to, "fixture");
  assert.equal(r.epss_score, 0.97401);
});

test("lookupEpss：HTTP 503 → fixture 降级", async () => {
  const r = await lookupEpss("CVE-2021-44228", {
    fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}), text: async () => "" }),
  });
  assert.equal(r.degraded_to, "fixture");
  assert.equal(r.epss_percentile, 0.99963);
});

test("lookupEpss：上游无该 CVE 数据行 → fixture 降级（不拿别的行冒充分值）", async () => {
  const r = await lookupEpss("CVE-2021-44228", {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ data: [{ cve: "CVE-1999-0001", epss: "0.1", percentile: "0.2" }] }),
      text: async () => "",
    }),
  });
  assert.equal(r.degraded_to, "fixture");
  assert.equal(r.epss_score, 0.97401);
});

test("lookupEpss：fixture 无样本的 CVE → null 分（不编造）", async () => {
  const r = await lookupEpss("CVE-1999-0001", { offline: true });
  assert.equal(r.degraded_to, "fixture");
  assert.equal(r.epss_score, null);
  assert.equal(r.epss_percentile, null);
});

test("lookupEpss：非法 CVE ID 直接抛错", async () => {
  await assert.rejects(() => lookupEpss("not-a-cve"), /非法 CVE ID/);
});

/* ---------- assessScore 多源仲裁 ---------- */

function makeItem(overrides: Partial<IntelItem> = {}): IntelItem {
  return {
    intel_id: "intel_test_001",
    cve_ids: ["CVE-2021-44228"],
    ghsa_ids: ["GHSA-jfh8-c2jp-5v3q"],
    source_ids: ["nvd_cve", "cve_org"],
    title: "Log4Shell",
    published_at: "2021-12-10T10:00:00Z",
    first_seen_at: "2026-09-28T12:00:00Z",
    entities: { product: "log4j-core", vendor: "apache", version_range: [], cwe: [], cpes: [] },
    raw_refs: ["fixtures/sources/nvd.sample.json"],
    source_reliability: 0.99,
    schema_version: "1.0",
    ...overrides,
  };
}

test("assessScore：多源冲突时按权威序取 nvd，低权威源只增强不改写", async () => {
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [
      { source_of_score: "ghsa", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_v3_base: 9.8 },
      { source_of_score: "cna", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 9.0, impact_summary: "CNA 影响描述" },
      { source_of_score: "nvd", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 10.0 },
    ],
  });
  assert.ok(score !== null);
  assert.equal(score.source_of_score, "nvd");
  assert.equal(score.cvss_v3_base, 10.0);
  assert.equal(score.cvss_v3_vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  assert.equal(score.impact_summary, "CNA 影响描述");
  assert.equal(score.confidence, 0.95);
});

test("assessScore：ghsa 高于 adp；EPSS 只从旁证补缺", async () => {
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [
      { source_of_score: "adp", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 8.8 },
      { source_of_score: "ghsa", cvss_v3_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", cvss_v3_base: 7.8, epss_score: 0.42, epss_percentile: 0.9 },
    ],
  });
  assert.ok(score !== null);
  assert.equal(score.source_of_score, "ghsa");
  assert.equal(score.cvss_v3_base, 7.8);
  assert.equal(score.epss_score, 0.42);
  assert.equal(score.confidence, 0.85);
});

test("assessScore：system_derived 缺 derived_reason 抛错（契约红线）", async () => {
  await assert.rejects(
    () =>
      assessScore(makeItem(), {
        sources: [{ source_of_score: "system_derived", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
      }),
    /derived_reason/,
  );
});

test("assessScore：仅 system_derived 时按向量重算基准分并带 derived_reason", async () => {
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [
      {
        source_of_score: "system_derived",
        cvss_v3_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        derived_reason: "由 NVD 公开向量重算：无上游公布分值",
      },
    ],
  });
  assert.ok(score !== null);
  assert.equal(score!.source_of_score, "system_derived");
  assert.equal(score!.cvss_v3_base, 7.8);
  assert.equal(score!.derived_reason, "由 NVD 公开向量重算：无上游公布分值");
  assert.equal(score!.confidence, 0.5);
});

test("assessScore：无可用来源 → null（禁止无源默认分）", async () => {
  assert.equal(await assessScore(makeItem(), { sources: [] }), null);
});

test("assessScore：KEV 命中（source_ids 含 kev）→ kev_flag=true 且 exploit_maturity=high", async () => {
  const score = await assessScore(makeItem({ source_ids: ["nvd_cve", "cisa_kev"] }), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [{ source_of_score: "nvd", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 10.0 }],
  });
  assert.equal(score!.kev_flag, true);
  assert.equal(score!.exploit_maturity, "high");
});

test("assessScore：KEV 命中（cve_ids 命中 kevSet）→ kev_flag=true", async () => {
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [{ source_of_score: "nvd", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 10.0 }],
    kevSet: new Set(["CVE-2021-44228", "CVE-2014-0160"]),
  });
  assert.equal(score!.kev_flag, true);
});

test("assessScore：KEV 未命中 → kev_flag 键不存在（不猜 false）", async () => {
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [{ source_of_score: "nvd", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 10.0 }],
  });
  assert.equal("kev_flag" in score!, false);
});

test("assessScore：无 epss 来源时内部查询 EPSS（离线 fixture 降级可见）", async () => {
  const events: string[] = [];
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [{ source_of_score: "nvd", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 10.0 }],
    emit: async (e) => {
      events.push(e.trigger);
    },
  });
  assert.equal(score!.epss_score, 0.97401);
  assert.equal(score!.epss_percentile, 0.99963);
  assert.equal(events.length, 1);
});

test("assessScore：产出对象不含 undefined 值键（契约 additionalProperties:false）", async () => {
  const score = await assessScore(makeItem(), {
    offline: true, // scoring arbitration tests use EPSS fixtures, never external HTTP
    sources: [{ source_of_score: "nvd", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss_v3_base: 10.0 }],
  });
  for (const [k, v] of Object.entries(score!)) {
    assert.notEqual(v, undefined, "键 " + k + " 不应为 undefined");
  }
});

/* ---------- raw_refs 评分源复原 ---------- */

test("loadScoreSourcesFromRawRefs：从 NVD/OSV fixture 抽多源评分并按源去重", async () => {
  const item = makeItem({
    raw_refs: ["fixtures/sources/nvd.sample.json", "fixtures/sources/osv.sample.json", "fixtures/sources/kev.sample.json"],
  });
  const sources = await loadScoreSourcesFromRawRefs(item);
  const bySource = new Map(sources.map((s) => [s.source_of_score, s]));
  assert.equal(sources.length, 2);
  assert.equal(bySource.get("nvd")!.cvss_v3_base, 10.0);
  assert.equal(bySource.get("ghsa")!.cvss_v3_vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
});

test("loadScoreSourcesFromRawRefs：raw_refs 缺失 → 空数组（交由上层记维度失败）", async () => {
  const sources = await loadScoreSourcesFromRawRefs(makeItem({ raw_refs: ["fixtures/sources/不存在.json"] }));
  assert.deepEqual(sources, []);
});

test("EPSS null/boolean/blank/out-of-range/duplicate rows never count as genuine probabilities",async()=>{
  for(const value of [null,false,true,"", " ", -0.1,1.1,"NaN","Infinity"]){
    const result=await lookupEpss("CVE-2026-99999",{fetchImpl:async()=>({ok:true,status:200,text:async()=>"",json:async()=>({data:[{cve:"CVE-2026-99999",epss:value,percentile:"0.9"}]})})});
    assert.equal(result.degraded_to,"fixture");assert.equal(result.epss_score,null);
  }
  const duplicated=await lookupEpss("CVE-2026-99999",{fetchImpl:async()=>({ok:true,status:200,text:async()=>"",json:async()=>({data:[{cve:"CVE-2026-99999",epss:"0.1",percentile:"0.9"},{cve:"CVE-2026-99999",epss:"0.8",percentile:"0.2"}]})})});
  assert.equal(duplicated.degraded_to,"fixture");assert.equal(duplicated.epss_score,null);
});

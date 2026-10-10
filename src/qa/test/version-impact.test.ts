/**
 * P-03 回归：问答侧「某版本是否受影响」确定性入口。
 * 口径：结论与依据由规则产出（与资产线同一实现），不进相似度/模型；
 * unknown 必须显式说明原因；拒答路径同样展示判定。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { EvidenceChunk, IntelItem, RetrievalResponse } from "@safetrace/shared";
import { classifyIntent } from "../src/q1-intent.js";
import { synthesizeAnswer } from "../src/q4-answer.js";
import { answerVersionImpact, versionImpactStatusLabel } from "../src/version-impact.js";

/** 判定只需要情报的 entities 子集；其余字段与测试无关。 */
function intel(intel_id: string, product: string | null, version_range: string[], cve_ids: string[]): IntelItem {
  return {
    intel_id, cve_ids,
    entities: { product, vendor: null, version_range, cwe: [], cpes: [] },
  } as unknown as IntelItem;
}

const LOG4J = intel("intel_kev_cve_2021_44228", "Log4j", ["<=2.14.1", ">=2.0-beta9 <2.15.0"], ["CVE-2021-44228", "CVE-2021-45046"]);
const SPRING = intel("intel_spring", "Spring Framework", [">=5.3.0 <5.3.18"], ["CVE-2022-22965"]);

test("P-03：版本命中受影响区间 → affected 且带规则与命中区间", () => {
  const v = answerVersionImpact([LOG4J], { product: "Log4j", version: "2.14.1" });
  assert.equal(v.status, "affected");
  assert.equal(v.tested_version, "2.14.1");
  assert.deepEqual(v.matched_ranges, ["<=2.14.1"]);
  assert.equal(v.rule, "<=2.14.1 OR >=2.0-beta9 <2.15.0");
  assert.equal(v.intel_id, LOG4J.intel_id);
  assert.equal(v.cve_id, "CVE-2021-44228");
  assert.equal(v.vendor_unverified, true);
  assert.ok(v.reason.includes("厂商身份未经本地核实"));
});

test("P-03：产品标识使用显式词典别名归一，不依赖模糊相似度", () => {
  const upper = answerVersionImpact([LOG4J], { product: "LOG4J", version: "2.14.0" });
  assert.equal(upper.status, "affected", "大小写归一后应命中");
  const alias = answerVersionImpact([LOG4J], { product: "log4shell", version: "2.14.0" });
  assert.equal(alias.status, "affected", "Log4Shell 是词典中显式登记的 Log4j 别名");
  assert.equal(alias.candidates, 1);
});

test("P-03：版本不在区间 → not_affected（确定性结论，不靠模型）", () => {
  const v = answerVersionImpact([SPRING], { product: "Spring Framework", version: "5.3.20" });
  assert.equal(v.status, "not_affected");
  assert.deepEqual(v.matched_ranges, []);
});

test("P-03：存在无法解析的版本规则时不过度结论——不能排除即 unknown", () => {
  // LOG4J 规则含 beta 版本（>=2.0-beta9 <2.15.0 不可解析）：2.16.0 虽在区间外，
  // 但一条规则无法解析就不能排除受影响 → unknown 并说明原因（fail-closed，不硬判 not_affected）
  const v = answerVersionImpact([LOG4J], { product: "Log4j", version: "2.16.0" });
  assert.equal(v.status, "unknown");
  assert.match(v.reason, /不能排除受影响/);
});

test("P-03：版本格式不受支持 / 无该产品情报 → unknown 且说明原因（不等于安全）", () => {
  const bad = answerVersionImpact([LOG4J], { product: "Log4j", version: "abc" });
  assert.equal(bad.status, "unknown");
  assert.match(bad.reason, /格式不受支持/);
  const absent = answerVersionImpact([LOG4J], { product: "nginx", version: "1.0.0" });
  assert.equal(absent.status, "unknown");
  assert.equal(absent.candidates, 0);
  assert.match(absent.reason, /未找到产品/);
});

test("P-03：cve_id 限定只判关联情报；限定不到 → unknown", () => {
  const hit = answerVersionImpact([LOG4J], { product: "Log4j", version: "2.14.1", cve_id: "cve-2021-45046" });
  assert.equal(hit.status, "affected");
  assert.equal(hit.cve_id, "CVE-2021-45046");
  const miss = answerVersionImpact([LOG4J], { product: "Log4j", version: "2.14.1", cve_id: "CVE-1999-0001" });
  assert.equal(miss.status, "unknown");
  assert.match(miss.reason, /CVE-1999-0001/);
});

test("P-03：同产品多源聚合——任一 affected 优先，否则 unknown，再否则 not_affected", () => {
  // 产品标识归一化后精确相等才候选（与资产线同口径：无模糊匹配）
  const springOld = intel("intel_spring_old", "Spring Framework", [], ["CVE-2022-22965"]); // 无版本规则 → unknown
  const affected = answerVersionImpact([springOld, SPRING], { product: "Spring Framework", version: "5.3.10" });
  assert.equal(affected.status, "affected", "存在带规则且命中的候选时必须给 affected");
  assert.equal(affected.candidates, 2);
  const onlyUnknown = answerVersionImpact([springOld], { product: "Spring Framework", version: "5.3.10" });
  assert.equal(onlyUnknown.status, "unknown");
  assert.match(onlyUnknown.reason, /未提供受影响版本规则/);
  const notAffected = answerVersionImpact([SPRING], { product: "Spring Framework", version: "5.3.20" });
  assert.equal(notAffected.status, "not_affected");
  // 产品标识不精确相等 → 不候选（禁模糊匹配把 not_affected 说成 affected 或反之）
  const mismatch = answerVersionImpact([SPRING], { product: "springlike", version: "5.3.10" });
  assert.equal(mismatch.status, "unknown");
  assert.equal(mismatch.candidates, 0);
});

test("P-03：状态标签三态", () => {
  assert.equal(versionImpactStatusLabel("affected"), "受影响");
  assert.equal(versionImpactStatusLabel("not_affected"), "不受影响");
  assert.equal(versionImpactStatusLabel("unknown"), "无法判定");
});

function chunk(id: string, over: Partial<EvidenceChunk> = {}): EvidenceChunk {
  return { chunk_id: id, doc_type: "vuln_advisory", text: "CVE-2021-44228 affects Log4j2.", score_sparse: 0.95, quality_score: 0.98, provenance: { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", section: "description" }, ...over };
}
function evidence(chunks: EvidenceChunk[]): RetrievalResponse {
  return { query_id: "q_p03", chunks, retrieval_ms: 5, embedder_model_id: "bm25-lite-v1", trace_id: "tr_p03", schema_version: "1.0" };
}
const NOW = new Date("2026-10-10T12:00:00.000Z");

test("P-03：判定进答案正文与推理链（含依据规则与命中区间）", async () => {
  const question = "Log4Shell 2.14.1 是否受 CVE-2021-44228 影响？";
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: question });
  const impact = answerVersionImpact([LOG4J], { product: plan.slots.products[0]!, version: plan.slots.versions[0]!, cve_id: plan.slots.cve_ids[0] });
  assert.equal(impact.status, "affected");
  const ans = await synthesizeAnswer(question, plan, evidence([chunk("c_p03", { published_at: "2026-10-01T00:00:00.000Z", trust: "trusted" })]), {
    session_id: "s", turn_id: "t", now: NOW, version_impact: impact,
  });
  assert.match(ans.text_md, /## 版本影响判定（确定性规则）/, "正文必须出现版本影响判定段");
  assert.ok(ans.text_md.includes("**受影响**"), "判定结论必须显式");
  assert.ok(ans.text_md.includes("<=2.14.1"), "命中区间必须可见");
  assert.ok(ans.text_md.includes("无法判定不等于安全") || ans.text_md.includes("厂商身份未经本地核实"), "unknown/厂商身份口径必须显式");
  assert.ok(ans.reasoning_chain.some((s) => s.includes("P-03 版本影响判定") && s.includes("非相似度/模型生成")),
    "推理链必须记录判定来自确定性规则");
});

test("P-03：拒答路径同样展示版本判定（证据不足不抹掉确定性结论）", async () => {
  const question = "Log4Shell 2.14.1 是否受 CVE-2021-44228 影响？";
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: question });
  const impact = answerVersionImpact([LOG4J], { product: "Log4j", version: "2.14.1" });
  const ans = await synthesizeAnswer(question, plan, evidence([]), {
    session_id: "s", turn_id: "t", now: NOW, version_impact: impact,
  });
  assert.ok(ans.abstained);
  assert.match(ans.text_md, /## 版本影响判定（确定性规则）/);
  assert.ok(ans.text_md.includes("**受影响**"));
});

test("P-03：未提供判定时答案不出现版本影响段", async () => {
  const question = "Log4Shell 影响哪些版本？";
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: question });
  const ans = await synthesizeAnswer(question, plan, evidence([chunk("c_p03_none", { published_at: "2026-10-01T00:00:00.000Z", trust: "trusted" })]), {
    session_id: "s", turn_id: "t", now: NOW,
  });
  assert.ok(!ans.text_md.includes("## 版本影响判定"));
});
import { test } from "node:test";
import assert from "node:assert/strict";
import type { EvidenceChunk, RetrievalResponse } from "@safetrace/shared";
import { MemoryIndex } from "../src/q2-retrieval.js";
import { classifyIntent, staleThresholdDays } from "../src/q1-intent.js";
import { synthesizeAnswer } from "../src/q4-answer.js";
import { naturalConclusion } from "../../../scripts/natural-answer.js";
import { coversProducts } from "../src/evidence-identity.js";

const now = new Date("2026-10-10T12:00:00Z");
function chunk(text: string, over: Partial<EvidenceChunk> = {}): EvidenceChunk {
  return {chunk_id:"proof",doc_type:"vuln_advisory",text,score_sparse:1,quality_score:1,trust:"trusted",published_at:"2026-10-01T00:00:00Z",provenance:{url:"https://example.org/advisory",section:"original"},...over};
}
function evidence(chunks: EvidenceChunk[]): RetrievalResponse {
  return {query_id:"q",trace_id:"tr",schema_version:"1.0",embedder_model_id:"bm25-lite-v1",retrieval_ms:0,chunks};
}
async function answer(question: string, chunks: EvidenceChunk[]) {
  const plan = classifyIntent({session_id:"s",turn_id:"t",text:question});
  return synthesizeAnswer(question,plan,evidence(chunks),{now});
}
test("质量门禁：比较题必须覆盖所有完整 CVE，编号前缀不算证据", async () => {
  const result = await answer("比较 CVE-2026-10001 和 CVE-2026-10002 的影响范围",[chunk("CVE-2026-10001 Log4j 受影响")]);
  assert.equal(result.abstained,true);
  assert.match(result.text_md,/全部 CVE/);
  const prefix = await answer("CVE-2026-10001 的影响范围",[chunk("CVE-2026-100010 Log4j 受影响")]);
  assert.equal(prefix.abstained,true);
});
test("检索过滤：空索引也不能忽略不可解析的时间窗；CVE 不用前缀匹配", async () => {
  const index = new MemoryIndex();
  const req={query_id:"q",trace_id:"tr",schema_version:"1.0",query_text:"影响范围",top_k:5};
  await assert.rejects(index.search({...req,published_after:"yesterday"}),/published_after/);
  await index.upsert([chunk("CVE-2026-100010 影响范围")]);
  assert.equal((await index.search({...req,cve_ids:["CVE-2026-10001"]})).chunks.length,0);
});
test("质量门禁：BM25 相对榜首1不能替代产品身份相关性", async () => {
  assert.equal(coversProducts(["nginx"],["Log4j 影响范围"]),false);
  assert.equal(coversProducts(["log4j"],["Log4Shell 影响范围"]),true);
  const result=await answer("nginx 影响哪些版本？",[chunk("Log4j 影响版本",{score_sparse:1})]);
  assert.equal(result.abstained,true);
  assert.match(result.text_md,/指定的产品/);
});
test("时效门禁：多意图取最严阈值，所有 Q4 调用方共用意图默认", async () => {
  const plan=classifyIntent({session_id:"s",turn_id:"t",text:"近期漏洞趋势与影响范围"});
  plan.intents=["impact_range","trend"];
  assert.equal(staleThresholdDays(plan),7);
  const result=await synthesizeAnswer("近期漏洞趋势与影响范围",plan,evidence([chunk("近期漏洞趋势与影响范围")]),{now});
  assert.equal(result.stale_warning?.threshold_days,7);
});
test("版本门禁：没有结构化判定时不能把自由文本变成确定性状态", async () => {
  const q="CVE-2026-10001 版本 2.4.0 是否受影响？";
  const good=await answer(q,[chunk("CVE-2026-10001 版本 2.4.0 受影响。")]);
  assert.equal(good.abstained,true);
  assert.ok(!good.text_md.includes("## 版本影响判定（确定性规则）"));
  assert.equal((await answer(q,[chunk("CVE-2026-10001 漏洞影响待核实")])).abstained,true);
  assert.equal((await answer(q,[chunk("CVE-2026-10001 版本 2.4.0 受影响。版本 2.4.0 不受影响。")])).abstained,true);
});
test("修复门禁：影响版本+否定修复句不是安全修复版本", async () => {
  const result=await answer("CVE-2026-10002 具体升级哪个版本？",[chunk("CVE-2026-10002 影响 1.0.0 至 1.9.0；没有已核验的修复版本。")]);
  assert.equal(result.abstained,true);
  assert.match(result.text_md,/修复版本/);
});
test("版本及修复门禁：转述否定/条件/引用不当确定性事实", async () => {
  for (const text of [
    "CVE-2026-10001 log4j 报告说 2.4.0 不受影响，但该说法不成立，尚待核实。",
    "CVE-2026-10001 log4j 若已安装补丁，2.4.0 不受影响。",
    "CVE-2026-10001 log4j 错误地认为 2.4.0 不受影响。",
    "CVE-2026-10001 log4j 如果打了补丁，2.4.0 不受影响。",
    "CVE-2026-10001 log4j 厂商声称 \"2.4.0 不受影响\"，尚未确认。",
  ]) assert.equal((await answer("CVE-2026-10001 log4j 2.4.0 是否受影响？", [chunk(text)])).abstained, true);
  for (const text of [
    "CVE-2026-10002 was not fixed in version 2.14.1.",
    "CVE-2026-10002 2.14.1 尚未修复漏洞。",
    "CVE-2026-10002 2.14.1 未修复此问题。",
  ]) assert.equal((await answer("CVE-2026-10002 修复版本是什么？", [chunk(text)])).abstained, true);
});

test("版本判定必须绑定请求 CVE，不能借第三个漏洞或单汇总解释比较题", async () => {
  const question = "CVE-2026-10001 和 CVE-2026-10002 log4j 2.14.1 是否受影响？";
  const plan = classifyIntent({text:question,session_id:"s",turn_id:"t"});
  const unrelated = {intel_id:"third",cve_ids:["CVE-2026-10003"],cve_id:"CVE-2026-10003",product:"log4j",version:"2.14.1",tested_version:"2.14.1",rule:">=2.0.0 <2.15.0",matched_ranges:[">=2.0.0 <2.15.0"],status:"affected" as const,reason:"third CVE only",vendor_unverified:true,candidates:1};
  const result = await synthesizeAnswer(question,plan,evidence([chunk("CVE-2026-10001 log4j"),chunk("CVE-2026-10002 log4j")]),{now,version_impact:unrelated});
  assert.equal(result.abstained,true);
  assert.ok(!result.text_md.includes("CVE-2026-10003"));
  assert.ok(!result.text_md.includes("**受影响**"));
  const single = await synthesizeAnswer("CVE-2026-10001 log4j 2.14.1 是否受影响？",classifyIntent({text:"CVE-2026-10001 log4j 2.14.1 是否受影响？",session_id:"s",turn_id:"t"}),evidence([chunk("CVE-2026-10001 log4j")]),{now,version_impact:unrelated});
  assert.equal(single.abstained,true);
});

function score(id:string,base:number,source="nvd") {
  return chunk(id+" CVSS v3 base score: "+base+"\n"+JSON.stringify({cvss_v3_base:base,cvss_v3_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",source_of_score:source}),{doc_type:"enrichment"});
}
test("自然结论：指定 CVE 不借其他 CVE 分值，比较题逐条绑定 ID", () => {
  const a=score("CVE-2026-10001",5.5),b=score("CVE-2026-10002",9.8);
  const single=naturalConclusion({cve_id:"CVE-2026-10001",chunks:[b,a]})!;
  assert.match(single,/CVE-2026-10001.*5\.5/);
  assert.ok(!single.includes("9.8"));
  const comparison=naturalConclusion({cve_id:null,chunks:[b,a]})!;
  assert.match(comparison,/CVE-2026-10001.*5\.5/);
  assert.match(comparison,/CVE-2026-10002.*9\.8/);
  assert.equal(naturalConclusion({cve_id:"CVE-2026-100010",chunks:[a,b]}),null);
});
test("冲突：同 CVE 不同评分显式保留，不把不同 CVE 分值当冲突", async () => {
  const same=await answer("CVE-2026-10001 影响范围",[score("CVE-2026-10001",7.5),score("CVE-2026-10001",9.8,"cna")]);
  assert.match(same.text_md,/来源冲突/);
  assert.match(same.text_md,/未自行仲裁/);
  const distinct=await answer("CVE-2026-10001 与 CVE-2026-10002 影响范围",[score("CVE-2026-10001",7.5),score("CVE-2026-10002",9.8)]);
  assert.ok(!distinct.text_md.includes("## 来源冲突"));
});

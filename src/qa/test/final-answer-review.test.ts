import {test} from "node:test";
import assert from "node:assert/strict";
import {validateReviewedSummary} from "../../../scripts/final-answer-review.js";
const quote="CVE-2025-12345 CVSS base 9.8; official scoring evidence only; no exploitation or remediation information is available.";
const text="现有引用给出的基础评分是 9.8，但评分本身并不能说明实际环境已经遭到攻击。这段材料没有提供利用情况或修复信息，因此不能据此断言已经被利用、已经修复或没有风险。判断具体影响还需要更多对应证据。";
const payload=()=>({supported:true,issues:[],claims:[{text,chunk_id:"chunk",quote}]});
const evidence=[{chunk_id:"chunk",quote}];
test("reviewed prose requires positive review and exact per-sentence evidence",()=>{
 assert.equal(validateReviewedSummary(payload(),evidence),text);
 assert.equal(validateReviewedSummary({...payload(),supported:false},evidence),null);
 assert.equal(validateReviewedSummary({...payload(),issues:["修复信息无依据"]},evidence),null);
 for(const change of [{chunk_id:"invented"},{quote:"invented original quotation"},{text:text+"新评分为 7.5。"},{text:text+"CVE-2026-99999"},{text:text+"https://evil.example"},{text:text+"<script>alert(1)</script>"}]){
  assert.equal(validateReviewedSummary({...payload(),claims:[{...payload().claims[0],...change}]},evidence),null);
 }
 assert.equal(validateReviewedSummary({supported:true,issues:[],claims:[]},evidence),null);
 assert.equal(validateReviewedSummary(null,evidence),null);
});

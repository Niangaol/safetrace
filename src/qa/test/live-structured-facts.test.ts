import { test } from "node:test";
import assert from "node:assert/strict";
import type { IntelItem, RawDoc } from "@safetrace/shared";
import { rawKnowledgeRecords } from "../src/knowledge-projection.js";
import type { ProjectedEvidence } from "../src/knowledge-projection.js";
import { cnaVersionFacts, nvdVersionFacts, recordScoreFacts } from "../src/raw-structured-facts.js";
import { sourceVersionChunks, sourceVersionImpact, sourceScoreConflicts } from "../src/live-structured-facts.js";

const item={intel_id:"intel",cve_ids:["CVE-2026-10001","CVE-2026-10002"],entities:{product:"Log4j",vendor:"apache",version_range:["<99"]}} as IntelItem;
function proof(over: Partial<ProjectedEvidence> = {}): ProjectedEvidence {
  return {kind:"source",intel_id:"intel",intel_event_id:"ev",original_sha256:"a".repeat(64),text_sha256:"b".repeat(64),parent_lineage_ids:["lineage"],source_cve_ids:["CVE-2026-10002"],
    version_facts:[{product:"Log4j",vendor:"apache",version_range:[">=2.0.0 <2.15.0"]}],score_facts:[],
    chunk:{chunk_id:"source",doc_type:"vuln_advisory",text:"CVE-2026-10002 Log4j",published_at:"2026-10-01T00:00:00Z",provenance:{url:"https://example.org/original",section:"body",sha256:"a".repeat(64)}},...over};
}
test("live 结构事实：逐记录 CVE 规则不借合并条目版本判定另一个 CVE", () => {
  const wrong=sourceVersionImpact([item],[proof()],{product:"log4j",version:"2.14.1",cve_id:"CVE-2026-10001"});
  assert.equal(wrong.status,"unknown");
  const hit=sourceVersionImpact([item],[proof()],{product:"Log4Shell",version:"2.14.1",cve_id:"CVE-2026-10002"});
  assert.equal(hit.status,"affected");
  const clear=sourceVersionImpact([item],[proof()],{product:"log4j",version:"2.16.0",cve_id:"CVE-2026-10002"});
  assert.equal(clear.status,"not_affected");
  assert.equal(sourceVersionImpact([item],[proof({original_sha256:undefined})],{product:"log4j",version:"2.14.1"}).status,"unknown");
});
test("live 结构事实：派生版本证据保持原文 URL/hash，未绑定证明不入索引", () => {
  const chunks=sourceVersionChunks([proof()]);
  assert.equal(chunks.length,1);
  assert.equal(chunks[0]!.provenance.url,proof().chunk.provenance.url);
  assert.match(chunks[0]!.text,/CVE-2026-10002/);
  assert.match(chunks[0]!.text,/>=2.0.0 <2.15.0/);
  assert.equal(sourceVersionChunks([proof({parent_lineage_ids:[]})]).length,0);
});
test("live 结构事实：只聚合同 CVE/同版本评分分歧，不能跨漏洞制造冲突", () => {
  const a={cve_id:"CVE-2026-10002",source:"nvd" as const,score:9.8,vector:"CVSS:3.1/AV:N"};
  const b={...a,source:"cna" as const,score:7.5};
  const p=proof({score_facts:[a,b]});
  const conflicts=sourceScoreConflicts([p],[p.chunk]);
  assert.equal(conflicts.length,1); assert.equal(conflicts[0]!.resolved,false);
  assert.match(conflicts[0]!.rationale!,/CVE-2026-10002/);
  assert.equal(sourceScoreConflicts([proof({score_facts:[a,{...b,cve_id:"CVE-2026-10001"}]})],[p.chunk]).length,0);
  assert.equal(sourceScoreConflicts([p],[{...p.chunk,text:"CVE-2026-10001"}]).length,0);
});
test("原文规则：CNA changes/default/排除项不可支持时必须 unknown，不误判安全", () => {
  const facts=cnaVersionFacts({affected:[{product:"Log4j",versions:[{version:"2.0.0",lessThan:"2.15.0",status:"affected"}]}]});
  assert.deepEqual(facts[0]!.version_range,[">=2.0.0 <2.15.0"]);
  const complex=cnaVersionFacts({affected:[{product:"Log4j",versions:[{version:"2.0.0",lessThan:"2.15.0",status:"affected",changes:[{at:"2.12.2",status:"unaffected"}]}]}]});
  assert.deepEqual(complex[0]!.version_range,["unsupported_version_rule"]);
  const cpe={vulnerable:true,criteria:"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",versionStartIncluding:"2.0.0",versionEndExcluding:"2.15.0"};
  assert.deepEqual(nvdVersionFacts({configurations:[{nodes:[{operator:"OR",cpeMatch:[cpe]}]}]})[0]!.version_range,[">=2.0.0 <2.15.0"]);
  assert.deepEqual(nvdVersionFacts({configurations:[{nodes:[{operator:"AND",cpeMatch:[cpe]}]}]})[0]!.version_range,["unsupported_version_rule"]);
});
test("原文评分：v2/v3.0、未绑定来源和越界分不冒充v3.1冲突事实", () => {
  const rows=recordScoreFacts({id:"CVE-2026-10002",metrics:[{source_of_score:"nvd",baseScore:9.8,vectorString:"CVSS:3.1/AV:N"},{source_of_score:"cna",baseScore:10,vectorString:"CVSS:3.0/AV:N"},{source_of_score:"blog",baseScore:1,vectorString:"CVSS:3.1/AV:N"}]});
  assert.equal(rows.length,1);
  const raw={source_type:"cve_org"} as RawDoc;
  const data={cveMetadata:{cveId:"CVE-2026-10002",state:"PUBLISHED",datePublished:"2026-10-01T00:00:00Z"},containers:{cna:{descriptions:[{value:"Log4j flaw"}],affected:[{product:"Log4j",versions:[{version:"2.14.1",status:"affected"}]}]}}};
  const parsed=rawKnowledgeRecords(raw,new TextEncoder().encode(JSON.stringify(data)));
  assert.equal(parsed[0]!.id,"CVE-2026-10002");
  assert.deepEqual(parsed[0]!.versions![0]!.version_range,["=2.14.1"]);
});

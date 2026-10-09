import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { AssetsStore } from "../../assets/src/store.js";
import { assetRun } from "../../assets/test/asset-fixture.js";
import { SqliteExtensionReceiptStore } from "../src/extension-receipts.js";
import { prepareAssetReceipt, commitAssetReceipt } from "../src/asset-extension.js";
import { preparePocReceipt, commitPocReceipt } from "../src/poc-extension.js";
import { buildTriageReport, rankTriage, triageDigest } from "../src/triage.js";

const PROV={model:"Qwen/Qwen3.5-2B",checkpoint_sha256:"c".repeat(64),base_revision:"15852e8c16360a2fea060d615a32b45270f8a8fc",code_commit:"80ca8e81d08992cb2a4cbb6a0caa1355ad3e5aee",device:"cuda:0"};
const ans=(r:number)=>({model:PROV.model,metadata:{method:"lora_decision_head",checkpoint_sha256:PROV.checkpoint_sha256,base_revision:PROV.base_revision,code_commit:PROV.code_commit,device:PROV.device},answers:{relevance:{type:"choice",choice:r>=0.5?"related":"unrelated",probabilities:{related:r,unrelated:Number((1-r).toFixed(6)),uncertain:0},confidence:Math.max(r,1-r)}}});

test("triage 只汇总已收据：资产命中+修复指导排最前，unknown 不是安全", async () => {
  const root=await mkdtemp(join(tmpdir(),"triage-")),path=join(root,"intel.sqlite");
  const events=new SqliteEventStore(path),bus=new EventBus({store:events});
  const keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR","NVD_API_KEY"] as const,saved=keys.map(k=>process.env[k]);
  try {
    process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY="mock";
    const payload={resultsPerPage:1,startIndex:0,totalResults:1,vulnerabilities:[{cve:{id:"CVE-2026-1001",sourceIdentifier:"security@example.org",published:"2026-10-01T00:00:00.000",lastModified:"2026-10-01T00:00:00.000",vulnStatus:"Analyzed",descriptions:[{lang:"en",value:"Vue before 3.5.0 allows script injection."}],weaknesses:[{source:"nvd@nist.gov",type:"Primary",description:[{lang:"en",value:"CWE-79"}]}],metrics:{},configurations:[{nodes:[{operator:"OR",cpeMatch:[{vulnerable:true,criteria:"cpe:2.3:a:example:vue:*:*:*:*:*:*:*:*",versionEndExcluding:"3.5.0"}]}]}],references:[{url:"https://example.test/exploit.py",source:"security@example.org",tags:["Exploit"]}]}}]};
    globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
    await runIngestOnce({store:events,offline:false,sourceIds:["nvd_cve"],limit:1});
    globalThis.fetch=(async()=>{throw new Error("triage must not call transports");}) as typeof fetch;
    const item=[...readIntelIndexSnapshot(path).accepted.values()][0]!.item;
    const assets=new AssetsStore(join(root,"assets.sqlite"));
    assets.upsertGroup({group_id:"g1",name:"Fixture",roots:[root],enabled:true,note:null,created_at:"2026-10-01T00:00:00Z"});
    assets.saveScanRun(assetRun(root),0);
    const store=new SqliteExtensionReceiptStore(path);
    commitAssetReceipt({sqlitePath:path,assetsPath:join(root,"assets.sqlite"),store,receipt:await prepareAssetReceipt({sqlitePath:path,payloadRoots:[root],assetsPath:join(root,"assets.sqlite"),item})});
    commitPocReceipt({sqlitePath:path,store,receipt:await preparePocReceipt({sqlitePath:path,payloadRoots:[root],item,jevModelId:"Open-Jev-2B@0c7aa49",jevProvenance:PROV,fetchImpl:(async()=>Response.json(ans(0.97))) as typeof fetch})});
    const report=buildTriageReport(path,{now:new Date("2026-10-09T00:00:00Z")});
    assert.equal(report.entries.length,1);
    assert.equal(report.entries[0]!.tier,"review_first");
    assert.equal(report.entries[0]!.asset.potentially_affected,1);
    assert.equal(report.entries[0]!.poc.candidates,1);
    assert.equal(report.entries[0]!.remediation.status,"absent");
    assert.ok(report.entries[0]!.rationale.includes("修复指导")===false||report.entries[0]!.rationale.includes("暂无"));
    assert.equal(report.business_writes,0);assert.equal(report.network_calls,0);assert.equal(report.model_calls,0);
    assert.equal(triageDigest(report),triageDigest(report));
    store.close();assets.close();
  } finally {
    globalThis.fetch=saved.length?((globalThis.fetch as unknown) as typeof fetch):globalThis.fetch;
    keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});
    events.close();await rm(root,{recursive:true,force:true});
  }
});

test("排序纯函数：unknown 资产高于仅有 PoC 候选，未命中只是 informational", () => {
  const ranked=rankTriage([
    {intel_id:"a",asset:{status:"verified",potentially_affected:0,unknown:0,groups:[]},remediation:{status:"absent",vendor_statements:0,agency_guidance:0},poc:{status:"verified",candidates:3,advisory_supported:0}},
    {intel_id:"b",asset:{status:"verified",potentially_affected:0,unknown:2,groups:["g1"]},remediation:{status:"absent",vendor_statements:0,agency_guidance:0},poc:{status:"absent",candidates:0,advisory_supported:0}},
    {intel_id:"c",asset:{status:"verified",potentially_affected:1,unknown:0,groups:["g1"]},remediation:{status:"verified",vendor_statements:1,agency_guidance:0},poc:{status:"absent",candidates:0,advisory_supported:0}},
  ]);
  assert.deepEqual(ranked.map(r=>r.intel_id),["c","a","b"],"资产命中排最前；同级 review_next 按 intel_id 稳定排序");
  assert.equal(ranked[0]!.tier,"review_first");
  assert.ok(ranked[0]!.rationale.includes("修复指导"));
  assert.equal(ranked[1]!.tier,"review_next");
  assert.ok(ranked[1]!.rationale.includes("PoC 候选"));
  assert.equal(ranked[2]!.tier,"review_next");
  assert.ok(ranked[2]!.rationale.includes("unknown 不是安全"));
});
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SqliteEventStore, SqliteEnrichmentStateStore, EventBus, sha256Json } from "@safetrace/shared";
import { databaseBackupStats, createVerifiedBackup } from "../../shared/src/backup.js";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { releasedIntelPayload } from "../../ingest/src/intel-payload.js";
import { runEnrichment } from "../src/index.js";
import { reconcileCapturedCvss } from "../src/captured-cvss.js";
import { readKnowledgeProjection } from "../../qa/src/knowledge-reader.js";

test("captured CVSS dry plan is read-only; explicit apply publishes only proved primary score and is resumable",async()=>{
  const root=await mkdtemp(join(tmpdir(),"captured-cvss-")),path=join(root,"db.sqlite"),store=new SqliteEventStore(path),bus=new EventBus({store});
  const oldFetch=fetch,keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR","NVD_API_KEY"] as const,prior=keys.map(k=>process.env[k]);
  try{
    process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY="mock-only";
    const payload=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8"));globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
    const ingested=await runIngestOnce({store,offline:false,sourceIds:["nvd_cve"],limit:1});globalThis.fetch=oldFetch;
    const before=databaseBackupStats(path),options={sqlitePath:path,payloadRoots:[root],limit:1};
    const preview=await reconcileCapturedCvss(options);assert.equal(preview.written,0);assert.equal(preview.selected.length,1);assert.deepEqual(databaseBackupStats(path),before);
    await assert.rejects(reconcileCapturedCvss({...options,apply:true,backupDirectory:""}),/requires/);assert.deepEqual(databaseBackupStats(path),before);
    const backup=await createVerifiedBackup({sqlitePath:path,outputRoot:join(root,"backups"),rawPayloadRoots:[root],qdrantUrl:"http://127.0.0.1:1",collection:"test",fetchImpl:(async url=>String(url).endsWith("/points/scroll")?Response.json({result:{points:[],next_page_offset:null}}):Response.json({result:{points_count:0,config:{params:{vectors:{dense:{size:2}}}}}})) as typeof fetch});
    let calls=0;globalThis.fetch=(async()=>{calls++;throw new Error("no network/model calls allowed in captured reconciliation");}) as typeof fetch;
    const result=await reconcileCapturedCvss({...options,apply:true,backupDirectory:backup.directory});assert.equal(result.written,1);assert.equal(calls,0);
    const published=(await store.read<any>("enrich.items"))[0]!.payload;assert.deepEqual(published.dimensions_completed,["cvss"]);assert.equal(published.artifacts.papers,undefined);assert.equal(published.artifacts.score_assessment.epss_score,undefined);
    const projection=await readKnowledgeProjection({sqlitePath:path,payloadRoots:[root]});assert.equal(projection.evidence.filter(p=>p.kind==="cvss").length,1,JSON.stringify(projection.rejected));
    const resumed=await reconcileCapturedCvss({...options,apply:true,backupDirectory:backup.directory});assert.equal(resumed.written,0);assert.equal(resumed.counts.already_current,1);assert.equal((await store.read("enrich.items")).length,1);
    await bus.publish("dq.verdicts",{...ingested.verdicts[0]!,verdict:"quarantine"},{trace_id:"tr_blocked",causation_id:ingested.causation_by_intel_id[ingested.merged[0]!.intel_id]});
    const rejected=await reconcileCapturedCvss(options);assert.equal(rejected.selected.length,0);assert.equal((await readKnowledgeProjection({sqlitePath:path,payloadRoots:[root]})).chunks.length,0);
  }finally{globalThis.fetch=oldFetch;keys.forEach((k,i)=>{if(prior[i]===undefined)delete process.env[k];else process.env[k]=prior[i];});store.close();await rm(root,{recursive:true,force:true});}
});

test("captured reconciliation cannot let unproved raw files borrow a valid NIST proof",async()=>{
  const root=await mkdtemp(join(tmpdir(),"cvss-proof-scope-")),path=join(root,"db.sqlite"),store=new SqliteEventStore(path),bus=new EventBus({store}),originalFetch=fetch;
  const keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR","NVD_API_KEY"] as const,saved=keys.map(k=>process.env[k]);
  try{
    process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY="mock";
    const payload=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8"));globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
    const run=await runIngestOnce({store,offline:false,sourceIds:["nvd_cve"],limit:1});globalThis.fetch=originalFetch;
    const forged=join(root,"unproved.json");const fake=structuredClone(payload);fake.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore=1.1;await writeFile(forged,JSON.stringify(fake));
    const item={...releasedIntelPayload(run.merged[0]!),raw_refs:[forged,...run.merged[0]!.raw_refs]};
    const intel=await bus.publish("intel.items",item,{trace_id:run.trace_id});const verdict={...run.verdicts[0]!,item_id:item.intel_id};const dq=await bus.publish("dq.verdicts",verdict,{trace_id:run.trace_id,causation_id:intel.event_id});
    await bus.recordLineage({trace_id:run.trace_id,parent_lineage_ids:Object.values(run.lineage_parent_by_intel_id),stage:"ingest.dq1",operation_version:"test",status:"success",causation_id:dq.event_id,input_refs:[{kind:"IntelItem",id:item.intel_id,sha256:sha256Json(item)}],output_refs:[{kind:"QualityVerdict",id:"dq:"+item.intel_id,sha256:sha256Json(verdict)}]});
    const projection=await readKnowledgeProjection({sqlitePath:path,payloadRoots:[root]});assert.ok(projection.rejected.some(r=>r.scope.includes(forged)));
    const plan=await reconcileCapturedCvss({sqlitePath:path,payloadRoots:[root],limit:1});assert.equal(plan.selected[0]!.cvss_v3_base,10,"a valid source cannot vouch for unproved 1.1");
  }finally{globalThis.fetch=originalFetch;keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});store.close();await rm(root,{recursive:true,force:true});}
});

test("captured CVSS refresh preserves verified paper visibility, EPS receipt and freshness",async()=>{
  const root=await mkdtemp(join(tmpdir(),"cvss-retained-")),path=join(root,"db.sqlite"),store=new SqliteEventStore(path),states=new SqliteEnrichmentStateStore(path),bus=new EventBus({store}),originalFetch=fetch;
  const keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR","NVD_API_KEY"] as const,saved=keys.map(k=>process.env[k]);
  try{
    process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY="mock";
    const payload=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8"));globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
    const run=await runIngestOnce({store,offline:false,sourceIds:["nvd_cve"],limit:1}),item=releasedIntelPayload(run.merged[0]!);globalThis.fetch=originalFetch;
    const now=new Date("2026-10-04T00:00:00Z");await runEnrichment([item],{bus,stateStore:states,now,causation_by_intel_id:run.causation_by_intel_id,lineage_parent_by_intel_id:run.lineage_parent_by_intel_id,
      fetchImpl:async()=>({ok:true,status:200,text:async()=>'<feed><entry><id>https://arxiv.org/abs/2610.00001</id><title>Apache Log4j2 Glass Lantern study</title><summary>Apache Log4j2 CVE-2021-44228 remote code execution</summary><published>2026-10-03T00:00:00Z</published></entry></feed>',json:async()=>({data:[{cve:item.cve_ids[0],epss:"0.4",percentile:"0.8",date:"2026-10-04"}]})})});
    const oldPaper=states.get(item.intel_id,"paper")!,oldEps=states.get(item.intel_id,"epss")!,cvss=states.get(item.intel_id,"cvss")!;
    states.put({...cvss,status:"failed",artifact:null,result_hash:sha256Json(null),reason:"explicit score revalidation requested"});
    const backup=await createVerifiedBackup({sqlitePath:path,outputRoot:join(root,"backups"),rawPayloadRoots:[root],qdrantUrl:"http://127.0.0.1:1",collection:"test",fetchImpl:(async url=>String(url).endsWith("/points/scroll")?Response.json({result:{points:[],next_page_offset:null}}):Response.json({result:{points_count:0,config:{params:{vectors:{dense:{size:2}}}}}})) as typeof fetch});
    const result=await reconcileCapturedCvss({sqlitePath:path,payloadRoots:[root],limit:1,apply:true,backupDirectory:backup.directory,now:new Date("2026-10-04T00:01:00Z")});assert.equal(result.written,1);
    const current=(await store.read<any>("enrich.items")).at(-1)!;assert.equal(current.payload.artifacts.papers.length,1);assert.equal(current.payload.artifacts.score_assessment.epss_score,0.4);
    assert.equal(states.get(item.intel_id,"paper")!.enrich_event_id,current.event_id);assert.equal(states.get(item.intel_id,"paper")!.updated_at,oldPaper.updated_at);
    assert.equal(states.get(item.intel_id,"epss")!.enrich_event_id,current.event_id);assert.equal(states.get(item.intel_id,"epss")!.updated_at,oldEps.updated_at);
    const projection=await readKnowledgeProjection({sqlitePath:path,payloadRoots:[root]});assert.equal(projection.evidence.filter(p=>p.kind==="paper").length,1);assert.equal(projection.evidence.filter(p=>p.kind==="cvss").length,1);
  }finally{globalThis.fetch=originalFetch;keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});states.close();store.close();await rm(root,{recursive:true,force:true});}
});

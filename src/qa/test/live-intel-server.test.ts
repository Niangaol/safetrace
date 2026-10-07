import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore, SqliteEnrichmentStateStore, sha256Json } from "@safetrace/shared";
import { databaseBackupStats } from "../../shared/src/backup.js";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { releasedIntelPayload } from "../../ingest/src/intel-payload.js";
import { runEnrichment } from "../../enrich/src/index.js";
import { createLiveIntelServer } from "../../../scripts/live-intel-server.js";

async function listen(server:ReturnType<typeof createLiveIntelServer>){await new Promise<void>((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);});return "http://127.0.0.1:"+(server.address() as {port:number}).port;}
async function close(server:ReturnType<typeof createLiveIntelServer>){await new Promise<void>(resolve=>{server.close(()=>resolve());server.closeAllConnections();});}
function frames(text:string){return text.split("\n\n").filter(frame=>frame.startsWith("data: ")).map(frame=>JSON.parse(frame.slice(6)));}

test("live API lists only proven artifact values, cites enrichment in chat and reflects latest quarantine without DB writes",async()=>{
  const root=await mkdtemp(join(tmpdir(),"safetrace-live-api-")),path=join(root,"db.sqlite"),store=new SqliteEventStore(path),states=new SqliteEnrichmentStateStore(path),bus=new EventBus({store});
  const originalFetch=fetch,keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR","NVD_API_KEY"] as const,saved=keys.map(key=>process.env[key]);let server:ReturnType<typeof createLiveIntelServer>|undefined;
  try{
    process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY="mock";
    const payload=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8"));
    globalThis.fetch=(async input=>{assert.match(String(input),/services.nvd.nist.gov/);return Response.json(payload);}) as typeof fetch;
    const run=await runIngestOnce({store,offline:false,sourceIds:["nvd_cve"],limit:1}),item=releasedIntelPayload(run.merged[0]!);
    await runEnrichment([item],{offline:false,bus,stateStore:states,now:new Date("2026-10-04T00:00:00Z"),lineage_parent_by_intel_id:run.lineage_parent_by_intel_id,causation_by_intel_id:run.causation_by_intel_id,
      fetchImpl:async url=>({ok:true,status:200,text:async()=>'<feed><entry><id>https://arxiv.org/abs/2610.00001v1</id><title>Log4j2 Glass Lantern Study</title><summary>Apache Log4j2 CVE-2021-44228 security analysis.</summary><published>2026-10-03T00:00:00Z</published></entry></feed>',json:async()=>({data:[{cve:item.cve_ids[0],epss:"0.4",percentile:"0.8",date:"2026-10-04"}]})})});
    const historical={...item,intel_id:"intel_historical"};const historicalEnv=await bus.publish("intel.items",historical,{trace_id:run.trace_id});
    const historicalDq=await bus.publish("dq.verdicts",{...run.verdicts[0]!,item_id:historical.intel_id},{trace_id:run.trace_id,causation_id:historicalEnv.event_id});
    await bus.recordLineage({trace_id:run.trace_id,stage:"ingest.dq1",operation_version:"test",status:"success",causation_id:historicalDq.event_id,input_refs:[{kind:"IntelItem",id:historical.intel_id,sha256:sha256Json(historical)}],output_refs:[{kind:"QualityVerdict",id:"dq:"+historical.intel_id,sha256:sha256Json({...run.verdicts[0]!,item_id:historical.intel_id})}]});
    const old=(await store.read<any>("enrich.items"))[0]!.payload;await bus.publish("enrich.items",{...old,intel_id:historical.intel_id},{trace_id:"tr_old",causation_id:historicalEnv.event_id});
    globalThis.fetch=originalFetch;
    const before=databaseBackupStats(path);server=createLiveIntelServer({sqlitePath:path,payloadRoots:[root]});const url=await listen(server);
    const health=await (await fetch(url+"/api/v1/health")).json() as any;assert.equal(health.data_mode,"live");assert.equal(health.model_calls_enabled,false);assert.equal(health.read_only,true);
    const list=await (await fetch(url+"/api/v1/vulns")).json() as any;assert.equal(list.total,2);
    const unknown=list.items.find((row:any)=>row.id==="intel_historical");assert.equal(unknown.enriched,false);assert.equal(unknown.enrichment_recorded,true);assert.equal(unknown.cvss_score,null);
    const detail=await (await fetch(url+"/api/v1/vulns/"+item.intel_id+"/evidence")).json() as any;assert.equal(detail.enrichments.length,2);assert.ok(detail.enrichments.every((e:any)=>e.mock===false&&e.evidence.length));
    assert.ok(detail.enrichments.find((e:any)=>e.dimension==="paper").evidence[0].url.includes("arxiv.org/abs/2610.00001"));
    const metrics=await (await fetch(url+"/api/v1/metrics/overview")).json() as any;assert.equal(metrics.enrich.records,1);assert.equal(metrics.enrich.recorded_unverified,1);
    const reply=await fetch(url+"/api/v1/qa/chat",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({question:"CVE-2021-44228 paper Glass Lantern"})});const data=frames(await reply.text());
    const done=data.find((e:any)=>e.event==="done");assert.equal(done.data_mode,"live");assert.equal(done.model_calls,0);assert.equal(done.answer_mode,"template");assert.equal(done.abstained,false);assert.equal(done.final_review.status,"skipped");assert.match(done.final_review.reason,/未执行模型复核/);
    assert.ok(data.some((e:any)=>e.event==="citation"&&e.url.includes("arxiv.org/abs/2610.00001")));assert.ok(data.some((e:any)=>e.event==="token"&&e.text.includes("Glass Lantern")));
    assert.deepEqual(databaseBackupStats(path),before,"readonly API cannot migrate tables or append QA/model records to business DB");
    assert.equal((await fetch(url+"/api/v1/health",{headers:{origin:"https://foreign.example"}})).status,403);
    assert.equal((await fetch(url+"/api/v1/qa/chat",{method:"POST",headers:{"content-type":"application/json"},body:"bad JSON"})).status,400);
    const captured=run.fetched[0]!.payload_ref,original=await readFile(captured,"utf8");
    const revised=JSON.parse(original);revised.vulnerabilities[0].cve.descriptions[0].value += " changed without a new source receipt";
    await writeFile(captured,JSON.stringify(revised));
    const invalidated=await (await fetch(url+"/api/v1/health")).json() as any;assert.equal(invalidated.verified_artifact_count,0,"same-path raw edits invalidate cached provenance, not just TTL");
    await writeFile(captured,original);assert.equal((await (await fetch(url+"/api/v1/health")).json() as any).verified_artifact_count,2);
    await bus.publish("dq.verdicts",{...run.verdicts[0]!,verdict:"quarantine"},{trace_id:run.trace_id,causation_id:run.causation_by_intel_id[item.intel_id]});
    assert.equal((await fetch(url+"/api/v1/vulns/"+item.intel_id)).status,404);
    const after=frames(await (await fetch(url+"/api/v1/qa/chat",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({question:"paper Glass Lantern"})})).text());
    assert.equal(after.find((e:any)=>e.event==="done").abstained,true);assert.equal(after.filter((e:any)=>e.event==="citation").length,0);
  }finally{globalThis.fetch=originalFetch;if(server)await close(server);keys.forEach((key,index)=>{if(saved[index]===undefined)delete process.env[key];else process.env[key]=saved[index];});states.close();store.close();await rm(root,{recursive:true,force:true});}
});
test("live API missing source stays failed without silently serving fixture",async()=>{
  const server=createLiveIntelServer({sqlitePath:"unused",readView:async()=>{throw new Error("source unavailable");}});const url=await listen(server);try{const response=await fetch(url+"/api/v1/health");assert.equal(response.status,503);assert.equal((await response.json() as any).data_mode,"live");}finally{await close(server);}
});

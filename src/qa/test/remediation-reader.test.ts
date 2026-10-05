import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import { databaseBackupStats } from "../../shared/src/backup.js";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { readRemediationEvidence } from "../src/remediation-reader.js";
import { MemoryIndex } from "../src/q2-retrieval.js";
import { classifyIntent } from "../src/q1-intent.js";
import { synthesizeAnswer } from "../src/q4-answer.js";
import { createLiveIntelServer } from "../../../scripts/live-intel-server.js";

test("captured agency guidance becomes readonly cited evidence without claiming fixed versions or verified repairs",async()=>{
 const root=await mkdtemp(join(tmpdir(),"remediation-reader-")),path=join(root,"db.sqlite"),store=new SqliteEventStore(path),bus=new EventBus({store});
 const original=fetch,keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR"] as const,saved=keys.map(k=>process.env[k]);let server:ReturnType<typeof createLiveIntelServer>|undefined;
 try{
  process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;const payload=JSON.parse(await readFile("fixtures/sources/kev.sample.json","utf8"));globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
  const run=await runIngestOnce({store,offline:false,sourceIds:["cisa_kev"],limit:1});globalThis.fetch=original;const item=run.merged[0]!,before=databaseBackupStats(path);
  const guidance=await readRemediationEvidence({sqlitePath:path,payloadRoots:[root],intelIds:[item.intel_id],limit:1});assert.equal(guidance.evidence.length,1);
  const proof=guidance.evidence[0]!;assert.equal(proof.artifact.validation_level,"agency_guidance");assert.deepEqual(proof.artifact.fixed_packages,[]);assert.equal(proof.artifact.published_at_granularity,"day");assert.equal(proof.chunk.published_at,undefined,"day is not an invented exact UTC publication instant");assert.ok(proof.chunk.text.includes("not a verified fix"));
  const index=new MemoryIndex();await index.upsert(guidance.chunks);const evidence=await index.search({query_id:"q",query_text:item.cve_ids[0]+" remediation",top_k:1,trace_id:"tr",schema_version:"1.0"});
  const question=item.cve_ids[0]+" 怎么修复？",plan=classifyIntent({text:question,session_id:"s",turn_id:"t"});const answer=await synthesizeAnswer(question,plan,evidence);assert.equal(answer.abstained,false);assert.equal(answer.citations[0]!.url,proof.artifact.source_url);
  server=createLiveIntelServer({sqlitePath:path,payloadRoots:[root]});await new Promise<void>(resolve=>server!.listen(0,"127.0.0.1",resolve));const url="http://127.0.0.1:"+(server.address() as {port:number}).port;
  const detail=await(await fetch(url+"/api/v1/vulns/"+item.intel_id+"/evidence")).json() as any;const dimension=detail.enrichments.find((e:any)=>e.dimension==="remediation");assert.equal(dimension.value.guidance[0].validation_level,"agency_guidance");assert.ok(dimension.storage.includes("readonly-source-derived"));
  assert.deepEqual(databaseBackupStats(path),before,"derived guidance is not a public-result schema rewrite or production write");
  await bus.publish("dq.verdicts",{...run.verdicts[0]!,verdict:"quarantine"},{trace_id:"tr_revoke",causation_id:run.causation_by_intel_id[item.intel_id]});
  assert.equal((await readRemediationEvidence({sqlitePath:path,payloadRoots:[root],intelIds:[item.intel_id],limit:1})).chunks.length,0);
 }finally{globalThis.fetch=original;if(server)await new Promise<void>(resolve=>{server!.close(()=>resolve());server!.closeAllConnections();});keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});store.close();await rm(root,{recursive:true,force:true});}
});

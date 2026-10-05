import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore, SqliteEnrichmentStateStore } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { releasedIntelPayload } from "../../ingest/src/intel-payload.js";
import { runEnrichment } from "../../enrich/src/index.js";
import { readKnowledgeProjection } from "../src/knowledge-reader.js";
import { MemoryIndex } from "../src/q2-retrieval.js";
import { classifyIntent } from "../src/q1-intent.js";
import { synthesizeAnswer } from "../src/q4-answer.js";

/** Real adapters/event SQLite/sidecar/projection/retrieval; all provider transports are explicit mocks. */
test("captured raw → DQ → real-mode mock enrichment → persisted sidecar → source/artifact retrieval and citation",async()=>{
  const root=await mkdtemp(join(tmpdir(),"safetrace-knowledge-e2e-")),dbPath=join(root,"db.sqlite");
  const store=new SqliteEventStore(dbPath),stateStore=new SqliteEnrichmentStateStore(dbPath),bus=new EventBus({store});
  const keys=["OFFLINE_FIXTURES","SAFETRACE_CACHE_DIR","NVD_API_KEY"] as const,saved=keys.map(k=>process.env[k]);const originalFetch=fetch;
  try{
    process.env.OFFLINE_FIXTURES="false";process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY="mock-only";
    const nvd=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8"));
    globalThis.fetch=(async input=>{assert.match(String(input),/services.nvd.nist.gov/);return Response.json(nvd);}) as typeof fetch;
    const ingested=await runIngestOnce({store,offline:false,sourceIds:["nvd_cve"],limit:1});
    const rawItem=ingested.merged[0]!,item:IntelItem=releasedIntelPayload(rawItem);assert.equal(ingested.verdicts[0]!.verdict,"pass");
    const xml='<feed><entry><id>https://arxiv.org/abs/2610.00001v1</id><title>Log4j2 Glass Lantern Study</title><summary>Apache Log4j2 JNDI remote code execution CVE-2021-44228 security mitigations</summary><published>2026-10-03T00:00:00Z</published></entry></feed>';
    await runEnrichment([item],{offline:false,bus,stateStore,now:new Date("2026-10-04T00:00:00Z"),traceId:"tr_enrich_e2e",lineage_parent_by_intel_id:ingested.lineage_parent_by_intel_id,causation_by_intel_id:ingested.causation_by_intel_id,
      fetchImpl:async url=>{if(url.includes("arxiv"))return {ok:true,status:200,text:async()=>xml,json:async()=>({})};assert.match(url,/api.first.org/);return {ok:true,status:200,text:async()=>"",json:async()=>({data:[{cve:item.cve_ids[0],epss:"0.8",percentile:"0.9",date:"2026-10-04"}]})};}});
    assert.equal(stateStore.get(item.intel_id,"paper")!.status,"live");assert.equal(stateStore.get(item.intel_id,"cvss")!.status,"live");assert.equal(stateStore.get(item.intel_id,"epss")!.status,"live");
    const projected=await readKnowledgeProjection({sqlitePath:dbPath,payloadRoots:[root]});
    assert.equal(projected.evidence.filter(e=>e.kind==="paper").length,1,JSON.stringify(projected.rejected));
    assert.equal(projected.evidence.filter(e=>e.kind==="cvss").length,1,JSON.stringify(projected.rejected));
    const paper=projected.evidence.find(e=>e.kind==="paper")!;assert.equal(paper.chunk.provenance.url,"https://arxiv.org/abs/2610.00001");assert.equal(paper.chunk.published_at,"2026-10-03T00:00:00Z");
    assert.ok(!projected.evidence.find(e=>e.kind==="source")!.chunk.text.includes("Glass Lantern"));
    assert.ok(!projected.evidence.find(e=>e.kind==="cvss")!.chunk.text.includes("epss_score"),"auxiliary proof is not silently merged into CVSS evidence");
    const index=new MemoryIndex();await index.upsert(projected.chunks);
    const evidence=await index.search({query_id:"q",query_text:"Glass Lantern",doc_types:["paper"],top_k:1,trace_id:"tr_qa",schema_version:"1.0"});assert.equal(evidence.chunks[0]!.chunk_id,paper.chunk.chunk_id);
    const question="CVE-2021-44228 的关联论文有哪些？",plan=classifyIntent({session_id:"s",turn_id:"t",text:question});
    const answer=await synthesizeAnswer(question,{...plan,needs_clarify:false},evidence,{now:new Date("2026-10-04T00:00:00Z")});
    assert.equal(answer.abstained,false);assert.equal(answer.citations[0]!.url,paper.chunk.provenance.url);assert.ok(answer.text_md.includes("Glass Lantern"));
    await bus.publish("dq.verdicts",{...ingested.verdicts[0]!,verdict:"quarantine"},{trace_id:"tr_revoked",causation_id:ingested.causation_by_intel_id[item.intel_id]});
    const revoked=await readKnowledgeProjection({sqlitePath:dbPath,payloadRoots:[root]});assert.equal(revoked.chunks.length,0);
    const replacement=new MemoryIndex();await replacement.upsert(revoked.chunks);assert.equal((await replacement.search({query_id:"q",query_text:"Glass Lantern",top_k:1,trace_id:"tr",schema_version:"1.0"})).chunks.length,0);
  }finally{globalThis.fetch=originalFetch;keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});stateStore.close();store.close();await rm(root,{recursive:true,force:true});}
});

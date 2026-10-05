import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, MemoryEventStore, SqliteEnrichmentStateStore, enrichmentInputHash, enrichmentRetryDue, sha256Json } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { loadScoreSourcesFromRawRefs, assessScore } from "../src/f4-cvss.js";
import { runEnrichment } from "../src/index.js";
import { searchPapers } from "../src/f1-papers.js";
import { planPendingEnrichment } from "../src/pending.js";

const HIGH="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",LOW="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N";
const item:IntelItem={intel_id:"intel_quality",cve_ids:["CVE-2024-1111"],title:"OpenSSL remote code execution",source_ids:["nvd_cve"],published_at:"2026-10-01T00:00:00Z",first_seen_at:"2026-10-04T00:00:00Z",entities:{product:"OpenSSL",vendor:"OpenSSL",version_range:[],cwe:[],cpes:[]},raw_refs:[],source_reliability:0.9,schema_version:"1.0"};
const sources=[{source_of_score:"nvd" as const,cve_id:item.cve_ids[0],cvss_v3_base:10,cvss_v3_vector:HIGH}];
const now=new Date("2026-10-04T00:00:00Z");
const atom=(title:string,summary:string)=>'<feed><entry><id>https://arxiv.org/abs/2610.00001v1</id><title>'+title+'</title><summary>'+summary+'</summary><published>2026-10-03T00:00:00Z</published></entry></feed>';

test("primary CVE scoring cannot borrow a sibling CVE value or attach its EPSS",async()=>{
  const root=await mkdtemp(join(tmpdir(),"score-primary-"));try{
    const path=join(root,"raw.json");await writeFile(path,JSON.stringify({vulnerabilities:[{cve:{id:"CVE-2021-44228",metrics:{cvssMetricV31:[{source:"nvd@nist.gov",type:"Primary",cvssData:{vectorString:HIGH,baseScore:10}}]}}}]}));
    const target={...item,cve_ids:["CVE-2024-9999","CVE-2021-44228"],raw_refs:[path]};const loaded=await loadScoreSourcesFromRawRefs(target);assert.deepEqual(loaded,[]);
    let requests=0;assert.equal(await assessScore(target,{sources:loaded,fetchImpl:async()=>{requests++;throw new Error("must not query EPS for mismatched CVSS");}}),null);assert.equal(requests,0);
    await assert.rejects(assessScore(target,{sources:[{source_of_score:"nvd",cvss_v3_base:10,cvss_v3_vector:HIGH}]}),/explicit source CVE identity/);
  }finally{await rm(root,{recursive:true,force:true});}
});

test("NVD Secondary/CNA order cannot impersonate NIST Primary metric authority",async()=>{
  const root=await mkdtemp(join(tmpdir(),"score-authority-"));try{
    const path=join(root,"raw.json");const nist={source:"nvd@nist.gov",type:"Primary",cvssData:{vectorString:HIGH,baseScore:10}},cna={source:"vendor@example.org",type:"Secondary",cvssData:{vectorString:LOW,baseScore:3.7}};
    for(const order of [[cna,nist],[nist,cna]]){
      await writeFile(path,JSON.stringify({vulnerabilities:[{cve:{id:item.cve_ids[0],sourceIdentifier:"vendor@example.org",metrics:{cvssMetricV31:order}}}]}));
      const loaded=await loadScoreSourcesFromRawRefs({...item,raw_refs:[path]});assert.deepEqual(loaded.map(x=>x.source_of_score),["nvd","cna"]);
      const score=await assessScore(item,{sources:loaded,offline:true});assert.equal(score!.source_of_score,"nvd");assert.equal(score!.cvss_v3_base,10);
    }
  }finally{await rm(root,{recursive:true,force:true});}
});

test("generic RCE words in an astronomy paper do not form a live OpenSSL association",async()=>{
  const stateStore=new SqliteEnrichmentStateStore(":memory:");try{
    await runEnrichment([item],{stateStore,now,scoreSources:[],fetchImpl:async()=>({ok:true,status:200,text:async()=>atom("Astronomy remote code execution","remote code execution among stars"),json:async()=>({})})});
    assert.equal(stateStore.get(item.intel_id,"paper")!.status,"empty");assert.deepEqual(stateStore.get(item.intel_id,"paper")!.artifact,[]);
  }finally{stateStore.close();}
});

test("HTTP 200 HTML is a protocol failure, never cached as successful zero-paper lookup",async()=>{
  const result=await searchPapers("OpenSSL protocol check",{fetchImpl:async()=>({ok:true,status:200,text:async()=>"<html>upstream error page</html>",json:async()=>({})})});
  assert.equal(result.degraded_to,"fixture");assert.equal(result.source_evidence,undefined);
});

test("offline supplied EPS and undated supplied values cannot become real live dimensions",async()=>{
  for(const offline of [true,false]){const stateStore=new SqliteEnrichmentStateStore(":memory:");try{
    await runEnrichment([item],{stateStore,now,offline,scoreSources:[{...sources[0]!,epss_score:0.97}],fetchImpl:async()=>({ok:true,status:200,text:async()=>atom("OpenSSL security","OpenSSL remote code execution"),json:async()=>({})})});
    assert.notEqual(stateStore.get(item.intel_id,"epss")!.status,"live");
  }finally{stateStore.close();}}
});

test("state refresh rejects stale writes, preserves last-good and does not cache live forever",()=>{
  const store=new SqliteEnrichmentStateStore(":memory:");try{
    const good={intel_id:item.intel_id,dimension:"cvss" as const,status:"live" as const,input_hash:enrichmentInputHash(item),result_hash:sha256Json({base:10}),enrich_event_id:"ev_good",retry_after:null,reason:"good",attempts:1,updated_at:now.toISOString(),artifact:{base:10}};
    store.put(good);assert.equal(enrichmentRetryDue(good,good.input_hash,new Date("2026-10-05T00:00:01Z")),true);
    store.put({...good,status:"failed",result_hash:sha256Json(null),artifact:null,reason:"source temporarily unavailable",updated_at:"2026-10-04T00:01:00Z"});
    assert.deepEqual(store.get(item.intel_id,"cvss")!.last_good!.artifact,{base:10});assert.equal(store.get(item.intel_id,"cvss")!.status,"failed");
    assert.throws(()=>store.put(good),/stale/);
    assert.throws(()=>store.atomic(()=>{store.put({...good,updated_at:"2026-10-04T00:02:00Z"});store.put({...good,dimension:"paper",result_hash:"forged",updated_at:"2026-10-04T00:02:00Z"});}),/invalid/);
    assert.equal(store.get(item.intel_id,"cvss")!.status,"failed","batch transaction must roll back its first dimension");
  }finally{store.close();}
});

test("no-bus cached computation gains a durable result receipt later without fresh source calls",async()=>{
  const stateStore=new SqliteEnrichmentStateStore(":memory:");try{
    await runEnrichment([item],{stateStore,now,offline:true,scoreSources:sources});assert.equal(stateStore.get(item.intel_id,"cvss")!.enrich_event_id,null);
    const store=new MemoryEventStore(),bus=new EventBus({store});let calls=0;
    await runEnrichment([item],{stateStore,now,offline:true,scoreSources:sources,bus,causation_by_intel_id:{[item.intel_id]:"ev_current"},fetchImpl:async()=>{calls++;throw new Error("must repair receipts from cache only");}});
    assert.equal(calls,0);const receipt=(await store.read("enrich.items"))[0]!;assert.equal(receipt.causation_id,"ev_current");assert.equal(stateStore.get(item.intel_id,"cvss")!.enrich_event_id,receipt.event_id);
  }finally{stateStore.close();}
});

test("quarantined items never contribute real-live dimension statistics",()=>{
  const score={base:10};const state={intel_id:item.intel_id,dimension:"cvss" as const,status:"live" as const,input_hash:enrichmentInputHash(item),result_hash:sha256Json(score),enrich_event_id:"ev",retry_after:null,reason:"x",attempts:1,updated_at:now.toISOString(),artifact:score};
  const plan=planPendingEnrichment([item],[{item_id:item.intel_id,verdict:"quarantine"} as any],[],{states:[state],now});assert.equal(plan.real_live_dimensions,0);
});

test("secondary KEV and secondary score source cannot elevate primary CVE severity",async()=>{
  const multi={...item,cve_ids:["CVE-2026-1111","CVE-2026-2222"],source_ids:["nvd_cve","cisa_kev"]};
  const score=await assessScore(multi,{offline:true,kevSet:["CVE-2026-2222"],sources:[{...sources[0]!,cve_id:"CVE-2026-1111"},{...sources[0]!,cve_id:"CVE-2026-2222",kev_flag:true}]});
  assert.equal(score!.kev_flag,undefined);assert.equal(score!.exploit_maturity,undefined);
  assert.equal((await assessScore(multi,{offline:true,kevSet:["CVE-2026-1111"],sources:[{...sources[0]!,cve_id:"CVE-2026-1111"}]}))!.kev_flag,true);
});

test("psychology memory-corruption paper cannot replace a known product anchor",async()=>{
  const store=new SqliteEnrichmentStateStore(":memory:");try{
    await runEnrichment([{...item,title:"OpenSSL heap memory corruption"}],{stateStore:store,now,scoreSources:[],fetchImpl:async()=>({ok:true,status:200,text:async()=>atom("Memory corruption in human cognitive recall","A psychology study of human memory corruption."),json:async()=>({})})});
    assert.equal(store.get(item.intel_id,"paper")!.status,"empty");assert.deepEqual(store.get(item.intel_id,"paper")!.artifact,[]);
  }finally{store.close();}
});

test("same-path source edits and REJECTED revisions invalidate live CVSS before its TTL",async()=>{
  const root=await mkdtemp(join(tmpdir(),"score-source-refresh-"));const states=new SqliteEnrichmentStateStore(":memory:");try{
    const raw=join(root,"raw.json"),scored={...item,raw_refs:[raw]};
    const document=(score:number,status="Analyzed")=>({vulnerabilities:[{cve:{id:item.cve_ids[0],vulnStatus:status,metrics:{cvssMetricV31:[{source:"nvd@nist.gov",type:"Primary",cvssData:{vectorString:score===10?HIGH:LOW,baseScore:score}}]}}}]});
    await writeFile(raw,JSON.stringify(document(10)));await runEnrichment([scored],{stateStore:states,offline:true,now});const original=states.get(item.intel_id,"cvss")!.dependency_hash;
    await writeFile(raw,JSON.stringify(document(3.7)));await runEnrichment([scored],{stateStore:states,offline:true,now:new Date("2026-10-04T00:01:00Z")});
    assert.notEqual(states.get(item.intel_id,"cvss")!.dependency_hash,original);assert.equal((states.get(item.intel_id,"cvss")!.artifact as {cvss_v3_base:number}).cvss_v3_base,3.7);
    await writeFile(raw,JSON.stringify(document(3.7,"REJECTED")));await runEnrichment([scored],{stateStore:states,offline:true,now:new Date("2026-10-04T00:02:00Z")});
    assert.notEqual(states.get(item.intel_id,"cvss")!.status,"live");assert.equal(states.get(item.intel_id,"cvss")!.artifact,null);assert.equal((states.get(item.intel_id,"cvss")!.last_good!.artifact as {cvss_v3_base:number}).cvss_v3_base,3.7);
  }finally{states.close();await rm(root,{recursive:true,force:true});}
});

test("pending selects missing result receipts and changed IntelItem event bindings",async()=>{
  const states=new SqliteEnrichmentStateStore(":memory:");try{
    const xml=atom("OpenSSL CVE study","OpenSSL remote code execution "+item.cve_ids[0]);
    await runEnrichment([item],{stateStore:states,now,scoreSources:sources,fetchImpl:async url=>({ok:true,status:200,text:async()=>xml,json:async()=>({data:[{cve:item.cve_ids[0],epss:"0.3",percentile:"0.9",date:"2026-10-04"}]})})});
    const verdict={item_id:item.intel_id,verdict:"pass"} as any;
    const unbound=planPendingEnrichment([item],[verdict],[],{states:states.list(),now,publishedEnrichments:[]});assert.deepEqual(unbound.pending.map(x=>x.intel_id),[item.intel_id]);
    const bus=new EventBus({store:new MemoryEventStore()});await runEnrichment([item],{stateStore:states,bus,now,scoreSources:sources,causation_by_intel_id:{[item.intel_id]:"ev_old"}});
    const receipts=await bus.readEvents<any>("enrich.items");
    const changed=planPendingEnrichment([item],[verdict],receipts.map(e=>e.payload),{states:states.list(),now,publishedEnrichments:receipts,currentIntelEventIds:new Map([[item.intel_id,"ev_new"]])});assert.equal(changed.pending.length,1);
  }finally{states.close();}
});

test("EPS can be verified independently without fabricating a missing CVSS vector",async()=>{
  const states=new SqliteEnrichmentStateStore(":memory:");try{
    await runEnrichment([item],{stateStore:states,now,scoreSources:[],fetchImpl:async url=>({ok:true,status:200,text:async()=>atom("OpenSSL study","OpenSSL vulnerability analysis"),json:async()=>({data:[{cve:item.cve_ids[0],epss:"0.4",percentile:"0.8",date:"2026-10-04"}]})})});
    assert.equal(states.get(item.intel_id,"cvss")!.status,"empty");assert.equal(states.get(item.intel_id,"cvss")!.artifact,null);
    assert.equal(states.get(item.intel_id,"epss")!.status,"live");assert.deepEqual(states.get(item.intel_id,"epss")!.artifact,{epss_score:0.4,epss_percentile:0.8});
  }finally{states.close();}
});

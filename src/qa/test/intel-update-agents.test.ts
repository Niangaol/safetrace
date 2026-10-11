import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IntelItem } from "@safetrace/shared";
import { IntelligenceUpdateAgents, updateTimeliness } from "../src/orchestrator/intel-update-agents.js";
import type { AgentUpdateSnapshot, AgentUpdateEvent } from "../src/orchestrator/intel-update-agents.js";
import { MemoryUpdateQueue, SQLiteUpdateQueue } from "../src/orchestrator/update-queue.js";
import type { AcceptedIntel } from "../src/intel-index-plan.js";
function entry(seq=2,id="intel_new"):AcceptedIntel {
  const item={intel_id:id,title:"new captured CVE",summary:"changed "+seq,cve_ids:["CVE-2026-40001"],source_ids:["nvd_cve"],raw_refs:["captured.json"],published_at:"2026-10-11T11:59:00Z",first_seen_at:"2026-10-11T12:00:00Z",entities:{product:"acme",vendor:"vendor",version_range:["<2"],cwe:[],cpes:[]},source_reliability:1,schema_version:"1.0"} as IntelItem;
  const verdict={item_id:id,item_kind:"intel" as const,verdict:"pass" as const,quality_score:1,dimension_scores:{structure:1,completeness:1,consistency:1,timeliness:1,sourcing:1},flags:[],gate_version:"1.1.0"};
  return {item,verdict,intel_event:{seq,event_id:"ev_"+seq,trace_id:"tr",causation_id:null,topic:"intel.items",payload:item},verdict_event:{seq:seq+1,event_id:"dq_"+seq,trace_id:"tr",causation_id:"ev_"+seq,topic:"dq.verdicts",payload:verdict}};
}
function view(entries:AcceptedIntel[]):AgentUpdateSnapshot {
  return {snapshot:{watermark:Math.max(1,...entries.map(e=>e.verdict_event.seq)),fingerprint:entries.map(e=>e.intel_event.event_id).join(","),accepted:new Map(entries.map(e=>[e.item.intel_id,e])),rejected:new Map()},states:[],receipts:[]};
}
const ready={visible:true,source_chunks:1,artifact_chunks:1,mode:"test" as const};
function barrier(){let release!:()=>void;const promise=new Promise<void>(done=>release=done);return {promise,release};}

test("内部协作：原始来源先ready，快速维度不含paper，单次唤醒立即索引不用等下一轮源poll",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z");const queue=new MemoryUpdateQueue({clock:()=>now}),events:AgentUpdateEvent[]=[];
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,workerConcurrency:1,readSnapshot:async()=>view([entry()]),
    refreshSources:async()=>{now+=10;return {source_chunks:1,mode:"test"};},enrich:async(_e,dims,guard)=>{assert.deepEqual(dims,["cvss","epss"]);assert.equal(await guard(),true);now+=100;},index:async()=>{now+=15;return ready;},onEvent:e=>{events.push(e);}});
  await runtime.observe();runtime.wake();await runtime.whenIdle();
  assert.equal(queue.get("intel_new")?.status,"done");
  assert.ok(events.findIndex(e=>e.stage==="source_ready")<events.findIndex(e=>e.stage==="enrich"));
  assert.equal(updateTimeliness(queue.list(),now).detected_to_index_ready_ms.p95,125);
  await runtime.stop();
});
test("内部协作：旧任务慢返回时新版本抢先交接，旧结果不能完成新版本任务",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z"),snapshot=view([entry()]);const queue=new MemoryUpdateQueue({clock:()=>now}),started=barrier(),finish=barrier();const committed:number[]=[];
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,workerConcurrency:1,readSnapshot:async()=>snapshot,
    enrich:async(e,_dims,guard)=>{if(e.intel_event.seq===2){started.release();await finish.promise;}if(!await guard())throw new Error("stale observed before commit");committed.push(e.intel_event.seq);},index:async()=>ready});
  await runtime.observe();const work=runtime.drain();await started.promise;
  snapshot=view([entry(8)]);await runtime.observe();finish.release();await work;
  assert.deepEqual(committed,[8]);assert.equal(queue.get("intel_new")?.intel_event_seq,8);assert.equal(queue.get("intel_new")?.status,"done");await runtime.stop();
});
test("内部协作：索引交接跨SQLite重开续接，不重跑已经完成的富化",async()=>{
  const root=await mkdtemp(join(tmpdir(),"safetrace-agent-handoff-"));let now=Date.parse("2026-10-11T12:00:00Z"),enriched=0,indexed=0;
  try {
    const path=join(root,"q.sqlite"),first=new SQLiteUpdateQueue(path,{clock:()=>now});
    const a=new IntelligenceUpdateAgents({queue:first,now:()=>now,workerConcurrency:1,maxJobsPerWake:1,readSnapshot:async()=>view([entry()]),enrich:async()=>{enriched++;},index:async()=>{indexed++;return ready;}});
    await a.observe();await a.drain();assert.equal(first.get("intel_new")?.stage,"index");await a.stop();first.close();
    const second=new SQLiteUpdateQueue(path,{clock:()=>now});const b=new IntelligenceUpdateAgents({queue:second,now:()=>now,workerConcurrency:1,readSnapshot:async()=>view([entry()]),enrich:async()=>{enriched++;},index:async()=>{indexed++;return ready;}});
    await b.observe();await b.drain();assert.equal(enriched,1);assert.equal(indexed,1);assert.equal(second.get("intel_new")?.status,"done");await b.stop();second.close();
  } finally {await rm(root,{recursive:true,force:true});}
});
test("内部协作：失败尊重退避，不会每个源poll立即重新请求",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z"),calls=0;const queue=new MemoryUpdateQueue({clock:()=>now,backoffBaseMs:1000});
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,workerConcurrency:1,readSnapshot:async()=>view([entry()]),enrich:async()=>{if(++calls===1)throw new Error("source temporarily failed");},index:async()=>ready});
  await runtime.observe();await runtime.drain();await runtime.observe();await runtime.drain();assert.equal(calls,1);
  now+=1000;await runtime.drain();assert.equal(calls,2);assert.equal(queue.get("intel_new")?.status,"done");await runtime.stop();
});
test("内部协作：DQ隔离撤销正在执行的任务，不产生索引完成",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z"),snapshot=view([entry()]),indexed=0;const started=barrier(),finish=barrier(),queue=new MemoryUpdateQueue({clock:()=>now});
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,readSnapshot:async()=>snapshot,enrich:async(_e,_d,guard)=>{started.release();await finish.promise;if(!await guard())throw new Error("quarantined");},index:async()=>{indexed++;return ready;}});
  await runtime.observe();const work=runtime.drain();await started.promise;snapshot=view([]);snapshot.snapshot.watermark=10;snapshot.snapshot.rejected.set("intel_new","quarantine");await runtime.observe();finish.release();await work;
  assert.equal(queue.get("intel_new")?.status,"revoked");assert.equal(indexed,0);await runtime.stop();
});
test("内部协作：没有来源证明时不能把empty索引计成完成",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z");const queue=new MemoryUpdateQueue({clock:()=>now});
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,readSnapshot:async()=>view([entry()]),enrich:async()=>{},index:async()=>({...ready,visible:false,source_chunks:0})});
  await runtime.observe();await runtime.drain();assert.equal(queue.get("intel_new")?.stage,"index");assert.equal(queue.get("intel_new")?.indexed_at,null);assert.equal(updateTimeliness(queue.list(),now).detected_to_index_ready_ms.samples,0);await runtime.stop();
});
test("内部协作：重复drain合并且stop等待观察读取，停止后不再交接",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z");const queue=new MemoryUpdateQueue({clock:()=>now}),started=barrier(),finish=barrier();
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,readSnapshot:async()=>{started.release();await finish.promise;return view([entry()]);},enrich:async()=>{},index:async()=>ready});
  const observe=runtime.observe();await started.promise;let stopped=false;const stopping=runtime.stop().then(()=>{stopped=true;});await Promise.resolve();assert.equal(stopped,false);finish.release();await observe;await stopping;assert.equal(stopped,true);
  const a=runtime.drain(),b=runtime.drain();assert.equal(a,b);await a;assert.equal(await runtime.observe(),0);
});
test("内部协作：空来源证明不发source_ready，未富化也不冒充当前可用",async()=>{
  const now=Date.parse("2026-10-11T12:00:00Z"),events:AgentUpdateEvent[]=[],queue=new MemoryUpdateQueue({clock:()=>now});
  const runtime=new IntelligenceUpdateAgents({queue,now:()=>now,readSnapshot:async()=>view([entry()]),refreshSources:async()=>({source_chunks:0,mode:"test"}),enrich:async()=>{},index:async()=>({...ready,visible:false,source_chunks:0}),onEvent:e=>{events.push(e);}});
  await runtime.observe();assert.equal(events.some(e=>e.stage==="source_ready"),false);assert.ok(events.some(e=>e.stage==="failed"));await runtime.stop();
});

test("观察定时器拒绝溢出，后台错误只保留最近100条",async()=>{
  const queue=new MemoryUpdateQueue(),runtime=new IntelligenceUpdateAgents({queue,readSnapshot:async()=>{throw new Error("snapshot unavailable");},enrich:async()=>{},index:async()=>ready});
  assert.throws(()=>runtime.start(2_147_483_648),/32-bit/);
  // Inject the timer callback without real wall-clock busy loops.
  const original=globalThis.setInterval;let tick!:()=>void;
  globalThis.setInterval=((callback:()=>void)=>{tick=callback;return 1;}) as unknown as typeof setInterval;
  try{runtime.start(5000);for(let i=0;i<120;i++){tick();await Promise.resolve();await Promise.resolve();await Promise.resolve();await Promise.resolve();}
    await runtime.stop();assert.ok(runtime.errors.length>0);assert.ok(runtime.errors.length<=100);
  }finally{globalThis.setInterval=original;await runtime.stop();}
});

test("时效指标：没有完成样本不造0ms，负时间不计准确延迟",()=>{
  assert.equal(updateTimeliness([],100).detected_to_index_ready_ms.p95,null);
  const q=new MemoryUpdateQueue({clock:()=>100});q.enqueue({intel_id:"intel_a",input_hash:"h",refs:["ev"],intel_event_seq:1,detected_at:100});const task=q.list()[0]!;task.indexed_at=50;
  const metric=updateTimeliness([task],100);assert.equal(metric.rejected_negative_timestamps,1);assert.equal(metric.detected_to_index_ready_ms.samples,0);
});

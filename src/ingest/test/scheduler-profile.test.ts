import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryEventStore } from "@safetrace/shared";
import { MemorySourceScheduleStore } from "../src/schedule-state.js";
import { runIngestScheduler } from "../src/scheduler.js";
import type { IngestRunResult } from "../src/pipeline.js";

test("协作快速轮询档：NVD30分钟、KEV15分钟；经典registry默认不被修改",async()=>{
  const previous=process.env.OFFLINE_FIXTURES;process.env.OFFLINE_FIXTURES="false";
  try {
    for(const fast of [false,true]){
      let now=Date.parse("2026-10-11T12:00:00Z");const calls:string[]=[],store=new MemoryEventStore(),state=new MemorySourceScheduleStore();
      const options={store,scheduleState:state,sourceIds:["nvd_cve","cisa_kev"],offline:false,maxCycles:1,runLogPath:null,nowMs:()=>now,
        ...(fast?{pollIntervalOverridesS:{nvd_cve:1800,cisa_kev:900}}:{}),
        runSource:async (id:string)=>{calls.push(id);return {trace_id:"t",fetched:[],parsed:[],merged:[],verdicts:[],fallbackEvents:[]} as unknown as IngestRunResult;}};
      await runIngestScheduler(options);assert.equal(calls.length,2);
      now+=15*60_000;await runIngestScheduler(options);
      assert.equal(calls.filter(id=>id==="cisa_kev").length,fast?2:1);assert.equal(calls.filter(id=>id==="nvd_cve").length,1);
      now+=15*60_000;await runIngestScheduler(options);assert.equal(calls.filter(id=>id==="nvd_cve").length,fast?2:1);
    }
  } finally {if(previous===undefined)delete process.env.OFFLINE_FIXTURES;else process.env.OFFLINE_FIXTURES=previous;}
});
test("停止后只等待正在执行的source，不能启动pending的新请求",async()=>{
  const prior=process.env.OFFLINE_FIXTURES;process.env.OFFLINE_FIXTURES="false";let stop=false;let release!:()=>void,started!:()=>void;
  const gate=new Promise<void>(done=>release=done),ready=new Promise<void>(done=>started=done);const calls:string[]=[];
  try {const work=runIngestScheduler({store:new MemoryEventStore(),sourceIds:["nvd_cve","cisa_kev"],maxConcurrency:1,maxCycles:1,runLogPath:null,shouldStop:()=>stop,runSource:async id=>{calls.push(id);started();await gate;return {fetched:[],parsed:[],merged:[],verdicts:[],fallbackEvents:[],trace_id:"t"} as unknown as IngestRunResult;}});
    await ready;stop=true;release();await work;assert.equal(calls.length,1);
  }finally{release?.();if(prior===undefined)delete process.env.OFFLINE_FIXTURES;else process.env.OFFLINE_FIXTURES=prior;}
});

test("长驻source记录内存有上限，完整source记录数明确保留",async()=>{
  let now=Date.parse("2026-10-11T12:00:00Z");
  const result=await runIngestScheduler({store:new MemoryEventStore(),sourceIds:["nvd_cve"],offline:true,maxCycles:3,maxRetainedRecords:2,runLogPath:null,nowMs:()=>now,sleep:async()=>{now+=7200_000;},runSource:async()=>({fetched:[],parsed:[],merged:[],verdicts:[],fallbackEvents:[],trace_id:"t"} as unknown as IngestRunResult)});
  assert.equal(result.records.length,2);assert.equal(result.records_total,3);assert.equal(result.records_dropped_from_memory,1);
});

test("快速轮询档不能配置成无限猛刷，最短五分钟且仍使用源transport限流",async()=>{
  await assert.rejects(runIngestScheduler({store:new MemoryEventStore(),sourceIds:["nvd_cve"],maxCycles:1,runLogPath:null,pollIntervalOverridesS:{nvd_cve:1}}),/300/);
});

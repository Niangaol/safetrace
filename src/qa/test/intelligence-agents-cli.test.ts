import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { AddressInfo } from "node:net";
import { SqliteEventStore } from "@safetrace/shared";
import { createVerifiedBackup } from "../../shared/src/backup.js";
import { parseIntelligenceAgentArgs,requireAgentWriteGate,runIntelligenceAgents } from "../../../scripts/intelligence-agents.js";
import { readKnowledgeProjection } from "../src/knowledge-reader.js";
import { createLiveIntelServer } from "../../../scripts/live-intel-server.js";
function barrier(){let release!:()=>void;const promise=new Promise<void>(done=>release=done);return {promise,release};}

test("Agent入口：非演示路径与live必须apply+同库备份，旁路sidecar也不能绕过",async()=>{
  const offline=parseIntelligenceAgentArgs([],{});assert.equal(offline.offline,true);assert.equal(offline.cycles,1);await requireAgentWriteGate(offline,async()=>{throw new Error("not expected");});
  await assert.rejects(requireAgentWriteGate({...offline,sqlitePath:resolve("var/official.sqlite")}),/--apply/);
  await assert.rejects(requireAgentWriteGate({...offline,statePath:resolve("var/sidecar.sqlite")}),/--apply/);
  await assert.rejects(requireAgentWriteGate({...offline,offline:false}),/--apply/);
  let verified:string|undefined;await requireAgentWriteGate({...offline,offline:false,apply:true},async path=>{verified=path;});assert.equal(verified,offline.sqlitePath);
  assert.throws(()=>parseIntelligenceAgentArgs(["--live","--offline"],{}),/conflict/);
  assert.throws(()=>parseIntelligenceAgentArgs(["--workers","0"],{}),/workers/);
});

test("Agent实际接线：mock live采集→持久交接→CVSS/EPSS→来源索引，原始新情报不等慢EPSS就能问答",async()=>{
  const root=await mkdtemp(join(tmpdir(),"safetrace-agent-flow-")),dbPath=join(root,"events.sqlite"),init=new SqliteEventStore(dbPath);init.close();
  const transport=(async input=>String(input).endsWith("/points/scroll")?Response.json({result:{points:[],next_page_offset:null}}):Response.json({result:{points_count:0,config:{params:{vectors:{dense:{size:2,distance:"Cosine"}}}}}})) as typeof fetch;
  const backup=await createVerifiedBackup({sqlitePath:dbPath,outputRoot:join(root,"backups"),qdrantUrl:"http://127.0.0.1:1",collection:"mock-empty",fetchImpl:transport});
  const oldBackup=process.env.SAFETRACE_VERIFIED_BACKUP_DIR,originalFetch=fetch,requested=barrier(),release=barrier();let server:ReturnType<typeof createLiveIntelServer>|undefined;let run:ReturnType<typeof runIntelligenceAgents>|undefined;
  try {
    process.env.SAFETRACE_VERIFIED_BACKUP_DIR=backup.directory;
    const payload=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8")),id="CVE-2026-40001";
    payload.vulnerabilities[0].cve.id=id;payload.vulnerabilities[0].cve.published=new Date(Date.now()-60_000).toISOString();
    payload.vulnerabilities[0].cve.descriptions[0].value="NEW-AGENT-SOURCE-MARKER Log4j remote vulnerability; explicit test data.";
    globalThis.fetch=(async(input,options)=>{
      const url=String(input);
      if(url.startsWith("https://services.nvd.nist.gov/"))return Response.json(payload);
      if(url.startsWith("https://api.first.org/")){requested.release();await release.promise;return Response.json({status:"OK",data:[{cve:id,epss:"0.12",percentile:"0.78",date:new Date().toISOString().slice(0,10)}]});}
      return originalFetch(input,options); // network guard only permits loopback; unexpected outside calls fail.
    }) as typeof fetch;
    const opts=parseIntelligenceAgentArgs(["--live","--apply","--sqlite",dbPath,"--state",join(root,"queue.sqlite"),"--log",join(root,"updates.jsonl"),"--sources","nvd_cve","--cycles","1"],{});
    run=runIntelligenceAgents(opts);await requested.promise;
    const projection=await readKnowledgeProjection({sqlitePath:dbPath,payloadRoots:[join(root,"payloads")]});
    assert.ok(projection.chunks.some(c=>c.text.includes("NEW-AGENT-SOURCE-MARKER")),"source proofs already ready while EPSS request is waiting");
    assert.equal(projection.evidence.filter(e=>e.kind==="cvss").length,0,"do not pretend unfinished enrichment is ready");
    server=createLiveIntelServer({sqlitePath:dbPath,payloadRoots:[join(root,"payloads")]});
    await new Promise<void>(done=>server!.listen(0,"127.0.0.1",done));
    const base="http://127.0.0.1:"+(server.address() as AddressInfo).port;
    const response=await fetch(base+"/api/v1/qa/chat",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({question:id+" 的影响范围是什么？"})});
    const frames=(await response.text()).split("\n\n").filter(s=>s.startsWith("data: ")).map(s=>JSON.parse(s.slice(6)));
    assert.equal(frames.find(f=>f.event==="done")?.abstained,false);assert.equal(frames.find(f=>f.event==="done")?.model_calls,0);
    assert.ok(frames.filter(f=>f.event==="token").map(f=>f.text).join("").includes("NEW-AGENT-SOURCE-MARKER"));
    release.release();const result=await run;assert.equal(result.update_status,"ready");assert.equal(result.tasks.length,1);assert.equal(result.tasks[0]!.status,"done");assert.equal(result.model_calls,0);
    const stages=(result.events as {stage:string}[]).map(e=>e.stage);assert.ok(stages.indexOf("source_ready")<stages.indexOf("enrich"));assert.ok(stages.indexOf("enrich")<stages.indexOf("index"));
    assert.equal(result.timeliness.detected_to_index_ready_ms.samples,1);
  } finally {
    release.release();await run?.catch(()=>{});globalThis.fetch=originalFetch;
    if(server)await new Promise<void>(done=>{server!.close(()=>done());server!.closeAllConnections();});
    if(oldBackup===undefined)delete process.env.SAFETRACE_VERIFIED_BACKUP_DIR;else process.env.SAFETRACE_VERIFIED_BACKUP_DIR=oldBackup;
    await rm(root,{recursive:true,force:true});
  }
});

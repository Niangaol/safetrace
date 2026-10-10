import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { createLiveIntelServer } from "../../../scripts/live-intel-server.js";
import { databaseBackupStats } from "../../shared/src/backup.js";
function frames(text:string):any[] {return text.split("\n\n").filter(s=>s.startsWith("data: ")).map(s=>JSON.parse(s.slice(6)));}

test("live HTTP：原文版本与分值分歧进答案，撤销 DQ 后不再放行，不写业务库", async () => {
  const root=await mkdtemp(join(tmpdir(),"safetrace-live-facts-")),path=join(root,"db.sqlite"),store=new SqliteEventStore(path),bus=new EventBus({store});
  const originalFetch=fetch,old=process.env.SAFETRACE_CACHE_DIR;let server:ReturnType<typeof createLiveIntelServer>|undefined;
  try {
    process.env.SAFETRACE_CACHE_DIR=root;
    const payload=JSON.parse(await readFile("fixtures/sources/nvd.sample.json","utf8"));
    const c=payload.vulnerabilities[0].cve;
    c.configurations=[{nodes:[{operator:"OR",cpeMatch:[{vulnerable:true,criteria:"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",versionStartIncluding:"2.0.0",versionEndExcluding:"2.15.0"}]}]}];
    c.metrics.cvssMetricV31.push({...c.metrics.cvssMetricV31[0],source:"security@apache.org",cvssData:{...c.metrics.cvssMetricV31[0].cvssData,baseScore:8.8}});
    globalThis.fetch=(async input=>{assert.match(String(input),/services.nvd.nist.gov/);return Response.json(payload);}) as typeof fetch;
    const run=await runIngestOnce({store,offline:false,sourceIds:["nvd_cve"],limit:1});
    globalThis.fetch=originalFetch;
    const before=databaseBackupStats(path);
    server=createLiveIntelServer({sqlitePath:path,payloadRoots:[root]});
    await new Promise<void>((done,reject)=>{server!.once("error",reject);server!.listen(0,"127.0.0.1",done);});
    const base="http://127.0.0.1:"+(server.address() as {port:number}).port;
    async function ask(question:string) {
      const response=await fetch(base+"/api/v1/qa/chat",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({question})});
      assert.equal(response.status,200);
      const output=frames(await response.text());
      return {done:output.find(f=>f.event==="done"),text:output.filter(f=>f.event==="token").map(f=>f.text).join(""),output};
    }
    const affected=await ask("Log4Shell 2.14.1 是否受 CVE-2021-44228 影响？");
    assert.equal(affected.done.abstained,false);
    assert.equal(affected.done.model_calls,0);
    assert.match(affected.text,/版本影响判定（确定性规则）/);
    assert.match(affected.text,/\*\*受影响\*\*/);
    assert.match(affected.text,/来源冲突/);
    assert.match(affected.text,/8\.8/);
    assert.match(affected.text,/未以单一结论覆盖/);
    const outside=await ask("Log4j 2.16.0 是否受 CVE-2021-44228 影响？");
    assert.equal(outside.done.abstained,false);
    assert.match(outside.text,/\*\*不受影响\*\*/);
    const incomplete=await ask("比较 CVE-2021-44228 与 CVE-2099-99999999 的影响范围");
    assert.equal(incomplete.done.abstained,true);
    assert.equal(incomplete.output.filter(f=>f.event==="citation").length,0);
    assert.deepEqual(databaseBackupStats(path),before);
    const quarantine={...run.verdicts[0]!,verdict:"quarantine"};
    await bus.publish("dq.verdicts",quarantine,{trace_id:run.trace_id,causation_id:run.causation_by_intel_id[run.merged[0]!.intel_id]});
    const revoked=await ask("Log4j 2.14.1 是否受 CVE-2021-44228 影响？");
    assert.equal(revoked.done.abstained,true);
    assert.ok(!revoked.text.includes("**受影响**"));
  } finally {
    globalThis.fetch=originalFetch;if(old===undefined)delete process.env.SAFETRACE_CACHE_DIR;else process.env.SAFETRACE_CACHE_DIR=old;
    if(server)await new Promise<void>(done=>{server!.close(()=>done());server!.closeAllConnections();});
    store.close();await rm(root,{recursive:true,force:true});
  }
});

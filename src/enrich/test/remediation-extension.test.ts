import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { EventBus, SqliteEventStore, sha256Json } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { runIngestOnce } from "../../ingest/src/pipeline.js";
import { runEnrichment } from "../src/index.js";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { prepareRemediationReceipt, commitRemediationReceipt } from "../src/remediation-extension.js";
import { SqliteExtensionReceiptStore, validateExtensionReceipt } from "../src/extension-receipts.js";
import { readRemediationEvidence } from "../../qa/src/remediation-reader.js";
import { createLiveIntelServer } from "../../../scripts/live-intel-server.js";
const localFetch = fetch;

async function captured(run: (f:{root:string;path:string;events:SqliteEventStore;bus:EventBus;item:IntelItem})=>Promise<void>) {
  const root=await mkdtemp(join(tmpdir(),'remediation-extension-')),path=join(root,'db.sqlite');
  const events=new SqliteEventStore(path),bus=new EventBus({store:events});
  const original=fetch,keys=['OFFLINE_FIXTURES','SAFETRACE_CACHE_DIR'] as const,saved=keys.map(k=>process.env[k]);
  try {
    process.env.OFFLINE_FIXTURES='false';process.env.SAFETRACE_CACHE_DIR=root;
    const payload=JSON.parse(await readFile('fixtures/sources/kev.sample.json','utf8'));
    globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
    await runIngestOnce({store:events,offline:false,sourceIds:['cisa_kev'],limit:1});
    globalThis.fetch=(async()=>{throw new Error('Unexpected network request in deterministic extension');}) as typeof fetch;
    const item=[...readIntelIndexSnapshot(path).accepted.values()][0]!.item;
    await run({root,path,events,bus,item});
  } finally {
    globalThis.fetch=original;keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});events.close();await rm(root,{recursive:true,force:true});
  }
}

test('修复建议接主编排：独立收据重启可读，默认旧 payload 不变，重复提交幂等',async()=>{
  await captured(async f=>{
    let store=new SqliteExtensionReceiptStore(f.path);
    try {
      let receiptId='',runs=0;
      const ctx={dimensions:[] as const,extensionDimensions:['remediation'] as const,bus:f.bus,traceId:'tr_extension',
        extensionRunner:async(item:typeof f.item)=>{runs++;return commitRemediationReceipt({sqlitePath:f.path,store,receipt:await prepareRemediationReceipt({sqlitePath:f.path,payloadRoots:[f.root],item})});},
        onExtension:(_id:string,summary:{receipt_id:string})=>{receiptId=summary.receipt_id;}};
      const result=await runEnrichment([f.item],ctx);
      assert.equal(runs,1);assert.ok(receiptId);assert.equal(result[0]!.artifacts.papers,undefined);
      assert.equal((await f.events.read('enrich.items',0,100)).length,0,'extension-only 不重写旧 enrich.items');
      const receipt=store.get(f.item.intel_id)!;assert.equal(receipt.status,'live');assert.equal(receipt.artifacts[0]!.validation_level,'agency_guidance');
      assert.deepEqual(receipt.artifacts[0]!.fixed_packages,[],'KEV 不冒充供应商固定版本');
      const next=await prepareRemediationReceipt({sqlitePath:f.path,payloadRoots:[f.root],item:f.item});
      const repeat=commitRemediationReceipt({sqlitePath:f.path,store,receipt:next});assert.equal(repeat.newly_recorded,false);assert.equal(repeat.receipt_id,receiptId);
      store.close();store=new SqliteExtensionReceiptStore(f.path,{readOnly:true});
      assert.equal(store.get(f.item.intel_id)!.receipt_id,receiptId);
      const evidence=await readRemediationEvidence({sqlitePath:f.path,payloadRoots:[f.root],intelIds:[f.item.intel_id],limit:1});
      assert.equal(evidence.evidence.length,1);assert.equal(evidence.evidence[0]!.receipt_id,receiptId);
      assert.ok(evidence.chunks[0]!.text.includes('not a verified fix'));
      const server = createLiveIntelServer({sqlitePath:f.path,payloadRoots:[f.root]});
      try {
        await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
        const address = server.address() as {port:number};
        const detail = await (await localFetch('http://127.0.0.1:'+address.port+'/api/v1/vulns/'+f.item.intel_id+'/evidence')).json() as {enrichments:{dimension:string;storage:string;evidence:{receipt_id?:string}[]}[]};
        const remediation = detail.enrichments.find(e=>e.dimension==='remediation')!;
        assert.match(remediation.storage,/verified-extension-receipt/);
        assert.equal(remediation.evidence[0]!.receipt_id,receiptId);
      } finally { await new Promise<void>(resolve=>{server.close(()=>resolve());server.closeAllConnections();}); }
      const lineage=await f.bus.readLineage('tr_extension');assert.ok(lineage.some(r=>r.stage==='enrich.f5_remediation'&&r.status==='success'));
      const db=new DatabaseSync(f.path,{readOnly:true});try { assert.equal(db.prepare('SELECT COUNT(*) n FROM enrichment_extension_history').get()!.n,1); } finally { db.close(); }
    } finally {store.close();}
  });
});

test('提交前最新 DQ 隔离/原文改动拒绝，失败不会落 live 收据',async()=>{
  for(const mutation of ['dq','raw']) await captured(async f=>{
    const store=new SqliteExtensionReceiptStore(f.path);
    try {
      const receipt=await prepareRemediationReceipt({sqlitePath:f.path,payloadRoots:[f.root],item:f.item});
      if(mutation==='dq') {
        const entry=readIntelIndexSnapshot(f.path).accepted.get(f.item.intel_id)!;
        await f.bus.publish('dq.verdicts',{...entry.verdict,verdict:'quarantine'},{trace_id:'tr_revoke',causation_id:entry.intel_event.event_id});
      } else {const source=receipt.sources[0]!;await writeFile(source.raw_ref,(await readFile(source.raw_ref,'utf8'))+' ');}
      assert.throws(()=>commitRemediationReceipt({sqlitePath:f.path,store,receipt}),/changed/);
      assert.equal(store.get(f.item.intel_id),undefined);
    } finally {store.close();}
  });
});

test('已发布修复收据：DQ 撤销、原文变更、伪造 hash 均不回退成成功',async()=>{
  for(const mutation of ['dq','raw','hash']) await captured(async f=>{
    const store=new SqliteExtensionReceiptStore(f.path);
    try {
      const receipt=await prepareRemediationReceipt({sqlitePath:f.path,payloadRoots:[f.root],item:f.item});
      commitRemediationReceipt({sqlitePath:f.path,store,receipt});
      if(mutation==='dq') {const entry=readIntelIndexSnapshot(f.path).accepted.get(f.item.intel_id)!;await f.bus.publish('dq.verdicts',{...entry.verdict,verdict:'quarantine'},{trace_id:'tr_revoke',causation_id:entry.intel_event.event_id});}
      else if(mutation==='raw')await writeFile(receipt.sources[0]!.raw_ref,(await readFile(receipt.sources[0]!.raw_ref,'utf8'))+' ');
      else {const db=new DatabaseSync(f.path);try {db.prepare('UPDATE enrichment_extension_receipts SET payload=?').run(JSON.stringify({...receipt,artifact_sha256:'a'.repeat(64)}));}finally{db.close();}}
      const evidence=await readRemediationEvidence({sqlitePath:f.path,payloadRoots:[f.root],intelIds:[f.item.intel_id],limit:1});
      assert.equal(evidence.chunks.length,0);
      if(mutation!=='dq')assert.ok(evidence.rejected.length>0);
    } finally {store.close();}
  });
});

test('旧库只读无隐式建表，artifact/hash/源证明校验拒绝畸形',async()=>{
  await captured(async f=>{
    const ro=new SqliteExtensionReceiptStore(f.path,{readOnly:true});try{assert.equal(ro.get(f.item.intel_id),undefined);}finally{ro.close();}
    const db=new DatabaseSync(f.path,{readOnly:true});try{assert.equal(db.prepare("SELECT 1 FROM sqlite_master WHERE name='enrichment_extension_receipts'").get(),undefined);}finally{db.close();}
    const receipt=await prepareRemediationReceipt({sqlitePath:f.path,payloadRoots:[f.root],item:f.item});
    for(const patch of [{artifact_sha256:'bad'},{dependency_sha256:'b'.repeat(64)},{status:'empty'},{sources:[]}])assert.throws(()=>validateExtensionReceipt({...receipt,...patch} as typeof receipt),/Invalid|lacks/);
    assert.equal(receipt.intel_sha256,sha256Json(f.item));
  });
});

test('扩展缺省不执行，缺少显式 runner 失败，发布失败不伪造成功',async()=>{
  await captured(async f=>{
    let calls=0;
    await runEnrichment([f.item],{dimensions:[],extensionRunner:async()=>{calls++;throw new Error('should not run');}});
    assert.equal(calls,0);
    await assert.rejects(runEnrichment([f.item],{dimensions:[],extensionDimensions:['remediation']}),/missing/);
    await assert.rejects(runEnrichment([f.item],{dimensions:[],extensionDimensions:['remediation'],bus:f.bus,traceId:'tr_fail',extensionRunner:async()=>{throw new Error('publication failed');}}),/publication failed/);
    const lineage=await f.bus.readLineage('tr_fail');assert.ok(lineage.some(r=>r.status==='failed'));assert.ok(!lineage.some(r=>r.status==='success'));
  });
});

import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,relative,isAbsolute} from 'node:path';
import {SqliteEventStore,EventBus} from '@safetrace/shared';
import {runIngestOnce} from '../../ingest/src/pipeline.js';
import {AssetsStore} from '../../assets/src/store.js';
import {assetRun} from '../../assets/test/asset-fixture.js';
import {readIntelIndexSnapshot} from '../../../scripts/intel-index-data.js';
import {SqliteExtensionReceiptStore} from '../src/extension-receipts.js';
import {prepareAssetReceipt,commitAssetReceipt,readAssetImpactReceipt} from '../src/asset-extension.js';
import {runEnrichment} from '../src/index.js';
import type {IntelItem} from '@safetrace/shared';
import {createLiveIntelServer} from '../../../scripts/live-intel-server.js';
const localFetch=fetch;

/** NVD-shaped mock transport and explicit synthetic local scans, never production facts. */
async function fixture(run:(f:{root:string;path:string;assetsPath:string;events:SqliteEventStore;bus:EventBus;assets:AssetsStore;item:IntelItem})=>Promise<void>){
  const root=await mkdtemp(join(tmpdir(),'asset-extension-')),path=join(root,'intel.sqlite'),assetsPath=join(root,'assets.sqlite');
  const events=new SqliteEventStore(path),bus=new EventBus({store:events}),assets=new AssetsStore(assetsPath);
  const original=fetch,keys=['OFFLINE_FIXTURES','SAFETRACE_CACHE_DIR','NVD_API_KEY'] as const,saved=keys.map(k=>process.env[k]);
  try{
    process.env.OFFLINE_FIXTURES='false';process.env.SAFETRACE_CACHE_DIR=root;process.env.NVD_API_KEY='mock';
    const payload={resultsPerPage:1,startIndex:0,totalResults:1,vulnerabilities:[{cve:{id:'CVE-2026-1001',sourceIdentifier:'security@example.org',published:'2026-10-01T00:00:00.000',lastModified:'2026-10-01T00:00:00.000',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Vue before 3.5.0 allows script injection via invalid input.'}],weaknesses:[{source:'nvd@nist.gov',type:'Primary',description:[{lang:'en',value:'CWE-79'}]}],metrics:{},configurations:[{nodes:[{operator:'OR',cpeMatch:[{vulnerable:true,criteria:'cpe:2.3:a:example:vue:*:*:*:*:*:*:*:*',versionEndExcluding:'3.5.0'}]}]}]}}]};
    globalThis.fetch=(async()=>Response.json(payload)) as typeof fetch;
    await runIngestOnce({store:events,offline:false,sourceIds:['nvd_cve'],limit:1});
    globalThis.fetch=(async()=>{throw new Error('Asset extension must not call any transport');}) as typeof fetch;
    const item=[...readIntelIndexSnapshot(path).accepted.values()][0]!.item;
    assert.equal(item.entities.product,'vue');assert.ok(item.entities.version_range.length);
    assets.upsertGroup({group_id:'g1',name:'Synthetic fixture',roots:[root],enabled:true,note:null,created_at:'2026-10-01T00:00:00Z'});assets.saveScanRun(assetRun(root),0);
    await run({root,path,assetsPath,events,bus,assets,item});
  }finally{globalThis.fetch=original;keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];});assets.close();events.close();await rm(root,{recursive:true,force:true});}
}

test('真实扫描形态接资产富化：源 Intel/DQ + group/run/component 快照绑定，路径不进 artifact',async()=>{
  await fixture(async f=>{
    const store=new SqliteExtensionReceiptStore(f.path);
    try{
      const receipt=await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]});
      assert.equal(receipt.artifacts.length,1);assert.equal(receipt.artifacts[0]!.status,'potentially_affected');assert.equal(receipt.artifacts[0]!.vendor_unverified,true);
      assert.ok(!JSON.stringify(receipt.artifacts).includes(f.root));
      const summary=commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt,store});assert.equal(summary.newly_recorded,true);
      assert.equal((await readAssetImpactReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,intelId:f.item.intel_id,payloadRoots:[f.root]})).status,'verified');
      const server=createLiveIntelServer({sqlitePath:f.path,assetsSqlitePath:f.assetsPath,payloadRoots:[f.root]});
      try{
        await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
        const address=server.address() as {port:number};
        const detail=await(await localFetch('http://127.0.0.1:'+address.port+'/api/v1/vulns/'+f.item.intel_id+'/evidence')).json() as any;
        assert.equal(detail.asset_assessment_status,'verified');const asset=detail.enrichments.find((e:any)=>e.dimension==='asset');
        assert.equal(asset.evidence[0].receipt_id,summary.receipt_id);assert.equal(asset.value.assessments[0].status,'potentially_affected');
        assert.ok(!JSON.stringify(asset.value).includes(f.root));
      }finally{await new Promise<void>(resolve=>{server.close(()=>resolve());server.closeAllConnections();});}
      const again=commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt:await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]}),store});assert.equal(again.newly_recorded,false);assert.equal(again.receipt_id,summary.receipt_id);
      await runEnrichment([f.item],{dimensions:[],extensionDimensions:['asset'],extensionRunner:async()=>again,bus:f.bus,traceId:'tr_asset_receipt'});
      assert.equal((await f.events.read('enrich.items',0,100)).length,0);
      assert.ok((await f.bus.readLineage('tr_asset_receipt')).some(r=>r.stage==='enrich.f2_assets'&&r.status==='success'));
    }finally{store.close();}
  });
});

test('资产快照变化：提交前拒绝陈旧收据、提交后读取为 stale，不借旧命中',async()=>{
  await fixture(async f=>{
    const store=new SqliteExtensionReceiptStore(f.path);
    try{
      const receipt=await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]});
      commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt,store});
      f.assets.saveScanRun(assetRun(f.root,'scan_2','3.6.0'),0);
      assert.throws(()=>commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt:{...receipt,receipt_id:'rx_stale'},store}),/snapshot changed/);
      assert.equal((await readAssetImpactReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,intelId:f.item.intel_id,payloadRoots:[f.root]})).status,'stale');
    }finally{store.close();}
  });
});

test('跨生态同名与范围下界不猜身份或实际安装版本，unknown 不等于安全',async()=>{
  await fixture(async f=>{
    const run=assetRun(f.root,'scan_2','3.6.0',true);run.repos[0]!.components.push({...run.repos[0]!.components[0]!,ecosystem:'pypi'});run.component_count=2;f.assets.saveScanRun(run,0);
    const receipt=await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]});
    assert.ok(receipt.artifacts.every(a=>a.status==='unknown'));assert.ok(receipt.artifacts.every(a=>a.version_is_range_floor));
  });
});

test('源原文变更与分组停用会撤销旧资产证据，不产生安全结论',async()=>{
  for(const mutation of ['raw','group'])await fixture(async f=>{
    const store=new SqliteExtensionReceiptStore(f.path);
    try{
      const receipt=await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]});commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt,store});
      if(mutation==='raw'){
        const p=receipt.sources[0]!.raw_ref;const rel=relative(f.root,resolve(p));assert.ok(rel&&!rel.startsWith("..")&&!isAbsolute(rel));await writeFile(p,(await readFile(p,'utf8'))+' ');
        await assert.rejects(prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]}),/verified source/);
        assert.equal((await readAssetImpactReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,intelId:f.item.intel_id,payloadRoots:[f.root]})).status,'invalid');
      }else{
        f.assets.upsertGroup({...f.assets.getGroup('g1')!,enabled:false});
        assert.equal((await readAssetImpactReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,intelId:f.item.intel_id,payloadRoots:[f.root]})).status,'stale');
        const next=await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]});assert.equal(next.status,'empty');assert.deepEqual(next.artifacts,[]);
      }
    }finally{store.close();}
  });
});

test('资产 DQ 撤销后不展示持久收据',async()=>{
  await fixture(async f=>{
    const store=new SqliteExtensionReceiptStore(f.path);
    try{
      const receipt=await prepareAssetReceipt({...f,sqlitePath:f.path,payloadRoots:[f.root]});commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt,store});
      const entry=readIntelIndexSnapshot(f.path).accepted.get(f.item.intel_id)!;
      await f.bus.publish('dq.verdicts',{...entry.verdict,verdict:'quarantine'},{trace_id:'tr_revoked',causation_id:entry.intel_event.event_id});
      assert.equal((await readAssetImpactReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,intelId:f.item.intel_id,payloadRoots:[f.root]})).status,'revoked');
      assert.throws(()=>commitAssetReceipt({sqlitePath:f.path,assetsPath:f.assetsPath,receipt,store}),/Intel.DQ changed/);
    }finally{store.close();}
  });
});

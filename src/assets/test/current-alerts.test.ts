import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createServer} from 'node:http';
import {EventBus,SqliteEventStore} from '@safetrace/shared';
import {AssetsStore} from '../src/store.js';
import {autoMatchGroup} from '../src/auto-match.js';
import {currentAssetAlertView} from '../src/current-alerts.js';
import {withReleasedIntel} from '../src/intel-admission.js';
import {readLiveKnowledgeView} from '../../qa/src/live-knowledge-view.js';
import {handleAssetsRequest} from '../../../scripts/assets-api.js';
import {assetIntel,assetDq,assetRun} from './asset-fixture.js';

async function setup() {
  const root=await mkdtemp(join(tmpdir(),'current-assets-')),path=join(root,'intel.sqlite');
  const events=new SqliteEventStore(path),bus=new EventBus({store:events});
  const e=await bus.publish('intel.items',assetIntel(),{trace_id:'tr_asset'});
  await bus.publish('dq.verdicts',assetDq(),{trace_id:'tr_asset',causation_id:e.event_id});
  const assets=new AssetsStore(join(root,'var','assets.sqlite'));
  const group={group_id:'g1',name:'Fixture group',roots:[root],enabled:true,note:null,created_at:'2026-10-01T00:00:00Z'};
  assets.upsertGroup(group);assets.saveScanRun(assetRun(root),0);
  await autoMatchGroup(events,assets,group);
  return {root,path,events,bus,e,assets,group,close:async()=>{assets.close();events.close();await rm(root,{recursive:true,force:true});}};
}

test('历史告警只保留当前 DQ/快照仍命中的项，unknown/版本升级不当作安全',async()=>{
  const f=await setup();
  try {
    const current=()=>withReleasedIntel(f.events,items=>currentAssetAlertView(f.assets,items));
    assert.equal(current().unread_count,1);assert.equal(current().alerts[0]!.assessment,'potentially_affected');
    f.assets.saveScanRun(assetRun(f.root,'scan_2','3.6.0',true),0);
    assert.equal(current().alerts.length,0,'范围下界未命中为 unknown，不是当前告警');
    assert.match(current().assessment,/absent_alerts_are_not_safety/);
    assert.equal(f.assets.listAlerts().length,1,'历史记录不删除');
    f.assets.saveScanRun(assetRun(f.root,'scan_3','3.4.1'),0);
    assert.equal(current().alerts[0]!.version,'3.4.1');assert.equal(current().alerts[0]!.historical_version,'3.4.0');
    await f.bus.publish('dq.verdicts',assetDq('intel_vue','quarantine'),{trace_id:'tr_revoke',causation_id:f.e.event_id});
    assert.equal(current().unread_count,0);assert.equal(current().alerts.length,0);
    assert.equal(f.assets.listAlerts().length,1,'DQ 撤销不删除审计历史');
  }finally{await f.close();}
});

test('资产 API alerts/overview/groups 在 DQ 撤销后立即隐藏历史风险，读模型失败不回放旧数据',async()=>{
  const f=await setup();let unavailable=false;
  const server=createServer(async(req,res)=>{
    try { const url=new URL(req.url??'/','http://127.0.0.1');await handleAssetsRequest(req,res,url,url.pathname,{cwd:f.root,intelSqlitePath:f.path,localOrigin:()=>true,publishActivity:()=>{},readView:async()=>{if(unavailable)throw new Error('unavailable');return readLiveKnowledgeView({sqlitePath:f.path,payloadRoots:[f.root]});}}); }
    catch(error){res.writeHead(500);res.end(String(error));}
  });
  try {
    await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
    const url='http://127.0.0.1:'+(server.address() as {port:number}).port;
    const before=await(await fetch(url+'/api/v1/assets/alerts')).json() as any;assert.equal(before.alerts.length,1);assert.equal(before.unread_count,1);
    await f.bus.publish('dq.verdicts',assetDq('intel_vue','quarantine'),{trace_id:'tr_revoke',causation_id:f.e.event_id});
    const alerts=await(await fetch(url+'/api/v1/assets/alerts')).json() as any;assert.deepEqual(alerts.alerts,[]);assert.equal(alerts.unread_count,0);
    const overview=await(await fetch(url+'/api/v1/assets/overview')).json() as any;assert.equal(overview.unread_count,0);assert.equal(overview.historical_unread_count,1);
    const groups=await(await fetch(url+'/api/v1/assets/groups')).json() as any;assert.equal(groups.groups[0].unread_count,0);
    unavailable=true;const error=await fetch(url+'/api/v1/assets/alerts');assert.equal(error.status,503);const body=await error.json() as any;assert.deepEqual(body.alerts,[]);assert.equal(body.unread_count,null);
  }finally{await new Promise<void>(resolve=>{server.close(()=>resolve());server.closeAllConnections();});await f.close();}
});

test('资产只读模式不隐式初始化或迁移缺失数据库',async()=>{
  const root=await mkdtemp(join(tmpdir(),'assets-readonly-'));
  try {assert.throws(()=>new AssetsStore(join(root,'absent.sqlite'),{readOnly:true}));}
  finally{await rm(root,{recursive:true,force:true});}
});

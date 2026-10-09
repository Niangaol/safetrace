import { DatabaseSync } from 'node:sqlite';
import { existsSync,readFileSync } from 'node:fs';
import {resolve} from 'node:path';
import {nextId,sha256,sha256Json} from '@safetrace/shared';
import type {IntelItem} from '@safetrace/shared';
import {AssetsStore} from '../../assets/src/store.js';
import {matchComponent,nameVariants} from '../../assets/src/matcher.js';
import {normalizeName} from './f2-assets.js';
import {readKnowledgeProjection} from '../../qa/src/knowledge-reader.js';
import {readIntelIndexSnapshot} from '../../../scripts/intel-index-data.js';
import {extensionDependency,SqliteExtensionReceiptStore,type AssetReceipt,type AssetImpactArtifact,type ExtensionRunSummary,type ExtensionSourceProof} from './extension-receipts.js';

/** All private paths remain in the asset database or hashed bindings, never model/SSE state. */
export function captureAssetSnapshot(assetsPath:string){
  const assets=new AssetsStore(assetsPath,{readOnly:true});
  try {
    return assets.readSnapshot(()=>{
      const groups=assets.listGroups(),enabled=new Set(groups.filter(g=>g.enabled).map(g=>g.group_id));
      const runs=assets.latestRunPerGroup().filter(r=>r.group_id==='adhoc'||enabled.has(r.group_id)).sort((a,b)=>a.group_id.localeCompare(b.group_id));
      const components=assets.latestComponents().filter(c=>runs.some(r=>r.group_id===c.group_id));
      const datasetId=sha256Json({assets_path:resolve(assetsPath)});
      const fingerprint=sha256Json({datasetId,groups,runs,components});
      return {fingerprint,datasetId,runs,components,groups};
    });
  }finally{assets.close();}
}
export async function prepareAssetReceipt(options:{sqlitePath:string;assetsPath:string;payloadRoots?:readonly string[];item:IntelItem;now?:Date}):Promise<AssetReceipt>{
  const intel=readIntelIndexSnapshot(options.sqlitePath),entry=intel.accepted.get(options.item.intel_id);
  if(!entry||sha256Json(entry.item)!==sha256Json(options.item))throw new Error('Asset extension input not latest DQ released');
  const projection=await readKnowledgeProjection(options);
  const proofs=projection.evidence.filter(p=>p.kind==='source'&&p.intel_id===entry.item.intel_id&&p.intel_event_id===entry.intel_event.event_id&&p.raw_ref&&p.original_sha256);
  if(!proofs.length)throw new Error('Asset assessment requires independently verified source Intel evidence');
  const db=new DatabaseSync(options.sqlitePath,{readOnly:true});let raw;
  try{raw=db.prepare("SELECT payload FROM events WHERE topic='raw.docs' ORDER BY seq").all().map(row=>JSON.parse(String(row.payload)));}finally{db.close();}
  const sourceRows=proofs.map(proof=>{
    const candidates=raw.filter(r=>r.payload_ref===proof.raw_ref&&entry.item.source_ids.includes(r.source_id));
    if(candidates.length!==1)throw new Error('Asset Intel source identity absent/ambiguous');
    return {raw_ref:proof.raw_ref!,source_id:candidates[0].source_id,source_url:candidates[0].url,source_sha256:proof.original_sha256!,parent_lineage_ids:[...proof.parent_lineage_ids].sort()} as ExtensionSourceProof;
  });
  const sources=[...new Map(sourceRows.map(p=>[sha256Json(p),p])).values()].sort((a,b)=>sha256Json(a).localeCompare(sha256Json(b)));
  const snapshot=captureAssetSnapshot(options.assetsPath),product=normalizeName(entry.item.entities.product);
  const ecosystems=new Set(snapshot.components.filter(c=>nameVariants(c.name).includes(product)).map(c=>c.ecosystem));
  const artifacts:AssetImpactArtifact[]=snapshot.components.slice(0,2000).map(c=>{
    const match=matchComponent(entry.item,c),run=snapshot.runs.find(r=>r.group_id===c.group_id)!;
    const collision=ecosystems.size>1&&nameVariants(c.name).includes(product);
    return {group_id:c.group_id,run_id:run.run_id,component_identity:sha256Json(c),repo_identity:sha256Json({repo_path:c.repo_path}),ecosystem:c.ecosystem,name:c.name,version:c.version,constraint_raw:c.constraint_raw,version_is_range_floor:c.version_is_range_floor,vendor_unverified:true,
      status:collision?'unknown':match.status==='affected'?'potentially_affected':match.status==='unknown'?'unknown':nameVariants(c.name).includes(product)?'version_outside_declared_range':'not_matching',
      rule:match.rule,matched_ranges:collision?[]:match.matched_ranges,reason:collision?'同名组件跨生态，不能证明产品身份':match.reason,scan_status:run.status,scan_degraded_to:run.degraded_to};
  });
  if(readIntelIndexSnapshot(options.sqlitePath).fingerprint!==intel.fingerprint||captureAssetSnapshot(options.assetsPath).fingerprint!==snapshot.fingerprint)throw new Error('Intel/DQ/asset snapshot changed during assessment');
  const receipt={receipt_id:nextId('rx'),dimension:'asset',operation_version:'f2-assets.v1',intel_id:entry.item.intel_id,intel_event_id:entry.intel_event.event_id,intel_sha256:sha256Json(entry.item),dq_event_id:entry.verdict_event.event_id,dq_sha256:sha256Json(entry.verdict),status:artifacts.length?'live':'empty',created_at:(options.now??new Date()).toISOString(),sources,artifacts,artifact_sha256:sha256Json(artifacts),asset_scope:{asset_snapshot_sha256:snapshot.fingerprint,dataset_id:snapshot.datasetId,truncated:snapshot.components.length>2000,groups:snapshot.runs.map(r=>({group_id:r.group_id,run_id:r.run_id,status:r.status,finished_at:r.finished_at}))}} as Omit<AssetReceipt,'dependency_sha256'>;
  return {...receipt,dependency_sha256:extensionDependency(receipt)};
}
export function commitAssetReceipt(options:{sqlitePath:string;assetsPath:string;receipt:AssetReceipt;store:SqliteExtensionReceiptStore}):ExtensionRunSummary{
  const committed=options.store.put(options.receipt,()=>{
    const entry=readIntelIndexSnapshot(options.sqlitePath).accepted.get(options.receipt.intel_id);
    if(!entry||entry.intel_event.event_id!==options.receipt.intel_event_id||entry.verdict_event.event_id!==options.receipt.dq_event_id||sha256Json(entry.item)!==options.receipt.intel_sha256||sha256Json(entry.verdict)!==options.receipt.dq_sha256)throw new Error('Intel/DQ changed before asset receipt commit');
    for(const p of options.receipt.sources)if(sha256(readFileSync(p.raw_ref))!==p.source_sha256)throw new Error('Asset Intel source changed');
    if(!existsSync(options.assetsPath))throw new Error('Asset database disappeared');
    const db=new DatabaseSync(options.assetsPath);db.exec('PRAGMA busy_timeout=5000');
    try{db.exec('BEGIN IMMEDIATE');if(captureAssetSnapshot(options.assetsPath).fingerprint!==options.receipt.asset_scope.asset_snapshot_sha256)throw new Error('Asset snapshot changed before commit');}
    catch(error){db.close();throw error;}
    // Release only after the Intel receipt transaction commits; lock order Intel -> Assets.
    return ()=>db.close();
  });
  return {dimension:'asset',status:committed.receipt.status,receipt_id:committed.receipt.receipt_id,artifacts:committed.receipt.artifacts.length,newly_recorded:committed.newly_recorded};
}
export async function readAssetImpactReceipt(options:{sqlitePath:string;assetsPath:string;intelId:string;payloadRoots?:readonly string[]}){
  const store=new SqliteExtensionReceiptStore(options.sqlitePath,{readOnly:true});
  try{
    const receipt=store.get(options.intelId,'asset');if(!receipt)return {status:'absent' as const,receipt:null};
    const entry=readIntelIndexSnapshot(options.sqlitePath).accepted.get(options.intelId);if(!entry)return {status:'revoked' as const,receipt:null};
    const current=await prepareAssetReceipt({...options,item:entry.item});
    if(receipt.dependency_sha256!==current.dependency_sha256||Date.parse(receipt.created_at)>Date.now()+300000)return {status:'stale' as const,receipt:null};
    return {status:'verified' as const,receipt};
  }catch(error){return {status:'invalid' as const,receipt:null,reason:error instanceof Error?error.message:'asset proof verification failed'};}
  finally{store.close();}
}

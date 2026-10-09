import { DatabaseSync } from "node:sqlite";
import { sha256Json } from "@safetrace/shared";
import type { RemediationArtifact } from "./f5-remediation.js";

/** Private typed sidecars; existing enrich.items contract and scores stay unchanged. */
export type ExtensionDimension = "remediation" | "asset" | "poc";
export interface ExtensionSourceProof { raw_ref:string;source_id:string;source_url:string;source_sha256:string;parent_lineage_ids:string[] }
interface ReceiptBinding {
  receipt_id:string;intel_id:string;intel_event_id:string;intel_sha256:string;dq_event_id:string;dq_sha256:string;
  status:"live"|"empty";created_at:string;sources:ExtensionSourceProof[];artifact_sha256:string;dependency_sha256:string;
}
export interface RemediationReceipt extends ReceiptBinding {dimension:"remediation";operation_version:"f5-remediation.v1";artifacts:RemediationArtifact[]}
export interface AssetImpactArtifact {
  group_id:string;run_id:string;component_identity:string;repo_identity:string;ecosystem:string;name:string;version:string;
  constraint_raw:string;version_is_range_floor:boolean;vendor_unverified:true;status:"potentially_affected"|"version_outside_declared_range"|"not_matching"|"unknown";
  rule:string;matched_ranges:string[];reason:string;scan_status:string;scan_degraded_to:string|null;
}
export interface AssetScope {
  asset_snapshot_sha256:string;dataset_id:string;truncated:boolean;
  groups:{group_id:string;run_id:string;status:string;finished_at:string}[];
}
export interface AssetReceipt extends ReceiptBinding {dimension:"asset";operation_version:"f2-assets.v1";artifacts:AssetImpactArtifact[];asset_scope:AssetScope}
export interface PocCandidateArtifact {
  candidate_id:string;cve_id:string;source_id:string;raw_ref:string;source_url:string;source_sha256:string;
  reference_url:string;reference_tags:string[];evidence_kind:"reference_tag_poc"|"reference_tag_exploit";parent_lineage_ids:string[];
  note:string;
}
export interface PocAdvisory {
  candidate_id:string;model_id:string;provider:string;choice:"related"|"unrelated"|"uncertain";
  p_related:number;confidence:number;checkpoint_sha256:string;base_revision:string;code_commit:string;device:string;requested_at:string;
}
export interface PocReceipt extends ReceiptBinding {dimension:"poc";operation_version:"f3-poc-candidates.v1";artifacts:PocCandidateArtifact[];advisories:PocAdvisory[]}
export type ExtensionReceipt = RemediationReceipt | AssetReceipt | PocReceipt;
export interface ExtensionRunSummary {dimension:ExtensionDimension;status:ExtensionReceipt['status'];receipt_id:string;artifacts:number;newly_recorded:boolean}

export function extensionDependency(receipt:Pick<ExtensionReceipt,'dimension'|'operation_version'|'intel_id'|'intel_event_id'|'intel_sha256'|'dq_event_id'|'dq_sha256'|'sources'|'artifact_sha256'> & {asset_scope?:AssetScope;advisories?:PocAdvisory[]}):string {
  return sha256Json({dimension:receipt.dimension,version:receipt.operation_version,intel_id:receipt.intel_id,
    intel_event_id:receipt.intel_event_id,intel_sha256:receipt.intel_sha256,dq_event_id:receipt.dq_event_id,dq_sha256:receipt.dq_sha256,
    sources:receipt.sources,artifact_sha256:receipt.artifact_sha256,...(receipt.asset_scope?{asset_scope:receipt.asset_scope}:{}),...(receipt.advisories?{advisories:receipt.advisories}:{})});
}
export function validateExtensionReceipt(value:ExtensionReceipt):void {
  const hex=(s:unknown)=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
  if(!value || !['remediation','asset','poc'].includes(value.dimension) || !value.receipt_id || !value.intel_id || !value.intel_event_id || !value.dq_event_id
    || !hex(value.intel_sha256)||!hex(value.dq_sha256)||!hex(value.dependency_sha256)||!Number.isFinite(Date.parse(value.created_at))
    || !['live','empty'].includes(value.status)||!Array.isArray(value.artifacts)||!Array.isArray(value.sources)
    || value.artifact_sha256!==sha256Json(value.artifacts)||value.dependency_sha256!==extensionDependency(value)
    || (value.status==='live')!==(value.artifacts.length>0))throw new Error('Invalid extension receipt or artifact/dependency hash');
  for(const proof of value.sources){
    let url:URL;try{url=new URL(proof.source_url);}catch{throw new Error('Invalid extension source URL');}
    if(url.protocol!=='https:'||url.username||url.password||!proof.raw_ref||!proof.source_id||!hex(proof.source_sha256)
      || !Array.isArray(proof.parent_lineage_ids)||!proof.parent_lineage_ids.length||proof.parent_lineage_ids.some(id=>typeof id!=='string'||!id))throw new Error('Invalid extension source proof');
  }
  if(value.dimension==='remediation'){
    if(value.operation_version!=='f5-remediation.v1'||value.sources.some(p=>!['cisa_kev','ubuntu_usn'].includes(p.source_id)))throw new Error('Invalid remediation version/source');
    for(const artifact of value.artifacts)if(artifact.evidence_kind!=='live'||!value.sources.some(p=>p.raw_ref===artifact.raw_ref&&p.source_id===artifact.source_id&&p.source_url===artifact.source_url&&p.source_sha256===artifact.source_sha256))throw new Error('Artifact lacks its own live source proof');
  }else if(value.dimension==='poc'){
    if(value.operation_version!=='f3-poc-candidates.v1'||!Array.isArray(value.advisories))throw new Error('Invalid poc version/advisories');
    for(const artifact of value.artifacts){
      if(!artifact.candidate_id||!artifact.cve_id||!['reference_tag_poc','reference_tag_exploit'].includes(artifact.evidence_kind)||!artifact.raw_ref
        ||!hex(artifact.source_sha256)||!Array.isArray(artifact.reference_tags)||!Array.isArray(artifact.parent_lineage_ids)||!artifact.parent_lineage_ids.length
        ||!artifact.note||!value.sources.some(p=>p.raw_ref===artifact.raw_ref&&p.source_id===artifact.source_id&&p.source_url===artifact.source_url&&p.source_sha256===artifact.source_sha256)
        ||!artifact.reference_url.startsWith('https://'))throw new Error('Invalid poc candidate artifact');
      let url:URL;try{url=new URL(artifact.reference_url);}catch{throw new Error('Invalid poc reference URL');}
      if(url.username||url.password)throw new Error('Credentialed poc reference URL');
    }
    for(const advisory of value.advisories){
      if(!['related','unrelated','' + 'uncertain'].includes(advisory.choice)||typeof advisory.p_related!=='number'||!Number.isFinite(advisory.p_related)||advisory.p_related<0||advisory.p_related>1
        ||!advisory.model_id||advisory.provider!=='openjev'||!hex(advisory.checkpoint_sha256)||!advisory.base_revision||!advisory.code_commit||!advisory.device
        ||!Number.isFinite(Date.parse(advisory.requested_at))||!value.artifacts.some(a=>a.candidate_id===advisory.candidate_id))throw new Error('Invalid poc model advisory');
    }
    if(value.advisories.length>value.artifacts.length)throw new Error('Poc advisories cannot exceed candidates');
  }else{
    if(value.operation_version!=='f2-assets.v1'||!value.asset_scope||!hex(value.asset_scope.asset_snapshot_sha256)||!hex(value.asset_scope.dataset_id)||typeof value.asset_scope.truncated!=='boolean'||!Array.isArray(value.asset_scope.groups)||!value.sources.length)throw new Error('Invalid asset snapshot/source binding');
    for(const artifact of value.artifacts)if(!hex(artifact.component_identity)||!hex(artifact.repo_identity)||!artifact.group_id||!artifact.run_id||artifact.vendor_unverified!==true||typeof artifact.version_is_range_floor!=='boolean'
      || !['potentially_affected','version_outside_declared_range','not_matching','unknown'].includes(artifact.status)||!Array.isArray(artifact.matched_ranges)
      || !value.asset_scope.groups.some(g=>g.group_id===artifact.group_id&&g.run_id===artifact.run_id))throw new Error('Invalid asset assessment');
  }
}

/** Stored receipts are not a trust oracle; readers rederive and compare current evidence. */
export class SqliteExtensionReceiptStore {
  private readonly db:DatabaseSync;private readonly readOnly:boolean;private readonly exists:boolean;
  constructor(path:string,options:{readOnly?:boolean}={}){
    this.readOnly=options.readOnly??false;this.db=new DatabaseSync(path,{readOnly:this.readOnly});
    if(!this.readOnly)this.db.exec('CREATE TABLE IF NOT EXISTS enrichment_extension_receipts(intel_id TEXT NOT NULL,dimension TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(intel_id,dimension));CREATE TABLE IF NOT EXISTS enrichment_extension_history(seq INTEGER PRIMARY KEY AUTOINCREMENT,receipt_id TEXT NOT NULL UNIQUE,payload TEXT NOT NULL);');
    this.exists=!!this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_extension_receipts'").get();
  }
  get(intelId:string,dimension?:'remediation'):RemediationReceipt|undefined;
  get(intelId:string,dimension:'asset'):AssetReceipt|undefined;
  get(intelId:string,dimension:ExtensionDimension):ExtensionReceipt|undefined;
  get(intelId:string,dimension:'poc'):PocReceipt|undefined;
  get(intelId:string,dimension:ExtensionDimension='remediation'):ExtensionReceipt|undefined{
    if(!this.exists)return undefined;
    const row=this.db.prepare('SELECT payload FROM enrichment_extension_receipts WHERE intel_id=? AND dimension=?').get(intelId,dimension);if(!row)return undefined;
    const receipt=JSON.parse(String(row.payload)) as ExtensionReceipt;validateExtensionReceipt(receipt);
    if(receipt.dimension!==dimension||receipt.intel_id!==intelId)throw new Error('Extension receipt identity mismatch');return receipt;
  }
  put<T extends ExtensionReceipt>(receipt:T,guard:()=>void|(()=>void)):{receipt:T;newly_recorded:boolean}{
    if(this.readOnly)throw new Error('Extension receipt store is read-only');validateExtensionReceipt(receipt);this.db.exec('BEGIN IMMEDIATE');
    let release:(()=>void)|undefined;
    try{
      release=guard()??undefined;const old=this.get(receipt.intel_id,receipt.dimension);
      if(old?.dependency_sha256===receipt.dependency_sha256){this.db.exec('COMMIT');return{receipt:old as T,newly_recorded:false};}
      if(old&&Date.parse(receipt.created_at)<Date.parse(old.created_at))throw new Error('Stale extension receipt cannot replace newer record');
      const payload=JSON.stringify(receipt);
      this.db.prepare('INSERT INTO enrichment_extension_history(receipt_id,payload) VALUES(?,?)').run(receipt.receipt_id,payload);
      this.db.prepare('INSERT INTO enrichment_extension_receipts VALUES(?,?,?) ON CONFLICT(intel_id,dimension) DO UPDATE SET payload=excluded.payload').run(receipt.intel_id,receipt.dimension,payload);
      this.db.exec('COMMIT');return{receipt,newly_recorded:true};
    }catch(error){this.db.exec('ROLLBACK');throw error;}finally{release?.();}
  }
  /** Read-only receipt identity list for triage summaries; no payload trust assumed. */
  listReceiptIds(dimension?:ExtensionDimension):{intel_id:string;dimension:ExtensionDimension;created_at:string}[]{
    if(!this.exists)return [];
    const rows=dimension===undefined
      ? this.db.prepare("SELECT intel_id,dimension,payload FROM enrichment_extension_receipts").all()
      : this.db.prepare("SELECT intel_id,dimension,payload FROM enrichment_extension_receipts WHERE dimension=?").all(dimension);
    return (rows as Array<{intel_id:string;dimension:string;payload:string}>).flatMap(row=>{
      try{const receipt=JSON.parse(row.payload) as ExtensionReceipt;return [{intel_id:row.intel_id,dimension:receipt.dimension,created_at:receipt.created_at}];}
      catch{return [];}
    });
  }
  close():void{this.db.close();}
}

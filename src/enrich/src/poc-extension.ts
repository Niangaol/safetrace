/** PoC 候选收据：从已验证原文提取候选 + 本地 Jev 相关性建议。零网络抓取、零执行。 */
import { readFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { nextId, sha256, sha256Json } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { DatabaseSync } from "node:sqlite";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { readKnowledgeProjection } from "../../qa/src/knowledge-reader.js";
import { extractPocCandidates, type PocCandidate } from "./poc-candidates.js";
import { requestJevChoice } from "./jev-decision-client.js";
import { extensionDependency, SqliteExtensionReceiptStore, type ExtensionRunSummary, type ExtensionSourceProof, type PocAdvisory, type PocCandidateArtifact, type PocReceipt } from "./extension-receipts.js";

export interface PocPrepareOptions {
  sqlitePath:string;payloadRoots?:readonly string[];item:IntelItem;now?:Date;
  /** 本地 Jev 服务基地址；缺省读 env JEV_BASE_URL。 */
  jevBaseUrl?:string;
  /** 钉死的模型标识（落 advisory）。 */
  jevModelId:string;
  /** 期望的服务端 provenance（checkpoint/base/code/device）；缺省不核对。 */
  jevProvenance?:{model:string;checkpoint_sha256:string;base_revision:string;code_commit:string;model_revision?:string;device?:string};
  timeoutMs?:number;fetchImpl?:typeof fetch;
  /** 读取路径用：只重算来源绑定，不请求模型（建议按已存 provenance 展示）。 */
  skipAdvisories?:boolean;
}

/** 候选必须来自当前 DQ 放行情报的已验证原文；否则显式失败，不产空成功。 */
export async function preparePocReceipt(options:PocPrepareOptions):Promise<PocReceipt> {
  if(!options.jevModelId || options.jevModelId.trim()==="")throw new Error("PoC advisory requires a pinned local model id");
  const intel=readIntelIndexSnapshot(options.sqlitePath),entry=intel.accepted.get(options.item.intel_id);
  if(!entry||sha256Json(entry.item)!==sha256Json(options.item))throw new Error("PoC input not latest DQ released");
  const projection=await readKnowledgeProjection(options);
  const proofs=projection.evidence.filter(p=>p.kind==="source"&&p.intel_id===entry.item.intel_id&&p.intel_event_id===entry.intel_event.event_id&&p.raw_ref&&p.original_sha256);
  if(!proofs.length)throw new Error("PoC candidates require independently verified source evidence");
  const db=new DatabaseSync(options.sqlitePath,{readOnly:true});let rawDocs:Array<{payload_ref:string;source_id:string;url:string}>;
  try{rawDocs=db.prepare("SELECT payload FROM events WHERE topic='raw.docs' ORDER BY seq").all().map(row=>JSON.parse(String(row.payload)));}finally{db.close();}
  const candidates:PocCandidate[]=[],sources:ExtensionSourceProof[]=[];
  for(const proof of proofs){
    const matches=rawDocs.filter(r=>r.payload_ref===proof.raw_ref);
    if(matches.length!==1)throw new Error("PoC raw identity absent/ambiguous");
    const doc=matches[0]!;
    if(!existsSync(doc.payload_ref))throw new Error("PoC raw payload missing on disk");
    const bytes=readFileSync(doc.payload_ref);
    if(sha256(bytes)!==proof.original_sha256)throw new Error("PoC raw payload changed since verification");
    const found=extractPocCandidates({intel_id:entry.item.intel_id,cve_ids:entry.item.cve_ids,item:{title:entry.item.title,...(entry.item.summary!==undefined?{summary:entry.item.summary}:{}),entities:{product:entry.item.entities.product,vendor:entry.item.entities.vendor}},raw:{payload_ref:doc.payload_ref,source_id:doc.source_id,url:doc.url,source_type:"raw"},payload_bytes:bytes,payload_sha256:proof.original_sha256!,parent_lineage_ids:[...proof.parent_lineage_ids].sort()});
    candidates.push(...found);
    const proofRow={raw_ref:doc.payload_ref,source_id:doc.source_id,source_url:doc.url,source_sha256:proof.original_sha256!,parent_lineage_ids:[...proof.parent_lineage_ids].sort()};
    if(!sources.some(p=>sha256Json(p)===sha256Json(proofRow)))sources.push(proofRow);
  }
  const unique=[...new Map(candidates.map(c=>[c.candidate_id,c])).values()].sort((a,b)=>a.candidate_id.localeCompare(b.candidate_id));
  if(readIntelIndexSnapshot(options.sqlitePath).fingerprint!==intel.fingerprint)throw new Error("Intel/DQ changed while preparing PoC candidates");
  const advisories:PocAdvisory[]=[];
  for(const candidate of options.skipAdvisories?[]:unique.slice(0,5)){
    const state=["Vulnerability report:",entry.item.title,...(entry.item.summary?["",entry.item.summary]:[]),"","Referenced URL (metadata only, not fetched):",candidate.reference_url,"Advisory tags:",candidate.reference_tags.join(", ")].join("\n");
    const decision=await requestJevChoice({state,questions:{relevance:{type:"choice",instructions:"Does this referenced URL plausibly point to exploit or proof-of-concept material for this specific vulnerability? Pick the single best answer.",criteria:{related:"The reference is described by the advisory as an exploit or proof-of-concept for this same product/CVE.",unrelated:"The reference is a vendor advisory, patch note, generic write-up, or concerns a different product.",uncertain:"The URL and tags alone do not establish what the page contains; abstain rather than guess."}}}},{baseUrl:options.jevBaseUrl,modelId:options.jevModelId,timeoutMs:options.timeoutMs,fetchImpl:options.fetchImpl,...(options.jevProvenance?{expectedProvenance:options.jevProvenance}:{})});
    advisories.push({candidate_id:candidate.candidate_id,model_id:decision.model,provider:"openjev",choice:decision.answer.choice as PocAdvisory["choice"],p_related:decision.answer.probabilities.related ?? 0,confidence:decision.answer.confidence,checkpoint_sha256:String(decision.metadata.checkpoint_sha256??""),base_revision:String(decision.metadata.base_revision??""),code_commit:String(decision.metadata.code_commit??""),device:String(decision.metadata.device??""),requested_at:(options.now??new Date()).toISOString()});
  }
  const artifacts:PocCandidateArtifact[]=unique.map(c=>({...c,parent_lineage_ids:[...c.parent_lineage_ids].sort()}));
  const sortedSources=sources.sort((a,b)=>sha256Json(a).localeCompare(sha256Json(b)));
  const receipt={receipt_id:nextId("rx"),dimension:"poc",operation_version:"f3-poc-candidates.v1",intel_id:entry.item.intel_id,intel_event_id:entry.intel_event.event_id,intel_sha256:sha256Json(entry.item),dq_event_id:entry.verdict_event.event_id,dq_sha256:sha256Json(entry.verdict),status:artifacts.length?"live":"empty",created_at:(options.now??new Date()).toISOString(),sources:sortedSources,artifacts,advisories,artifact_sha256:sha256Json(artifacts)} as Omit<PocReceipt,"dependency_sha256">;
  return {...receipt,dependency_sha256:extensionDependency(receipt)};
}

export function commitPocReceipt(options:{sqlitePath:string;receipt:PocReceipt;store:SqliteExtensionReceiptStore}):ExtensionRunSummary{
  // Idempotency follows the source/candidate binding only: a refreshed model advisory
  // reuses the existing receipt instead of appending a duplicate history row.
  const binding=(r:PocReceipt)=>sha256Json({intel_event_id:r.intel_event_id,dq_event_id:r.dq_event_id,intel_sha256:r.intel_sha256,
    dq_sha256:r.dq_sha256,sources:r.sources,artifacts:r.artifacts});
  // A reused receipt still must match the CURRENT Intel/DQ and raw payloads.
  const entry=readIntelIndexSnapshot(options.sqlitePath).accepted.get(options.receipt.intel_id);
  if(!entry||entry.intel_event.event_id!==options.receipt.intel_event_id||entry.verdict_event.event_id!==options.receipt.dq_event_id
    ||sha256Json(entry.item)!==options.receipt.intel_sha256||sha256Json(entry.verdict)!==options.receipt.dq_sha256)
    throw new Error("Intel/DQ changed before PoC receipt commit");
  for(const p of options.receipt.sources)if(sha256(readFileSync(p.raw_ref))!==p.source_sha256)throw new Error("PoC source changed before commit");
  const existing=options.store.get(options.receipt.intel_id,"poc");
  if(existing&&binding(existing)===binding(options.receipt))
    return {dimension:"poc",status:existing.status,receipt_id:existing.receipt_id,artifacts:existing.artifacts.length,newly_recorded:false};
  const committed=options.store.put(options.receipt,()=>{
    const current=readIntelIndexSnapshot(options.sqlitePath).accepted.get(options.receipt.intel_id);
    if(!current||current.intel_event.event_id!==options.receipt.intel_event_id||current.verdict_event.event_id!==options.receipt.dq_event_id
      ||sha256Json(current.item)!==options.receipt.intel_sha256||sha256Json(current.verdict)!==options.receipt.dq_sha256)throw new Error("Intel/DQ changed before PoC receipt commit");
    for(const p of options.receipt.sources)if(sha256(readFileSync(p.raw_ref))!==p.source_sha256)throw new Error("PoC source changed before commit");
  });
  return {dimension:"poc",status:committed.receipt.status,receipt_id:committed.receipt.receipt_id,artifacts:committed.receipt.artifacts.length,newly_recorded:committed.newly_recorded};
}

/** 读取时重新派生当前候选并核对绑定；模型建议永不升级为事实。 */
export async function readPocCandidates(options:{sqlitePath:string;payloadRoots?:readonly string[];intelId:string}){
  const store=new SqliteExtensionReceiptStore(options.sqlitePath,{readOnly:true});
  try{
    const receipt=store.get(options.intelId,"poc");if(!receipt)return {status:"absent" as const,receipt:null};
    const entry=readIntelIndexSnapshot(options.sqlitePath).accepted.get(options.intelId);if(!entry)return {status:"revoked" as const,receipt:null};
    if(Date.parse(receipt.created_at)>Date.now()+300000)return {status:"stale" as const,receipt:null};
    // Re-derive source-bound candidates only; model advisories are never re-requested on read.
    const current=await preparePocReceipt({...options,item:entry.item,jevModelId:receipt.advisories[0]?.model_id??"pinned",skipAdvisories:true});
    if(receipt.intel_event_id!==current.intel_event_id||receipt.dq_event_id!==current.dq_event_id||receipt.intel_sha256!==current.intel_sha256
      ||receipt.dq_sha256!==current.dq_sha256||receipt.artifact_sha256!==current.artifact_sha256||sha256Json(receipt.sources)!==sha256Json(current.sources))return {status:"stale" as const,receipt:null};
    return {status:"verified" as const,receipt};
  }catch(error){return {status:"invalid" as const,receipt:null,reason:error instanceof Error?error.message:"poc proof verification failed"};}
  finally{store.close();}
}
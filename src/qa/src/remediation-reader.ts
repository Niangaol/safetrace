import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { sha256, sha256Json } from "@safetrace/shared";
import type { EvidenceChunk, RawDoc, IntelItem } from "@safetrace/shared";
import { enrichRemediation } from "../../enrich/src/f5-remediation.js";
import type { RemediationArtifact } from "../../enrich/src/f5-remediation.js";
import { readKnowledgeProjection } from "./knowledge-reader.js";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { SqliteExtensionReceiptStore } from "../../enrich/src/extension-receipts.js";
export interface RemediationEvidence { intel_id:string;artifact:RemediationArtifact;chunk:EvidenceChunk;parent_lineage_ids:string[];intel_event_id:string;receipt_id?:string }
/** Independent read-derived dimension, without rewriting the frozen EnrichmentResult artifact schema. */
export async function readRemediationEvidence(options:{sqlitePath:string;payloadRoots?:readonly string[];intelIds?:readonly string[];limit?:number;receiptMode?:"prefer"|"derive"}) {
  const limit=options.limit??10;if(!Number.isSafeInteger(limit)||limit<1||limit>50)throw new Error("remediation view limit must be 1–50 intelligence items");
  const projection=await readKnowledgeProjection(options),snapshot=readIntelIndexSnapshot(options.sqlitePath);
  const db=new DatabaseSync(options.sqlitePath,{readOnly:true});let raw:RawDoc[];
  try{raw=db.prepare("SELECT payload FROM events WHERE topic='raw.docs' ORDER BY seq").all().map(row=>JSON.parse(String(row.payload)) as RawDoc);}finally{db.close();}
  const selected=[...snapshot.accepted].filter(([id,item])=>(!options.intelIds||options.intelIds.includes(id))&&item.item.source_ids.some(s=>["ubuntu_usn","cisa_kev"].includes(s))).slice(0,limit);
  const bytes=new Map<string,Uint8Array>(),evidence:RemediationEvidence[]=[],rejected:Array<{intel_id:string;reason:string}>=[];
  for(const [id,entry] of selected){
    const proofs=projection.evidence.filter(p=>p.kind==="source"&&p.intel_id===id&&p.intel_event_id===entry.intel_event.event_id&&p.raw_ref&&p.original_sha256&&raw.some(r=>r.payload_ref===p.raw_ref&&["ubuntu_usn","cisa_kev"].includes(r.source_id)));
    if (!proofs.length && entry.item.raw_refs.length) rejected.push({intel_id:id,reason:"no verified source proof for remediation input"});
    for(const proof of proofs){
      const candidates=raw.filter(r=>r.payload_ref===proof.raw_ref&&["ubuntu_usn","cisa_kev"].includes(r.source_id));if(candidates.length!==1){rejected.push({intel_id:id,reason:"remediation raw identity absent/ambiguous"});continue;}
      const doc=candidates[0]!;let payload=bytes.get(doc.payload_ref);if(!payload){payload=await readFile(doc.payload_ref);bytes.set(doc.payload_ref,payload);}
      if(sha256(payload)!==proof.original_sha256){rejected.push({intel_id:id,reason:"captured guidance source changed during read"});continue;}
      const artifacts=enrichRemediation(entry.item,[{raw:doc,payload_bytes:payload,proof:{source_id:doc.source_id,source_url:doc.url,raw_ref:doc.payload_ref,source_sha256:proof.original_sha256!,source_status:"active",evidence_kind:"live"}}]);
      for(const artifact of artifacts){
        const artifactHash=sha256Json(artifact),text=[artifact.cve_id,"Source-provided remediation guidance (not a verified fix)",...artifact.actions,"Fixed packages stated by vendor: "+JSON.stringify(artifact.fixed_packages),...artifact.limitations,"Source publication: "+artifact.published_at+" ("+artifact.published_at_granularity+")"].join("\n");
        const chunk:EvidenceChunk={chunk_id:"chunk_remediation_"+sha256Json({event:entry.intel_event.event_id,artifactHash}).slice(0,32),doc_type:"enrichment",text,trust:"untrusted",quality_score:entry.verdict.quality_score,
          ...(artifact.published_at_granularity==="instant"?{published_at:artifact.published_at}:{}),provenance:{url:artifact.source_url,section:"remediation:"+artifact.validation_level+";date-granularity="+artifact.published_at_granularity,sha256:artifactHash}};
        evidence.push({intel_id:id,artifact,chunk,parent_lineage_ids:proof.parent_lineage_ids,intel_event_id:entry.intel_event.event_id});
      }
    }
  }
  // Stored receipts never bypass source projection. Recompute both artifacts and source/DQ binding.
  // Invalid/stale receipt suppresses the item instead of silently falling back to derived success.
  if (options.receiptMode !== "derive") {
    const receipts = new SqliteExtensionReceiptStore(options.sqlitePath,{readOnly:true});
    try {
      for(const [id,entry] of selected) {
        let receipt;
        try { receipt = receipts.get(id); }
        catch { rejected.push({intel_id:id,reason:"invalid persisted remediation receipt"}); for(let i=evidence.length-1;i>=0;i--)if(evidence[i]!.intel_id===id)evidence.splice(i,1);continue; }
        if(!receipt)continue; // Old database has no receipt: preserve explicit read-derived mode.
        const rows = evidence.filter(e=>e.intel_id===id);
        const artifacts = rows.map(e=>e.artifact).sort((a,b)=>sha256Json(a).localeCompare(sha256Json(b)));
        const proofs = rows.map(e=>({raw_ref:e.artifact.raw_ref,source_id:e.artifact.source_id,source_url:e.artifact.source_url,source_sha256:e.artifact.source_sha256,parent_lineage_ids:[...e.parent_lineage_ids].sort()}));
        const sources = [...new Map(proofs.map(p=>[sha256Json(p),p])).values()].sort((a,b)=>sha256Json(a).localeCompare(sha256Json(b)));
        if(receipt.intel_event_id!==entry.intel_event.event_id || receipt.dq_event_id!==entry.verdict_event.event_id
          || receipt.intel_sha256!==sha256Json(entry.item) || receipt.dq_sha256!==sha256Json(entry.verdict)
          || receipt.artifact_sha256!==sha256Json(artifacts) || sha256Json(receipt.sources)!==sha256Json(sources)
          || Date.parse(receipt.created_at)>Date.now()+300000 || rejected.some(r=>r.intel_id===id)) {
          rejected.push({intel_id:id,reason:"persisted remediation receipt does not match current Intel/DQ/raw evidence"});
          for(let i=evidence.length-1;i>=0;i--)if(evidence[i]!.intel_id===id)evidence.splice(i,1);
        } else { for(const row of rows) row.receipt_id=receipt.receipt_id; }
      }
    } finally {receipts.close();}
  }
  const current=readIntelIndexSnapshot(options.sqlitePath);if(current.fingerprint!==snapshot.fingerprint)throw new Error("Intel/DQ changed during guidance projection; retry");
  return {mode:"readonly-remediation-evidence",stored_receipts_verified:new Set(evidence.map(e=>e.receipt_id).filter(Boolean)).size,evidence,chunks:evidence.map(e=>e.chunk),selected_intelligence:selected.length,rejected,business_writes:0,network_calls:0,validation:"vendor/agency statement, never verified repair or asset applicability"};
}

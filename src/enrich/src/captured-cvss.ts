import { DatabaseSync } from "node:sqlite";
import { EventBus, SqliteEventStore, SqliteEnrichmentStateStore, enrichmentInputHash, enrichmentRetryDue, enrichmentRetryAfter, nextId, sha256Json } from "@safetrace/shared";
import type { EnrichmentResult, IntelItem, ScoreAssessment, PaperLink, EnrichmentDimensionState } from "@safetrace/shared";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { acquireIntelIndexLease } from "../../../scripts/intel-index-lock.js";
import { requireVerifiedBackup } from "../../../scripts/verified-backup-gate.js";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { readFile } from "node:fs/promises";
import { sha256 } from "@safetrace/shared";
import { readKnowledgeProjection } from "../../qa/src/knowledge-reader.js";
import { loadScoreSourcesFromRawRefs, assessScore, scoreSourceDependencyHash } from "./f4-cvss.js";
import { summarizeEnrichment } from "./f6-verify.js";

export interface CapturedCvssOptions { sqlitePath:string;payloadRoots?:readonly string[];apply?:boolean;limit?:number;backupDirectory?:string;now?:Date }
interface Candidate {item:IntelItem;score:ScoreAssessment;dependency:string;intel_event_id:string;parent_lineage_ids:string[];source_hashes:string[];verified_refs:string[];retained_papers:PaperLink[];paper_state?:EnrichmentDimensionState;epss_state?:EnrichmentDimensionState}
/** Reconcile only captured, verified primary-CVE NIST scores. No F1/FIRST/model/vector code paths. */
export async function reconcileCapturedCvss(options:CapturedCvssOptions) {
  const limit=options.limit??20;if(!Number.isSafeInteger(limit)||limit<1||limit>50)throw new Error("captured CVSS limit must be 1–50");
  const release=options.apply?acquireIntelIndexLease("http://127.0.0.1","enrichment-db:"+resolve(options.sqlitePath),fileURLToPath(new URL("../../../.tmp/data-maintenance-locks/",import.meta.url))):undefined;
  let writer:SqliteEventStore|undefined,states:SqliteEnrichmentStateStore|undefined;
  try {
    if(options.apply)await requireVerifiedBackup(options.sqlitePath,options.backupDirectory);
    const now=options.now??new Date(),snapshot=readIntelIndexSnapshot(options.sqlitePath),projection=await readKnowledgeProjection(options);
    const sourceProofs=new Map<string,typeof projection.evidence>();
    for(const proof of projection.evidence)if(proof.kind==="source"){const rows=sourceProofs.get(proof.intel_id)??[];rows.push(proof);sourceProofs.set(proof.intel_id,rows);}
    states=new SqliteEnrichmentStateStore(options.sqlitePath,{readOnly:true});
    const receiptReader=new DatabaseSync(options.sqlitePath,{readOnly:true});
    let receipts:Map<string,{event_id:string;payload:EnrichmentResult}>;
    try {receipts=new Map(receiptReader.prepare("SELECT event_id,payload FROM events WHERE topic='enrich.items' ORDER BY seq").all().map(row=>{const payload=JSON.parse(String(row.payload)) as EnrichmentResult;return [payload.intel_id,{event_id:String(row.event_id),payload}];}));} finally {receiptReader.close();}
    const rawEligibility = new Set<string>();
    const rawProof = new Map(projection.evidence.filter(e=>e.kind==="source"&&e.raw_ref&&e.original_sha256).map(e=>[e.raw_ref!,e.original_sha256!]));
    for(const [ref,hash] of rawProof) {
      if(ref.startsWith("sqlite-page:"))continue;
      const bytes=await readFile(ref);if(sha256(bytes)!==hash)throw new Error("captured payload changed during eligibility planning");
      const data=JSON.parse(bytes.toString("utf8"));
      for(const row of data.vulnerabilities??[]){const c=row.cve;if(!c?.id||/^(REJECT|RESERVED|DISPUTED)/i.test(String(c.vulnStatus??"")))continue;
        if(c.metrics?.cvssMetricV31?.some((m:any)=>String(m.source).toLowerCase()==="nvd@nist.gov"))rawEligibility.add(ref+"|"+String(c.id).toUpperCase());}
    }
    const eligible=[...snapshot.accepted].filter(([id,e])=>sourceProofs.has(id)&&e.item.raw_refs.some(ref=>rawEligibility.has(ref+"|"+e.item.cve_ids[0]?.toUpperCase())));
    const candidates:Candidate[]=[],counts={accepted:snapshot.accepted.size,source_verified:sourceProofs.size,nist_v31_eligible:eligible.length,already_current:0,not_eligible_for_nist_pass:snapshot.accepted.size-eligible.length,invalid:0,checked:0,unvisited_eligible:eligible.length};
    for(const [id,entry] of eligible){
      if(candidates.length>=limit)break;counts.checked++;counts.unvisited_eligible--;
      const proofs=sourceProofs.get(id)??[];
      const verifiedRefs=[...new Set(proofs.map(proof=>proof.raw_ref).filter((ref):ref is string=>Boolean(ref)))];
      const sources=await loadScoreSourcesFromRawRefs({...entry.item,raw_refs:verifiedRefs});if(!sources.some(s=>s.source_of_score==="nvd"&&s.cve_id===entry.item.cve_ids[0])){counts.invalid++;continue;}
      try {
        const score=await assessScore(entry.item,{sources,skipEpss:true,fetchImpl:async()=>{throw new Error("captured score reconciliation must never request network");}});
        if(!score||score.source_of_score!=="nvd"){counts.not_eligible_for_nist_pass++;continue;}
        // Auxiliary fields are not validated in this pass and must not piggyback on the result.
        delete score.epss_score;delete score.epss_percentile;
        const dependency=await scoreSourceDependencyHash(entry.item),previous=states.get(id,"cvss");
        const verifiedPrior=projection.evidence.some(proof=>proof.kind==="cvss"&&proof.intel_id===id&&proof.enrich_event_id===previous?.enrich_event_id&&proof.artifact_sha256===sha256Json(score));
        const previousReceipt=receipts.get(id),paperState=states.get(id,"paper"),epssState=states.get(id,"epss");
        const retainedPapers=previousReceipt?.payload.artifacts.papers?.filter(paper=>projection.evidence.some(proof=>proof.kind==="paper"&&proof.intel_id===id&&proof.enrich_event_id===previousReceipt.event_id&&proof.artifact_sha256===sha256Json(paper)))??[];
        const retainPaper=retainedPapers.length>0&&paperState?.status==="live"&&paperState.enrich_event_id===previousReceipt?.event_id&&paperState.input_hash===enrichmentInputHash(entry.item);
        const receipt=epssState?.source_receipt,epss=epssState?.artifact as {epss_score?:number;epss_percentile?:number}|undefined;
        const age=receipt?.as_of_date?now.getTime()-Date.parse(receipt.as_of_date+"T00:00:00Z"):NaN;
        const epssRows=(receipt?.payload as {data?:Array<{cve?:unknown;epss?:unknown;percentile?:unknown}>}|undefined)?.data?.filter(row=>row.cve===entry.item.cve_ids[0])??[];
        const retainEpss=epssRows.length===1&&Number(epssRows[0]!.epss)===epss?.epss_score&&Number(epssRows[0]!.percentile)===epss?.epss_percentile&&epssState?.status==="live"&&epssState.enrich_event_id===previousReceipt?.event_id&&epssState.input_hash===enrichmentInputHash(entry.item)
          && !!receipt && receipt.cve_id===entry.item.cve_ids[0]&&receipt.sha256===sha256Json(receipt.payload)&&Number.isFinite(age)&&age>=0&&age<=2*24*3600_000
          && typeof epss?.epss_score==="number"&&epss.epss_score>=0&&epss.epss_score<=1&&typeof epss.epss_percentile==="number"&&epss.epss_percentile>=0&&epss.epss_percentile<=1;
        if(retainEpss){score.epss_score=epss!.epss_score;score.epss_percentile=epss!.epss_percentile;}
        if(verifiedPrior&&previous?.status==="live"&&previous.dependency_hash===dependency&&previous.intel_event_id===entry.intel_event.event_id&&previous.enrich_event_id&&previous.result_hash===sha256Json(score)&&!enrichmentRetryDue(previous,enrichmentInputHash(entry.item),now)){counts.already_current++;continue;}
        if(candidates.length<limit)candidates.push({item:entry.item,score,dependency,intel_event_id:entry.intel_event.event_id,parent_lineage_ids:[...new Set(proofs.flatMap(p=>p.parent_lineage_ids))],source_hashes:proofs.map(p=>p.original_sha256!).filter(Boolean),verified_refs:verifiedRefs,retained_papers:retainPaper?retainedPapers:[],...(retainPaper?{paper_state:paperState}:{}),...(retainEpss?{epss_state:epssState}:{})});
      }catch{counts.invalid++;}
    }
    const selected=candidates.map(c=>({intel_id:c.item.intel_id,cve_id:c.item.cve_ids[0],source_of_score:c.score.source_of_score,cvss_v3_base:c.score.cvss_v3_base}));
    if(!options.apply)return {mode:"readonly-captured-cvss-plan",counts,selected,written:0,network_calls:0,model_calls:0,vector_writes:0};
    states.close();states=new SqliteEnrichmentStateStore(options.sqlitePath);writer=new SqliteEventStore(options.sqlitePath);const bus=new EventBus({store:writer}),trace=nextId("tr"),written:string[]=[];
    for(const candidate of candidates){
      const current=readIntelIndexSnapshot(options.sqlitePath).accepted.get(candidate.item.intel_id);
      if(!current||current.intel_event.event_id!==candidate.intel_event_id||sha256Json(current.item)!==sha256Json(candidate.item))throw new Error("current Intel/DQ changed; stop captured reconciliation");
      if(await scoreSourceDependencyHash(candidate.item)!==candidate.dependency)throw new Error("captured original bytes changed; stop reconciliation");
      const parent=await bus.recordLineage({trace_id:trace,parent_lineage_ids:candidate.parent_lineage_ids,stage:"enrich.captured_cvss_verify",operation_version:"captured-cvss.v1",status:"success",causation_id:candidate.intel_event_id,
        input_refs:[{kind:"IntelItem",id:candidate.item.intel_id,sha256:sha256Json(candidate.item)},...candidate.source_hashes.map((hash,i)=>({kind:"RawPayload",id:candidate.item.intel_id+":"+i,sha256:hash}))],
        output_refs:[{kind:"ScoreAssessment",id:candidate.item.intel_id,sha256:sha256Json(candidate.score)}],decision:{reason:"verified archived NIST primary-CVE v3.1 metadata; no current fetch, paper, EPS, model or vector request"}});
      const outcome=summarizeEnrichment(candidate.item,{scoreAssessment:candidate.score,papers:candidate.retained_papers});
      const {conflicts,...payload}=outcome;void conflicts;
      // Preserve any older result append-only; only the explicitly reverified dimension is published here.
      const event=await bus.publish<EnrichmentResult>("enrich.items",payload,{trace_id:trace,causation_id:candidate.intel_event_id});
      await bus.recordLineage({trace_id:trace,parent_lineage_ids:[parent.lineage_id],stage:"enrich.f6",operation_version:"captured-cvss.v1",status:"success",causation_id:event.event_id,
        input_refs:[{kind:"IntelItem",id:candidate.item.intel_id,sha256:sha256Json(candidate.item)}],output_refs:[{kind:"EnrichmentResult",id:candidate.item.intel_id,sha256:sha256Json(payload)}],decision:{reason:"CVSS-only captured-source reconciliation; other dimensions not verified by this pass"}});
      const previous=states.get(candidate.item.intel_id,"cvss");
      states.atomic(()=>{
      states!.put({intel_id:candidate.item.intel_id,dimension:"cvss",status:"live",input_hash:enrichmentInputHash(candidate.item),result_hash:sha256Json(candidate.score),enrich_event_id:event.event_id,intel_event_id:candidate.intel_event_id,
        dependency_hash:candidate.dependency,retry_after:enrichmentRetryAfter("live",(previous?.attempts??0)+1,now),reason:"source-verified archived NIST v3.1 score; not realtime acquisition",attempts:(previous?.attempts??0)+1,updated_at:now.toISOString(),artifact:candidate.score});
      if(candidate.paper_state)states!.put({...candidate.paper_state,artifact:candidate.retained_papers,result_hash:sha256Json(candidate.retained_papers),enrich_event_id:event.event_id,intel_event_id:candidate.intel_event_id});
      if(candidate.epss_state)states!.put({...candidate.epss_state,enrich_event_id:event.event_id,intel_event_id:candidate.intel_event_id});
      });
      written.push(candidate.item.intel_id);
    }
    return {mode:"applied-captured-cvss",trace_id:trace,counts,selected,written:written.length,written_ids:written,network_calls:0,model_calls:0,vector_writes:0};
  }finally{states?.close();writer?.close();release?.();}
}

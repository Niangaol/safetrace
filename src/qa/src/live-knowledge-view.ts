import { DatabaseSync } from "node:sqlite";
import { sha256Json } from "@safetrace/shared";
import type { EnrichmentResult, IntelItem, RawDoc, EnrichmentDimensionState, PaperLink } from "@safetrace/shared";
import { readKnowledgeProjection } from "./knowledge-reader.js";
import { latestIntelSnapshot } from "./intel-index-plan.js";
import type { IntelIndexEvent } from "./intel-index-plan.js";
import type { KnowledgeProjection } from "./knowledge-projection.js";

export interface LiveKnowledgeView { intel: IntelItem[]; raw: RawDoc[]; recorded: Map<string,EnrichmentResult>;
  verified: Map<string,EnrichmentResult>; states: EnrichmentDimensionState[]; projection: KnowledgeProjection }
/** Every request gets a coherent read-only view. No fixture imports or model/collector transports. */
export async function readLiveKnowledgeView(options:{sqlitePath:string;payloadRoots?:readonly string[]}):Promise<LiveKnowledgeView> {
  const projection=await readKnowledgeProjection(options);
  const db=new DatabaseSync(options.sqlitePath,{readOnly:true});db.exec("BEGIN");
  try {
    const rows=db.prepare("SELECT seq,event_id,trace_id,causation_id,topic,payload FROM events WHERE topic IN ('raw.docs','intel.items','dq.verdicts','enrich.items') ORDER BY seq").all();
    if(Number(rows.at(-1)?.seq??0)!==projection.watermark)throw new Error("knowledge changed while constructing the API snapshot; retry");
    const events=rows.map(r=>({seq:Number(r.seq),event_id:String(r.event_id),trace_id:String(r.trace_id),causation_id:typeof r.causation_id==="string"?r.causation_id:null,topic:r.topic as IntelIndexEvent["topic"]|"enrich.items",payload:JSON.parse(String(r.payload))}));
    const current=latestIntelSnapshot(events.filter((e):e is IntelIndexEvent=>e.topic!=="enrich.items"));
    const raw=events.filter(e=>e.topic==="raw.docs").map(e=>e.payload as RawDoc);
    const latest=new Map(events.filter(e=>e.topic==="enrich.items").map(e=>[(e.payload as EnrichmentResult).intel_id,e]));
    const recorded=new Map([...latest].map(([id,event])=>[id,event.payload as EnrichmentResult]));
    const hasStates=!!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_dimension_state'").get();
    const states=hasStates?db.prepare("SELECT payload FROM enrichment_dimension_state ORDER BY intel_id,dimension").all().map(r=>JSON.parse(String(r.payload)) as EnrichmentDimensionState):[];
    const verified=new Map<string,EnrichmentResult>();
    for(const [id,entry] of current.accepted){
      const event=latest.get(id);if(!event)continue;const original=event.payload as EnrichmentResult;
      const proofs=projection.evidence.filter(p=>p.intel_id===id&&p.enrich_event_id===event.event_id&&p.result_sha256===sha256Json(original));
      const papers=(original.artifacts.papers??[]).filter(p=>proofs.some(proof=>proof.kind==="paper"&&proof.artifact_sha256===sha256Json(p)));
      const score=original.artifacts.score_assessment && proofs.some(p=>p.kind==="cvss"&&p.artifact_sha256===sha256Json(original.artifacts.score_assessment))?{...original.artifacts.score_assessment}:undefined;
      if(score){delete score.epss_score;delete score.epss_percentile;}
      if(!papers.length&&!score)continue;
      const completed:EnrichmentResult["dimensions_completed"]=[];if(papers.length)completed.push("paper");if(score)completed.push("cvss");
      verified.set(id,{...original,dimensions_completed:completed,dimensions_failed:(["paper","cvss"] as const).filter(d=>!completed.includes(d)),artifacts:{...(papers.length?{papers:papers as PaperLink[]}:{}),...(score?{score_assessment:score}:{})}});
      void entry;
    }
    return {intel:[...current.accepted.values()].map(e=>e.item),raw,recorded,verified,states,projection};
  } finally {db.exec("ROLLBACK");db.close();}
}
export function liveIntelItem(view:LiveKnowledgeView,item:IntelItem) {
  const enriched=view.verified.get(item.intel_id),score=enriched?.artifacts.score_assessment,base=score?.cvss_v3_base??null;
  const raw=view.raw.filter(r=>item.source_ids.includes(r.source_id)&&item.raw_refs.includes(r.payload_ref));
  return {id:item.intel_id,cve_id:item.cve_ids[0]??"",ghsa_id:item.ghsa_ids?.[0]??null,title:item.title,description:item.summary??item.title,summary:item.summary??"",
    severity:base===null?"unknown":base>=9?"critical":base>=7?"high":base>=4?"medium":"low",cvss_score:base,cvss_vector:score?.cvss_v3_vector??null,
    cwe:item.entities.cwe,cpe:item.entities.cpes,ai_risk_category:null,exploit_status:score?.kev_flag?"known_exploited":null,
    published_at:item.published_at,fetched_at:raw.map(r=>r.fetched_at).sort().at(-1)??null,collect_latency_seconds:null,source_count:item.source_ids.length,
    enriched:!!enriched,enrichment_recorded:view.recorded.has(item.intel_id),enrichment_verification:enriched?"source_and_artifact_verified":view.recorded.has(item.intel_id)?"unknown_historical":"pending",
    data_mode:"live",read_only:true,related:{papers:enriched?.artifacts.papers??[],pocs:[]}};
}
export function liveEvidenceView(view:LiveKnowledgeView,item:IntelItem) {
  const proofs=view.projection.evidence.filter(p=>p.intel_id===item.intel_id),result=view.verified.get(item.intel_id);
  const evidence=(kind:"paper"|"cvss")=>proofs.filter(p=>p.kind===kind).map(p=>({evidence_id:p.chunk.chunk_id,source:p.kind,url:p.chunk.provenance.url,snippet:p.chunk.text,
    fetched_at:null,original_sha256:p.original_sha256??null,artifact_sha256:p.artifact_sha256??null,text_sha256:p.text_sha256,parent_lineage_ids:p.parent_lineage_ids}));
  const enrichments=[];
  if(result?.artifacts.papers?.length)enrichments.push({dimension:"paper",value:{papers:result.artifacts.papers},source:["arxiv"],evidence:evidence("paper"),confidence:null,confidence_kind:"heuristic_not_accuracy",model:"rule",agent:"f1",version:2,mock:false,degraded_to:null,created_at:result.completed_at});
  if(result?.artifacts.score_assessment)enrichments.push({dimension:"cvss",value:{...result.artifacts.score_assessment},source:[result.artifacts.score_assessment.source_of_score],evidence:evidence("cvss"),confidence:null,model:"rule",agent:"f4",version:2,mock:false,degraded_to:null,created_at:result.completed_at});
  return {data_mode:"live",read_only:true,enrichments,dimension_states:view.states.filter(s=>s.intel_id===item.intel_id).map(s=>({dimension:s.dimension,status:s.status,reason:s.reason,retry_after:s.retry_after,has_last_good:!!s.last_good})),
    recorded_result_present:view.recorded.has(item.intel_id),historical_unknown:view.recorded.has(item.intel_id)&&!result,graph:{nodes:[],edges:[]}};
}

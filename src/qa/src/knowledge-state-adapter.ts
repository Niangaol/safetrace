import { enrichmentInputHash, sha256Json, sha256 } from "@safetrace/shared";
import type { EnrichmentDimensionState, EnrichmentResult, LineageRecord, RawDoc } from "@safetrace/shared";
import { arxivPaperRecords } from "../../enrich/src/f1-papers.js";
import { latestIntelSnapshot } from "./intel-index-plan.js";
import { rawKnowledgeRecords } from "./knowledge-projection.js";
import type { ArtifactEvidence, KnowledgeEvent, KnowledgeEnrichmentState } from "./knowledge-projection.js";

/** Sidecar live status alone never creates evidence. Re-check artifact hash, result event, input and actual source records. */
export async function knowledgeStatesFromDimensions(input:{events:readonly KnowledgeEvent[];lineage:readonly LineageRecord[];states:readonly EnrichmentDimensionState[];
  readRaw:(raw:RawDoc)=>Promise<Uint8Array>;explicitPaperEvidence?:readonly ({intel_id:string;enrich_event_id:string}&ArtifactEvidence)[]}):Promise<KnowledgeEnrichmentState[]> {
  if(input.states.length===0)return []; // historical results without sidecars are unknown, not a per-item scan
  const enrichEvents=new Map(input.events.filter(e=>e.topic==="enrich.items").map(e=>[(e.payload as EnrichmentResult).intel_id,e]));
  const statesByIntel=new Map<string,EnrichmentDimensionState[]>();
  for(const state of input.states){const group=statesByIntel.get(state.intel_id)??[];group.push(state);statesByIntel.set(state.intel_id,group);}
  const snapshot=latestIntelSnapshot(input.events.filter((e):e is Exclude<KnowledgeEvent,{topic:"enrich.items"}> & {topic:"intel.items"|"dq.verdicts"|"raw.docs"}=>e.topic!=="enrich.items"));
  const result:KnowledgeEnrichmentState[]=[];const rawCache=new Map<string,ReturnType<typeof rawKnowledgeRecords>>();
  for(const [id,entry] of snapshot.accepted){
    const event=enrichEvents.get(id);
    if(!event || event.causation_id!==entry.intel_event.event_id)continue;
    const enriched=event.payload as EnrichmentResult, artifacts:ArtifactEvidence[]=[];
    const states=(statesByIntel.get(id)??[]).filter(s=> s.status==="live" && s.input_hash===enrichmentInputHash(entry.item) && s.enrich_event_id===event.event_id && s.result_hash===sha256Json(s.artifact));
    const cvss=states.find(s=>s.dimension==="cvss"),score=enriched.artifacts.score_assessment;
    if(cvss && score && sha256Json(cvss.artifact)===sha256Json(score)){
      for(const ref of entry.item.raw_refs){
        const raws=input.events.filter(e=>e.topic==="raw.docs"&&(e.payload as RawDoc).payload_ref===ref);
        if(raws.length!==1)continue;const raw=raws[0]!.payload as RawDoc;
        if(!((raw.source_type==="nvd_cve"&&score.source_of_score==="nvd")||(raw.source_type==="cve_org"&&score.source_of_score==="cna")))continue;
        try{let records=rawCache.get(raws[0]!.event_id);if(!records){records=rawKnowledgeRecords(raw,await input.readRaw(raw));rawCache.set(raws[0]!.event_id,records);}
          const row=records.find(r=>entry.item.cve_ids.includes(r.id)&&r.metrics.some(m=>m?.source_of_score===score.source_of_score&&m?.baseScore===score.cvss_v3_base&&m?.vectorString===score.cvss_v3_vector));
          if(row)artifacts.push({key:"cvss",artifactHash:sha256Json(score),url:raw.url,published_at:row.published_at,trust:"untrusted",raw_ref:ref,cve_id:row.id});
        }catch{/* Projection logs unsupported/unreadable source errors; never guess a score source. */}
      }
      if(artifacts.filter(a=>a.key==="cvss").length>1)artifacts.splice(0,artifacts.length); // ambiguous score provenance is not selected arbitrarily
    }
    const paper=states.find(s=>s.dimension==="paper");
    if(paper && sha256Json(paper.artifact)===sha256Json(enriched.artifacts.papers ?? [])){
      const receipt=paper.provenance;
      if(receipt && sha256(receipt.text)===receipt.sha256) {
        const query = new URL(receipt.query_url);
        if(query.protocol === "https:" && query.hostname === "export.arxiv.org" && query.pathname === "/api/query" && !query.username && !query.password) {
          const records=arxivPaperRecords(receipt.text);
          for(const p of enriched.artifacts.papers??[]) {
            const record=records[p.paper_id], claimed=receipt.paper_records[p.paper_id];
            if(record && claimed && sha256Json(record)===sha256Json(claimed) && record.title===p.title && p.relevance_score>0) artifacts.push({key:"paper:"+p.paper_id,artifactHash:sha256Json(p),url:record.url,published_at:record.published_at,trust:"untrusted"});
          }
        }
      }
      for(const proof of input.explicitPaperEvidence??[])if(proof.intel_id===id&&proof.enrich_event_id===event.event_id)artifacts.push(proof);
    }
    if(!artifacts.length)continue;
    const lineage_ids=input.lineage.filter(r=>r.stage==="enrich.f6"&&r.causation_id===event.event_id&&r.status==="success"&&r.output_refs.some(x=>x.id===id&&x.sha256===sha256Json(enriched))).map(r=>r.lineage_id);
    result.push({intel_id:id,mode:"live",status:"success",inputHash:enrichmentInputHash(entry.item),inputHashMode:"facts",resultHash:sha256Json(enriched),enrich_event_id:event.event_id,lineage_ids,artifacts});
  }
  return result;
}

import { DatabaseSync } from "node:sqlite";
import { readFile, realpath, stat } from "node:fs/promises";
import { resolve, relative, isAbsolute } from "node:path";
import type { LineageRecord, RawDoc, StoredPageSnapshot, EnrichmentDimensionState } from "@safetrace/shared";
import { projectKnowledgeEvidence } from "./knowledge-projection.js";
import type { KnowledgeEvent, KnowledgeProjection, ArtifactEvidence } from "./knowledge-projection.js";
import { knowledgeStatesFromDimensions } from "./knowledge-state-adapter.js";

/** Read-only snapshot adapter: no schema initialization, implicit network, embedding, or vector writes. */
export async function readKnowledgeProjection(options:{sqlitePath:string;payloadRoots?:readonly string[];
  explicitPaperEvidence?:readonly ({intel_id:string;enrich_event_id:string}&ArtifactEvidence)[]}):Promise<KnowledgeProjection> {
  const db=new DatabaseSync(options.sqlitePath,{readOnly:true});db.exec("BEGIN");
  try {
    const events=db.prepare("SELECT seq,event_id,trace_id,causation_id,topic,payload FROM events WHERE topic IN ('raw.docs','intel.items','dq.verdicts','enrich.items') ORDER BY seq").all().map(row=>({
      seq:Number(row.seq),event_id:String(row.event_id),trace_id:String(row.trace_id),causation_id:row.causation_id===null?null:String(row.causation_id),topic:row.topic as KnowledgeEvent["topic"],payload:JSON.parse(String(row.payload))
    }));
    const lineage=db.prepare("SELECT payload FROM lineage_records ORDER BY seq").all().map(row=>JSON.parse(String(row.payload)) as LineageRecord);
    const has=(name:string)=>!!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name);
    const states=has("enrichment_dimension_state")?db.prepare("SELECT payload FROM enrichment_dimension_state ORDER BY intel_id,dimension").all().map(row=>JSON.parse(String(row.payload)) as EnrichmentDimensionState):[];
    const roots=await Promise.all((options.payloadRoots??[resolve("tmp/ingest-cache")]).map(root=>realpath(resolve(root))));
    const bytes=new Map<string,Promise<Uint8Array>>();
    const readRaw=(raw:RawDoc):Promise<Uint8Array>=>{
      let pending=bytes.get(raw.payload_ref);
      if(!pending){pending=(async()=>{
        if(!/[.](json|xml|html?|txt|payload)$/i.test(raw.payload_ref))throw new Error("unsupported/private raw payload file type");
        const full=await realpath(resolve(raw.payload_ref));
        if(!roots.some(root=>{const p=relative(root,full);return p!==""&&!p.startsWith("..")&&!isAbsolute(p);}))throw new Error("raw payload outside explicit captured roots");
        if((await stat(full)).size>25*1024*1024)throw new Error("raw payload exceeds 25MiB projection limit");
        return readFile(full);
      })();bytes.set(raw.payload_ref,pending);}
      return pending;
    };
    const page=(hash:string):Promise<StoredPageSnapshot|undefined>=>{
      if(!has("page_snapshot_history"))return Promise.resolve(undefined);
      const rows=db.prepare("SELECT * FROM page_snapshot_history WHERE content_sha256=?").all(hash);
      if(rows.length!==1)return Promise.resolve(undefined);
      const row=rows[0]!;return Promise.resolve({...row,lineage_ids:JSON.parse(String(row.lineage_ids))} as unknown as StoredPageSnapshot);
    };
    const enrichment_states=await knowledgeStatesFromDimensions({events,lineage,states,readRaw,explicitPaperEvidence:options.explicitPaperEvidence});
    return await projectKnowledgeEvidence({events,lineage,enrichment_states,read_raw_payload:readRaw,read_page_snapshot:page});
  } finally {db.exec("ROLLBACK");db.close();}
}

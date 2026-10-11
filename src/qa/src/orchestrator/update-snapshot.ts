/** 一致的只读event/state快照；原文依赖哈希按ref共享读取，不按每个CVE重复读大报文。 */
import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { resolve, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Json, enrichmentInputHash } from "@safetrace/shared";
import type { EnrichmentDimensionState, EnrichmentResult } from "@safetrace/shared";
import { latestIntelSnapshot } from "../intel-index-plan.js";
import type { IntelIndexEvent } from "../intel-index-plan.js";
import type { AgentUpdateSnapshot } from "./intel-update-agents.js";
const root = fileURLToPath(new URL("../../../../",import.meta.url));
export async function readAgentUpdateSnapshot(sqlitePath:string):Promise<AgentUpdateSnapshot> {
  const db=new DatabaseSync(sqlitePath,{readOnly:true});db.exec("BEGIN");
  let snapshot;let states:EnrichmentDimensionState[];let receipts:{event_id:string;payload:EnrichmentResult}[];
  try {
    const rows=db.prepare("SELECT seq,event_id,trace_id,causation_id,topic,payload FROM events WHERE topic IN ('raw.docs','intel.items','dq.verdicts','enrich.items') ORDER BY seq").all();
    const events=rows.map(r=>({seq:Number(r.seq),event_id:String(r.event_id),trace_id:String(r.trace_id),causation_id:typeof r.causation_id==="string"?r.causation_id:null,topic:String(r.topic),payload:JSON.parse(String(r.payload))}));
    snapshot=latestIntelSnapshot(events.filter(e=>e.topic!=="enrich.items") as IntelIndexEvent[]);
    receipts=events.filter(e=>e.topic==="enrich.items").map(e=>({event_id:e.event_id,payload:e.payload as EnrichmentResult}));
    const has=!!db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='enrichment_dimension_state'").get();
    states=has?db.prepare("SELECT payload FROM enrichment_dimension_state ORDER BY intel_id,dimension").all().map(r=>JSON.parse(String(r.payload)) as EnrichmentDimensionState):[];
  } finally {db.exec("ROLLBACK");db.close();}
  const liveStates=new Map(states.filter(s=>s.dimension==="cvss"&&s.status==="live").map(s=>[s.intel_id,s]));
  const reads=new Map<string,Promise<string|null>>();
  const hashRef=(ref:string)=>{
    let read=reads.get(ref);if(!read){read=(async()=>{
      const candidates=isAbsolute(ref)||/^[a-zA-Z]:[\\/]/.test(ref)?[ref]:[resolve(root,ref),resolve(process.cwd(),ref)];
      for(const candidate of candidates){try{return sha256Json(await readFile(candidate,"utf8"));}catch{}}
      return null;
    })();reads.set(ref,read);}return read;
  };
  const kevCveIds=new Set([...snapshot.accepted.values()].filter(e=>e.item.source_ids.includes("cisa_kev")).flatMap(e=>e.item.cve_ids));
  const cvssDependencyHashes=new Map<string,string>();
  for(const entry of snapshot.accepted.values()) {
    const state=liveStates.get(entry.item.intel_id);if(!state||state.input_hash!==enrichmentInputHash(entry.item))continue;
    const raw=await Promise.all(entry.item.raw_refs.map(async ref=>({ref,sha256:await hashRef(ref)})));
    cvssDependencyHashes.set(entry.item.intel_id,sha256Json({revision:"cvss-source-dependencies.v3",primary_cve:entry.item.cve_ids[0]??null,raw,injected:null,kev:[...kevCveIds].sort()}));
  }
  return {snapshot,states,receipts,cvssDependencyHashes,kevCveIds};
}

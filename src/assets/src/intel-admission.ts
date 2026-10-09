import { DatabaseSync } from "node:sqlite";
import { existsSync } from "node:fs";
import type { EventStore, IntelAdmissionEvent, IntelItem } from "@safetrace/shared";
import { latestIntelSnapshot } from "../../qa/src/intel-index-plan.js";

/** Shares exactly the API latest-DQ gate; no timestamps or fabricated cross-topic ordering. */
export function releasedIntel(events: readonly IntelAdmissionEvent[]): IntelItem[] {
  return [...latestIntelSnapshot(events).accepted.values()].map(e=>e.item);
}
export function withReleasedIntel<T>(store:EventStore,operation:(items:IntelItem[])=>T): T {
  if(!store.withIntelAdmissionSnapshot)throw new Error('Asset matching needs a globally ordered Intel/DQ snapshot-capable store');
  return store.withIntelAdmissionSnapshot(events=>operation(releasedIntel(events)));
}
/** API counterpart: no schema initialization or Intel content writes. Writer reservation prevents DQ changing during local alert commit. */
export function withReleasedIntelDb<T>(path:string,operation:(items:IntelItem[])=>T): T {
  if(!existsSync(path))throw new Error('Intel database missing; asset matches refused');
  const db=new DatabaseSync(path);db.exec('PRAGMA busy_timeout=5000');
  try {
    db.exec('BEGIN IMMEDIATE');
    try {
      const events=db.prepare("SELECT seq,event_id,trace_id,causation_id,topic,payload FROM events WHERE topic IN ('raw.docs','intel.items','dq.verdicts') ORDER BY seq").all().map(row=>({seq:Number(row.seq),event_id:String(row.event_id),trace_id:String(row.trace_id),causation_id:row.causation_id===null?null:String(row.causation_id),topic:row.topic as IntelAdmissionEvent['topic'],payload:JSON.parse(String(row.payload))}));
      const value=operation(releasedIntel(events));db.exec('COMMIT');return value;
    } catch(error){db.exec('ROLLBACK');throw error;}
  } finally {db.close();}
}

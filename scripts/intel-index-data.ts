import { DatabaseSync } from "node:sqlite";
import { latestIntelSnapshot } from "../src/qa/src/intel-index-plan.js";
import type { IntelIndexEvent, IntelSnapshot } from "../src/qa/src/intel-index-plan.js";

/** A single SELECT gives one SQLite read snapshot; malformed latest events never silently disappear. */
export function readIntelIndexSnapshot(path: string): IntelSnapshot {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const rows = db.prepare("SELECT seq,event_id,trace_id,causation_id,topic,payload FROM events WHERE topic IN ('intel.items','dq.verdicts','raw.docs') ORDER BY seq").all();
    const events = rows.map(row => {
      if (typeof row.payload !== "string") throw new Error("invalid stored event payload at seq=" + row.seq);
      let payload: unknown;
      try { payload = JSON.parse(row.payload); }
      catch { throw new Error("malformed stored event JSON at seq=" + row.seq); }
      return { seq: Number(row.seq), event_id: String(row.event_id), trace_id: String(row.trace_id),
        causation_id: typeof row.causation_id === "string" ? row.causation_id : null,
        topic: row.topic as IntelIndexEvent["topic"], payload };
    });
    return latestIntelSnapshot(events);
  } finally { db.close(); }
}

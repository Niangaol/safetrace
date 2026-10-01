import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { summarizeIngestDiagnostics } from "../../../scripts/ingest-diagnostics.js";

function lineage(traceId: string, source: string, status: string, outputRefs: unknown[], decision: unknown = {}): string {
  return JSON.stringify({
    lineage_id: "ln_" + source,
    trace_id: traceId,
    stage: "ingest.fetch",
    operation_version: source + ".fetch.v1",
    status,
    started_at: "2026-10-01T01:00:00.000Z",
    completed_at: "2026-10-01T01:00:01.000Z",
    recorded_at: "2026-10-01T01:00:01.000Z",
    output_refs: outputRefs,
    decision,
  });
}

test("采集诊断：区分真实、fixture、无新文档并显示富化缺口", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec("CREATE TABLE lineage_records(seq INTEGER PRIMARY KEY, trace_id TEXT, stage TEXT, recorded_at TEXT, payload TEXT)");
    db.exec("CREATE TABLE events(seq INTEGER PRIMARY KEY, trace_id TEXT, topic TEXT, payload TEXT)");
    const trace = "tr_diagnostics";
    const putLineage = db.prepare("INSERT INTO lineage_records(trace_id,stage,recorded_at,payload) VALUES(?,?,?,?)");
    putLineage.run(trace,"ingest.fetch","2026-10-01T01:00:01Z",lineage(trace,"cisa_kev","success",[{kind:"RawDoc"}]));
    putLineage.run(trace,"ingest.fetch","2026-10-01T01:00:01Z",lineage(trace,"osv","success",[],{reason:"not_requested: no upstream CVE IDs available",outcome:"no_new_data"}));
    putLineage.run(trace,"ingest.fetch","2026-10-01T01:00:02Z",lineage(trace,"ubuntu_usn","degraded",[{kind:"RawDoc"}],{fallback_to:"fixture",reason:"network failed"}));
    const putEvent = db.prepare("INSERT INTO events(trace_id,topic,payload) VALUES(?,?,?)");
    putEvent.run(trace,"raw.docs",JSON.stringify({source_id:"cisa_kev",payload_ref:"tmp/cache/kev.json"}));
    putEvent.run(trace,"raw.docs",JSON.stringify({source_id:"ubuntu_usn",payload_ref:"fixtures/sources/usn.sample.json"}));
    putEvent.run(trace,"intel.items",JSON.stringify({intel_id:"intel_test",source_ids:["cisa_kev"]}));
    putEvent.run(trace,"dq.verdicts",JSON.stringify({verdict:"pass"}));
    putEvent.run(trace,"fallback.events",JSON.stringify({trigger:"arxiv_http_429",user_visible:true}));
    const result = summarizeIngestDiagnostics(db,"test.sqlite",false);
    assert.equal(result.database_available,true);
    assert.equal(result.latest_run?.mode,"mixed");
    assert.equal(result.latest_run?.sources.find((s)=>s.source_id==="cisa_kev")?.state,"live");
    assert.equal(result.latest_run?.sources.find((s)=>s.source_id==="osv")?.state,"no_new_data");
    assert.equal(result.latest_run?.sources.find((s)=>s.source_id==="ubuntu_usn")?.state,"fixture");
    assert.equal(result.latest_run?.counts.unique_intel_ids,1);
    assert.equal(result.latest_run?.counts.enrich_coverage,0);
    assert.equal(result.latest_run?.fallbacks[0]?.trigger,"arxiv_http_429");
    assert.ok(result.latest_run?.warnings.some((warning)=>warning.includes("not_requested")));
  } finally { db.close(); }
});

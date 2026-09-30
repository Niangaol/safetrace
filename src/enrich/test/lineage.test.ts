import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore, sha256Json } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { runEnrichment } from "../src/index.js";

const item: IntelItem = {
  intel_id: "intel_lineage_test",
  cve_ids: ["CVE-2021-44228"],
  source_ids: ["nvd_cve"],
  title: "Apache Log4j2 remote code execution vulnerability",
  published_at: "2021-12-10T00:00:00Z",
  first_seen_at: "2026-09-29T00:00:00Z",
  entities: { product: "Apache Log4j2", vendor: "Apache", version_range: [], cwe: [], cpes: [] },
  raw_refs: [],
  source_reliability: 0.9,
  schema_version: "1.0",
};

test("enrichment lineage：F1/F4/F6 links IntelItem, model/fallback metadata and hashes", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const traceId = "tr_enrichment_lineage";
  const parent = await bus.recordLineage({
    trace_id: traceId,
    stage: "ingest.dq1",
    operation_version: "dq1.v1",
    status: "success",
    output_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }],
  });
  const result = await runEnrichment([item], {
    offline: true,
    bus,
    traceId,
    scoreSources: [],
    lineage_parent_by_intel_id: { [item.intel_id]: parent.lineage_id },
    causation_by_intel_id: { [item.intel_id]: "ev_intel_items_test" },
  });
  assert.equal(result.length, 1);
  const records = await bus.readLineage(traceId);
  const f1 = records.find((record) => record.stage === "enrich.f1");
  const f4 = records.find((record) => record.stage === "enrich.f4");
  const f6 = records.find((record) => record.stage === "enrich.f6");
  assert.ok(f1 && f4 && f6);
  assert.deepEqual(f1.parent_lineage_ids, [parent.lineage_id]);
  assert.ok(f4.parent_lineage_ids.includes(f1.lineage_id));
  assert.ok(f6.parent_lineage_ids.includes(f1.lineage_id));
  assert.ok(f6.parent_lineage_ids.includes(f4.lineage_id));
  assert.ok(f1.input_refs.some((ref) => ref.id === item.intel_id && ref.sha256 === sha256Json(item)));
  assert.ok(f6.output_refs.some((ref) => ref.kind === "EnrichmentResult" && /^[a-f0-9]{64}$/.test(ref.sha256 ?? "")));
  assert.ok(records.some((record) => record.stage === "enrich.fallback" && record.status === "degraded"));
  assert.ok(records.every((record) => record.trace_id === traceId));
});

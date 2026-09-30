import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import { ask } from "../src/cli.js";

test("ask lineage：Q1 → BM25 index/search → Q4 answer shares trace and parent links", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const traceId = "tr_cli_lineage";
  const answer = await ask("Log4Shell 影响哪些版本？", { bus, trace_id: traceId, session_id: "sess_lineage", turn_id: "turn_lineage" });
  assert.ok(answer.citations.length > 0);
  const records = await bus.readLineage(traceId);
  const q1 = records.find((record) => record.stage === "qa.q1_classify");
  const q2 = records.find((record) => record.stage === "q2.bm25_search");
  const q4 = records.find((record) => record.stage === "qa.q4_answer");
  assert.ok(q1 && q2 && q4);
  assert.ok(q2.parent_lineage_ids.includes(q1.lineage_id));
  assert.ok(q4.parent_lineage_ids.includes(q1.lineage_id));
  assert.ok(q4.parent_lineage_ids.includes(q2.lineage_id));
  assert.ok(records.some((record) => record.stage === "q2.bm25_index"));
  assert.ok(!JSON.stringify(records).includes("Log4Shell 影响哪些版本"), "store hashes and references, not the user query text");
});

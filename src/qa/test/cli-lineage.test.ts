import { test } from "node:test";
import assert from "node:assert/strict";
import { EventBus, MemoryEventStore } from "@safetrace/shared";
import { ask, buildRetrievalRequest } from "../src/cli.js";
import { classifyIntent } from "../src/q1-intent.js";
import type { QueryTurn } from "@safetrace/shared";

test("A-05：buildRetrievalRequest 把 time_range 槽位转成 published_after 硬过滤", () => {
  const now = new Date("2026-10-10T12:00:00.000Z");
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "最近一周的漏洞趋势" } as QueryTurn);
  assert.equal(plan.slots.time_range, "7d");
  const req = buildRetrievalRequest("最近一周的漏洞趋势", plan, "tr_t", now);
  assert.equal(req.published_after, "2026-10-03T12:00:00.000Z", "「最近一周」= 只召回 7 天内发布的证据");
  const cvePlan = classifyIntent({ session_id: "s", turn_id: "t", text: "CVE-2021-44228 怎么修复？" } as QueryTurn);
  const cveReq = buildRetrievalRequest("CVE-2021-44228 怎么修复？", cvePlan, "tr_t", now);
  assert.deepEqual(cveReq.cve_ids, ["CVE-2021-44228"], "CVE 槽位过滤保持原行为");
  assert.equal(cveReq.published_after, undefined, "无时间表述不得注入 published_after（兼容既有行为）");
});

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

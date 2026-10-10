/**
 * C-04 回归：Answer 新增可选 stale_warning / injection_guard，且必须如实填充。
 * 契约位见 contracts/events.md 内联 Answer；实现见 src/qa/src/q4-answer.ts。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { EventBus, MemoryEventStore, validateInstance } from "@safetrace/shared";
import type { Answer, EvidenceChunk, RetrievalResponse } from "@safetrace/shared";
import { classifyIntent } from "../src/q1-intent.js";
import { synthesizeAnswer } from "../src/q4-answer.js";

const ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");

const ANSWER_INLINE: Record<string, unknown> = {
  type: "object", additionalProperties: false,
  required: ["session_id", "turn_id", "text_md", "citations", "reasoning_chain", "confidence", "abstained"],
  properties: {
    session_id: { type: "string" },
    turn_id: { type: "string" },
    text_md: { type: "string" },
    citations: { type: "array" },
    reasoning_chain: { type: "array" },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    abstained: { type: "boolean" },
    degraded_to: { type: "string" },
    stale_warning: { type: "object", additionalProperties: false, required: ["threshold_days", "unknown_published_at", "note"], properties: {
      threshold_days: { type: "number" },
      oldest_published_at: { type: "string" },
      unknown_published_at: { type: "number" },
      note: { type: "string" },
    } },
    injection_guard: { type: "object", additionalProperties: false, required: ["screened", "untrusted_evidence", "note"], properties: {
      screened: { type: "boolean" },
      max_score: { type: "number", minimum: 0, maximum: 1 },
      flags: { type: "array" },
      untrusted_evidence: { type: "number" },
      note: { type: "string" },
    } },
  },
};

function chunk(id: string, over: Partial<EvidenceChunk> = {}): EvidenceChunk {
  return { chunk_id: id, doc_type: "vuln_advisory", text: "CVE-2021-44228 affects Log4j2.", score_sparse: 0.95, quality_score: 0.98, provenance: { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", section: "description" }, ...over };
}
function evidence(chunks: EvidenceChunk[]): RetrievalResponse {
  return { query_id: "q_stale", chunks, retrieval_ms: 5, embedder_model_id: "bm25-lite-v1", trace_id: "tr_stale", schema_version: "1.0" };
}
const NOW = new Date("2026-09-30T12:00:00.000Z");

test("契约位：旧形状合法，新字段结构与缺省语义符合内联契约", () => {
  const legacy: Record<string, unknown> = { session_id: "s", turn_id: "t", text_md: "x", citations: [], reasoning_chain: [], confidence: 0, abstained: true };
  assert.deepEqual(validateInstance(legacy, ANSWER_INLINE), [], "无新字段的旧 Answer 必须仍合法（纯追加）");
  const events = read("contracts/events.md");
  assert.match(events, /stale_warning/, "内联契约须登记 stale_warning");
  assert.match(events, /injection_guard/, "内联契约须登记 injection_guard");
  const mirror = read("src/shared/src/types.ts");
  assert.match(mirror, /export interface StaleWarning/, "TS 镜像须同步 StaleWarning");
  assert.match(mirror, /export interface InjectionGuard/, "TS 镜像须同步 InjectionGuard");
});

test("过龄证据必须显式带 stale_warning，并把说明写进正文", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const old = chunk("c_old", { published_at: "2021-12-10T10:15:08.540Z", trust: "trusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([old]), { session_id: "s", turn_id: "t", now: NOW });
  assert.ok(ans.stale_warning, "过龄证据必须提示");
  assert.equal(ans.stale_warning!.threshold_days, 365);
  assert.equal(ans.stale_warning!.oldest_published_at, "2021-12-10T10:15:08.540Z");
  assert.equal(ans.stale_warning!.unknown_published_at, 0);
  assert.ok(ans.text_md.includes("证据时效提示"), "用户可见正文须含时效提示");
  assert.deepEqual(validateInstance(ans, ANSWER_INLINE), [], "答案须通过内联契约校验");
});

test("缺 published_at 按未知时效提示，不用当前时间顶替", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const unknown = chunk("c_unknown", { trust: "trusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([unknown]), { session_id: "s", turn_id: "t", now: NOW });
  assert.equal(ans.stale_warning?.unknown_published_at, 1);
  assert.equal(ans.stale_warning?.oldest_published_at, undefined, "无来源时间时不得编造");
  assert.ok(ans.text_md.includes("时效未知"));
});

test("A-05：trend 意图按时效阈值 7 天判定过龄（阈值随意图收紧）", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "最近一个月安全社区的热点漏洞趋势是怎样的？" });
  assert.deepEqual(plan.intents[0], "trend");
  const old = chunk("c_trend_old", { published_at: "2026-09-01T00:00:00.000Z", trust: "trusted" });
  const ans = await synthesizeAnswer("最近一个月安全社区的热点漏洞趋势是怎样的？", plan, evidence([old]), {
    session_id: "s", turn_id: "t", now: NOW, stale_after_days: 7,
  });
  assert.ok(ans.stale_warning, "trend 阈值 7 天下，39 天前的证据必须过龄提示");
  assert.equal(ans.stale_warning!.threshold_days, 7, "阈值按意图收紧为 7 天");
  assert.ok(ans.text_md.includes("阈值 7 天"), "正文提示须写明收紧后的阈值");
});

test("证据新鲜且时间齐全时不加 stale_warning", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const fresh = chunk("c_fresh", { published_at: "2026-09-01T00:00:00.000Z", trust: "trusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([fresh]), { session_id: "s", turn_id: "t", now: NOW });
  assert.equal(ans.stale_warning, undefined, "新鲜证据不应误报");
  assert.ok(ans.injection_guard, "注入筛查状态必须始终显式出现");
});

test("A-04 启发式筛查如实标注状态并保留不可信证据计数", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const web = chunk("c_web", { published_at: "2026-09-01T00:00:00.000Z", trust: "untrusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([web]), { session_id: "s", turn_id: "t", now: NOW });
  assert.ok(ans.injection_guard, "注入筛查状态必须始终显式出现");
  assert.equal(ans.injection_guard.screened, true, "本地 A-04 heuristic 已实际运行");
  assert.equal(ans.injection_guard.untrusted_evidence, 1);
  assert.ok(ans.injection_guard.note.includes("Heuristic screening is not a guarantee"));
  const screened = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([web]), { session_id: "s", turn_id: "t", now: NOW, injectionGuard: { screened: true, max_score: 0.9, flags: ["instruction_override"], note: "已筛查" } });
  assert.ok(screened.injection_guard);
  assert.equal(screened.injection_guard.screened, true);
  assert.equal(screened.injection_guard.untrusted_evidence, 1, "不可信计数仍按证据如实统计");
});

test("lineage 记录时效决策且不复制证据正文", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const old = chunk("c_lineage", { published_at: "2021-12-10T10:15:08.540Z", trust: "trusted" });
  const ans: Answer = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([old]), { session_id: "s", turn_id: "t", now: NOW, bus });
  const rows = await bus.readLineage("tr_stale");
  const q4 = rows.find(r => r.stage === "qa.q4_answer")!;
  assert.match(q4.decision?.reason ?? "", /stale/, "lineage 须记录时效处置");
  assert.ok(!JSON.stringify(rows).includes("CVE-2021-44228 affects"), "lineage 不复制证据正文");
  assert.ok(ans.abstained === false);
});

/**
 * P-05 回归：多源分值冲突必须显式进答案（含拒答路径），不压成单一结论。
 * 契约位见 contracts/events.md 内联 Answer（v1.2.2）；实现见 src/qa/src/q4-answer.ts。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { EvidenceChunk, RetrievalResponse, SourceConflict } from "@safetrace/shared";
import { classifyIntent } from "../src/q1-intent.js";
import { normalizeSourceConflicts, synthesizeAnswer } from "../src/q4-answer.js";

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
    source_conflicts: { type: "array", items: { type: "object", additionalProperties: false, required: ["field", "values", "resolved"], properties: {
      field: { type: "string", enum: ["cvss_v3_base"] },
      values: { type: "array", items: { type: "object", additionalProperties: false, required: ["source", "score"], properties: {
        source: { type: "string", enum: ["nvd", "cna", "ghsa", "adp", "system_derived"] },
        score: { type: "number", minimum: 0, maximum: 10 },
      } } },
      resolved: { type: "boolean" },
      rationale: { type: "string" },
    } } },
  },
};

function chunk(id: string, over: Partial<EvidenceChunk> = {}): EvidenceChunk {
  return { chunk_id: id, doc_type: "vuln_advisory", text: "CVE-2021-44228 affects Log4j2.", score_sparse: 0.95, quality_score: 0.98, provenance: { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", section: "description" }, ...over };
}
function evidence(chunks: EvidenceChunk[]): RetrievalResponse {
  return { query_id: "q_p05", chunks, retrieval_ms: 5, embedder_model_id: "bm25-lite-v1", trace_id: "tr_p05", schema_version: "1.0" };
}
const NOW = new Date("2026-10-10T12:00:00.000Z");

const RESOLVED: SourceConflict = {
  field: "cvss_v3_base",
  values: [{ source: "nvd", score: 7.5 }, { source: "cna", score: 8.8 }],
  resolved: true,
  rationale: "采用 nvd 的 7.5 分：权威序 nvd > cna 中 nvd 优先级最高；差异源仅作旁证，不改写分值",
};
const UNRESOLVED: SourceConflict = {
  field: "cvss_v3_base",
  values: [{ source: "nvd", score: 9.0 }, { source: "adp", score: 6.1 }],
  resolved: false,
  rationale: "未产出最终评分（无可用评分来源），多源分差未仲裁",
};

test("P-05：冲突显式进答案正文、reasoning_chain 与 Answer 对象（不压成单一结论）", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const fresh = chunk("c_p05", { published_at: "2026-10-01T00:00:00.000Z", trust: "trusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([fresh]), {
    session_id: "s", turn_id: "t", now: NOW, source_conflicts: [RESOLVED, UNRESOLVED],
  });
  assert.ok(!ans.abstained);
  assert.match(ans.text_md, /## 来源冲突/, "正文必须出现来源冲突段落");
  assert.ok(ans.text_md.includes("nvd 7.5 vs cna 8.8"), "分歧数值必须对用户可见");
  assert.ok(ans.text_md.includes("未仲裁"), "未仲裁状态必须显式标注");
  assert.ok(ans.text_md.includes(RESOLVED.rationale!), "仲裁理由必须可见");
  assert.deepEqual(ans.source_conflicts, [RESOLVED, UNRESOLVED], "Answer 对象必须携带冲突明细");
  assert.ok(ans.reasoning_chain.some((s) => s.includes("P-05 冲突保留") && s.includes("未仲裁 1 条")),
    "推理链必须记录冲突保留与未仲裁条数");
});

test("P-05：拒答路径同样保留冲突（证据不足不抹掉分歧信息）", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([]), {
    session_id: "s", turn_id: "t", now: NOW, source_conflicts: [UNRESOLVED],
  });
  assert.ok(ans.abstained, "无证据必须拒答");
  assert.match(ans.text_md, /## 来源冲突/, "拒答答案同样展示冲突段落");
  assert.deepEqual(ans.source_conflicts, [UNRESOLVED]);
});

test("P-05：未提供冲突时答案不带 source_conflicts（缺省不当无冲突）", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const fresh = chunk("c_p05_none", { published_at: "2026-10-01T00:00:00.000Z", trust: "trusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([fresh]), {
    session_id: "s", turn_id: "t", now: NOW,
  });
  assert.equal(ans.source_conflicts, undefined);
  assert.ok(!ans.text_md.includes("## 来源冲突"));
});

test("P-05：冲突归一化 fail-closed（同值/越界来源/缺 rationale/重复条目）", () => {
  assert.deepEqual(normalizeSourceConflicts(undefined), []);
  assert.deepEqual(normalizeSourceConflicts([]), []);
  // 重复条目去重（按内容哈希）
  assert.deepEqual(normalizeSourceConflicts([RESOLVED, { ...RESOLVED }]), [RESOLVED]);
  // 同值无分歧 → 抛错
  assert.throws(() => normalizeSourceConflicts([{ field: "cvss_v3_base", values: [{ source: "nvd", score: 7.5 }, { source: "cna", score: 7.5 }], resolved: false }]),
    /分歧/);
  // 来源越界 → 抛错
  assert.throws(() => normalizeSourceConflicts([{ field: "cvss_v3_base", values: [{ source: "vendor_blog" as "nvd", score: 7.5 }, { source: "cna", score: 8.8 }], resolved: false }]),
    /来源非法/);
  // 分值越界 → 抛错
  assert.throws(() => normalizeSourceConflicts([{ field: "cvss_v3_base", values: [{ source: "nvd", score: 11 }, { source: "cna", score: 8.8 }], resolved: false }]),
    /0-10/);
  // 已仲裁但缺 rationale → 抛错
  assert.throws(() => normalizeSourceConflicts([{ field: "cvss_v3_base", values: [{ source: "nvd", score: 7.5 }, { source: "cna", score: 8.8 }], resolved: true }]),
    /rationale/);
  // 字段越界 → 抛错
  assert.throws(() => normalizeSourceConflicts([{ field: "epss_score" as "cvss_v3_base", values: [{ source: "nvd", score: 0.1 }, { source: "cna", score: 0.4 }], resolved: false }]),
    /仅支持/);
});

test("P-05：契约位——旧形状合法，source_conflicts 结构与 events.md 一致", async () => {
  const plan = classifyIntent({ session_id: "s", turn_id: "t", text: "Log4Shell 影响哪些版本？" });
  const fresh = chunk("c_p05_contract", { published_at: "2026-10-01T00:00:00.000Z", trust: "trusted" });
  const ans = await synthesizeAnswer("Log4Shell 影响哪些版本？", plan, evidence([fresh]), {
    session_id: "s", turn_id: "t", now: NOW, source_conflicts: [RESOLVED, UNRESOLVED],
  });
  const { validateInstance } = await import("@safetrace/shared");
  assert.deepEqual(validateInstance(ans, ANSWER_INLINE), [], "带冲突的答案须通过内联契约校验");
  const legacy: Record<string, unknown> = { session_id: "s", turn_id: "t", text_md: "x", citations: [], reasoning_chain: [], confidence: 0, abstained: true };
  assert.deepEqual(validateInstance(legacy, ANSWER_INLINE), [], "无冲突字段的旧 Answer 必须仍合法（纯追加）");
});
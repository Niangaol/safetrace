/**
 * Q4 答案合成：四段式模板（结论—证据—推理链—置信度），引用与证据 chunk 一一对应。
 * 纪律：
 * - 证据为空 / 最高可用召回分 < 0.3 / 证据不覆盖问题中的 CVE / Q1 低置信度需澄清
 *   → abstained=true，文案显式说明证据不足，禁止编造；
 * - degraded_to 从 RetrievalResponse 原样透传，并在答案尾部给用户可见提示。
 */
import { degrade, nowIso, parseLoose, screenPromptInjection, sha256, sha256Json } from "@safetrace/shared";
import type { Answer, EventBus, InjectionFlag, InjectionGuard, RetrievalResponse, SourceConflict, StaleWarning } from "@safetrace/shared";
import { versionImpactStatusLabel } from "./version-impact.js";
import type { VersionImpactAnswer } from "./version-impact.js";
import { staleThresholdDays } from "./q1-intent.js";
import type { QueryPlan } from "./q1-intent.js";
import { coversProducts, evidenceCveIds } from "./evidence-identity.js";

/**
 * 注入接口：由上层编排连接 StepFun 等模型；原模板继续负责证据门禁并作为模型失败时的兜底。
 * 本包不 import gateway，以保持 Q4 可独立测试与离线运行。
 */
export interface AnswerSynthesizer {
  synthesize(question: string, plan: QueryPlan, evidence: RetrievalResponse): Promise<Answer> | Answer;
}

export interface SynthesizeOptions {
  synth?: AnswerSynthesizer;
  /** Optional lineage identity for an injected generator (e.g. StepFun or template fallback). */
  synthesizer?: { provider: string; model_id: string; model_version?: string };
  /** 编排层应显式传入；缺省时 session_id 为空串、turn_id 回落 evidence.trace_id */
  session_id?: string;
  turn_id?: string;
  /** Optional persistent processing-lineage sink. */
  bus?: EventBus;
  parent_lineage_ids?: string[];
  causation_id?: string | null;
  /** C-04：时效阈值（天）；编排层可按意图覆盖，A-05 落地后由意图驱动。 */
  stale_after_days?: number;
  /** 评估基准时间（测试注入用）；缺省当前时间。 */
  now?: Date;
  /** 上游筛查结果与本地 A-04 heuristic 合并；screened=false 会禁止外部 synthesizer 出云。 */
  injectionGuard?: Omit<InjectionGuard, "untrusted_evidence">;
  /**
   * P-05：多源分值冲突（富化 F6 产出）。提供即显式进答案（含拒答路径），
   * 禁止把冲突压成单一结论；缺省 = 本轮未提供冲突信息，不当当"无冲突"。
   */
  source_conflicts?: readonly SourceConflict[];
  /**
   * P-03：版本影响判定（确定性规则产出，问答侧入口）。提供即在答案中显式展示
   * 判定结果与依据（含拒答路径）；缺省 = 本轮未做版本判定。
   */
  version_impact?: VersionImpactAnswer;
}

/** 没有独立 reranker 时，以当前可用的 dense/sparse 召回分做保守拒答门槛。 */
export const ABSTAIN_RETRIEVAL_SCORE_FLOOR = 0.3;
/** @deprecated 兼容既有调用方；该值不再代表独立重排模型的分数。 */
export const ABSTAIN_RERANK_FLOOR = ABSTAIN_RETRIEVAL_SCORE_FLOOR;

function retrievalScore(chunk: RetrievalResponse["chunks"][number]): number {
  if (chunk.score_rerank !== undefined) return chunk.score_rerank;
  const componentScores = [chunk.score_dense, chunk.score_sparse].filter((score): score is number =>
    typeof score === "number" && Number.isFinite(score),
  );
  return componentScores.length > 0 ? Math.max(...componentScores) : 0;
}

interface Ctx {
  topScore: number;
  avgQuality: number;
  stale?: StaleWarning;
  injection: InjectionGuard;
  /** P-05：归一化后的多源冲突（可能为空数组 = 未提供）。 */
  conflicts: SourceConflict[];
  /** P-03：版本影响判定（未提供为 undefined）。 */
  versionImpact?: VersionImpactAnswer;
}

/** C-04 默认时效阈值（天）。A-05 将按意图细化；此处保证"过龄/未知"必须显式可见。 */
const DEFAULT_STALE_THRESHOLD_DAYS = 365;

interface BaseAnswer {
  session_id: string;
  turn_id: string;
  degraded_to?: string;
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x));
}

/** 取首句（超长截断）；结论段只摘录证据原文，不转写不发挥。 */
function firstSentence(text: string, maxLen = 160): string {
  const m = text.match(/^.*?[。！？.!?](\s|$)/s);
  let s = (m ? m[0] : text).trim();
  if (s.length === 0) s = text.trim().slice(0, maxLen);
  if (s.length > maxLen) s = s.slice(0, maxLen) + "…";
  return s;
}

/** 多 CVE 请求必须逐个覆盖；完整标识符匹配，不能用编号前缀或邻近漏洞代替。 */
function coversRequestedCve(plan: QueryPlan, evidence: RetrievalResponse): boolean {
  const covered = new Set(evidence.chunks.flatMap(c => (c.text.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map(id => id.toUpperCase())));
  return plan.slots.cve_ids.every(id => covered.has(id.toUpperCase()));
}

function intentLabel(plan: QueryPlan): string {
  const label = plan.intents.length > 0 ? plan.intents.join("+") : "未识别（意图不明确）";
  return plan.classifier_source === "stepplan" ? label + "（StepPlan 辅助 Q1）" : label + "（规则）";
}

/**
 * C-04：基于 C-02 的 published_at 做时效评估。
 * - 缺 published_at 的证据按"未知时效"计入，不用抓取时间顶替；
 * - 最早一条早于阈值 → 显式提示；全部未知也提示。
 */
function assessStaleness(evidence: RetrievalResponse, now: Date, thresholdDays: number): StaleWarning | undefined {
  const cited = evidence.chunks;
  if (cited.length === 0) return undefined;
  const times = cited.map(c => (c.published_at ? parseLoose(c.published_at) : null));
  const unknown = times.filter(t => t === null).length;
  const known = times.filter((t): t is number => t !== null);
  if (known.length === 0) {
    return { threshold_days: thresholdDays, unknown_published_at: unknown, note: "⚠️ 证据时效提示：引用证据均无上游发布时间（published_at 缺失），时效未知、无法确认新鲜度，请谨慎采用。" };
  }
  const oldest = Math.min(...known);
  const ageDays = Math.floor((now.getTime() - oldest) / 86400000);
  if (ageDays <= thresholdDays && unknown === 0) return undefined;
  const parts: string[] = [];
  if (ageDays > thresholdDays) parts.push("最早证据发布于 " + ageDays + " 天前（阈值 " + thresholdDays + " 天）");
  if (unknown > 0) parts.push(unknown + " 条证据缺上游发布时间，时效未知");
  return { threshold_days: thresholdDays, oldest_published_at: new Date(oldest).toISOString(), unknown_published_at: unknown, note: "⚠️ 证据时效提示：" + parts.join("；") + "。结论请结合最新通告核对。" };
}

const CONFLICT_SOURCES = new Set(["nvd", "cna", "ghsa", "adp", "system_derived"]);

/**
 * P-05：冲突入答案前的归一化校验（fail-closed）。
 * 形态非法、来源越界、分值非 0-10 有限数、同值无分歧 → 抛错；
 * 静默丢弃等于把"冲突被算出来又被丢掉"的 bug 留在答案侧。
 */
export function normalizeSourceConflicts(input: readonly SourceConflict[] | undefined): SourceConflict[] {
  if (input === undefined) return [];
  if (!Array.isArray(input)) throw new Error("source_conflicts 必须是数组");
  const rows: readonly SourceConflict[] = input;
  const out: SourceConflict[] = [];
  const seen = new Set<string>();
  for (const raw of rows) {
    if (!raw || typeof raw !== "object") throw new Error("冲突条目必须是对象");
    if (raw.field !== "cvss_v3_base") throw new Error("冲突字段仅支持 cvss_v3_base（收到 " + String(raw.field) + "）");
    if (!Array.isArray(raw.values) || raw.values.length < 2) throw new Error("冲突必须至少携带两个来源的分值");
    const values = raw.values.map((v) => {
      if (!v || typeof v !== "object") throw new Error("冲突分值必须是对象");
      if (!CONFLICT_SOURCES.has(v.source)) throw new Error("冲突分值来源非法：" + String(v.source));
      if (typeof v.score !== "number" || !Number.isFinite(v.score) || v.score < 0 || v.score > 10) {
        throw new Error("冲突分值必须是 0-10 的有限数（CVSS v3 基础分域）");
      }
      return { source: v.source, score: v.score };
    });
    if (new Set(values.map((v) => v.score)).size <= 1) throw new Error("冲突条目必须实际存在分歧（同值不构成冲突）");
    if (typeof raw.resolved !== "boolean") throw new Error("冲突 resolved 必须是布尔值");
    if (raw.rationale !== undefined && (typeof raw.rationale !== "string" || raw.rationale.trim() === "")) {
      throw new Error("冲突 rationale 必须是非空字符串");
    }
    if (raw.resolved && raw.rationale === undefined) throw new Error("已仲裁冲突必须写明 rationale（采用哪源、为何）");
    const key = sha256Json({ field: raw.field, values, resolved: raw.resolved, rationale: raw.rationale ?? null });
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ field: raw.field, values, resolved: raw.resolved, ...(raw.rationale !== undefined ? { rationale: raw.rationale } : {}) });
  }
  return out;
}

/** P-03：版本影响判定的用户可见段落（确定性规则；进正文）+ 推理链条目。 */
function renderVersionImpact(vi: VersionImpactAnswer | undefined): { section: string[]; chainEntry: string | null } {
  if (!vi) return { section: [], chainEntry: null };
  const label = versionImpactStatusLabel(vi.status);
  const lines: string[] = ["## 版本影响判定（确定性规则）"];
  lines.push(
    "产品 " + vi.product + " 版本 " + (vi.tested_version || "(未提供)") +
    (vi.cve_id ? "（" + vi.cve_id + "）" : "") + "：**" + label + "**" +
    (vi.intel_id ? "（依据情报 " + vi.intel_id + "，评估 " + vi.candidates + " 条）" : ""),
  );
  lines.push("- 判定规则：" + vi.rule);
  if (vi.matched_ranges.length > 0) lines.push("- 命中区间：" + vi.matched_ranges.join("；"));
  lines.push("- 依据说明：" + vi.reason);
  if (vi.vendor_unverified) lines.push("- 厂商身份未经本地核实；无法判定不等于安全。");
  const chainEntry =
    "P-03 版本影响判定（确定性规则，非相似度/模型生成）：" + vi.product + " " +
    (vi.tested_version || "(未提供)") + " → " + label + "（" + vi.reason + "）";
  return { section: lines, chainEntry };
}

/** P-05：冲突的用户可见段落（进正文）+ 推理链条目。空数组返回空段落。 */
function renderConflicts(conflicts: readonly SourceConflict[]): { section: string[]; chainEntry: string | null } {
  if (conflicts.length === 0) return { section: [], chainEntry: null };
  const lines: string[] = ["## 来源冲突"];
  lines.push(
    "检测到 " + conflicts.length + " 条多源分值冲突，按项目纪律显式保留、未压成单一结论：",
  );
  conflicts.forEach((c, i) => {
    const pairs = c.values.map((v) => v.source + " " + v.score).join(" vs ");
    const state = c.resolved ? "已仲裁" : "未仲裁";
    lines.push((i + 1) + ". `" + c.field + "`：" + pairs + "（" + state + (c.rationale ? "：" + c.rationale : "") + "）");
  });
  const unresolved = conflicts.filter((c) => !c.resolved).length;
  const chainEntry =
    "P-05 冲突保留：" + conflicts.length + " 条多源分值冲突进入答案（未仲裁 " + unresolved +
    " 条），分歧本身对用户可见，不用单一结论覆盖";
  return { section: lines, chainEntry };
}

function bindVersionImpact(plan: QueryPlan, impact: VersionImpactAnswer | undefined): VersionImpactAnswer | undefined {
  if (!impact || plan.slots.versions.length !== 1 || impact.tested_version !== plan.slots.versions[0] || plan.slots.cve_ids.length > 1) return undefined;
  if (plan.slots.cve_ids.length === 1 && (impact.cve_id?.toUpperCase() !== plan.slots.cve_ids[0]!.toUpperCase() || !impact.cve_ids.some(id => id.toUpperCase() === plan.slots.cve_ids[0]!.toUpperCase()))) return undefined;
  if (!coversProducts(plan.slots.products, [impact.product])) return undefined;
  return impact;
}


/** 文本证据里的显式评分分歧只做提示，不推断来源权威身份、不自行仲裁。 */
function observedScoreDisagreement(evidence: RetrievalResponse): string[] {
  const groups = new Map<string, Set<number>>();
  for (const chunk of evidence.chunks) {
    if (chunk.doc_type !== "enrichment") continue;
    const id = chunk.text.match(/^(CVE-\d{4}-\d{4,})\b/i)?.[1]?.toUpperCase();
    const score = chunk.text.match(/CVSS\s+v3(?:\.1)?(?:\s+base score:\s*|[^\n]{0,35}?(?:评分|基础分)\s*)(\d+(?:\.\d+)?)/i)?.[1];
    const value = Number(score);
    if (!id || score === undefined || !Number.isFinite(value) || value < 0 || value > 10) continue;
    const values = groups.get(id) ?? new Set<number>(); values.add(value); groups.set(id, values);
  }
  return [...groups].filter(([,values]) => values.size > 1).map(([id,values]) => id + " 的证据存在评分冲突（" + [...values].join(" / ") + "）；这是来源陈述分歧，未自行仲裁，需核对原文与评分版本。");
}
function hasRepairVersionEvidence(evidence: RetrievalResponse): boolean {
  return evidence.chunks.some(c => c.text.split(/[。！？\n]/).some(sentence =>
    /(?:fixed|fix|修复|补丁|升级|upgrade)/i.test(sentence) && /\d+\.\d+(?:\.\d+)?/.test(sentence)
    && !/(?:没有|未提供|未知|无可靠|未修复|未解决|未验证|尚未|不成立|并非|不是|不可确认|据说|声称|如果|除非|unavailable|not\s+(?:known|fixed|patched|resolved|verified)|no\s+(?:known|fix|patch)|never\s+fixed|unpatched)/i.test(sentence)));
}

/** C-04/A-04 部分筛查状态：screened 表示本地启发式扫描已运行，不保证能识别所有注入；未运行时必须显式为 false。 */
function assessInjectionGuard(question: string, evidence: RetrievalResponse, opts: SynthesizeOptions): InjectionGuard {
  const untrusted = evidence.chunks.filter((chunk) => chunk.trust === "untrusted").length;
  const scan = screenPromptInjection([question, ...evidence.chunks.map((chunk) => chunk.text)]);
  const supplied = opts.injectionGuard;
  const flags = [...new Set([...scan.flags, ...(supplied?.flags ?? [])])].sort();
  return {
    screened: scan.screened && (supplied?.screened ?? true),
    max_score: Math.max(scan.max_score, supplied?.max_score ?? 0),
    flags,
    untrusted_evidence: untrusted,
    note: [scan.note, supplied?.note].filter(Boolean).join(" "),
  };
}

function degradedNote(evidence: RetrievalResponse): string | null {
  if (!evidence.degraded_to) return null;
  return "> ⚠️ 本次检索经过降级通道（degraded_to=" + evidence.degraded_to + "），证据覆盖可能不完整，结论请谨慎采用。";
}

function buildAbstain(
  question: string,
  plan: QueryPlan,
  evidence: RetrievalResponse,
  reasons: string[],
  ctx: Ctx,
  base: BaseAnswer,
): Answer {
  void question;
  const lines: string[] = [];
  lines.push("## 结论");
  lines.push("**证据不足，本次不予作答（abstained）。** " + reasons.join("；") + "。按项目红线：证据不足时禁止编造答案。");
  lines.push("## 证据");
  if (evidence.chunks.length === 0) {
    lines.push("（无可用证据块）");
  } else if ((ctx.injection.flags?.length ?? 0) > 0) {
    lines.push("（本地注入筛查命中风险标记；为避免传播恶意指令，本次不展示可疑原文，请人工复核。）");
  } else {
    lines.push("以下证据未达作答标准，仅列出备查，不作为答案依据：");
    evidence.chunks.forEach((c, i) => {
      lines.push(
        "[" + (i + 1) + "] " + c.doc_type + "｜" + c.provenance.url +
        "｜召回分 " + retrievalScore(c).toFixed(2) +
        (c.quality_score !== undefined ? "｜质量分 " + c.quality_score.toFixed(2) : ""),
      );
      lines.push("> " + firstSentence(c.text, 80));
    });
  }
  const chain: string[] = [
    "Q1 意图判定：" + intentLabel(plan) + "，检索策略 " + plan.strategy,
    "Q2 检索返回 " + evidence.chunks.length + " 条证据（索引模型 " + evidence.embedder_model_id + "），最高召回分 " + ctx.topScore.toFixed(2),
    "触发拒答条件：" + reasons.join("；"),
    plan.needs_clarify && plan.clarify_question
      ? "处置：先向用户澄清——" + plan.clarify_question
      : "处置：请补充检索条件（如指定 CVE、放宽 min_quality、扩大时间范围）后重试",
  ];
  const observations = ctx.conflicts.length === 0 ? observedScoreDisagreement(evidence) : [];
  if (observations.length) { lines.push("## 来源冲突", ...observations); chain.push(...observations); }
  const conflictView = renderConflicts(ctx.conflicts);
  for (const line of conflictView.section) lines.push(line);
  if (conflictView.chainEntry) chain.push(conflictView.chainEntry);
  const impactView = renderVersionImpact(ctx.versionImpact);
  for (const line of impactView.section) lines.push(line);
  if (impactView.chainEntry) chain.push(impactView.chainEntry);
  lines.push("## 推理链");
  chain.forEach((s, i) => lines.push((i + 1) + ". " + s));
  lines.push("## 置信度");
  lines.push("0.00 —— 拒答：无可靠证据支撑，不以低置信度硬答。");
  const note = degradedNote(evidence);
  if (note) lines.push(note);
  const staleNote = ctx.stale?.note;
  if (staleNote) lines.push(staleNote);
  if (!ctx.injection.screened) lines.push("⚠️ 本轮未完成提示注入筛查；当前为本地模板路径，不把证据发送到模型。");
  if (evidence.chunks.some((chunk) => chunk.trust !== "trusted")) lines.push("⚠️ 检索证据包含 unknown/untrusted trust；不会交给云端模型。");
  return {
    ...base,
    text_md: lines.join("\n\n"),
    citations: [],
    reasoning_chain: chain,
    confidence: 0,
    abstained: true,
    ...(ctx.stale ? { stale_warning: ctx.stale } : {}),
    ...(ctx.conflicts.length > 0 ? { source_conflicts: ctx.conflicts } : {}),
    injection_guard: ctx.injection,
  };
}

function buildAnswer(
  question: string,
  plan: QueryPlan,
  evidence: RetrievalResponse,
  ctx: Ctx,
  base: BaseAnswer,
): Answer {
  const n = evidence.chunks.length;
  const top = evidence.chunks[0]!;
  const confidence = round2(clamp01(0.6 * ctx.topScore + 0.05 * Math.min(n - 1, 3) + 0.2 * ctx.avgQuality));
  const citations = evidence.chunks.map((c) => ({ chunk_id: c.chunk_id, url: c.provenance.url }));

  const lines: string[] = [];
  lines.push("## 结论");
  lines.push(
    "针对「" + question + "」，检索到 " + n + " 条可回溯证据（最高召回分 " + ctx.topScore.toFixed(2) + "）。" +
    "主要证据 [1]（" + top.doc_type + "）原文摘录：",
  );
  lines.push("> " + firstSentence(top.text));
  lines.push("## 证据");
  evidence.chunks.forEach((c, i) => {
    lines.push(
      "[" + (i + 1) + "] " + c.doc_type + "｜[原文链接](" + c.provenance.url + ")｜召回分 " +
      retrievalScore(c).toFixed(2) +
      (c.quality_score !== undefined ? "｜质量分 " + c.quality_score.toFixed(2) : ""),
    );
    lines.push("> " + c.text);
  });
  const chain: string[] = [
    "Q1 意图判定：" + intentLabel(plan) + "，检索策略 " + plan.strategy,
    "Q2 检索返回 " + n + " 条证据，最高召回分 " + ctx.topScore.toFixed(2) + "，索引模型 " + evidence.embedder_model_id,
    "逐条核对 provenance：" + n + " 条证据均可回溯到原文 URL，正文角标 [1]-[" + n + "] 与 citations 一一对应",
    "置信度 = 0.6×最高召回分 + 0.05×附加证据数(≤3) + 0.2×平均质量分 = " + confidence.toFixed(2),
  ];
  const observations = ctx.conflicts.length === 0 ? observedScoreDisagreement(evidence) : [];
  if (observations.length) { lines.push("## 来源冲突", ...observations); chain.push(...observations); }
  const conflictView = renderConflicts(ctx.conflicts);
  for (const line of conflictView.section) lines.push(line);
  if (conflictView.chainEntry) chain.push(conflictView.chainEntry);
  const impactView = renderVersionImpact(ctx.versionImpact);
  for (const line of impactView.section) lines.push(line);
  if (impactView.chainEntry) chain.push(impactView.chainEntry);
  lines.push("## 推理链");
  chain.forEach((s, i) => lines.push((i + 1) + ". " + s));
  lines.push("## 置信度");
  lines.push(
    confidence.toFixed(2) + "（启发式分值，非校准概率或准确率；依据：最高召回分 " + ctx.topScore.toFixed(2) +
    "、证据 " + n + " 条、平均质量分 " + ctx.avgQuality.toFixed(2) + "）",
  );
  const note = degradedNote(evidence);
  if (note) lines.push(note);
  const staleNote = ctx.stale?.note;
  if (staleNote) lines.push(staleNote);
  if (!ctx.injection.screened) lines.push("⚠️ 本轮未完成提示注入筛查；当前为本地模板路径，不把证据发送到模型。");
  if (evidence.chunks.some((chunk) => chunk.trust !== "trusted")) lines.push("⚠️ 检索证据包含 unknown/untrusted trust；不会交给云端模型。");
  return {
    ...base,
    text_md: lines.join("\n\n"),
    citations,
    reasoning_chain: chain,
    confidence,
    abstained: false,
    ...(ctx.stale ? { stale_warning: ctx.stale } : {}),
    ...(ctx.conflicts.length > 0 ? { source_conflicts: ctx.conflicts } : {}),
    injection_guard: ctx.injection,
  };
}

function addQ4Notice(answer: Answer, note: string, degradedTo?: string): Answer {
  const header = "## 结论\n";
  const text = answer.text_md.startsWith(header) ? answer.text_md.replace(header, header + note + "\n\n") : note + "\n\n" + answer.text_md;
  return { ...answer, text_md: text, ...(degradedTo ? { degraded_to: degradedTo } : {}) };
}

/**
 * 合成答案。证据不满足作答标准时显式拒答（abstained=true），不产出任何编造内容。
 */
export async function synthesizeAnswer(
  question: string,
  plan: QueryPlan,
  evidence: RetrievalResponse,
  opts: SynthesizeOptions = {},
): Promise<Answer> {
  const startedAt = nowIso();
  const inputRefs = [
    { kind: "Query", id: evidence.query_id, sha256: sha256(question) },
    { kind: "QueryPlan", id: evidence.query_id, sha256: sha256Json(plan) },
    { kind: "RetrievalResponse", id: evidence.query_id, sha256: sha256Json(evidence) },
    ...evidence.chunks.map((chunk) => ({ kind: "EvidenceChunk", id: chunk.chunk_id, sha256: sha256Json(chunk), url: chunk.provenance.url })),
  ];
  let answer: Answer;
  let usedSynth = false;
  let blockedSynth = false;
  let effectiveSynthesizer = opts.synthesizer;
  let fallbackEventId: string | null = null;
  try {
    const base: BaseAnswer = {
      session_id: opts.session_id ?? "",
      turn_id: opts.turn_id ?? evidence.trace_id,
      ...(evidence.degraded_to ? { degraded_to: evidence.degraded_to } : {}),
    };
    const topScore = evidence.chunks.reduce((m, c) => Math.max(m, retrievalScore(c)), 0);
    const qs = evidence.chunks.map((c) => c.quality_score).filter((q): q is number => typeof q === "number");
    const ctx: Ctx = {
      topScore,
      avgQuality: qs.length > 0 ? qs.reduce((sum, q) => sum + q, 0) / qs.length : 0,
      stale: assessStaleness(evidence, opts.now ?? new Date(), opts.stale_after_days ?? staleThresholdDays(plan)),
      injection: assessInjectionGuard(question, evidence, opts),
      conflicts: normalizeSourceConflicts(opts.source_conflicts),
      versionImpact: bindVersionImpact(plan, opts.version_impact),
    };
    const reasons: string[] = [];
    if (evidence.chunks.length === 0) reasons.push("检索没有返回任何证据块");
    if (evidence.chunks.length > 0 && topScore < ABSTAIN_RETRIEVAL_SCORE_FLOOR) {
      reasons.push("最高召回分 " + topScore.toFixed(2) + " 低于阈值 " + ABSTAIN_RETRIEVAL_SCORE_FLOOR.toFixed(2));
    }
    if (plan.needs_clarify) reasons.push("问题意图不明确（Q1 低置信度，需澄清）");
    if (plan.slots.cve_ids.length === 0 && !coversProducts(plan.slots.products, evidence.chunks.map(c => c.text))) reasons.push("证据未覆盖问题指定的产品，不能用 BM25 相对榜首分冒充相关性");
    if (!coversRequestedCve(plan, evidence)) reasons.push("证据未覆盖问题指定的全部 CVE：" + plan.slots.cve_ids.join("、"));
    if (plan.intents.includes("impact_range") && plan.slots.versions.length > 0 && plan.slots.cve_ids.length > 1) reasons.push("多个 CVE 的具体版本影响须逐漏洞绑定规则，不能用一个汇总判定替代所有漏洞");
    if (plan.intents.includes("impact_range") && plan.slots.versions.length > 0 && (!ctx.versionImpact || ctx.versionImpact.status === "unknown")) {
      reasons.push("缺少可判定的版本规则，无法确认指定版本是否受影响（unknown 不等于安全）");
    }
    if (/(?:修复版本|安全版本|fixed\s+version|(?:具体)?升级(?:到)?(?:哪个|什么)(?:版本)?)/i.test(question) && !hasRepairVersionEvidence(evidence)) {
      reasons.push("没有来源明确说明修复版本，不能把受影响版本或 CVSS 数值当成修复版本");
    }
    if ((ctx.injection.flags?.length ?? 0) > 0) reasons.push("注入筛查命中风险标记；本次拒答并不展示可疑原文");
    const externalSynth = Boolean(opts.synth) && opts.synthesizer?.provider !== "template";
    const trustConfirmed = evidence.chunks.every((chunk) => chunk.trust === "trusted");
    const screenPassed = ctx.injection.screened && ctx.injection.untrusted_evidence === 0 && (ctx.injection.flags?.length ?? 0) === 0 && trustConfirmed;
    if (externalSynth && !screenPassed) {
      blockedSynth = true;
      effectiveSynthesizer = { provider: "template", model_id: "q4-template-v1" };
      const why = !ctx.injection.screened ? "A-04 screen missing/failed" : (ctx.injection.flags?.length ?? 0) > 0 ? "A-04 risk signals found" : "evidence trust is unknown/untrusted";
      await degrade({
        layer: "L3", trigger: "Q4 external synthesizer blocked by A-04/trust gate: " + why, degradedOf: "template", traceId: evidence.trace_id,
        label: "Q4 出云安全门未通过；已阻止模型并保留本地路径", recoveryHint: "检查本地提示注入筛查和每条 EvidenceChunk trust；unknown/untrusted 来源需要人工复核。",
        emit: async (event) => {
          if (!opts.bus) return;
          const envelope = await opts.bus.publish("fallback.events", event, { trace_id: evidence.trace_id });
          fallbackEventId = envelope.event_id;
        },
      });
    }
    if (reasons.length > 0) {
      if (externalSynth) effectiveSynthesizer = { provider: "template", model_id: "q4-template-v1" };
      answer = buildAbstain(question, plan, evidence, reasons, ctx, base);
    } else if (opts.synth && !blockedSynth) {
      usedSynth = true;
      const generated = await opts.synth.synthesize(question, plan, evidence);
      answer = { ...generated, injection_guard: ctx.injection, ...(ctx.conflicts.length > 0 ? { source_conflicts: ctx.conflicts } : {}) };
    } else {
      answer = buildAnswer(question, plan, evidence, ctx, base);
    }
    if (blockedSynth) answer = addQ4Notice(answer, "⚠️ A-04/来源信任门未通过；证据没有发送到云端，当前使用本地规则路径。", "template");
  } catch (error) {
    await opts.bus?.recordLineage({
      trace_id: evidence.trace_id,
      parent_lineage_ids: opts.parent_lineage_ids ?? [],
      causation_id: opts.causation_id ?? null,
      stage: "qa.q4_answer",
      operation_version: opts.synth ? "answer-synthesizer." + (opts.synthesizer?.provider ?? "injected") + ".v1" : "q4-template.v1",
      status: "failed",
      started_at: startedAt,
      input_refs: inputRefs,
      execution: opts.synthesizer ? { component_version: "answer-synthesizer", provider: opts.synthesizer.provider, model_id: opts.synthesizer.model_id, ...(opts.synthesizer.model_version ? { model_version: opts.synthesizer.model_version } : {}) } : { component_version: opts.synth ? "injected" : "q4-template.v1" },
      error: "answer synthesis failed; source text omitted",
    });
    throw error;
  }
  await opts.bus?.recordLineage({
    trace_id: evidence.trace_id,
    parent_lineage_ids: opts.parent_lineage_ids ?? [],
    causation_id: fallbackEventId ?? opts.causation_id ?? null,
    stage: "qa.q4_answer",
    operation_version: usedSynth ? "answer-synthesizer." + (effectiveSynthesizer?.provider ?? "injected") + ".v1" : "q4-template.v1",
    status: blockedSynth || effectiveSynthesizer?.provider === "template" || answer.degraded_to ? "degraded" : "success",
    started_at: startedAt,
    input_refs: inputRefs,
    output_refs: [
      { kind: "Answer", id: answer.turn_id, sha256: sha256Json(answer) },
      ...answer.citations.map((citation) => ({ kind: "Citation", id: citation.chunk_id, url: citation.url })),
    ],
    execution: usedSynth && effectiveSynthesizer
      ? { component_version: "answer-synthesizer", provider: effectiveSynthesizer.provider, model_id: effectiveSynthesizer.model_id, ...(effectiveSynthesizer.model_version ? { model_version: effectiveSynthesizer.model_version } : {}) }
      : { component_version: "q4-template.v1", ...(effectiveSynthesizer?.provider === "template" ? { provider: "template", model_id: effectiveSynthesizer.model_id } : {}) },
    decision: {
      ...(blockedSynth || effectiveSynthesizer?.provider === "template" || answer.degraded_to ? { fallback_to: "template" } : {}),
      reason: blockedSynth
        ? "A-04/trust gate blocked external synthesis; local Q4 path retained"
        : effectiveSynthesizer?.provider === "template"
          ? "Template fallback used"
          : answer.abstained
            ? (answer.stale_warning ? "abstained: evidence gate; stale" : "abstained: evidence gate")
            : (answer.stale_warning ? "answered; stale" : "answered"),
    },
  });
  return answer;
}

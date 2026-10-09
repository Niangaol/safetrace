/**
 * DQ1 · 数据质量闸门（gate_version 1.1.0，对齐 02-report 3.8）：
 * 硬红线命中即 quarantine（与分数无关）：CVE 状态 REJECT/RESERVED/DISPUTED、
 * 时间戳早于 1999 或晚于 now+5min（含不可解析）、关键 5 字段全部为空、POC 链接存在但无 sha256。
 * 分档：>=0.90 pass；0.70-0.90 degrade；0.50-0.70 review；<0.50 quarantine。
 * 五维权重随 gate_version 版本化，同版本同输入必须同输出（可复算）。
 *
 * gate 1.1.0（A-04 注入防护落地，纯追加、不改五维权重与红线口径）：
 * - 对 title+summary 跑共享本地启发式 screenPromptInjection（确定性、离线、有界），
 *   结果写入契约 C-03 的 injection_score / injection_flags（缺省 = 未筛查，禁止当作已筛查干净）；
 * - 命中注入迹象 → verdict 至少为 review（路由人工复核，pipeline 不放行进 intel.items），
 *   不直接 quarantine：启发式有误判空间，宁可转人工也不可错放，也不可错杀；
 * - 筛查无法运行（输入为空/超限/形状非法）→ 不填注入字段（如实标注未筛查）且 verdict 至少 review（fail-closed）。
 */
import { parseLoose, screenPromptInjection } from "@safetrace/shared";
import type { DqFlag, DqVerdict, IntelItem, QualityVerdict } from "@safetrace/shared";
import { hasTzSuffix, isRedlineCveStatus, str } from "./common.js";

export const GATE_VERSION = "1.1.0";

/** 五维权重（structure/completeness/consistency/timeliness/sourcing）。 */
const WEIGHTS = { structure: 0.15, completeness: 0.2, consistency: 0.3, timeliness: 0.15, sourcing: 0.2 } as const;

/** 营销话术高频重复阈值（命中次数）。 */
const BOILERPLATE_THRESHOLD = 3;
const BOILERPLATE_PHRASES = [
  "业界领先", "遥遥领先", "全球首发", "世界领先", "颠覆性创新", "重新定义", "极致体验",
  "industry-leading", "best-in-class", "revolutionary", "cutting-edge",
];

/** 时间戳可解析区间（1999 ~ now+5min）。 */
const TS_MIN_MS = Date.parse("1999-01-01T00:00:00Z");
const TS_SKEW_MS = 5 * 60 * 1000;

/**
 * IntelItem 的 DQ1 扩展字段（契约外、下划线前缀，与 fixtures/dirty/ 同口径）。
 * shared 的 IntelItem 类型不含这些字段，运行时从 JSON 原样读入。
 */
export interface IntelItemDqExtras {
  _cve_status?: string;
  poc_link?: string;
  poc_sha256?: string;
  /** 内部逐源安全证据，运行时必须验证，未知形状不得静默丢弃。 */
  _dq_sources?: unknown;
}
export type DqInputItem = IntelItem & IntelItemDqExtras;

/**
 * P0 扩展 flag：契约 DqFlag 六枚举（events.md v1）暂无 unknown_version，
 * ingest 先按字面量登记以免信息丢失；契约追加需走 contract PR（见集成备注）。
 */
export type Dq1Flag = DqFlag | "unknown_version";
export const UNKNOWN_VERSION_FLAG: Dq1Flag = "unknown_version";

export interface AssessOpts {
  /** 判定基准时间（测试注入用），缺省当前时间。 */
  now?: Date;
  /** review 档的人工复核人（未指定则留空待派单）。 */
  reviewer?: string;
}

function lacksTz(value: unknown): boolean {
  return typeof value === "string" && value.trim() !== "" && !hasTzSuffix(value);
}

function entitiesFilled(entities: unknown): boolean {
  if (typeof entities !== "object" || entities === null) return false;
  const e = entities as Record<string, unknown>;
  return (
    str(e.product) !== "" || str(e.vendor) !== "" ||
    (Array.isArray(e.version_range) && e.version_range.length > 0) ||
    (Array.isArray(e.cwe) && e.cwe.length > 0) ||
    (Array.isArray(e.cpes) && e.cpes.length > 0)
  );
}

/** structure：契约形状是否完好（entities 五件套结构与 title 存在）。 */
function assessStructure(item: IntelItem): number {
  let score = 1;
  const entities = item.entities as unknown;
  const entitiesOk =
    typeof entities === "object" && entities !== null && !Array.isArray(entities) &&
    ["product", "vendor", "version_range", "cwe", "cpes"].every((k) => k in (entities as Record<string, unknown>));
  if (!entitiesOk) score -= 0.5;
  if (typeof item.title !== "string" || item.title.trim() === "") score -= 0.5;
  return Math.max(0, score);
}

/** completeness：关键 5 字段（title/summary/entities/raw_refs/published_at）填充率。 */
function assessCompleteness(item: IntelItem): number {
  const filled = [
    typeof item.title === "string" && item.title.trim() !== "",
    typeof item.summary === "string" && item.summary.trim() !== "",
    entitiesFilled(item.entities),
    Array.isArray(item.raw_refs) && item.raw_refs.length > 0,
    typeof item.published_at === "string" && item.published_at.trim() !== "",
  ].filter(Boolean).length;
  return filled / 5;
}

/** timeliness：时间戳可解析且落在合法区间得 1；无时区 0.3；越界/不可解析 0。 */
function assessTimeliness(pubMs: number | null, seenMs: number | null, noTz: boolean, badRange: boolean): number {
  if (pubMs === null || seenMs === null || badRange) return 0;
  if (noTz) return 0.3;
  return 1;
}

/** 营销话术命中次数（title+summary）。 */
function countBoilerplate(text: string): number {
  const lower = text.toLowerCase();
  let hits = 0;
  for (const phrase of BOILERPLATE_PHRASES) {
    const p = phrase.toLowerCase();
    let idx = lower.indexOf(p);
    while (idx !== -1) {
      hits += 1;
      idx = lower.indexOf(p, idx + p.length);
    }
  }
  return hits;
}

/** CVE 编号年份（CVE-2021-44228 → 2021）。 */
function cveYear(id: string): string | null {
  const m = /^CVE-(\d{4})-\d{4,}$/i.exec(id);
  return m ? m[1] ?? null : null;
}

/** GHSA ID 首段为 4 位数字时可当年份用（真实 GHSA 为随机串，不会误判）。 */
function ghsaYear(id: string): string | null {
  const m = /^GHSA-(\d{4})-/i.exec(id);
  return m ? m[1] ?? null : null;
}

/** 多套编号口径不一：aliases 中 CVE 年份与 cve_ids 不一致，或 GHSA 年份与 cve_ids 冲突。 */
function detectMultiIdMismatch(item: IntelItem): boolean {
  const cveIds = Array.isArray(item.cve_ids) ? item.cve_ids : [];
  const years = new Set(cveIds.map(cveYear).filter((y): y is string => y !== null));
  for (const a of Array.isArray(item.aliases) ? item.aliases : []) {
    const y = cveYear(a);
    if (y !== null && !years.has(y)) return true;
  }
  for (const g of Array.isArray(item.ghsa_ids) ? item.ghsa_ids : []) {
    const y = ghsaYear(g);
    if (y !== null && !years.has(y)) return true;
  }
  return false;
}

/** version_range 含 "unknown"（大小写不敏感）。 */
function versionRangeHasUnknown(item: IntelItem): boolean {
  const vr = (item.entities as { version_range?: unknown } | null | undefined)?.version_range;
  if (!Array.isArray(vr)) return false;
  return vr.some((v) => typeof v === "string" && v.toLowerCase().includes("unknown"));
}

function round4(x: number): number {
  return Math.round(x * 10000) / 10000;
}

/** adapters 的非红线状态；未知/错误类型不能通过 str() 被抹成空值。 */
const SAFE_CVE_STATUSES = new Set([
  "PUBLISHED", "ANALYZED", "MODIFIED", "RECEIVED", "AWAITING ANALYSIS", "UNDERGOING ANALYSIS", "DEFERRED",
]);

function assessDqMetadata(item: DqInputItem): { statusBad: boolean; pocDead: boolean } {
  let statusBad = false;
  let pocDead = false;
  const assess = (meta: Record<string, unknown>) => {
    if ("_cve_status" in meta) {
      const status = typeof meta._cve_status === "string" ? meta._cve_status.trim().toUpperCase() : "";
      if (isRedlineCveStatus(status) || !SAFE_CVE_STATUSES.has(status)) statusBad = true;
    }
    if ("poc_link" in meta || "poc_sha256" in meta) {
      const link = meta.poc_link;
      const sha = meta.poc_sha256;
      if (("poc_link" in meta && typeof link !== "string") ||
          ("poc_sha256" in meta && typeof sha !== "string")) pocDead = true;
      if (typeof link === "string" && link.trim() !== "" &&
          !(typeof sha === "string" && /^[a-f0-9]{64}$/i.test(sha))) pocDead = true;
    }
  };
  assess(item as unknown as Record<string, unknown>);
  if ("_dq_sources" in item) {
    if (!Array.isArray(item._dq_sources) || item._dq_sources.length === 0) {
      statusBad = true;
    } else {
      for (const source of item._dq_sources) {
        if (typeof source !== "object" || source === null || Array.isArray(source)) {
          statusBad = true;
          continue;
        }
        const meta = source as Record<string, unknown>;
        const strings = (value: unknown): boolean => Array.isArray(value) && value.length > 0 &&
          value.every((v) => typeof v === "string" && v.trim() !== "");
        if (typeof meta.intel_id !== "string" || meta.intel_id.trim() === "" ||
            !strings(meta.source_ids) || !strings(meta.raw_refs) ||
            !["_cve_status", "poc_link", "poc_sha256"].some((key) => key in meta) ||
            Object.keys(meta).some((key) => !["intel_id", "source_ids", "raw_refs", "_cve_status", "poc_link", "poc_sha256"].includes(key))) {
          statusBad = true;
        }
        assess(meta);
      }
    }
  }
  // PUBLISHED 与 NVD 的 ANALYZED/MODIFIED 是不同机构的工作流，不是撤回冲突。
  // 每源独立检查；任何红线/未知状态均已置 statusBad，不由安全来源洗白。
  return { statusBad, pocDead };
}

/** 对单条 IntelItem 出具质量判定（五维分 + flags + 四档 verdict）。 */
export function assessQualityVerdict(item: IntelItem, opts: AssessOpts = {}): QualityVerdict {
  const now = opts.now ?? new Date();
  const nowMs = now.getTime();
  const it = item as DqInputItem;
  const flags: Dq1Flag[] = [];
  let redline = false;

  // —— 硬红线 1：CVE 记录状态 ——
  const { statusBad, pocDead } = assessDqMetadata(it);
  if (statusBad) {
    redline = true;
    flags.push("reject_status");
  }

  // —— 硬红线 2：时间戳可解析区间（早于 1999 或晚于 now+5min，含不可解析）——
  const pubMs = parseLoose(item.published_at ?? "");
  const seenMs = parseLoose(item.first_seen_at ?? "");
  const tsUnparseable = pubMs === null || seenMs === null;
  const tsOutOfRange =
    !tsUnparseable && ([pubMs, seenMs] as number[]).some((t) => t < TS_MIN_MS || t > nowMs + TS_SKEW_MS);
  if (tsUnparseable || tsOutOfRange) redline = true;
  const noTz = lacksTz(item.published_at) || lacksTz(item.first_seen_at);
  if (noTz) flags.push("ts_no_tz");

  // —— 硬红线 3：关键 5 字段全部为空 ——
  const key5AllEmpty =
    str(item.title) === "" &&
    str(item.summary) === "" &&
    !entitiesFilled(item.entities) &&
    !(Array.isArray(item.raw_refs) && item.raw_refs.length > 0) &&
    str(item.published_at) === "";
  if (key5AllEmpty) {
    redline = true;
    flags.push("key5_missing");
  }

  // —— 硬红线 4：POC 链接存在但无 sha256 ——
  if (pocDead) {
    redline = true;
    flags.push("poc_dead_link");
  }

  // —— 软性 flags ——
  const multiId = detectMultiIdMismatch(item);
  if (multiId) flags.push("multi_id_mismatch");
  const unknownVersion = versionRangeHasUnknown(item);
  if (unknownVersion) flags.push(UNKNOWN_VERSION_FLAG);
  const boilerHits = countBoilerplate((item.title ?? "") + " " + (item.summary ?? ""));
  if (boilerHits >= BOILERPLATE_THRESHOLD) flags.push("boilerplate");

  // —— 五维分 ——
  const structure = assessStructure(item);
  const completeness = assessCompleteness(item);
  const consistency = multiId ? 0 : unknownVersion ? 0.5 : statusBad ? 0.2 : 1;
  const timeliness = assessTimeliness(pubMs, seenMs, noTz, tsOutOfRange || tsUnparseable);
  const sourcing = pocDead ? 0 : boilerHits >= BOILERPLATE_THRESHOLD ? 0.3 : 1;
  const score = round4(
    structure * WEIGHTS.structure +
      completeness * WEIGHTS.completeness +
      consistency * WEIGHTS.consistency +
      timeliness * WEIGHTS.timeliness +
      sourcing * WEIGHTS.sourcing,
  );

  let verdict: DqVerdict = score >= 0.9 ? "pass" : score >= 0.7 ? "degrade" : score >= 0.5 ? "review" : "quarantine";
  if (redline) verdict = "quarantine"; // 硬红线与分数无关

  // —— A-04 注入筛查（gate 1.1.0）：共享本地启发式，只扫人类可读文本 ——
  // 只扫 title+summary：IntelItem 的其余字段是标识符/枚举/引用，不是自然语言指令载体；
  // 原始正文在 raw.docs 侧由受控页面闸门另行筛查，不在这里重复展开。
  const injection = screenPromptInjection([str(item.title), str(item.summary)]);
  const injectionSuspicious = injection.screened && injection.flags.length > 0;
  if (injectionSuspicious || !injection.screened) {
    // 命中迹象 → 至少 review（人工复核后由复核人改判）；无法筛查 → fail-closed 同样至少 review。
    // quarantine 仍只由硬红线决定：启发式误杀会丢数据，review 保留可复核性。
    if (verdict === "pass" || verdict === "degrade") verdict = "review";
  }

  const result: QualityVerdict = {
    item_id: item.intel_id,
    item_kind: "intel",
    quality_score: score,
    dimension_scores: {
      structure: round4(structure),
      completeness: round4(completeness),
      consistency: round4(consistency),
      timeliness: round4(timeliness),
      sourcing: round4(sourcing),
    },
    flags: flags as DqFlag[],
    verdict,
    gate_version: GATE_VERSION,
  };
  // C-03 契约位：screened=false 时不填（缺省 = 未筛查），调用方不得当作"已筛查且干净"。
  if (injection.screened) {
    result.injection_score = injection.max_score;
    result.injection_flags = injection.flags;
  }
  if (verdict === "quarantine") result.quarantine_ref = "dq_quarantine:" + item.intel_id;
  if (verdict === "review" && opts.reviewer !== undefined) {
    result.reviewer = opts.reviewer;
    result.reviewed_at = now.toISOString();
  }
  return result;
}

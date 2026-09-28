/**
 * F4 CVSS/EPSS 富化。
 * - parseCvssV31Vector：按 FIRST CVSS v3.1 规范计算 baseScore
 *   （ISS -> Impact -> Exploitability -> Roundup 单进位取整）
 * - lookupEpss：FIRST EPSS API；离线/fetch 失败 -> fixture 常量 + degrade（红线：禁止静默兜底）
 * - assessScore：多源分值仲裁，权威序 nvd > cna > ghsa > adp > system_derived；
 *   冲突只增强（补 EPSS/佐证字段），不改写权威源分值
 * - loadScoreSourcesFromRawRefs：从 raw_refs 指向的本地 payload 复原多源评分（P0 离线演示）
 *
 * 纪律：产出对象里的键一律不落 undefined 值——EnrichmentResult.json 是
 * additionalProperties:false，带 undefined 值的可选键会挂掉运行时校验（见 f6.test.ts 契约校验用例）。
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { degrade, nextId } from "@safetrace/shared";
import type { FallbackEvent, IntelItem, ScoreAssessment, ScoreSource } from "@safetrace/shared";

/* ---------- 公共 HTTP 注入点（F1 复用） ---------- */

/** 测试可注入的最小 HTTP 响应面（全局 fetch 的 Response 结构满足之）。 */
export interface HttpResponseLike {
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json(): Promise<unknown>;
}
export type HttpFetcher = (url: string) => Promise<HttpResponseLike>;

/** OFFLINE_FIXTURES=true（env）或显式 offline=true → 全程离线回放。 */
export function isOffline(offline?: boolean): boolean {
  return offline === true || process.env.OFFLINE_FIXTURES === "true";
}

/** 删除值为 undefined 的键：契约对象必须“键要么不存在、要么有值”。 */
export function compact<T extends object>(obj: T): T {
  const rec = obj as Record<string, unknown>;
  for (const key of Object.keys(rec)) {
    if (rec[key] === undefined) delete rec[key];
  }
  return obj;
}

/* ---------- CVSS v3.1 向量解析 ---------- */

const PREFIX = "CVSS:3.1/";

export type AvValue = "N" | "A" | "L" | "P";
export type AcValue = "L" | "H";
export type PrValue = "N" | "L" | "H";
export type UiValue = "N" | "R";
export type ScopeValue = "U" | "C";
export type IciaValue = "N" | "L" | "H";

export interface ParsedCvssV31 {
  vector: string;
  AV: AvValue;
  AC: AcValue;
  PR: PrValue;
  UI: UiValue;
  S: ScopeValue;
  C: IciaValue;
  I: IciaValue;
  A: IciaValue;
  baseScore: number;
}

/** 规范 weight 表（FIRST CVSS v3.1 Specification 表 7/12/13/14/15）。 */
const AV_WEIGHT: Record<AvValue, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHT: Record<AcValue, number> = { L: 0.77, H: 0.44 };
const PR_WEIGHT: Record<ScopeValue, Record<PrValue, number>> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
};
const UI_WEIGHT: Record<UiValue, number> = { N: 0.85, R: 0.62 };
const ICIA_WEIGHT: Record<IciaValue, number> = { H: 0.56, L: 0.22, N: 0 };

/** 规范要求的 8 个度量及顺序。 */
const METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;

const METRIC_SPEC: Record<string, readonly string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  PR: ["N", "L", "H"],
  UI: ["N", "R"],
  S: ["U", "C"],
  C: ["N", "L", "H"],
  I: ["N", "L", "H"],
  A: ["N", "L", "H"],
};

/** 解析并计算 CVSS v3.1 基准分；任何结构性错误立即抛错（不兜底）。 */
export function parseCvssV31Vector(vector: string): ParsedCvssV31 {
  if (typeof vector !== "string" || !vector.trim().startsWith(PREFIX)) {
    throw new Error(`parseCvssV31Vector: 仅支持 CVSS:3.1 向量，收到 "${vector}"`);
  }
  // 先逐段解析（重复立即抛错），再做完整性/取值校验——错误消息要能指认原因
  const raw: Record<string, string> = {};
  for (const part of vector.trim().slice(PREFIX.length).split("/")) {
    const seg = part.split(":");
    if (seg.length !== 2 || !seg[0] || !seg[1]) {
      throw new Error(`parseCvssV31Vector: 片段格式非法 "${part}"（应为 K:V）: ${vector}`);
    }
    const [key, value] = seg as [string, string];
    if (key in raw) {
      throw new Error(`parseCvssV31Vector: 度量重复 ${key}: ${vector}`);
    }
    raw[key] = value;
  }
  for (const key of METRIC_ORDER) {
    if (!(key in raw)) {
      throw new Error(`parseCvssV31Vector: 度量缺失 ${key}（须 AV/AC/PR/UI/S/C/I/A 共 8 个）: ${vector}`);
    }
  }
  const extras = Object.keys(raw).filter((k) => !(METRIC_ORDER as readonly string[]).includes(k));
  if (extras.length > 0) {
    throw new Error(`parseCvssV31Vector: 未知度量 ${extras.join(",")}: ${vector}`);
  }
  const metrics = {
    AV: pickEnum<AvValue>(raw, "AV"),
    AC: pickEnum<AcValue>(raw, "AC"),
    PR: pickEnum<PrValue>(raw, "PR"),
    UI: pickEnum<UiValue>(raw, "UI"),
    S: pickEnum<ScopeValue>(raw, "S"),
    C: pickEnum<IciaValue>(raw, "C"),
    I: pickEnum<IciaValue>(raw, "I"),
    A: pickEnum<IciaValue>(raw, "A"),
  };
  return { vector: vector.trim(), ...metrics, baseScore: baseScoreOf(metrics) };
}

function pickEnum<T extends string>(raw: Record<string, string>, key: string): T {
  const value = raw[key];
  const allowed = METRIC_SPEC[key];
  if (value === undefined || allowed === undefined || !allowed.includes(value)) {
    throw new Error(`parseCvssV31Vector: 度量 ${key} 缺失或取值非法（允许 ${(allowed ?? []).join("/")}）`);
  }
  return value as T;
}

/** FIRST CVSS v3.1 计分主公式。 */
export function baseScoreOf(m: Omit<ParsedCvssV31, "vector" | "baseScore">): number {
  const iss = 1 - (1 - ICIA_WEIGHT[m.C]) * (1 - ICIA_WEIGHT[m.I]) * (1 - ICIA_WEIGHT[m.A]);
  const impact =
    m.S === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability =
    8.22 * AV_WEIGHT[m.AV] * AC_WEIGHT[m.AC] * PR_WEIGHT[m.S][m.PR] * UI_WEIGHT[m.UI];
  if (impact <= 0) return 0;
  const raw =
    m.S === "U"
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
  return roundUpOneDecimal(raw);
}

/** 规范 Roundup：整数运算，单进位取到 1 位小数。 */
export function roundUpOneDecimal(x: number): number {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/* ---------- EPSS 查询 ---------- */

/**
 * 离线 EPSS fixture 常量表（与 fixtures/sources 口径一致）。
 * 只收样本 CVE；无样本的 CVE 返回 null 分——禁止把别的 CVE 的分值套上来（那是编造）。
 */
export const EPSS_FIXTURES: Record<string, { epss_score: number; epss_percentile: number }> = {
  "CVE-2021-44228": { epss_score: 0.97401, epss_percentile: 0.99963 },
};

export interface EpssLookup {
  cve_id: string;
  /** null = fixture 无该 CVE 样本（不编造分值；调用侧不落 epss 字段） */
  epss_score: number | null;
  epss_percentile: number | null;
  /** 降级标记（红线：非空即表示当前值为 fixture 回放，非实时 API 结果）。 */
  degraded_to?: string;
}

export interface LookupEpssOptions {
  offline?: boolean;
  fetchImpl?: HttpFetcher;
  traceId?: string;
  /** FallbackEvent 落库/上总线回调。 */
  emit?: (event: FallbackEvent) => void | Promise<void>;
}

/** GET https://api.first.org/data/v1/epss?cve=...；离线/失败 -> fixture + degrade。 */
export async function lookupEpss(cveId: string, opts: LookupEpssOptions = {}): Promise<EpssLookup> {
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
    throw new Error(`lookupEpss: 非法 CVE ID: ${cveId}`);
  }
  const traceId = opts.traceId ?? nextId("tr");
  if (isOffline(opts.offline)) return replayEpssFixture(cveId, "offline_flag", traceId, opts.emit);

  const fetcher = opts.fetchImpl ?? (fetch as unknown as HttpFetcher);
  const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
  let payload: unknown;
  try {
    const res = await fetcher(url);
    if (!res.ok) return replayEpssFixture(cveId, `epss_http_${res.status}`, traceId, opts.emit);
    payload = await res.json();
  } catch (err) {
    return replayEpssFixture(cveId, `epss_fetch_failed: ${errText(err)}`, traceId, opts.emit);
  }
  const picked = pickEpss(payload, cveId);
  if (picked === null) {
    // 无此 CVE 的数据行或结构异常：同样按失败显式降级，不拿别的行顶替
    return replayEpssFixture(cveId, "epss_row_missing", traceId, opts.emit);
  }
  return { cve_id: cveId, epss_score: picked.score, epss_percentile: picked.percentile };
}

/** 精确匹配 cve 行；缺失/不可解析 -> null（绝不回退到 rows[0] 冒充分值）。 */
function pickEpss(payload: unknown, cveId: string): { score: number; percentile: number } | null {
  const data = (payload as { data?: unknown } | null)?.data;
  if (!Array.isArray(data)) return null;
  const rows = data as Array<Record<string, unknown>>;
  const row = rows.find((r) => r?.cve === cveId);
  if (!row) return null;
  const score = Number(row.epss);
  const percentile = Number(row.percentile);
  if (!Number.isFinite(score) || !Number.isFinite(percentile)) return null;
  return { score, percentile };
}

async function replayEpssFixture(
  cveId: string,
  trigger: string,
  traceId: string,
  emit?: (event: FallbackEvent) => void | Promise<void>,
): Promise<EpssLookup> {
  const d = await degrade({
    layer: "L3",
    trigger,
    degradedOf: "fixture",
    traceId,
    label: "EPSS 离线回放：使用 fixture 样本分，非实时 API 结果",
    recoveryHint: "恢复外网连通后重试 api.first.org",
    emit,
  });
  const hit = EPSS_FIXTURES[cveId];
  return {
    cve_id: cveId,
    epss_score: hit?.epss_score ?? null,
    epss_percentile: hit?.epss_percentile ?? null,
    degraded_to: d.degraded_to,
  };
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/* ---------- 多源分值仲裁 ---------- */

/** 权威序：nvd > cna > ghsa > adp > system_derived（对齐 EnrichmentResult.json 字段说明）。 */
export const SCORE_AUTHORITY: readonly ScoreSource[] = ["nvd", "cna", "ghsa", "adp", "system_derived"];

/** 一条分值来源。cvss_v3_vector 必填；cvss_v3_base 可缺（缺省时按向量重算）；
 *  system_derived 必须附 derived_reason。 */
export interface ScoreSourceInput extends Partial<ScoreAssessment> {
  source_of_score: ScoreSource;
  cvss_v3_vector: string;
}

export interface ArbitrateResult {
  adopted: ScoreSourceInput;
  others: ScoreSourceInput[];
}

/** 按权威序选主分，其余作旁证；输入不合法立即抛错（不兜底）。 */
export function arbitrateSources(sources: ScoreSourceInput[]): ArbitrateResult {
  if (sources.length === 0) {
    throw new Error("arbitrateSources: sources 不能为空");
  }
  for (const s of sources) {
    if (!SCORE_AUTHORITY.includes(s.source_of_score)) {
      throw new Error(`arbitrateSources: 非法 source_of_score: ${s.source_of_score}`);
    }
    if (typeof s.cvss_v3_vector !== "string" || !s.cvss_v3_vector.trim()) {
      throw new Error(`arbitrateSources: 来源 ${s.source_of_score} 缺 cvss_v3_vector`);
    }
    if (s.cvss_v3_base !== undefined && (!Number.isFinite(s.cvss_v3_base))) {
      throw new Error(`arbitrateSources: 来源 ${s.source_of_score} 的 cvss_v3_base 非法`);
    }
    if (s.source_of_score === "system_derived" && !s.derived_reason) {
      throw new Error("arbitrateSources: system_derived 必须附 derived_reason");
    }
  }
  const sorted = [...sources].sort(
    (a, b) => SCORE_AUTHORITY.indexOf(a.source_of_score) - SCORE_AUTHORITY.indexOf(b.source_of_score),
  );
  const adopted = sorted[0]!;
  return { adopted, others: sorted.slice(1) };
}

/** 无来源置信度时的默认置信度（权威越低置信越低；system_derived 最低）。 */
const SOURCE_CONFIDENCE: Record<ScoreSource, number> = {
  nvd: 0.95,
  cna: 0.9,
  ghsa: 0.85,
  adp: 0.8,
  system_derived: 0.5,
};

export interface AssessScoreOptions {
  sources: ScoreSourceInput[];
  kevSet?: Iterable<string>;
  offline?: boolean;
  fetchImpl?: HttpFetcher;
  traceId?: string;
  emit?: (event: FallbackEvent) => void | Promise<void>;
}

/**
 * 产出 ScoreAssessment（字段严格对齐 shared types；undefined 键已剔除）。
 * - 无可用来源 -> null（cvss 维度记失败，禁止无源默认分）
 * - 权威源缺 epss/佐证字段时按权威序从旁证源补（只增强不改写）
 * - KEV 命中 -> kev_flag=true
 */
export async function assessScore(item: IntelItem, opts: AssessScoreOptions): Promise<ScoreAssessment | null> {
  if (opts.sources.length === 0) return null;
  const { adopted, others } = arbitrateSources(opts.sources);

  // 权威源分值优先；缺 base 时按向量重算（向量非法会直接抛错）
  const base =
    typeof adopted.cvss_v3_base === "number"
      ? adopted.cvss_v3_base
      : parseCvssV31Vector(adopted.cvss_v3_vector).baseScore;

  // 增强字段：权威源缺省时按权威序从旁证源补（不改动分值/向量）
  const fill = <K extends keyof ScoreAssessment>(key: K): ScoreAssessment[K] | undefined => {
    if (adopted[key] !== undefined) return adopted[key] as ScoreAssessment[K];
    for (const o of others) {
      if (o[key] !== undefined) return o[key] as ScoreAssessment[K];
    }
    return undefined;
  };

  // KEV 命中：上游 source_ids 含 kev / 任一来源自带 kev_flag / CVE 命中 kevSet
  const kevSetArray = opts.kevSet === undefined ? undefined : [...opts.kevSet];
  const kev =
    item.source_ids.some((sid) => sid.toLowerCase().includes("kev")) ||
    opts.sources.some((s) => s.kev_flag === true) ||
    (kevSetArray !== undefined && item.cve_ids.some((c) => kevSetArray.includes(c)));

  const assessment = compact({
    cvss_v3_vector: adopted.cvss_v3_vector,
    cvss_v3_base: base,
    source_of_score: adopted.source_of_score,
    derived_reason: adopted.derived_reason,
    epss_score: fill("epss_score"),
    epss_percentile: fill("epss_percentile"),
    kev_flag: kev ? true : undefined,
    exploit_maturity: fill("exploit_maturity") ?? (kev ? "high" : undefined),
    impact_summary: fill("impact_summary"),
    confidence: fill("confidence") ?? SOURCE_CONFIDENCE[adopted.source_of_score],
  }) as ScoreAssessment;

  // EPSS：上游给了就用；否则按首个 CVE 查询（离线/fetch 失败 -> fixture + degrade）
  if (assessment.epss_score === undefined && item.cve_ids.length > 0) {
    const epss = await lookupEpss(item.cve_ids[0]!, {
      offline: opts.offline,
      fetchImpl: opts.fetchImpl,
      traceId: opts.traceId,
      emit: opts.emit,
    });
    if (epss.epss_score !== null) assessment.epss_score = epss.epss_score;
    if (epss.epss_percentile !== null) assessment.epss_percentile = epss.epss_percentile;
  }
  return assessment;
}

/* ---------- 从本地 payload（raw_refs）复原多源评分 ---------- */

/** 仓库根（src/enrich/src -> 仓库根三级）。 */
const REPO_ROOT = new URL("../../../", import.meta.url);

/**
 * P0 离线演示：从 IntelItem.raw_refs 指向的本地 payload 抽取 CVSS 评分来源。
 * 识别三种已知形态：NVD 2.0、CVE-ORG 5.x（cna/adp）、OSV/GHSA。
 * 文件缺失 / 非 JSON / 形态不识别 -> 跳过（输入缺失，非降级；assessScore 对空来源返回 null）。
 */
export async function loadScoreSourcesFromRawRefs(item: IntelItem): Promise<ScoreSourceInput[]> {
  const found: ScoreSourceInput[] = [];
  for (const ref of item.raw_refs) {
    const text = await readFirstReadable(ref);
    if (text === null) continue;
    let doc: unknown;
    try {
      doc = JSON.parse(text);
    } catch {
      continue; // payload 非 JSON：跳过
    }
    found.push(...extractScoreSources(doc));
  }
  return dedupeBySource(found);
}

function refCandidates(ref: string): string[] {
  if (/^[a-zA-Z]:[\\/]/.test(ref) || ref.startsWith("/")) return [ref];
  return [fileURLToPath(new URL(ref, REPO_ROOT)), resolve(process.cwd(), ref)];
}

async function readFirstReadable(ref: string): Promise<string | null> {
  for (const candidate of refCandidates(ref)) {
    try {
      return await readFile(candidate, "utf8");
    } catch {
      continue; // 尝试下一个候选路径
    }
  }
  return null;
}

function extractScoreSources(doc: unknown): ScoreSourceInput[] {
  const out: ScoreSourceInput[] = [];
  const root = asRecord(doc);
  if (root === undefined) return out;

  // NVD 2.0：vulnerabilities[].cve.metrics.cvssMetricV31[].cvssData
  for (const vuln of asArray(root.vulnerabilities) ?? []) {
    const cve = asRecord(asRecord(vuln)?.cve);
    for (const metric of asArray(asRecord(cve?.metrics)?.cvssMetricV31) ?? []) {
      const data = asRecord(asRecord(metric)?.cvssData);
      const vector = str(data?.vectorString);
      if (vector !== undefined) {
        out.push({ source_of_score: "nvd", cvss_v3_vector: vector, cvss_v3_base: num(data?.baseScore) });
      }
    }
  }

  // CVE-ORG 5.x：containers.cna / containers.adp 的 metrics[].cvssV3_1 | cvssV3_0
  const containers = asRecord(root.containers);
  const adpPairs: Array<["cna" | "adp", Record<string, unknown> | undefined]> = [
    ["cna", asRecord(containers?.cna)],
    ["adp", asRecord(containers?.adp)],
  ];
  for (const [role, container] of adpPairs) {
    for (const metric of asArray(container?.metrics) ?? []) {
      const v3 = asRecord(asRecord(metric)?.cvssV3_1) ?? asRecord(asRecord(metric)?.cvssV3_0);
      const vector = str(v3?.vectorString);
      if (vector !== undefined) {
        out.push({
          source_of_score: role,
          cvss_v3_vector: vector,
          cvss_v3_base: num(v3?.baseScore),
        });
      }
    }
  }

  // OSV / GHSA：results[].vulns[].severity[]（type=CVSS_V3*，score 为向量串）
  for (const result of asArray(root.results) ?? []) {
    for (const vuln of asArray(asRecord(result)?.vulns) ?? []) {
      for (const sev of asArray(asRecord(vuln)?.severity) ?? []) {
        const rec = asRecord(sev);
        const type = str(rec?.type);
        const vector = str(rec?.score);
        if (vector !== undefined && (type === "CVSS_V3" || type === "CVSS_V3_1")) {
          out.push({ source_of_score: "ghsa", cvss_v3_vector: vector });
        }
      }
    }
  }
  return out;
}

/** 同一来源多次出现只保留首个（避免同一 payload 重复计数为冲突）。 */
function dedupeBySource(sources: ScoreSourceInput[]): ScoreSourceInput[] {
  const seen = new Set<string>();
  return sources.filter((s) => {
    if (seen.has(s.source_of_score)) return false;
    seen.add(s.source_of_score);
    return true;
  });
}

/* ---------- 未知 JSON 安全读取助手 ---------- */

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function asArray(v: unknown): unknown[] | undefined {
  return Array.isArray(v) ? v : undefined;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

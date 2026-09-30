/**
 * ingest 包内部公共助手（index.ts 只导出其中的类型，不外泄实现）：
 * - Y1 连接器骨架共性：HTTP 指数退避重试 + 429 退避
 * - 离线优先：OFFLINE_FIXTURES=true 或抓取失败时回放 fixtures/sources/ 预置样本，
 *   所有回放一律经 shared.degrade() 显式登记（红线：禁止静默兜底）
 * - payload 落盘缓存（KEV 单文件全量带 fetched_at）与 JSON 读取（适配器读 payload_ref）
 * - 解析侧小工具：时间归一化、文本截断、intel_id 清洗、脏字段兜底读取
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { degrade } from "@safetrace/shared";
import type { FallbackEvent, IntelItem, RawDoc } from "@safetrace/shared";
import { getSource } from "./registry.js";
import type { SourceEntry } from "./registry.js";

/** 仓库根目录：本文件位于 <root>/src/ingest/src/common.ts，目录上溯 3 层。 */
export const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

/** 离线预置样本目录（fixtures/ 为只读样本，禁止写入）。 */
export const SOURCE_FIXTURES_DIR = "fixtures/sources";

/** 环境变量开关：OFFLINE_FIXTURES=true 时只读 fixtures，绝不发起外网请求。 */
export function isOfflineEnv(): boolean {
  return process.env.OFFLINE_FIXTURES === "true";
}

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Y1 采集器公共入参（各源特有参数在子接口扩展）。 */
export interface FetchOpts {
  /** 强制离线（测试/冒烟用）；为 true 时直接回放预置样本。 */
  offline?: boolean;
  traceId?: string;
  /** 单轮抓取条目上限（源侧自行实现，未实现的源忽略此项）。 */
  limit?: number;
  /** 降级事件回调：pipeline 用它把 FallbackEvent 收进 fallback.events 主题。 */
  emit?: (event: FallbackEvent) => void | Promise<void>;
}

/** Y2 适配器公共输出：items 为解析产物，warnings 为"缺字段只置空不猜测"的告警。 */
export interface ParseResult {
  items: IntelItem[];
  warnings: string[];
}

export type HttpAttempt =
  | { ok: true; data: unknown; etag?: string }
  | { ok: false; reason: string };

/**
 * 指数退避重试（默认 3 次）：网络异常、5xx、429 一律退避后重试。
 * 返回结构化失败原因，由调用方决定是否走 fixture 回放（显式降级）。
 */
export async function fetchJsonWithRetry(
  url: string,
  init: RequestInit = {},
  attempts = 3,
): Promise<HttpAttempt> {
  let lastReason = "未发起请求";
  for (let i = 0; i < attempts; i += 1) {
    if (i > 0) await sleep(2 ** i * 500); // 0.5s → 1s → 2s
    try {
      const res = await fetch(url, {
        ...init,
        headers: { Accept: "application/json", ...(init.headers as Record<string, string>) },
      });
      if (res.status === 429) {
        lastReason = `HTTP 429 限流：${url}`;
        continue;
      }
      if (!res.ok) {
        lastReason = `HTTP ${res.status}：${url}`;
        continue;
      }
      const text = await res.text();
      try {
        return { ok: true, data: JSON.parse(text) as unknown, etag: res.headers.get("etag") ?? undefined };
      } catch {
        return { ok: false, reason: `响应体非 JSON：${url}` };
      }
    } catch (err) {
      lastReason = `网络异常：${err instanceof Error ? err.message : String(err)}`;
    }
  }
  return { ok: false, reason: lastReason };
}

/** 读 JSON：相对路径按仓库根解析，绝对路径原样使用（适配器读 RawDoc.payload_ref）。 */
export async function readJsonFile(ref: string): Promise<unknown> {
  const abs = path.isAbsolute(ref) ? ref : path.join(REPO_ROOT, ref);
  const text = await readFile(abs, "utf8");
  return JSON.parse(text) as unknown;
}

/**
 * 统一的 fixture 回放降级登记（Y1 共性）：
 * layer=L2、degradedOf=fixture、label 明示"离线回放预置样本"，degraded_to="fixture"。
 */
export async function degradeToFixture(
  trigger: string,
  traceId: string,
  emit?: (event: FallbackEvent) => void | Promise<void>,
): Promise<void> {
  await degrade({
    layer: "L2",
    trigger,
    degradedOf: "fixture",
    traceId,
    label: `离线回放预置样本（${trigger}）`,
    recoveryHint: "外网恢复或将 OFFLINE_FIXTURES 置为 false 后自动回到实时采集",
    emit,
  });
}

/** 按源登记表取源配置；未登记直接抛错（不允许静默跳过）。 */
export function requireSource(sourceId: string): SourceEntry {
  const entry = getSource(sourceId);
  if (!entry) throw new Error(`源登记表未登记 source_id=${sourceId}`);
  return entry;
}

/** payload 落盘缓存目录（默认 tmp/ingest-cache，tmp/ 已在 .gitignore 忽略）。 */
export function cacheDir(): string {
  return process.env.SAFETRACE_CACHE_DIR ?? path.join(REPO_ROOT, "tmp", "ingest-cache");
}

/** 写入原始 payload 并附 fetched_at（KEV 单文件全量源的要求），返回仓库相对路径作 payload_ref。 */
export async function persistPayload(sourceId: string, payload: unknown, fetchedAt: string): Promise<string> {
  const dir = cacheDir();
  await mkdir(dir, { recursive: true });
  const stamp = fetchedAt.replace(/[:.]/g, "-");
  const abs = path.join(dir, `${sourceId}-${stamp}.json`);
  const doc =
    typeof payload === "object" && payload !== null
      ? { ...(payload as Record<string, unknown>), fetched_at: fetchedAt }
      : { payload, fetched_at: fetchedAt };
  await writeFile(abs, JSON.stringify(doc), "utf8");
  return path.relative(REPO_ROOT, abs).split(path.sep).join("/");
}

/** 是否带时区后缀（Z 或 ±hh:mm）。 */
export function hasTzSuffix(value: string): boolean {
  return /[zZ]|[+-]\d{2}:?\d{2}$/.test(value.trim());
}

export interface NormalizedTs {
  /** 归一化后的 ISO-8601 带 Z；不可解析为 null（调用方记 warning 并置空）。 */
  iso: string | null;
  /** 上游原文是否自带时区后缀。 */
  hadTz: boolean;
}

/** 归一化上游时间戳为 ISO-8601 UTC 带 Z；容忍纯日期（补 T00:00:00Z）。 */
export function normalizeTs(value: unknown): NormalizedTs {
  if (typeof value !== "string" || value.trim() === "") return { iso: null, hadTz: false };
  const cleaned = value.trim();
  const hadTz = hasTzSuffix(cleaned);
  let ms = Date.parse(hadTz ? cleaned : `${cleaned}Z`);
  if (Number.isNaN(ms)) ms = Date.parse(`${cleaned.slice(0, 10)}T00:00:00Z`); // 纯日期兜底
  return { iso: Number.isNaN(ms) ? null : new Date(ms).toISOString(), hadTz };
}

/** 文本截断（title 用）；clipped=true 时调用方应记 warning。 */
export function clip(text: string, max: number): { text: string; clipped: boolean } {
  const t = text.trim();
  return t.length <= max ? { text: t, clipped: false } : { text: `${t.slice(0, max)}…`, clipped: true };
}

/** intel_id 生成：intel_<来源短名>_<上游ID小写、非法字符转 _>，满足契约 pattern ^intel_[0-9A-Za-z_-]+$。 */
export function makeIntelId(sourceTag: string, externalId: string): string {
  const body = externalId
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `intel_${sourceTag}_${body || "unknown"}`;
}

/** CVE 编号格式（对齐 IntelItem 契约 cve_ids items pattern）。 */
export const CVE_PATTERN = /^CVE-[0-9]{4}-[0-9]{4,}$/;

/** 取字符串字段；非字符串或空串返回 ""（宁缺勿猜）。 */
export function str(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/** 取字符串数组字段；过滤非字符串与空串项。 */
export function strArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.trim() !== "") : [];
}

/** DQ1 硬红线状态判定（REJECTED/RESERVED/DISPUTED 及其大小写变体）。 */
const REDLINE_STATUS_PREFIXES = ["REJECT", "RESERVED", "DISPUTED"];
export function isRedlineCveStatus(status: unknown): boolean {
  if (typeof status !== "string") return false;
  const upper = status.trim().toUpperCase();
  return REDLINE_STATUS_PREFIXES.some((prefix) => upper.startsWith(prefix));
}

/** 命中硬红线状态时把 _cve_status 附到 IntelItem（契约外下划线字段，与 dirty fixtures 同口径）。 */
export function withCveStatus<T extends object>(item: T, status: unknown): T {
  if (typeof status !== "string" || !isRedlineCveStatus(status)) return item;
  return { ...item, _cve_status: status.trim() } as T;
}

/** 读 RawDoc.payload_ref 并兜底为对象；读失败/非对象时记 warning 并返回 {}。 */
export async function readPayloadObject(raw: RawDoc, warnings: string[]): Promise<Record<string, unknown>> {
  let data: unknown;
  try {
    data = await readJsonFile(raw.payload_ref);
  } catch (err) {
    warnings.push(`payload_ref 读取失败：${raw.payload_ref}（${err instanceof Error ? err.message : String(err)}）`);
    return {};
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    warnings.push(`payload_ref 内容非 JSON 对象：${raw.payload_ref}`);
    return {};
  }
  return data as Record<string, unknown>;
}

/**
 * Y2 · USN（Ubuntu 安全公告）适配器：一条公告 → 一条 IntelItem（可含多个 CVE，契约 cve_ids 为数组）。
 *
 * 宁缺勿猜的三条取舍（原始字段一律留在 payload_ref 里可回溯）：
 * - `release_packages` 给的是「各 Ubuntu release 的修复版本」，不是上游受影响版本区间，
 *   与 IntelItem.entities.version_range 的语义不同 → 置空并记 warning，不做臆造转换；
 * - USN 不声明上游 vendor → entities.vendor 置空；product 取首个 source package 名；
 * - USN 无 CWE/CPE 字段 → cwe、cpes 置空并记 warning。
 * 时间口径：上游 `published` 是无时区裸串（如 2021-12-14T13:39:20.973277），
 * 统一经 normalizeTs 归一化为 ISO-8601 带 Z（UTC），并记 warning。
 */
import { SCHEMA_VERSION, nowIso } from "@safetrace/shared";
import type { IntelItem, RawDoc } from "@safetrace/shared";
import {
  CVE_PATTERN,
  clip,
  makeIntelId,
  normalizeTs,
  readPayloadObject,
  str,
  strArray,
  type ParseResult,
} from "../common.js";

export const USN_SOURCE_ID = "ubuntu_usn";
/** 厂商官方公告：对本发行版权威，跨厂商覆盖有限，可靠度居中偏高。 */
export const USN_RELIABILITY = 0.85;

const TITLE_MAX = 120;
const SUMMARY_MAX = 500;

/** release_packages 是 { "<release>": [ {name, version, is_source} ... ] } 形态，取 source 包名。 */
function firstSourcePackageName(releasePackages: unknown): string | null {
  if (typeof releasePackages !== "object" || releasePackages === null) return null;
  for (const list of Object.values(releasePackages as Record<string, unknown>)) {
    if (!Array.isArray(list)) continue;
    for (const pkg of list) {
      if (typeof pkg !== "object" || pkg === null) continue;
      const rec = pkg as Record<string, unknown>;
      const name = str(rec.name);
      if (name === "") continue;
      if (rec.is_source === true) return name;
    }
  }
  return null;
}

/** 统计 release_packages 下的包条目总数（只用于 warning 说明，不进契约）。 */
function releasePackageCount(releasePackages: unknown): number {
  if (typeof releasePackages !== "object" || releasePackages === null) return 0;
  let n = 0;
  for (const list of Object.values(releasePackages as Record<string, unknown>)) {
    if (Array.isArray(list)) n += list.length;
  }
  return n;
}

export async function parseUsn(raw: RawDoc): Promise<ParseResult> {
  const warnings: string[] = [];
  const payload = await readPayloadObject(raw, warnings);
  const notices = Array.isArray(payload.notices) ? payload.notices : [];
  if (notices.length === 0) warnings.push("payload.notices 缺失或为空，未产出 IntelItem");

  const items: IntelItem[] = [];
  let skippedHidden = 0;
  let noCve = 0;
  for (const entry of notices) {
    if (typeof entry !== "object" || entry === null) {
      warnings.push("notices 中存在非对象条目，跳过");
      continue;
    }
    const n = entry as Record<string, unknown>;
    const noticeId = str(n.id);
    if (noticeId === "") {
      warnings.push("USN 公告缺 id，跳过该条（intel_id 无法生成）");
      continue;
    }
    if (n.is_hidden === true) {
      skippedHidden += 1;
      continue; // 上游标记隐藏的草稿公告不入库（脏数据不进底座）
    }

    const rawCves = strArray(n.cves_ids);
    const cveIds: string[] = [];
    for (const id of rawCves) {
      if (CVE_PATTERN.test(id)) cveIds.push(id);
      else warnings.push(noticeId + " 含不符合 CVE pattern 的标识：" + id + "（已剔除）");
    }
    if (cveIds.length === 0) noCve += 1;

    const rawSummary = str(n.summary).replace(/\s+/g, " ").trim();
    const summary = clip(rawSummary, SUMMARY_MAX);
    if (summary.clipped) warnings.push(noticeId + " summary 超长，已截断至 " + SUMMARY_MAX + " 字符（原文见 payload_ref）");
    const rawTitle = str(n.title).replace(/\s+/g, " ").trim();
    const clippedTitle = clip(rawTitle === "" ? noticeId : rawTitle, TITLE_MAX);
    if (rawTitle === "") warnings.push(noticeId + " 缺 title，title 回退为公告编号");

    const pub = normalizeTs(n.published);
    if (pub.iso === null) warnings.push(noticeId + " published 不可解析，published_at 置空");
    else if (!pub.hadTz) warnings.push(noticeId + " published 无时区后缀（上游裸 UTC 串），已按 UTC 归一化");

    const product = firstSourcePackageName(n.release_packages);
    if (product === null) warnings.push(noticeId + " release_packages 无 source 包，entities.product 置空");
    else if (releasePackageCount(n.release_packages) > 0) {
      warnings.push(
        noticeId + " release_packages 为各 Ubuntu release 的修复版本（" + releasePackageCount(n.release_packages) +
          " 项），与 version_range 语义不同，未写入 entities.version_range（原文见 payload_ref）",
      );
    }

    items.push({
      intel_id: makeIntelId("usn", noticeId),
      cve_ids: cveIds,
      aliases: [noticeId],
      source_ids: [USN_SOURCE_ID],
      title: clippedTitle.text,
      ...(summary.text === "" ? {} : { summary: summary.text }),
      published_at: pub.iso ?? "",
      first_seen_at: nowIso(),
      entities: { product, vendor: null, version_range: [], cwe: [], cpes: [] },
      raw_refs: [raw.payload_ref],
      source_reliability: USN_RELIABILITY,
      schema_version: SCHEMA_VERSION,
    });
  }

  if (skippedHidden > 0) warnings.push("跳过 is_hidden=true 的草稿公告 " + skippedHidden + " 条");
  if (noCve > 0) warnings.push("无 CVE 标识的 USN 公告 " + noCve + " 条（cve_ids 置空，不参与强标识归并）");
  return { items, warnings };
}

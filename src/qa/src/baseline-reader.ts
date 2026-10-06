import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { sha256 } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { readKnowledgeProjection } from "./knowledge-reader.js";
import { extractBaselineFacts, parseKevRecords, parseNvdRecords, parseUsnRecords, type BaselineFacts, BaselineGap } from "../../enrich/src/baseline-facts.js";

type Obj = Record<string, unknown>;
export interface BaselineIndex { nvd: Map<string, Obj>; kev: Map<string, Obj>; usn: Map<string, Obj[]> }

/** 只读：按当前已验证的原文引用加载本地批量文档；内容变化即重新解析。 */
export async function loadBaselineIndex(options: { sqlitePath: string; payloadRoots?: readonly string[] }): Promise<BaselineIndex> {
  const projection = await readKnowledgeProjection(options);
  const verified = new Map<string, string>();
  for (const proof of projection.evidence) if (proof.kind === "source" && proof.raw_ref && proof.original_sha256) verified.set(proof.raw_ref, proof.original_sha256);
  const db = new DatabaseSync(options.sqlitePath, { readOnly: true });
  let docs: Array<{ payload_ref: string; source_id: string }>;
  try {
    docs = db.prepare("SELECT payload FROM events WHERE topic='raw.docs' ORDER BY seq").all().map((row: any) => { const p = JSON.parse(String(row.payload)); return { payload_ref: String(p.payload_ref), source_id: String(p.source_id) }; });
  } finally { db.close(); }
  const index: BaselineIndex = { nvd: new Map(), kev: new Map(), usn: new Map() };
  const supported = new Set(["nvd_cve", "cisa_kev", "ubuntu_usn"]);
  for (const doc of docs) {
    if (doc.payload_ref.startsWith("sqlite-page:") || !verified.has(doc.payload_ref)) continue;
    if (!supported.has(doc.source_id)) continue;
    try {
      const bytes = await readFile(doc.payload_ref);
      if (sha256(bytes) !== verified.get(doc.payload_ref)) continue;
      if (doc.source_id === "nvd_cve") { for (const [k, v] of parseNvdRecords(bytes)) if (!index.nvd.has(k)) index.nvd.set(k, v); continue; }
      if (doc.source_id === "cisa_kev") { for (const [k, v] of parseKevRecords(bytes)) if (!index.kev.has(k)) index.kev.set(k, v); continue; }
      for (const [k, v] of parseUsnRecords(bytes)) if (!index.usn.has(k)) index.usn.set(k, v);
    } catch { /* 单个文档不可读不影响其它来源 */ }
  }
  return index;
}

export function baselineForItem(index: BaselineIndex, item: IntelItem, v31Proven: boolean): { facts: BaselineFacts; gaps: BaselineGap[] } {
  return extractBaselineFacts({ cve_ids: item.cve_ids, source_ids: item.source_ids, nvd: index.nvd, kev: index.kev, usn: index.usn, v31_proven: v31Proven });
}

/** 给自然语言结论用的基线事实描述（无 v3.1 分数时也能说人话）。 */
export function baselineNarrative(facts: BaselineFacts): string | null {
  const parts: string[] = [];
  if (facts.kev?.listed) parts.push("该漏洞已被 CISA 列入在野利用目录（加入日期 " + facts.kev.date_added + (facts.kev.ransomware ? "，且已知被勒索软件利用" : "") + "）");
  for (const score of facts.score_versions) if (score.base !== null) parts.push("本地 NVD 文档中有 CVSS " + score.version + " 评分 " + score.base.toFixed(1) + "（" + score.source + "，" + score.metric_type + "；非 NIST 主 v3.1，未经复核发布）");
  if (facts.usn?.length) for (const u of facts.usn) if (u.packages.length) parts.push("Ubuntu 公告 " + u.notice_id + " 给出的修复版本：" + u.packages.slice(0, 4).join("、") + "（厂商声明，尚未验证）");
  const text = parts.join("；");
  return text.trim() ? text + "。" : null
}

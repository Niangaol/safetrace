/**
 * F1 论文关联富化：arXiv Atom API + 正则解析（零第三方依赖）。
 * 离线回放：OFFLINE_FIXTURES / opts.offline / fetch 失败 -> fixtures/enrich/arxiv.sample.xml
 * 回放 + degrade（红线：禁止静默兜底；回放值带 degraded_to="fixture"）。
 */
import { readFile } from "node:fs/promises";
import { degrade, nextId } from "@safetrace/shared";
import type { FallbackEvent, PaperLink } from "@safetrace/shared";
import { compact, isOffline, type HttpFetcher } from "./f4-cvss.js";

export type { HttpFetcher } from "./f4-cvss.js";

const ARXIV_API = "https://export.arxiv.org/api/query";
const MAX_RESULTS = 5;

/** 查询词最小长度（过滤 of/the/an 之类噪声词）。 */
const MIN_TERM_LEN = 3;

/** 停用词（只作用于相关性打分的查询词切分）。 */
const STOPWORDS = new Set([
  "the", "and", "for", "with", "from", "that", "this", "its", "are", "was", "not", "but",
  "has", "have", "via", "such", "into", "over", "under", "when", "then", "than", "all",
  "can", "our", "out", "use", "using", "used", "also", "more", "most", "some", "each",
  "other", "only", "upon", "will", "would", "could", "should", "both", "does", "done",
  "been", "being", "they", "them", "their", "there", "here", "where", "which", "while",
  "what", "how", "why", "who",
]);

/** 离线回放 fixture：arXiv Atom 样本（查询词 Log4Shell JNDI remote code execution）。 */
const ARXIV_FIXTURE_URL = new URL("../../../fixtures/enrich/arxiv.sample.xml", import.meta.url);

export interface SearchPapersOptions {
  offline?: boolean;
  fetchImpl?: HttpFetcher;
  traceId?: string;
  /** FallbackEvent 落库/上总线回调。 */
  emit?: (event: FallbackEvent) => void | Promise<void>;
}

export interface PapersResult {
  papers: PaperLink[];
  /** 降级标记（红线：非空即表示当前论文列表为 fixture 回放，非实时检索结果）。 */
  degraded_to?: string;
}

/**
 * arXiv Atom 检索。query 为检索短语（拼进 search_query=all:"..."）。
 * 返回论文列表（按 relevance 降序，至多 5 条）+ 降级标记。
 */
export async function searchPapers(query: string, opts: SearchPapersOptions = {}): Promise<PapersResult> {
  const q = query.trim().replace(/\s+/g, " ");
  if (!q) throw new Error("searchPapers: query 不能为空");
  const traceId = opts.traceId ?? nextId("tr");
  if (isOffline(opts.offline)) return replayFixture(q, "offline_flag", traceId, opts.emit);

  const fetcher = opts.fetchImpl ?? (fetch as unknown as HttpFetcher);
  const url = buildArxivUrl(q);
  try {
    const res = await fetcher(url);
    if (!res.ok) return replayFixture(q, `arxiv_http_${res.status}`, traceId, opts.emit);
    const xml = await res.text();
    return { papers: parseArxivAtom(xml, q) };
  } catch (err) {
    return replayFixture(q, `arxiv_fetch_failed: ${errText(err)}`, traceId, opts.emit);
  }
}

export function buildArxivUrl(query: string): string {
  const encoded = encodeURIComponent(query.trim());
  return `${ARXIV_API}?search_query=all:%22${encoded}%22&start=0&max_results=${MAX_RESULTS}&sortBy=relevance`;
}

/**
 * 正则解析 Atom <entry>（title/id/published/summary），零第三方库。
 * 返回按 relevance 降序的 PaperLink[]；无标题/id 的 entry 跳过（脏数据不兜底）。
 */
export function parseArxivAtom(xml: string, query: string): PaperLink[] {
  const papers: PaperLink[] = [];
  for (const m of xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/g)) {
    const entry = m[1] ?? "";
    const rawTitle = firstMatch(entry, /<title\b[^>]*>([\s\S]*?)<\/title>/);
    const rawId = firstMatch(entry, /<id\b[^>]*>([\s\S]*?)<\/id>/);
    if (rawTitle === null || rawId === null) continue;
    const title = cleanText(rawTitle);
    if (!title) continue;
    const rawSummary = firstMatch(entry, /<summary\b[^>]*>([\s\S]*?)<\/summary>/) ?? "";
    const rawPublished = firstMatch(entry, /<published\b[^>]*>([\s\S]*?)<\/published>/) ?? "";
    const rel = relevanceOf(query, `${title} ${cleanText(rawSummary)}`);
    const year = /^\d{4}/.exec(rawPublished)?.[0];
    papers.push(
      compact({
        paper_id: arxivPaperId(rawId),
        source: "arxiv" as const,
        title,
        year: year !== undefined ? Number(year) : undefined,
        venue: "arXiv",
        relevance_score: round2(rel.score),
        confidence: confidenceFor(rel.score),
        evidence_terms: rel.terms,
      }),
    );
  }
  return papers.sort((a, b) => b.relevance_score - a.relevance_score).slice(0, MAX_RESULTS);
}

/** arXiv abs id -> 契约 paper_id（形如 arXiv:2112.00507，去掉版本号）。 */
export function arxivPaperId(absUrl: string): string {
  const m = /abs\/([^/?#\s]+)/.exec(absUrl.trim());
  if (!m) return absUrl.trim();
  const base = (m[1] ?? "").replace(/v\d+$/, "");
  return `arXiv:${base}`;
}

/* ---------- relevance / confidence 启发式 ---------- */

export interface Relevance {
  score: number;
  terms: string[];
}

/** 查询词与 title+summary 的词级重合度（0-1）：命中词数 / 查询词数（词表精确匹配，防子串误判）。 */
export function relevanceOf(query: string, text: string): Relevance {
  const terms = queryTerms(query);
  if (terms.length === 0) return { score: 0, terms: [] };
  const docTerms = new Set(tokenize(text));
  const hit = terms.filter((t) => docTerms.has(t));
  return { score: round2(hit.length / terms.length), terms: hit };
}

/** 查询词：小写切分 + 去停用词 + 去重（保序，保证 evidence_terms 顺序稳定）。 */
function queryTerms(query: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of tokenize(query)) {
    if (seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9\u4e00-\u9fff]+/)
    .filter((t) => t.length >= MIN_TERM_LEN && !STOPWORDS.has(t));
}

/** confidence 按分数分档（0-1）。 */
export function confidenceFor(score: number): number {
  if (score >= 0.75) return 0.9;
  if (score >= 0.5) return 0.8;
  if (score >= 0.25) return 0.6;
  if (score > 0) return 0.4;
  return 0.25;
}

/* ---------- 内部工具 ---------- */

function firstMatch(text: string, re: RegExp): string | null {
  return re.exec(text)?.[1] ?? null;
}

/** XML 实体反转义 + 空白折叠。 */
function cleanText(raw: string): string {
  const unescaped = raw.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body[0] === "#") {
      const codePoint = body[1] === "x" || body[1] === "X"
        ? Number.parseInt(body.slice(2), 16)
        : Number.parseInt(body.slice(1), 10);
      return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : whole;
    }
    const named: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
    return named[body] ?? whole;
  });
  return unescaped.replace(/\s+/g, " ").trim();
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** 离线/失败回放：读 fixture Atom 文件（缺失即显式抛错，不用空列表糊弄）。 */
async function replayFixture(
  query: string,
  trigger: string,
  traceId: string,
  emit?: (event: FallbackEvent) => void | Promise<void>,
): Promise<PapersResult> {
  const d = await degrade({
    layer: "L3",
    trigger,
    degradedOf: "fixture",
    traceId,
    label: "arXiv 离线回放：使用 fixture 论文样本，非实时检索结果",
    recoveryHint: "恢复外网连通后重试 export.arxiv.org",
    emit,
  });
  const xml = await readFile(ARXIV_FIXTURE_URL, "utf8");
  return { papers: parseArxivAtom(xml, query), degraded_to: d.degraded_to };
}

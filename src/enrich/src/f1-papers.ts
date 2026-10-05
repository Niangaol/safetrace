/**
 * F1 论文关联富化：arXiv Atom API + 正则解析（零第三方依赖）。
 * 离线回放：OFFLINE_FIXTURES / opts.offline / fetch 失败 -> fixtures/enrich/arxiv.sample.xml
 * 回放 + degrade（红线：禁止静默兜底；回放值带 degraded_to="fixture"）。
 */
import { readFile } from "node:fs/promises";
import { degrade, nextId, sha256 } from "@safetrace/shared";
import type { FallbackEvent, PaperLink, IntelItem } from "@safetrace/shared";
import { compact, isOffline, type HttpFetcher } from "./f4-cvss.js";

export type { HttpFetcher } from "./f4-cvss.js";

const ARXIV_API = "https://export.arxiv.org/api/query";
const MAX_RESULTS = 5;
const ARXIV_MIN_INTERVAL_MS = 3_000;
const ARXIV_SUCCESS_CACHE = new Map<string, { result: PapersResult; expires_at: number }>();
let lastArxivRequestAt = 0;

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
  /** Internal original response receipt; never copied into frozen PaperLink events. */
  source_evidence?: { url: string; sha256: string; text: string };
  paper_records?: Record<string, { title: string; summary: string; published_at: string; url: string }>;
}

/** arXiv Atom 检索：成功结果按规范化查询词缓存；在线请求串行限速并对 429/5xx 有界重试。 */
function retryAfterMilliseconds(header: string | null, fallback: number): number {
  if (!header) return fallback;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.min(30_000, Math.max(0, seconds * 1000));
  const date = Date.parse(header);
  return Number.isFinite(date) ? Math.min(30_000, Math.max(0, date - Date.now())) : fallback;
}

async function wait(milliseconds: number): Promise<void> {
  if (milliseconds > 0) await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

/** arXiv Atom 检索。query 为检索短语；失败仍走显式 fixture 降级。 */
export async function searchPapers(query: string, opts: SearchPapersOptions = {}): Promise<PapersResult> {
  const q = query.trim().replace(/\s+/g, " ");
  if (!q) throw new Error("searchPapers: query 不能为空");
  const traceId = opts.traceId ?? nextId("tr");
  if (isOffline(opts.offline)) return replayFixture(q, "offline_flag", traceId, opts.emit);
  const injectedFetcher = opts.fetchImpl !== undefined;
  const cacheKey = q.toLocaleLowerCase();
  const cached = ARXIV_SUCCESS_CACHE.get(cacheKey);
  if (!injectedFetcher && cached && cached.expires_at > Date.now()) return structuredClone(cached.result);
  const fetcher = opts.fetchImpl ?? ((url: string) => fetch(url, { signal: AbortSignal.timeout(15_000) }));
  const url = buildArxivUrl(q);
  let lastTrigger = "arxiv_fetch_failed: no attempt";
  for (let attempt = 0; attempt < 3; attempt++) {
    if (!injectedFetcher) {
      const waitForSlot = ARXIV_MIN_INTERVAL_MS - (Date.now() - lastArxivRequestAt);
      await wait(waitForSlot);
      lastArxivRequestAt = Date.now();
    }
    try {
      const res = await fetcher(url);
      if (res.ok) {
        const xml = await res.text();
        if (Buffer.byteLength(xml) > 2 * 1024 * 1024 || !/^\s*(?:<\?xml[^?]*\?>\s*)?<feed\b/i.test(xml) || !/(?:<\/feed>|<feed[^>]*\/>)\s*$/i.test(xml)) throw new Error("arXiv response is not bounded Atom XML");
        const result: PapersResult = { papers: parseArxivAtom(xml, q), paper_records: arxivPaperRecords(xml), source_evidence: { url, sha256: sha256(xml), text: xml } };
        if (!injectedFetcher) ARXIV_SUCCESS_CACHE.set(cacheKey, { result: structuredClone(result), expires_at: Date.now() + 6 * 3600_000 });
        return result;
      }
      lastTrigger = "arxiv_http_" + res.status;
      if (res.status !== 429 && res.status < 500) break;
      if (attempt < 2) await wait(res.status === 429 ? retryAfterMilliseconds(res.headers?.get("retry-after") ?? null, 1000 * (attempt + 1)) : 1000 * (attempt + 1));
    } catch (err) {
      lastTrigger = "arxiv_fetch_failed: " + errText(err);
      if (attempt < 2) await wait(1000 * (attempt + 1));
    }
  }
  return replayFixture(q, lastTrigger, traceId, opts.emit);
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
  try {
    const url = new URL(absUrl.trim());
    if (!["arxiv.org", "export.arxiv.org"].includes(url.hostname.toLowerCase()) || !["http:", "https:"].includes(url.protocol) || url.username || url.password) return absUrl.trim();
    const base = /^\/abs\/(.+)$/.exec(url.pathname)?.[1]?.replace(/v[0-9]+$/, "");
    return base ? "arXiv:" + base : absUrl.trim();
  } catch { return absUrl.trim(); }
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

export function arxivPaperRecords(xml: string): NonNullable<PapersResult["paper_records"]> {
  const records: NonNullable<PapersResult["paper_records"]> = {};
  for (const m of xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/g)) {
    const entry=m[1]??"",rawId=firstMatch(entry,/<id\b[^>]*>([\s\S]*?)<\/id>/);
    if(!rawId)continue;const key=arxivPaperId(rawId);
    if(!/^arXiv:(?:[0-9]{2}(?:0[1-9]|1[0-2])[.][0-9]{4,5}|[a-z-]+(?:[.][A-Z]{2})?[/][0-9]{7})$/.test(key))continue;
    const date=cleanText(firstMatch(entry,/<published\b[^>]*>([\s\S]*?)<\/published>/)??"");
    if(!/T.*(?:Z|[+-]\d{2}:\d{2})$/.test(date)||!Number.isFinite(Date.parse(date)))continue;
    records[key]={title:cleanText(firstMatch(entry,/<title\b[^>]*>([\s\S]*?)<\/title>/)??""),summary:cleanText(firstMatch(entry,/<summary\b[^>]*>([\s\S]*?)<\/summary>/)??""),published_at:date,url:"https://arxiv.org/abs/"+key.replace(/^arxiv:/i,"")};
  }
  return records;
}
const GENERIC_PAPER_TERMS=new Set(["remote","code","execution","vulnerability","vulnerabilities","security","flaw","flaws","allows","allow","arbitrary","attacker","attackers","attack","attacks","could","can","the","and","with","for","from","through","product","products","software","version","versions","server","servers","application","applications","issue","issues","apache","microsoft","google","ubuntu","linux","windows","overflow","buffer","denial","service","use","using","affected","affects","exploit","exploitation","of","in","to"]);
/** Entity/identifier anchor is necessary, not a guarantee of scientific relevance. */
export function anchoredPapers(item: Pick<IntelItem,"title"|"entities"|"cve_ids">, papers: PaperLink[], records: PapersResult["paper_records"] = {}): PaperLink[] {
  // A known product is mandatory when available: mechanism words such as memory/corruption are not product identity.
  const product=(item.entities.product??"").toLowerCase().trim();
  const productAliases: Record<string,string[]> = { "log4j-core": ["log4j", "log4j2"], "apache log4j2": ["log4j2", "log4j"], "langchain-core": ["langchain"], "langchain_core": ["langchain"] };
  const productTerms=[...(product.match(/[a-z][a-z0-9._+-]*/g)??[]), ...(productAliases[product]??[])];
  const anchorText=productTerms.length ? productTerms.join(" ") : item.title;
  const mechanismTerms=new Set(["memory","corruption","heap","stack","integer","out","bounds","read","write","access","control","privilege","escalation","authentication","bypass","improper","incorrect","validation","handling","management","information","disclosure"]);
  const anchors=[...new Set(anchorText.toLowerCase().match(/[a-z][a-z0-9._+-]*/g)??[])].filter(t=>t.length>=3&&!GENERIC_PAPER_TERMS.has(t)&&!mechanismTerms.has(t));
  return papers.filter(p=>{
    if(!(p.relevance_score>0))return false;
    const proof=records[p.paper_id];
    const body=(p.title+" "+(proof?.summary??"")).toLowerCase();
    const words=new Set(body.match(/[a-z0-9][a-z0-9._+-]*/g)??[]);
    const context=(item.title+" "+(item.entities.product??"")).toLowerCase();
    const focuses: Array<[RegExp, RegExp]> = [
      [/prompt[ -]+injection|instruction[ -]+injection/, /prompt[ -]+injection|instruction[ -]+injection/],
      [/adversarial[ -]+suffix|suffix[ -]+attack/, /adversarial[ -]+suffix|attack[ -]+suffix|suffixes/],
      [/extract(?:ing|ion)?[ -]+training[ -]+data|training[ -]+data[ -]+extract/, /training[ -]+data[ -]+extract|extract(?:ing|ion)?[ -]+training[ -]+data/],
      [/data[ -]+poison|model[ -]+poison|backdoor|sleeper[ -]+agent/, /poison|backdoor|sleeper[ -]+agent/],
    ];
    const applicable=focuses.filter(([query])=>query.test(context));
    if (applicable.length && !applicable.every(([,candidate])=>candidate.test(body))) return false;
    return item.cve_ids.slice(0,1).some(c=>words.has(c.toLowerCase())) || (applicable.length > 0 && productTerms.length === 0)
      || anchors.some(a=>words.has(a)||p.evidence_terms?.includes(a));
  });
}

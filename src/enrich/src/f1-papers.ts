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
  /**
   * 相关度打分用的上下文（默认等于检索短语）。
   * 检索短语为了命中率用产品锚点，打分上下文用标题+产品+CVE——
   * 否则“查得到”和“算得准”会互相打架（实测产品词查询让所有论文 relevance 归零）。
   */
  relevanceContext?: string;
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
  if (isOffline(opts.offline)) return replayFixture(q, "offline_flag", traceId, opts.emit, opts.relevanceContext);
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
        const scoringContext = opts.relevanceContext?.trim() ? opts.relevanceContext.trim() : q;
        const result: PapersResult = { papers: parseArxivAtom(xml, scoringContext), paper_records: arxivPaperRecords(xml), source_evidence: { url, sha256: sha256(xml), text: xml } };
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
  return replayFixture(q, lastTrigger, traceId, opts.emit, opts.relevanceContext);
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
  relevanceContext?: string,
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
  const scoringContext = relevanceContext?.trim() ? relevanceContext.trim() : query;
  return { papers: parseArxivAtom(xml, scoringContext), degraded_to: d.degraded_to };
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
export const PRODUCT_ALIASES: Record<string,string[]> = { "log4j-core": ["log4j", "log4j2"], "apache log4j2": ["log4j2", "log4j"], "langchain-core": ["langchain"], "langchain_core": ["langchain"] };
export const MECHANISM_TERMS = new Set(["memory","corruption","heap","stack","integer","out","bounds","read","write","access","control","privilege","escalation","authentication","bypass","improper","incorrect","validation","handling","management","information","disclosure"]);
/**
 *  identity 锚点：产品名优先（log4j 这样的产品词是身份），机制词（out-of-bounds 等）不是身份。
 *  产品缺失时才退回到标题里区分度高的词。锚点是“必要条件”，不是“相关”的保证。
 */
export function paperAnchorTerms(item: Pick<IntelItem,"title"|"entities"|"cve_ids">): { productTerms: string[]; anchors: string[] } {
  // A known product is mandatory when available: mechanism words such as memory/corruption are not product identity.
  const product=(item.entities.product??"").toLowerCase().trim();
  const productTerms=[...(product.match(/[a-z][a-z0-9._+-]*/g)??[]), ...(PRODUCT_ALIASES[product]??[])];
  const anchorText=productTerms.length ? productTerms.join(" ") : item.title;
  const anchors=[...new Set(anchorText.toLowerCase().match(/[a-z][a-z0-9._+-]*/g)??[])].filter(t=>t.length>=3&&!GENERIC_PAPER_TERMS.has(t)&&!MECHANISM_TERMS.has(t));
  return { productTerms: [...new Set(productTerms)], anchors: [...new Set(anchors)] };
}
/**
 *  arXiv 查询词：**不能用整段标题做精确短语匹配**（实测：任何标题短语都返回 0 条，
 *  因为 arXiv 全文检索不收录厂商标题原文）。要用身份锚点拼查询——产品词优先，
 *  因为实测产品词（log4j）能稳定召回真实论文，而 CVE 编号短语常常召不回。
 */
/**
 * 描述性/皮钦产品词表：KEV 的 product 字段大量是 "Multiple Products"、"Core"、
 * "Commerce and Magento" 这类**类别词**，不是产品身份。用它们做 arXiv 检索会召回
 * 同名旧论文（实测判相关率 100%，全是假阳性），所以必须先剔除。
 */
export const DESCRIPTIVE_PRODUCT_TERMS = new Set([
  "multiple","products","product","core","commerce","orchestrator","server","servers","client","clients",
  "manager","platform","platforms","device","devices","system","systems","software","app","apps","application",
  "framework","library","module","plugin","plugins","service","services","suite","tool","tools","web","cloud",
  "stack","engine","agent","host","hosts","node","nodes","gateway","proxy","router","switch","firewall",
  "console","desktop","mobile","phone","tablet","browser","editor","viewer","player","runtime","kernel",
  "driver","firmware","hardware","chip","cpu","gpu","memory","storage","database","cache","queue",
  "protocol","interface","api","sdk","library","component","components","engine","extension",
  "switches","gateways","routers","clusters","containers","endpoints","tenants","workspaces",
  "secure","security","virtual","private","public","managed","advanced","enterprise","unified",
]);
/** 真正的身份锚点：长度够、不是描述词、不是机制词、不是通用安全词。 */
export function isDistinctiveAnchor(term: string): boolean {
  const t = term.toLowerCase().trim();
  if (t.length < 4) return false;
  if (DESCRIPTIVE_PRODUCT_TERMS.has(t)) return false;
  // 复数形式同样没有区分度（GS1900 Series Switches → switches）。
  if (t.endsWith("s") && DESCRIPTIVE_PRODUCT_TERMS.has(t.slice(0, -1))) return false;
  if (GENERIC_PAPER_TERMS.has(t)) return false;
  if (MECHANISM_TERMS.has(t)) return false;
  // "out-of-bounds"/"use_after_free" 这类连字符机制词整体不是身份：拆开后每一段都必须有区分度。
  const parts = t.split(/[^a-z0-9]+/).filter(Boolean);
  if (parts.length > 1 && parts.every(part => !isDistinctiveAnchor(part))) return false;
  return true;
}
export function buildPaperQuery(item: Pick<IntelItem,"title"|"entities"|"cve_ids">): string {
  const { productTerms, anchors } = paperAnchorTerms(item);
  const preferred = productTerms.length ? productTerms : anchors;
  // 皮钦产品词不是身份：用它们检索只会召回同名旧论文（实测 100% 假阳性）。
  // "multiple products"/"core"/"commerce" 这类描述性词组必须先被剔除。
  const distinctive = preferred.filter(isDistinctiveAnchor);
  if (!distinctive.length) return "";
  // 只取区分度最高的一个身份词做短语检索：多词 AND 会进一步压低召回（实测 0 条）。
  const primary = distinctive.slice().sort((a, b) => b.length - a.length)[0]!;
  return primary;
}
/**.Entity/identifier anchor is necessary, not a guarantee of scientific relevance. */
export function anchoredPapers(item: Pick<IntelItem,"title"|"entities"|"cve_ids">, papers: PaperLink[], records: PapersResult["paper_records"] = {}): PaperLink[] {
  const { productTerms, anchors } = paperAnchorTerms(item);
  // 只用“区分度足够”的锚点做判断：描述性产品词（multiple/core/commerce）
  // 与任何论文共现都不构成相关性（实测 100% 假阳性）。
  const strongAnchors = anchors.filter(isDistinctiveAnchor);
  // CVE 锚点命中的论文要把该编号计入证据词并据实重算相关度：
  // 检索词没出现在论文里 relevance_score 会是 0，但这篇论文明确点了该 CVE，
  // 是最强证据；把它当 0 分挡在投影门外是错的（实测弄丢真相关论文）。
  const upgraded = new Map<PaperLink, PaperLink>();
  const kept = papers.filter(p=>{
    // CVE 编号是最强锚点，必须先于相关性打分判断：否则论文明明提到该 CVE，
    // 却会因为“检索词没出现在标题里”被词重合度门槛提前丢掉。
    const body0=(p.title+" "+(records[p.paper_id]?.summary??"")).toLowerCase();
    const words0=new Set(body0.match(/[a-z0-9][a-z0-9._+-]*/g)??[]);
    const cveTerm=item.cve_ids.slice(0,1).find(c=>words0.has(c.toLowerCase()));
    if(cveTerm!==undefined){
      const rel=relevanceOf(cveTerm,body0);
      upgraded.set(p,compact({...p,relevance_score:round2(Math.max(p.relevance_score,rel.score)),evidence_terms:[...new Set([...(p.evidence_terms??[]),...rel.terms])]}));
      return true;
    }
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
    // 相关性判据（三层，逐层变严）：
    //  1) 论文正文出现该 CVE 编号——最强锚点；
    //  2) 论文出现完整产品短语（多词产品名的全部词都出现，顺序不限）；
    //  3) 论文出现区分度足够的产品锚点词，且同时命中至少一个机制词或漏洞类词。
    // 只共用 "core"/"multiple" 这类描述词的一律判不相关。
    const cveHit = item.cve_ids.slice(0,1).some(c=>words.has(c.toLowerCase()));
    if (cveHit) return true;
    if (!strongAnchors.length) return applicable.length > 0 && productTerms.length === 0;
    const anchorHit = strongAnchors.some(a=>words.has(a)||p.evidence_terms?.includes(a));
    if (!anchorHit) return false;
    const productPhrase = productTerms.length > 1 && productTerms.every(t=>words.has(t.toLowerCase()));
    if (productPhrase) return true;
    const mechanismHit = [...MECHANISM_TERMS].some(m=>words.has(m));
    const vulnClassHit = /vulnerab|exploit|cve|security flaw|attack/.test(body);
    return mechanismHit || vulnClassHit;
  });
  return kept.map(p=>upgraded.get(p)??p);
}

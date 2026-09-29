import { createHash } from "node:crypto";

export type PageProvider = "direct" | "firecrawl" | "last_good";
export interface FetchStageFailure { stage: "direct" | "firecrawl"; reason: string }
export interface PageSnapshot {
  source_url: string;
  final_url: string;
  title: string;
  text: string;
  fetched_at: string;
  provider: "direct" | "firecrawl";
  content_sha256: string;
}
export interface PageFetchResult extends PageSnapshot {
  fetched_via: PageProvider;
  stale: boolean;
  degraded_to?: "firecrawl" | "last_good_snapshot";
  fallback_reasons: FetchStageFailure[];
}
export interface ControlledFetchOptions {
  /** 外网采集必须显式开启；默认关闭。 */
  enabled?: boolean;
  /** 精确 host allowlist；不支持通配符或任意 URL。 */
  allowed_hosts: readonly string[];
  firecrawl_api_key?: string;
  firecrawl_base_url?: string;
  /** API token 仅能发送到精确可信 endpoint host；默认 api.firecrawl.dev。 */
  firecrawl_api_hosts?: readonly string[];
  direct_retries?: number;
  retry_delay_ms?: number;
  timeout_ms?: number;
  max_bytes?: number;
  min_text_chars?: number;
  /** 默认读取 robots.txt；仅测试可显式关闭。 */
  respect_robots?: boolean;
  last_good?: PageSnapshot;
  fetch_impl?: typeof fetch;
  now?: () => Date;
}

export class UnsafePageUrlError extends Error {
  constructor(message: string) { super(message); this.name = "UnsafePageUrlError"; }
}
export class ControlledFetchError extends Error {
  readonly failures: FetchStageFailure[];
  constructor(url: string, failures: FetchStageFailure[]) {
    super("受控采集失败：" + url + "；" + failures.map((f) => f.stage + ": " + f.reason).join("；"));
    this.name = "ControlledFetchError";
    this.failures = failures;
  }
}
class PermanentFetchError extends Error {}
class RetryableFetchError extends Error {}

function normalizeHost(host: string): string { return host.toLowerCase().replace(/\.$/, ""); }
function assertAllowedUrl(rawUrl: string, allowedHosts: readonly string[]): URL {
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new UnsafePageUrlError("URL 格式无效"); }
  const host = normalizeHost(url.hostname);
  const allow = new Set(allowedHosts.map(normalizeHost));
  const isIpLiteral = /^\[|^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) {
    throw new UnsafePageUrlError("只允许无凭据的 HTTPS URL（端口限 443）");
  }
  if (isIpLiteral || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new UnsafePageUrlError("拒绝 IP / 本机 / 内网 host");
  }
  if (!allow.has(host)) throw new UnsafePageUrlError("host 不在精确允许列表中：" + host);
  return url;
}
function decodeEntities(text: string): string {
  return text
    .replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">").replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_m, n: string) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, n: string) => String.fromCodePoint(parseInt(n, 16)));
}
export function htmlToText(html: string): { title: string; text: string } {
  const title = decodeEntities((html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i)?.[1] ?? "").replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
  const text = decodeEntities(html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|noscript|svg)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ")
    .replace(/<\s*br\b[^>]*>/gi, "\n")
    .replace(/<\/(?:p|h[1-6]|li|section|article|div|tr)\s*>/gi, "\n")
    .replace(/<[^>]*>/g, " "))
    .replace(/[ \t\f\v]+/g, " ").replace(/\n\s*\n/g, "\n").trim();
  return { title, text };
}
function sha256(text: string): string { return createHash("sha256").update(text, "utf8").digest("hex"); }
function bytes(text: string): number { return new TextEncoder().encode(text).byteLength; }
async function readLimited(response: Response, limit: number): Promise<string> {
  const length = Number(response.headers.get("content-length") ?? 0);
  if (length > limit) throw new PermanentFetchError("响应超过大小限制");
  if (!response.body) {
    const text = await response.text();
    if (bytes(text) > limit) throw new PermanentFetchError("响应超过大小限制");
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parts: string[] = [];
  let total = 0;
  while (true) {
    const part = await reader.read();
    if (part.done) break;
    total += part.value.byteLength;
    if (total > limit) {
      await reader.cancel();
      throw new PermanentFetchError("响应超过大小限制");
    }
    parts.push(decoder.decode(part.value, { stream: true }));
  }
  parts.push(decoder.decode());
  return parts.join("");
}
function asMessage(error: unknown): string { return error instanceof Error ? error.message : String(error); }
function stamp(now: () => Date): string { return now().toISOString(); }
function makeSnapshot(sourceUrl: string, finalUrl: string, title: string, text: string, fetchedAt: string, provider: "direct" | "firecrawl"): PageSnapshot {
  return { source_url: sourceUrl, final_url: finalUrl, title, text, fetched_at: fetchedAt, provider, content_sha256: sha256(text) };
}


function robotsPatternMatches(pattern: string, path: string): boolean {
  if (!pattern) return false;
  const anchored = pattern.endsWith("$");
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const escaped = body.replace(/[|\\{}()[\]^$+?.]/g, "\\async function fetchDirect(url: string, options: ControlledFetchOptions, now: () => Date): Promise<PageSnapshot> {").replace(/\*/g, ".*");
  return new RegExp("^" + escaped + (anchored ? "$" : "")).test(path);
}
function robotsAllows(robots: string, path: string): boolean {
  type Rule = { allow: boolean; pattern: string };
  type Group = { agents: string[]; rules: Rule[] };
  const groups: Group[] = [];
  let current: Group = { agents: [], rules: [] };
  for (const rawLine of robots.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, "").trim();
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name === "user-agent") {
      if (current.rules.length > 0) {
        groups.push(current);
        current = { agents: [], rules: [] };
      }
      current.agents.push(value.toLowerCase());
    } else if ((name === "allow" || name === "disallow") && current.agents.length > 0 && value.length > 0) {
      current.rules.push({ allow: name === "allow", pattern: value });
    }
  }
  if (current.agents.length > 0) groups.push(current);
  const exact = groups.filter((group) => group.agents.some((agent) => agent === "safetracebot" || agent.startsWith("safetracebot/")));
  const selected = exact.length > 0 ? exact : groups.filter((group) => group.agents.includes("*"));
  const matches = selected.flatMap((group) => group.rules)
    .filter((rule) => robotsPatternMatches(rule.pattern, path))
    .sort((a, b) => b.pattern.replace(/[\*$]/g, "").length - a.pattern.replace(/[\*$]/g, "").length || Number(b.allow) - Number(a.allow));
  return matches.length === 0 || matches[0]!.allow;
}
async function ensureRobotsAllowed(url: string, options: ControlledFetchOptions): Promise<void> {
  const fetchImpl = options.fetch_impl ?? fetch;
  const origin = new URL(url).origin;
  let current = new URL("/robots.txt", url).toString();
  try {
    let response: Response | undefined;
    for (let hop = 0; hop <= 2; hop += 1) {
      response = await fetchImpl(current, {
        method: "GET",
        headers: { accept: "text/plain", "user-agent": "SafeTraceBot/0.1" },
        redirect: "manual",
        signal: AbortSignal.timeout(options.timeout_ms ?? 12_000),
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        if (hop === 2) throw new UnsafePageUrlError("robots.txt 重定向过多");
        const location = response.headers.get("location");
        if (!location) throw new UnsafePageUrlError("robots.txt 重定向缺少 Location");
        const target = assertAllowedUrl(new URL(location, current).toString(), options.allowed_hosts);
        if (target.origin !== origin) throw new UnsafePageUrlError("robots.txt 不允许跨 host 重定向");
        current = target.toString();
        continue;
      }
      break;
    }
    if (!response) throw new UnsafePageUrlError("robots.txt 无响应");
    if (response.status === 404 || response.status === 410) return;
    if (!response.ok) throw new UnsafePageUrlError("robots.txt HTTP " + response.status + "；按 fail-closed 拒绝抓取");
    const body = await readLimited(response, Math.min(options.max_bytes ?? 2_000_000, 128_000));
    const target = new URL(url);
    if (!robotsAllows(body, target.pathname + target.search)) throw new UnsafePageUrlError("robots.txt disallow 该路径");
  } catch (error) {
    if (error instanceof UnsafePageUrlError) throw error;
    throw new UnsafePageUrlError("robots.txt 检查失败；按 fail-closed 拒绝抓取：" + asMessage(error));
  }
}

async function fetchDirect(url: string, options: ControlledFetchOptions, now: () => Date): Promise<PageSnapshot> {
  const fetchImpl = options.fetch_impl ?? fetch;
  const retries = Math.max(0, Math.min(5, options.direct_retries ?? 2));
  const timeout = options.timeout_ms ?? 12_000;
  const maxBytes = options.max_bytes ?? 2_000_000;
  let lastError: unknown = new Error("direct fetch failed");
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      let current = url;
      let response: Response | undefined;
      for (let hop = 0; hop <= 3; hop += 1) {
        response = await fetchImpl(current, {
          method: "GET",
          headers: { accept: "text/html, application/xhtml+xml, text/plain;q=0.9" },
          redirect: "manual",
          signal: AbortSignal.timeout(timeout),
        });
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          if (hop === 3) throw new PermanentFetchError("重定向层数超过 3");
          const location = response.headers.get("location");
          if (!location) throw new PermanentFetchError("重定向缺少 Location");
          const target = assertAllowedUrl(new URL(location, current).toString(), options.allowed_hosts);
          if (target.origin !== new URL(url).origin) throw new UnsafePageUrlError("页面禁止跨 host 重定向");
          current = target.toString();
          continue;
        }
        break;
      }
      if (!response) throw new RetryableFetchError("未收到 HTTP 响应");
      if (response.status === 429 || response.status >= 500) throw new RetryableFetchError("HTTP " + response.status);
      if (!response.ok) throw new PermanentFetchError("HTTP " + response.status);
      const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
      if (contentType && !contentType.includes("text/html") && !contentType.includes("application/xhtml+xml") && !contentType.startsWith("text/plain")) {
        throw new PermanentFetchError("不支持的 content-type：" + contentType);
      }
      const raw = await readLimited(response, maxBytes);
      const parsed = htmlToText(raw);
      return makeSnapshot(url, current, parsed.title, parsed.text, stamp(now), "direct");
    } catch (error) {
      if (error instanceof UnsafePageUrlError || error instanceof PermanentFetchError) throw error;
      lastError = error;
      if (attempt >= retries) break;
      const wait = Math.max(0, options.retry_delay_ms ?? 250) * (2 ** attempt);
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
    }
  }
  throw lastError;
}

async function fetchFirecrawl(url: string, options: ControlledFetchOptions, now: () => Date): Promise<PageSnapshot> {
  const base = options.firecrawl_base_url ?? "https://api.firecrawl.dev/v2/scrape";
  const endpoint = assertAllowedUrl(base, options.firecrawl_api_hosts ?? ["api.firecrawl.dev"]);
  const response = await (options.fetch_impl ?? fetch)(endpoint.toString(), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + options.firecrawl_api_key },
    body: JSON.stringify({ url, formats: ["markdown"], onlyMainContent: true }),
    redirect: "manual",
    signal: AbortSignal.timeout(options.timeout_ms ?? 12_000),
  });
  if (!response.ok) {
    if (response.status === 429 || response.status >= 500) throw new RetryableFetchError("Firecrawl HTTP " + response.status);
    throw new PermanentFetchError("Firecrawl HTTP " + response.status);
  }
  const raw = await readLimited(response, options.max_bytes ?? 2_000_000);
  let json: any;
  try { json = JSON.parse(raw); } catch { throw new PermanentFetchError("Firecrawl 响应不是 JSON"); }
  if (json?.success === false) throw new PermanentFetchError("Firecrawl 返回 success=false");
  const data = json?.data ?? json;
  const markdown = typeof data?.markdown === "string" ? data.markdown.trim() : "";
  if (!markdown) throw new PermanentFetchError("Firecrawl 未返回 markdown");
  const metadata = data?.metadata ?? {};
  const finalUrl = String(metadata.sourceURL ?? metadata.url ?? data.url ?? url);
  assertAllowedUrl(finalUrl, options.allowed_hosts);
  const title = typeof metadata.title === "string" ? metadata.title.trim() : "";
  return makeSnapshot(url, finalUrl, title, markdown, stamp(now), "firecrawl");
}

/**
 * 受控的单页抓取链：allowlist → 直连重试 → Firecrawl（需显式 key）→ last-good 快照。
 * 不遍历链接、不执行页面脚本；线上失败不会回放 fixture。
 */
export async function fetchPageWithFallback(rawUrl: string, options: ControlledFetchOptions): Promise<PageFetchResult> {
  const sourceUrl = assertAllowedUrl(rawUrl, options.allowed_hosts).toString();
  if (options.enabled !== true) throw new ControlledFetchError(sourceUrl, [{ stage: "direct", reason: "web collector 默认关闭；须显式 enabled=true" }]);
  if (options.respect_robots !== false) await ensureRobotsAllowed(sourceUrl, options);
  const minChars = Math.max(1, options.min_text_chars ?? 80);
  const now = options.now ?? (() => new Date());
  const failures: FetchStageFailure[] = [];
  try {
    const direct = await fetchDirect(sourceUrl, options, now);
    if (direct.text.length >= minChars) return { ...direct, fetched_via: "direct", stale: false, fallback_reasons: failures };
    failures.push({ stage: "direct", reason: "页面正文过短（可能是 JS 壳或拦截页）" });
  } catch (error) {
    if (error instanceof UnsafePageUrlError) throw error;
    failures.push({ stage: "direct", reason: asMessage(error) });
  }
  if (options.firecrawl_api_key?.trim()) {
    try {
      const scraped = await fetchFirecrawl(sourceUrl, options, now);
      if (scraped.text.length < minChars) throw new PermanentFetchError("Firecrawl 正文过短");
      return { ...scraped, fetched_via: "firecrawl", stale: false, degraded_to: "firecrawl", fallback_reasons: failures };
    } catch (error) {
      if (error instanceof UnsafePageUrlError) throw error;
      failures.push({ stage: "firecrawl", reason: asMessage(error) });
    }
  } else {
    failures.push({ stage: "firecrawl", reason: "FIRECRAWL_API_KEY 未配置；云抓取保持关闭" });
  }
  const cached = options.last_good;
  if (cached && cached.source_url === sourceUrl && cached.text.trim().length >= minChars) {
    if (cached.content_sha256 !== sha256(cached.text)) {
      failures.push({ stage: "direct", reason: "last-good 快照 SHA-256 校验失败" });
    } else {
      try {
        assertAllowedUrl(cached.final_url, options.allowed_hosts);
        return { ...cached, fetched_via: "last_good", stale: true, degraded_to: "last_good_snapshot", fallback_reasons: failures };
      } catch {
        failures.push({ stage: "direct", reason: "last-good final_url 不在允许列表中" });
      }
    }
  }
  throw new ControlledFetchError(sourceUrl, failures);
}

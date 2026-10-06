/**
 * 预富化（baseline）：只依据本地已抓到的原始记录，把“不依赖 NIST v3.1 分数”的事实整理成结构化信息。
 * 分数一律按版本标注，绝不把 v4.0/v2 冒充成 v3.1；缺什么由 gaps 明确给出。
 */
export interface BaselineReference { url: string; tags: string[] }
export interface BaselineScoreVersion { version: string; base: number | null; vector: string | null; source: string; metric_type: string; verified: boolean }
export interface BaselineKev { listed: true; date_added: string; due_date: string | null; ransomware: boolean; required_action: string | null }
export interface BaselineUsn { notice_id: string; packages: string[] }
export interface BaselineFacts {
  description: string | null
  cwe: string[]
  references: BaselineReference[]
  score_versions: BaselineScoreVersion[]
  kev: BaselineKev | null
  usn: BaselineUsn[] | null
  source_ids: string[]
}
export interface BaselineGap { dimension: string; status: "proven" | "missing"; reason: string }

type Obj = Record<string, unknown>
const obj = (v: unknown): Obj | null => v !== null && typeof v === "object" && !Array.isArray(v) ? v as Obj : null
const arr = (v: unknown): unknown[] => Array.isArray(v) ? v : []
const str = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0
const num = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v)
const httpUrl = (v: unknown): v is string => { if (!str(v) || v.length > 2048) return false; try { const u = new URL(v); return u.protocol === "https:" && !u.username && !u.password; } catch { return false } }
const VERSION_OF: Record<string, string> = { cvssMetricV31: "v3.1", cvssMetricV30: "v3.0", cvssMetricV40: "v4.0", cvssMetricV2: "v2" }
const METRIC_TYPE: Record<string, string> = { Primary: "Primary（官方主指标）", Secondary: "Secondary（第三方）" }
function metricType(v: unknown): string { return str(v) ? (METRIC_TYPE[v] ?? String(v)) : "未标注" }
function scoreOf(metric: Obj): { base: number | null; vector: string | null } {
  const data = obj(metric.cvssData)
  const base = num(data?.baseScore) ? Number(data!.baseScore) : null
  const vector = str(data?.vectorString) ? String(data!.vectorString) : null
  return { base, vector }
}
export function parseNvdRecords(bytes: Uint8Array): Map<string, Obj> {
  const out = new Map<string, Obj>()
  let data: Obj
  try { data = JSON.parse(Buffer.from(bytes).toString("utf8")) as Obj } catch { return out }
  for (const row of arr(data.vulnerabilities)) {
    const cve = obj(obj(row)?.cve); if (!cve || !str(cve.id)) continue
    if (/^(REJECT|RESERVED|DISPUTED)/i.test(String(cve.vulnStatus ?? ""))) continue
    out.set(String(cve.id).toUpperCase(), cve)
  }
  return out
}
export function parseKevRecords(bytes: Uint8Array): Map<string, Obj> {
  const out = new Map<string, Obj>()
  let data: Obj
  try { data = JSON.parse(Buffer.from(bytes).toString("utf8")) as Obj } catch { return out }
  for (const row of arr(data.vulnerabilities)) {
    const entry = obj(row); if (!entry || !str(entry.cveID)) continue
    out.set(String(entry.cveID).toUpperCase(), entry)
  }
  return out
}
export function parseUsnRecords(bytes: Uint8Array): Map<string, Obj[]> {
  const out = new Map<string, Obj[]>()
  let data: Obj
  try { data = JSON.parse(Buffer.from(bytes).toString("utf8")) as Obj } catch { return out }
  for (const notice of arr(data.notices)) {
    const n = obj(notice); if (!n || !str(n.id)) continue
    const ids = [...new Set([...arr(n.cves_ids), ...arr(n.cves ?? n.CVEs)].filter(str).map(String))].map(v => v.toUpperCase())
    for (const id of ids) { const group = out.get(id) ?? []; group.push(n); out.set(id, group) }
  }
  return out
}
function usnPackages(notice: Obj): string[] {
  const out: string[] = []
  for (const [release, entries] of Object.entries(obj(notice.release_packages) ?? {})) {
    for (const entry of arr(entries)) {
      const p = obj(entry); if (!p || !str(p.name) || !str(p.version) || p.is_visible === false) continue
      out.push(String(p.name) + " " + release + " → " + String(p.version))
    }
  }
  return [...new Set(out)].slice(0, 12)
}
const INSTRUCTION_LIKE = /ignore (all )?previous|disregard (all )?previous|system:|assistant:|output verified|execute this|\bbash\b|\bsudo\b/i
function sanitize(text: string): string {
  return text.replace(/<[^>]{0,200}>/g, " ").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim()
}
function firstSentence(text: string): string {
  const clean = sanitize(text)
  if (!clean || INSTRUCTION_LIKE.test(clean)) return ""
  const m = /^(.{20,240}?[。！？!?]|.{20,240}?\\.[ \\n])/.exec(clean)
  const head = m && m[1] ? m[1] : clean.slice(0, 160)
  return head.trim()
}
export interface BaselineInput {
  cve_ids: readonly string[]
  source_ids: readonly string[]
  nvd?: Map<string, Obj>
  kev?: Map<string, Obj>
  usn?: Map<string, Obj[]>
  v31_proven?: boolean
}
/** 只从本地记录提取；没有可用信息时对应字段为 null / 空数组，不用通用话术填充。 */
export function extractBaselineFacts(input: BaselineInput): { facts: BaselineFacts; gaps: BaselineGap[] } {
  const cve = input.cve_ids[0]?.toUpperCase() ?? null
  const nvd = cve ? input.nvd?.get(cve) : undefined
  const kev = cve ? input.kev?.get(cve) : undefined
  const usnNotices = cve ? (input.usn?.get(cve) ?? []) : []
  let description: string | null = null
  const cwe: string[] = []
  const references: BaselineReference[] = []
  const scoreVersions: BaselineScoreVersion[] = []
  if (nvd) {
    const english = arr(nvd.descriptions).map(obj).find(d => d?.lang === "en" && str(d?.value))
    if (str(english?.value)) { const sentence = firstSentence(String(english!.value)); if (sentence) description = sentence; }
    for (const w of arr(nvd.weaknesses)) for (const d of arr(obj(w)?.description)) { const v = obj(d)?.value; if (str(v)) cwe.push(String(v)) }
    for (const r of arr(nvd.references)) { const ref = obj(r); if (ref && httpUrl(ref.url)) references.push({ url: String(ref.url), tags: arr(ref.tags).filter(str).map(String).slice(0, 6) }) }
    for (const [key, version] of Object.entries(VERSION_OF)) {
      for (const m of arr(obj(nvd.metrics)?.[key])) {
        const metric = obj(m); if (!metric) continue
        const { base, vector } = scoreOf(metric)
        const verified = input.v31_proven === true && version === "v3.1" && String(metric.source).toLowerCase() === "nvd@nist.gov" && metric.type === "Primary";
        scoreVersions.push({ version, base, vector, source: str(metric.source) ? String(metric.source) : "未标注来源", metric_type: metricType(metric.type), verified })
      }
    }
  }
  if (!description && kev && str(kev.shortDescription)) { const sentence = firstSentence(String(kev.shortDescription)); if (sentence) description = sentence; }
  if (!cwe.length && kev) for (const c of arr(kev.cwes)) if (str(c)) cwe.push(String(c))
  const kevFacts: BaselineKev | null = kev && str(kev.dateAdded) ? { listed: true, date_added: String(kev.dateAdded), due_date: str(kev.dueDate) ? String(kev.dueDate) : null, ransomware: kev.knownRansomwareCampaignUse === "Known", required_action: str(kev.requiredAction) ? firstSentence(String(kev.requiredAction)) : null } : null
  const usn: BaselineUsn[] | null = usnNotices.length ? usnNotices.map(n => ({ notice_id: String(n.id), packages: usnPackages(n) })) : null
  const facts: BaselineFacts = { description, cwe: [...new Set(cwe)].slice(0, 12), references: references.slice(0, 8), score_versions: scoreVersions.slice(0, 12), kev: kevFacts, usn, source_ids: [...new Set(input.source_ids)] }
  const gaps: BaselineGap[] = []
  const versions = [...new Set(scoreVersions.map(s => s.version))]
  const hasNvd = Boolean(nvd)
  if (input.v31_proven) gaps.push({ dimension: "cvss_v31", status: "proven", reason: "已从本地 NVD 原文复核 NIST 主 v3.1 指标并发布" })
  else if (!hasNvd) gaps.push({ dimension: "cvss_v31", status: "missing", reason: "本地 NVD 文档中没有该 CVE 记录；需要联网查询 NVD" })
  else if (!versions.includes("v3.1")) gaps.push({ dimension: "cvss_v31", status: "missing", reason: versions.length ? "本地 NVD 文档中该 CVE 只有 " + versions.join("、") + " 分数，没有 NIST 主 v3.1 指标" : "本地 NVD 文档中该 CVE 没有任何 CVSS 指标" })
  else gaps.push({ dimension: "cvss_v31", status: "missing", reason: "本地 NVD 文档有 v3.1 指标，但尚无 NIST 主指标或未完成复核发布" })
  gaps.push({ dimension: "paper", status: "missing", reason: "未联网检索 arXiv；论文维度尚无成功记录" })
  gaps.push({ dimension: "epss", status: "missing", reason: "未联网查询 FIRST；EPSS 维度尚无成功记录" })
  if (usn && usn.length) gaps.push({ dimension: "remediation", status: "proven", reason: "已从 Ubuntu USN 公告提取修复版本" })
  else if (kevFacts) gaps.push({ dimension: "remediation", status: "missing", reason: "CISA KEV 只给出通用处置建议，没有厂商修复版本" })
  else gaps.push({ dimension: "remediation", status: "missing", reason: "本地没有 USN 修复公告，也没有 KEV 记录" })
  return { facts, gaps }
}

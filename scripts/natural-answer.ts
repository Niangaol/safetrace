/**
 * 确定性自然语言结论：只依据已核验证据的结构化事实生成中文人话，绝不编造。
 * 没有可用信息时返回 null（不用空话填空）。
 */
export interface NaturalEvidenceChunk {
  chunk_id: string
  doc_type?: string
  text: string
}
export interface NaturalRemediation {
  source_id?: string
  validation_level?: string | null
  actions?: readonly string[]
  fixed_packages?: readonly { name: string; version: string; release?: string }[]
}
export interface NaturalInput {
  cve_id?: string | null
  chunks: readonly NaturalEvidenceChunk[]
  remediation?: readonly NaturalRemediation[]
  askRemediation?: boolean
}
export function severityBand(base: number): "critical" | "high" | "medium" | "low" | null {
  if (!Number.isFinite(base) || base <= 0 || base > 10) return null
  if (base >= 9) return "critical"
  if (base >= 7) return "high"
  if (base >= 4) return "medium"
  return "low"
}
const BAND_LABEL: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危" }
function vectorFacts(vector: string): string[] {
  const parts = vector.split("/").slice(1)
  const get = (prefix: string) => parts.find(p => p.startsWith(prefix))?.split(":")[1]
  const out: string[] = []
  const av = get("AV")
  if (av === "N") out.push("可通过网络远程利用")
  else if (av === "A") out.push("可通过相邻网络利用")
  else if (av === "L") out.push("需要本地访问才能利用")
  else if (av === "P") out.push("需要物理接触才能利用")
  const ac = get("AC")
  if (ac === "L") out.push("利用难度低")
  else if (ac === "H") out.push("利用难度较高")
  const pr = get("PR")
  if (pr === "N") out.push("不需要特殊权限")
  else if (pr === "L") out.push("只需要低权限")
  else if (pr === "H") out.push("需要较高权限")
  const ui = get("UI")
  if (ui === "N") out.push("不需要用户交互")
  else if (ui === "R") out.push("需要用户交互")
  return out
}
const INSTRUCTION_LIKE = /ignore (all )?previous|disregard (all )?previous|system:|assistant:|output verified|execute this|\bbash\b|\bsudo\b/i
function sanitize(text: string): string {
  return text.replace(/<[^>]{0,200}>/g, " ").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim()
}
function firstSentence(text: string): string {
  const clean = sanitize(text)
  if (!clean || INSTRUCTION_LIKE.test(clean)) return ""
  const window = clean.slice(0, 160)
  const ends = [...window.matchAll(/[。！？!?]|\.(?=\s|$)/g)]
  const last = ends.length ? ends[ends.length - 1]!.index! + 1 : Math.min(120, clean.length)
  return clean.slice(0, Math.max(10, last)).trim()
}
function cvssChunk(chunk: NaturalEvidenceChunk): { base: number; vector: string; kev?: boolean; maturity?: string } | null {
  const match = /^CVE-\d{4}-\d{4,} CVSS v3 base score: (\d+(?:\.\d+)?)\n(\{[\s\S]*\})$/.exec(chunk.text)
  if (!match || !match[1] || !match[2]) return null
  try {
    const parsed = JSON.parse(match[2]!) as { cvss_v3_vector?: unknown; kev_flag?: unknown; exploit_maturity?: unknown }
    const base = Number(match[1])
    if (!Number.isFinite(base) || typeof parsed.cvss_v3_vector !== "string") return null
    return { base, vector: parsed.cvss_v3_vector, kev: parsed.kev_flag === true, maturity: typeof parsed.exploit_maturity === "string" ? parsed.exploit_maturity : undefined }
  } catch { return null }
}
export function naturalConclusion(input: NaturalInput): string | null {
  const parts: string[] = []
  const cvss = input.chunks.map(cvssChunk).find((value): value is NonNullable<typeof value> => value !== null)
  if (cvss) {
    const band = severityBand(cvss.base)
    const facts = vectorFacts(cvss.vector)
    const head = input.cve_id ? input.cve_id + " 的 CVSS v3 基础评为 " + cvss.base.toFixed(1) + " 分" : "该漏洞的 CVSS v3 基础评为 " + cvss.base.toFixed(1) + " 分"
    parts.push(head + (band ? "（" + BAND_LABEL[band] + "）" : "") + (facts.length ? "：" + facts.join("，") : "") + "。")
    if (cvss.kev) parts.push("该漏洞已被 CISA 列入在野利用目录，说明已经有实际攻击。")
    else if (cvss.maturity === "high") parts.push("官方评估其利用成熟度为高。")
  }
  for (const chunk of input.chunks) {
    if (cvssChunk(chunk)) continue
    if (chunk.doc_type === "vuln_advisory" || /CVE-\d{4}-\d{4,}/.test(chunk.text)) {
      const withoutId = chunk.text.replace(/^CVE-\d{4}-\d{4,}\s*/, "")
      const sentence = firstSentence(withoutId || chunk.text)
      if (sentence && !parts.some(p => p.includes(sentence.slice(0, 12)))) parts.push(sentence.endsWith("。") || sentence.endsWith(".") ? sentence : sentence + "。")
    }
  }
  if (input.askRemediation) {
    for (const item of input.remediation ?? []) {
      const fixed = (item.fixed_packages ?? []).map(p => p.name + (p.release ? " " + p.release + " 的 " + p.version : " " + p.version))
      if (fixed.length) parts.push("厂商公告的修复版本：" + fixed.join("、") + "（以上为厂商声明，尚未验证）。")
      for (const action of item.actions ?? []) parts.push("机构 / 厂商建议：" + firstSentence(action) + "（以上为机构声明，尚未验证）。")
    }
  }
  const text = parts.join("")
  if (!text.trim()) return null
  return text.length > 400 ? text.slice(0, 397) + "…" : text
}

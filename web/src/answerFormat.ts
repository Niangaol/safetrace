/**
 * 把「四段式答案」解析成带结构的信息块，用于**突出关键内容**。
 *
 * 为什么需要：后端返回的是纯文本 markdown 风格（`\n\n` 分段、`**粗体**`、`[S1]` 引用、
 * 每段以"结论：/依据：/推理链：/建议动作："开头）。直接 `{{ answer }}` 渲染会有三个问题：
 *   1. 全篇同色同字重，关键结论淹没在正文里；
 *   2. 段落标题（结论/依据/…）看不出来；
 *   3. `[S1]` 引用号只是普通字符，**点不了**，无法回指证据。
 *
 * 这里只做**保守**解析：不认识的行原样保留，绝不吞字、不臆造内容。
 */

/** 高亮类别 → 展示语义（颜色在组件里映射） */
export type HighlightKind =
  | 'heading' // 段落标题（结论/依据/…）
  | 'citation' // [S1] 引用号
  | 'value' // 版本号、CVSS、CVE 编号等硬事实
  | 'danger' // 危险动作/风险词
  | 'action' // 建议动作类

export interface InlineToken {
  text: string
  kind?: HighlightKind
  /** citation 专用：引用编号，如 "S1" */
  ref?: string
}

export interface AnswerBlock {
  /** 段落标题（有则单独一行渲染） */
  heading?: string
  /** 正文行 */
  lines: InlineToken[][]
  /** 列表项（以 - 或数字. 开头） */
  bullets?: InlineToken[][]
  /** 该段行数（含列表项），用于折叠时显示"共 N 行" */
  lineCount: number
  /** 是否默认折叠（只保留最重要的段落展开，其余收起，减少视觉噪音） */
  collapsedByDefault: boolean
}

/**
 * 默认展开的段落：读者最先要看的结论与处置动作。
 * 其余（依据 / 推理链 / 摘要 …）默认收起 —— 需要核对时再展开，而不是一屏全是字。
 */
const PRIMARY_HEADINGS = new Set(['结论', '建议动作', '建议', '风险'])

/** 在 LLM 输出里被高频使用的"硬事实"模式 —— 这些最值得被眼睛抓住 */
const VALUE_PATTERNS: { re: RegExp; kind: HighlightKind }[] = [
  // CVE / GHSA 编号
  { re: /\bCVE-\d{4}-\d{4,7}\b/g, kind: 'value' },
  { re: /\bGHSA(-[0-9a-z]{4}){3}\b/gi, kind: 'value' },
  // 版本号（0.9.3、v1.2、4.53 等）
  { re: /\bv?\d+\.\d+(?:\.\d+)?\b/g, kind: 'value' },
  // 评分与概率
  { re: /\bCVSS\s*[:：]?\s*\d+(?:\.\d+)?/gi, kind: 'value' },
  { re: /\bEPSS\s*[:：]?\s*0?\.\d+/gi, kind: 'value' },
  // 危险/行动词
  { re: /(立即|尽快|务必|切勿|不要|禁止|必须|高危|严重|紧急|风险|漏洞|攻击|执行任意代码|RCE)/g, kind: 'danger' },
  { re: /(升级|修复|缓解|打补丁|更新到|回滚|隔离|禁用)/g, kind: 'action' },
]

/** 段落标题：`结论：` / `**依据**：` / `建议动作:` 等 */
const HEADING_RE = /^\s*\*{0,2}(结论|依据|推理链|建议动作|建议|风险|影响|摘要|总结|说明)\*{0,2}\s*[:：]\s*(.*)$/

/** 引用号 `[S1]` / `[S1][S2]` */
const CITATION_RE = /\[(S\d{1,3})\]/g

/**
 * 把一行文本切成 token 序列（先摘引用号，再套高亮模式）。
 *
 * 用"逐段扫描、取最早匹配"的方式而不是简单 replace，避免多个模式互相覆盖。
 */
function tokenizeInline(raw: string): InlineToken[] {
  // 先用引用号把行切开，引用号是最高优先级（否则 S1 里的数字会被版本号规则吃掉）
  const segments: InlineToken[] = []
  let cursor = 0
  CITATION_RE.lastIndex = 0
  for (;;) {
    const m = CITATION_RE.exec(raw)
    if (!m) break
    if (m.index > cursor) {
      segments.push(...tokenizePlain(raw.slice(cursor, m.index)))
    }
    segments.push({ text: m[0], kind: 'citation', ref: m[1] })
    cursor = m.index + m[0].length
  }
  if (cursor < raw.length) segments.push(...tokenizePlain(raw.slice(cursor)))
  return segments.length ? segments : [{ text: raw }]
}

/** 对不含引用号的片段套硬事实/动作词高亮 */
function tokenizePlain(text: string): InlineToken[] {
  if (!text) return []
  type Hit = { start: number; end: number; kind: HighlightKind }
  const hits: Hit[] = []
  for (const { re, kind } of VALUE_PATTERNS) {
    re.lastIndex = 0
    for (;;) {
      const m = re.exec(text)
      if (!m) break
      hits.push({ start: m.index, end: m.index + m[0].length, kind })
      if (m[0].length === 0) re.lastIndex++ // 防零宽死循环
    }
  }
  if (!hits.length) return [{ text }]

  // 按起点排序，**重叠时保留先到的**（先声明的模式优先），避免嵌套导致文本错乱
  hits.sort((a, b) => a.start - b.start || b.end - a.end)
  const picked: Hit[] = []
  let lastEnd = -1
  for (const h of hits) {
    if (h.start >= lastEnd) {
      picked.push(h)
      lastEnd = h.end
    }
  }

  const out: InlineToken[] = []
  let pos = 0
  for (const h of picked) {
    if (h.start > pos) out.push({ text: text.slice(pos, h.start) })
    out.push({ text: text.slice(h.start, h.end), kind: h.kind })
    pos = h.end
  }
  if (pos < text.length) out.push({ text: text.slice(pos) })
  return out
}

/**
 * 解析整篇答案。
 *
 * 结构规则（与后端 prompt 的四段式一致）：
 *   - 空行分段；
 *   - `结论：xxx` → 段落带 heading；
 *   - `- xxx` / `1. xxx` → bullets；
 *   - 其余按普通行。
 */
export function parseAnswer(answer: string): AnswerBlock[] {
  const text = (answer ?? '').replace(/\r\n/g, '\n').trim()
  if (!text) return []

  const blocks: AnswerBlock[] = []
  for (const rawPara of text.split(/\n{2,}/)) {
    const para = rawPara.trim()
    if (!para) continue

    const block: AnswerBlock = { lines: [], lineCount: 0, collapsedByDefault: false }
    for (const rawLine of para.split('\n')) {
      const line = rawLine.trim()
      if (!line) continue

      const heading = HEADING_RE.exec(line)
      if (heading) {
        // 标题行如果自带内容，作为首行正文
        if (!block.heading) {
          block.heading = heading[1]
        } else {
          // 同一段里出现第二个标题：另起一块，避免两段挤在一起
          blocks.push(block)
          const next: AnswerBlock = { heading: heading[1], lines: [], lineCount: 0, collapsedByDefault: false }
          if (heading[2]) {
            next.lines.push(tokenizeInline(heading[2]))
            next.lineCount++
          }
          blocks.push(next)
          continue
        }
        if (heading[2]) {
          block.lines.push(tokenizeInline(heading[2]))
          block.lineCount++
        }
        continue
      }

      const bullet = /^(?:[-*•]|\d+[.)])\s+(.*)$/.exec(line)
      if (bullet) {
        block.bullets = [...(block.bullets ?? []), tokenizeInline(bullet[1])]
        block.lineCount++
        continue
      }

      // 行内 `**粗体**` 去标记但保留文字（加粗语义交给高亮类别表达）
      block.lines.push(tokenizeInline(line.replace(/\*\*(.+?)\*\*/g, '$1')))
      block.lineCount++
    }

    if (block.lines.length || block.bullets?.length || block.heading) {
      block.collapsedByDefault = !!block.heading && !PRIMARY_HEADINGS.has(block.heading)
      blocks.push(block)
    }
  }
  return blocks
}

/** 供模板使用：把 `**粗体**` 去掉，避免残留在 UI 上 */
export function stripEmphasis(text: string): string {
  return text.replace(/\*\*(.+?)\*\*/g, '$1')
}


/**
 * 安全 Markdown 渲染 · 解析层（纯函数，零第三方依赖，不产出任何 HTML 字符串）。
 *
 * 使用场景：QA 回答与引用来源的展示。输入一律视为不可信文本（模型生成 / 检索片段），
 * 因此本模块只做「文本 → 节点数据」转换，由 Vue 组件渲染真实 DOM，
 * 全链路无 v-html / innerHTML，把 XSS 面压到零。
 *
 * 安全红线（逐条可在 web/scripts/smoke-markdown.mjs 中验证）：
 * 1. 链接协议白名单：只放行 http/https。javascript:、data:、file:、vbscript:、blob:、
 *    协议相对地址，以及大小写 / 空白 / 控制字符 / 零宽字符混淆（"JaVaScRiPt:"、
 *    "java\tscript:"、"\x01javascript:"）一律降级为纯文本，原文一个字符都不丢。
 * 2. 未闭合 / 畸形语法按纯文本降级：不抛错、不吞内容。
 * 3. 体量上限：source 超过 200000 字符截断并追加「（内容过长已截断）」；
 *    单行超过 4000 字符按 4000 硬断行，避免无换行长行把布局撑爆。
 * 4. 空输入返回 []。
 */

/** 行内片段：粗体 / 斜体 / 行内代码的 value 均为「字面文本」，不再嵌套解析。 */
export type MarkdownInline =
  | { type: 'text'; value: string }
  | { type: 'strong'; value: string }
  | { type: 'em'; value: string }
  | { type: 'code'; value: string }
  /** 链接文字与 href 分离存储：文字只是文本，目标必须通过协议白名单。 */
  | { type: 'link'; value: string; href: string }

export type MarkdownHeadingLevel = 1 | 2 | 3 | 4

export type MarkdownNode =
  | { type: 'heading'; level: MarkdownHeadingLevel; text: MarkdownInline[] }
  | { type: 'paragraph'; text: MarkdownInline[] }
  /** 列表项保存行内片段数组（items[i] 即第 i 项的行内内容）；有序 / 无序各自成节点。 */
  | { type: 'list'; ordered: boolean; items: MarkdownInline[][] }
  | { type: 'quote'; text: MarkdownInline[] }
  /** 代码块内容为原始文本（未经行内解析）；lang 仅在合法标识符时保留。 */
  | { type: 'code'; lang?: string; text: string }
  | { type: 'divider' }

/** source 上限：超过即截断，末尾追加 MARKDOWN_TRUNCATION_NOTICE。 */
export const MARKDOWN_MAX_SOURCE_LENGTH = 200000
/** 单行硬断行长度：超长行按此切片，防止布局爆炸。 */
export const MARKDOWN_MAX_LINE_LENGTH = 4000
/** 截断后追加给用户看的提示文本。 */
export const MARKDOWN_TRUNCATION_NOTICE = '（内容过长已截断）'

/** 链接文字 / 地址上限，避免病态输入造成超大切片。 */
const LINK_LABEL_MAX = 2000
const LINK_HREF_MAX = 2000

// ── 块级匹配 ────────────────────────────────────────────────

const FENCE_RE = /^ {0,3}(`{3,})(.*)$/
const CLOSE_FENCE_RE = /^ {0,3}(`{3,})\s*$/
const HEADING_RE = /^ {0,3}(#{1,6})(?:[ \t]+(.*))?[ \t]*$/
const DIVIDER_RE = /^ {0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/
const QUOTE_RE = /^ {0,3}>/
const UNORDERED_ITEM_RE = /^ {0,3}([-*+])[ \t]+(.*)$/
const ORDERED_ITEM_RE = /^ {0,3}(\d{1,9})[.)][ \t]+(.*)$/
const LANG_RE = /^[A-Za-z0-9_+#.-]+$/
/** 反斜杠转义只对 ASCII 标点生效，避免把 Windows 路径里的 \\ 吃成转义。 */
const ASCII_PUNCT_RE = /[!-/:-@[-`{-~]/

// ── 入口 ────────────────────────────────────────────────────

/**
 * 把 Markdown 源码解析为节点数组。永不抛错：任何畸形输入都按纯文本降级。
 * @param source 原始 Markdown 文本（可为空）
 */
export function renderMarkdown(source: string): MarkdownNode[] {
  if (typeof source !== 'string' || source.length === 0) return []
  const lines = hardBreakLines(normalizeLines(limitSource(source)))
  return parseBlocks(lines)
}

/** 把行内片段拼回纯文本（调用方需要「可核对的原文」时用）。 */
export function inlineToPlainText(inlines: MarkdownInline[]): string {
  return inlines.map((inline) => inline.value).join('')
}

// ── 预处理：换行归一化 / 截断 / 超长行硬断行 ────────────────

function normalizeLines(source: string): string[] {
  return source.replace(/\r\n?/g, '\n').split('\n')
}

/** 超长 source 截断并追加可见提示，防止超长回答拖垮渲染。 */
function limitSource(source: string): string {
  if (source.length <= MARKDOWN_MAX_SOURCE_LENGTH) return source
  return source.slice(0, MARKDOWN_MAX_SOURCE_LENGTH) + '\n\n' + MARKDOWN_TRUNCATION_NOTICE
}

/** 单行超过 4000 字符按 4000 硬断行（base64 / 长 URL / 压缩内容的常见形态）。 */
function hardBreakLines(lines: string[]): string[] {
  const out: string[] = []
  for (const line of lines) {
    if (line.length <= MARKDOWN_MAX_LINE_LENGTH) {
      out.push(line)
      continue
    }
    for (let i = 0; i < line.length; i += MARKDOWN_MAX_LINE_LENGTH) {
      out.push(line.slice(i, i + MARKDOWN_MAX_LINE_LENGTH))
    }
  }
  return out
}

// ── 块级解析 ────────────────────────────────────────────────

function parseBlocks(lines: string[]): MarkdownNode[] {
  const nodes: MarkdownNode[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]

    if (line.trim() === '') {
      i += 1
      continue
    }

    const fence = FENCE_RE.exec(line)
    if (fence) {
      const code = consumeCode(lines, i, fence[1].length, fence[2])
      nodes.push(code.node)
      i = code.next
      continue
    }

    const heading = matchHeading(line)
    if (heading) {
      // 空标题（"#" / "# "）不含任何内容，跳过而不渲染空壳节点
      if (heading.text.length > 0) {
        nodes.push({ type: 'heading', level: heading.level, text: parseInline(heading.text) })
      }
      i += 1
      continue
    }

    if (DIVIDER_RE.test(line)) {
      nodes.push({ type: 'divider' })
      i += 1
      continue
    }

    if (QUOTE_RE.test(line)) {
      const quote = consumeQuote(lines, i)
      if (quote.text.length > 0) {
        nodes.push({ type: 'quote', text: parseInline(quote.text) })
      }
      i = quote.next
      continue
    }

    if (UNORDERED_ITEM_RE.test(line) || ORDERED_ITEM_RE.test(line)) {
      const list = consumeList(lines, i)
      if (list.node.items.length > 0) nodes.push(list.node)
      i = list.next
      continue
    }

    const paragraph = consumeParagraph(lines, i)
    nodes.push({ type: 'paragraph', text: parseInline(paragraph.text) })
    i = paragraph.next
  }
  return nodes
}

/** 是否开启一个新块（用于中断段落）。 */
function startsBlock(line: string): boolean {
  if (line.trim() === '') return true
  return (
    FENCE_RE.test(line) ||
    DIVIDER_RE.test(line) ||
    QUOTE_RE.test(line) ||
    matchHeading(line) !== null ||
    UNORDERED_ITEM_RE.test(line) ||
    ORDERED_ITEM_RE.test(line)
  )
}

function matchHeading(line: string): { level: MarkdownHeadingLevel; text: string } | null {
  const m = HEADING_RE.exec(line)
  if (!m) return null
  const hashes = m[1]
  // 只支持 h1~h4；"#" 后必须跟空白，否则（如 "#tag"）降级为段落
  if (hashes.length > 4 || m[2] === undefined) return null
  const level = hashes.length as MarkdownHeadingLevel
  // 去掉 ATX 闭合序列："## 标题 ##" → "标题"
  const text = m[2].replace(/^[ \t]+/, '').replace(/[ \t]+#+[ \t]*$/, '').trim()
  return { level, text }
}

/** 围栏代码块：未闭合时一路吃到文末（内容不丢、不抛错）。 */
function consumeCode(lines: string[], start: number, markerLength: number, info: string): { node: MarkdownNode; next: number } {
  const firstToken = info.trim().split(/\s+/)[0] ?? ''
  const lang = firstToken !== '' && LANG_RE.test(firstToken) ? firstToken.toLowerCase() : undefined
  const body: string[] = []
  let i = start + 1
  while (i < lines.length) {
    const close = CLOSE_FENCE_RE.exec(lines[i])
    if (close && close[1].length >= markerLength) {
      i += 1
      break
    }
    body.push(lines[i])
    i += 1
  }
  const node: MarkdownNode = lang === undefined ? { type: 'code', text: body.join('\n') } : { type: 'code', lang, text: body.join('\n') }
  return { node, next: i }
}

function consumeQuote(lines: string[], start: number): { text: string; next: number } {
  const parts: string[] = []
  let i = start
  while (i < lines.length) {
    if (!QUOTE_RE.test(lines[i])) break
    parts.push(lines[i].replace(/^ {0,3}>[ \t]?/, ''))
    i += 1
  }
  return { text: parts.join('\n').trim(), next: i }
}

function matchListItem(line: string): { ordered: boolean; text: string } | null {
  const ordered = ORDERED_ITEM_RE.exec(line)
  if (ordered) return { ordered: true, text: ordered[2] }
  const unordered = UNORDERED_ITEM_RE.exec(line)
  if (unordered) return { ordered: false, text: unordered[2] }
  return null
}

/**
 * 列表：同类项（同为有序或同为无序）连续累积。空行后若紧跟同类项，视为松散列表
 * 继续累积；否则列表结束。条目内容做行内解析（支持粗体 / 行内代码 / 链接）。
 */
function consumeList(lines: string[], start: number): { node: Extract<MarkdownNode, { type: 'list' }>; next: number } {
  const first = matchListItem(lines[start])
  const ordered = first ? first.ordered : false
  const items: string[] = []
  let i = start
  while (i < lines.length) {
    const item = matchListItem(lines[i])
    if (!item || item.ordered !== ordered) break
    if (item.text.trim() !== '') items.push(item.text.trim())
    i += 1
    // 松散列表：跳过空行，若下一个非空行仍是同类列表项则继续同一列表
    if (i < lines.length && lines[i].trim() === '') {
      let j = i
      while (j < lines.length && lines[j].trim() === '') j += 1
      const next = j < lines.length ? matchListItem(lines[j]) : null
      if (next && next.ordered === ordered) {
        i = j
        continue
      }
      break
    }
  }
  return { node: { type: 'list', ordered, items: items.map(parseInline) }, next: i }
}

function consumeParagraph(lines: string[], start: number): { text: string; next: number } {
  const parts: string[] = []
  let i = start
  while (i < lines.length && !startsBlock(lines[i])) {
    parts.push(lines[i].replace(/[ \t]+$/, ''))
    i += 1
  }
  return { text: parts.join('\n').trim(), next: i }
}

// ── 行内解析 ────────────────────────────────────────────────

/**
 * 行内解析优先级：反斜杠转义 > `代码` > [文字](url) > **粗体** > *斜体* > 纯文本。
 * 代码 span 内容**不再二次解析**；畸形 / 未闭合语法按纯文本降级，原文保留。
 */
export function parseInline(source: string): MarkdownInline[] {
  const out: MarkdownInline[] = []
  let buffer = ''
  let i = 0

  const flush = () => {
    if (buffer !== '') {
      out.push({ type: 'text', value: buffer })
      buffer = ''
    }
  }

  while (i < source.length) {
    const ch = source[i]

    // 反斜杠转义：仅 ASCII 标点，原样输出下一个字符（"\*" 不触发斜体）
    if (ch === '\\' && i + 1 < source.length && ASCII_PUNCT_RE.test(source[i + 1])) {
      buffer += source[i + 1]
      i += 2
      continue
    }

    if (ch === '`') {
      const span = readCodeSpan(source, i)
      if (span) {
        flush()
        out.push({ type: 'code', value: span.value })
        i = span.next
        continue
      }
      buffer += ch
      i += 1
      continue
    }

    if (ch === '[') {
      const link = readLink(source, i)
      if (link) {
        flush()
        out.push({ type: 'link', value: link.value, href: link.href })
        i = link.next
        continue
      }
      // 恶意协议或畸形链接：整段按纯文本降级（内容一个字符都不丢）
      buffer += ch
      i += 1
      continue
    }

    if (ch === '*' && source[i + 1] === '*') {
      const strong = readDelimited(source, i, '**')
      if (strong) {
        flush()
        out.push({ type: 'strong', value: strong.value })
        i = strong.next
        continue
      }
      buffer += '**'
      i += 2
      continue
    }

    if (ch === '*') {
      const em = readDelimited(source, i, '*')
      if (em) {
        flush()
        out.push({ type: 'em', value: em.value })
        i = em.next
        continue
      }
      buffer += ch
      i += 1
      continue
    }

    buffer += ch
    i += 1
  }

  flush()
  return out
}

/** 读一段 `code` span；N 个反引号必须被同样长度的反引号闭合，否则返回 null。 */
function readCodeSpan(source: string, start: number): { value: string; next: number } | null {
  let ticks = 0
  while (source[start + ticks] === '`') ticks += 1
  let j = start + ticks
  while (j < source.length) {
    if (source[j] === '`') {
      let close = 0
      while (source[j + close] === '`') close += 1
      if (close === ticks) {
        let value = source.slice(start + ticks, j).replace(/\r?\n/g, ' ')
        // CommonMark 习惯：两端各一个空格且内容非全空格时剥掉这对空格
        if (value.length >= 2 && value.startsWith(' ') && value.endsWith(' ') && value.trim() !== '') {
          value = value.slice(1, -1)
        }
        return { value, next: j + close }
      }
      j += close
      continue
    }
    j += 1
  }
  return null
}

/** 读 *斜体* / **粗体**；marker 需成对且内容非空，否则返回 null（降级为纯文本）。 */
function readDelimited(source: string, start: number, marker: string): { value: string; next: number } | null {
  const from = start + marker.length
  const close = source.indexOf(marker, from)
  if (close === -1) return null
  const value = source.slice(from, close)
  if (value === '') return null
  return { value, next: close + marker.length }
}

/**
 * 读 [文字](url)。
 * - 括号按深度配对，兼容 https://x/Foo_(bar) 这类地址；
 * - 文字与 href 分离存储，href 必须通过协议白名单，否则返回 null
 *   （调用方按纯文本降级，原文一个字符都不丢）。
 */
function readLink(source: string, start: number): { value: string; href: string; next: number } | null {
  const closeBracket = source.indexOf(']', start + 1)
  if (closeBracket === -1) return null
  if (source[closeBracket + 1] !== '(') return null
  const closeParen = findClosingParen(source, closeBracket + 2)
  if (closeParen === -1) return null

  const value = source.slice(start + 1, closeBracket).trim()
  if (value === '' || value.length > LINK_LABEL_MAX) return null

  const rawHref = source.slice(closeBracket + 2, closeParen).trim()
  if (rawHref === '' || rawHref.length > LINK_HREF_MAX) return null
  // "url \"标题\" 形态：只取地址部分，标题不参与
  const href = rawHref.split(/\s+/)[0] ?? ''
  const safeHref = sanitizeHref(href)
  if (!safeHref) return null

  return { value, href: safeHref, next: closeParen + 1 }
}

function findClosingParen(source: string, start: number): number {
  let depth = 0
  for (let j = start; j < source.length; j += 1) {
    const ch = source[j]
    if (ch === '(') depth += 1
    else if (ch === ')') {
      if (depth === 0) return j
      depth -= 1
    }
  }
  return -1
}

/**
 * 链接协议白名单（安全红线）：只放行 http/https。
 *
 * 做法是「先清洗探针，再正向匹配」，让混淆手段全部失效：
 * 1. 剔除 C0/C1 控制字符与零宽 / BIDI 字符（"\t\n 插入" 因此失效）；
 * 2. 探针去掉全部空白、反斜杠统一成正斜杠（浏览器对特殊协议也这么解析，
 *    避免 "https:/\\" 之类绕过判断），再小写化；
 * 3. 必须以 http:// 或 https:// 开头，且 "://" 之后必须还有内容；
 * 4. 地址里出现引号 / 尖括号视为畸形或注入尝试，直接降级。
 *
 * 因此 "JaVaScRiPt:"、"java\tscript:"、"javascript:"、"data:text/html;...",
 * "vbscript:msgbox"、"file:///etc/passwd"、"blob:..."、"//evil.com" 全部被拒。
 */
export function sanitizeHref(raw: string): string | null {
  const cleaned = raw.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\ufeff]/g, '')
  if (cleaned === '') return null
  const probe = cleaned.replace(/\s+/g, '').replace(/\\/g, '/').toLowerCase()
  if (!probe.startsWith('http://') && !probe.startsWith('https://')) return null
  if (probe.length <= 8) return null
  if (/["'<>`]/.test(cleaned)) return null
  return cleaned
}

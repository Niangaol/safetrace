/**
 * 安全 Markdown 渲染冒烟脚本（无浏览器 / 无后端依赖，全部 Node 原生断言）。
 *
 * 覆盖：
 * - 解析层（web/src/markdown.ts）：标题 / 列表 / 引用 / 代码 / 分割线 / 粗斜体 /
 *   行内代码 / 链接，畸形输入降级，恶意协议拒绝，空输入，超长截断，超长行硬断行；
 * - 组件层（web/src/components/MarkdownBlock.vue）：用 vue/compiler-sfc 编译 +
 *   @vue/server-renderer 做真实 SSR 渲染，核对标签结构、链接属性、
 *   data-testid / data-markdown-source-length、prefers-reduced-motion 行为。
 *
 * 说明：反斜杠 / 反引号 / 换行等字符全部用码点常量拼装，因此本文件不含任何
 * 转义序列——既能原样表达 markdown 源码（含恶意载荷），也避免双重转义踩坑。
 *
 * 用法：node scripts/smoke-markdown.mjs（在 web/ 目录下）
 */

import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const WEB_ROOT = fileURLToPath(new URL('../', import.meta.url))
const url = (p) => pathToFileURL(join(WEB_ROOT, p)).href

const VUE_URL = url('node_modules/vue/index.mjs')
const SSR_URL = url('node_modules/@vue/server-renderer/dist/server-renderer.esm-bundler.js')
const COMPILER_SFC_URL = url('node_modules/vue/compiler-sfc/index.mjs')
const MARKDOWN_TS_URL = url('src/markdown.ts')
const COMPONENT_PATH = join(WEB_ROOT, 'src/components/MarkdownBlock.vue')

// 反斜杠 / 反引号 / 换行 / 制表符 / 零宽 / 控制字符等一律码点构造
const BS = String.fromCharCode(92)
const BT = String.fromCharCode(96)
const NL = String.fromCharCode(10)
const TAB = String.fromCharCode(9)
const SQ = String.fromCharCode(39)
const DQ = String.fromCharCode(34)
const FENCE = BT + BT + BT
const ZWSP = String.fromCharCode(0x200b)
const RLO = String.fromCharCode(0x202e)
const SOH = String.fromCharCode(1)
const NUL = String.fromCharCode(0)

// ── 断言计数（报告「断言项数」而不只是分组数） ──────────────
let assertionCount = 0
const A = {}
for (const key of Object.keys(assert)) {
  A[key] = (...args) => {
    assertionCount += 1
    return assert[key](...args)
  }
}

// ── 临时目录：优先系统 tmp，失败时退回 web/node_modules/.cache ─
function makeTempDir(prefix) {
  const bases = []
  try {
    bases.push(tmpdir())
  } catch {
    /* 某些受限环境没有 TMP/TEMP */
  }
  bases.push(join(WEB_ROOT, 'node_modules', '.cache'))
  let lastError = null
  for (const base of bases) {
    try {
      mkdirSync(base, { recursive: true })
      return mkdtempSync(join(base, prefix))
    } catch (error) {
      lastError = error
    }
  }
  throw lastError
}

// ── 载入被测模块 ───────────────────────────────────────────

// Node 22.18+/24 原生支持 .ts 类型剥离，直接 import 真实源码即可
const {
  renderMarkdown,
  parseInline,
  sanitizeHref,
  inlineToPlainText,
  MARKDOWN_TRUNCATION_NOTICE,
  MARKDOWN_MAX_SOURCE_LENGTH,
  MARKDOWN_MAX_LINE_LENGTH,
} = await import(MARKDOWN_TS_URL)

/** 编译真实 SFC 并载入：把裸模块名改写成绝对 file URL（Node ESM 不向上找 node_modules）。 */
async function loadMarkdownBlock() {
  const sfcSource = readFileSync(COMPONENT_PATH, 'utf8')
  const { parse, compileScript } = await import(COMPILER_SFC_URL)
  const { descriptor } = parse(sfcSource, { filename: 'MarkdownBlock.vue' })
  const compiled = compileScript(descriptor, { id: 'smoke-markdown-block', inlineTemplate: true })
  let code = compiled.content
  // 编译器可能输出单引号或双引号导入，两种都替换
  for (const q of [SQ, DQ]) {
    code = code.split('from ' + q + 'vue' + q).join('from ' + JSON.stringify(VUE_URL))
    code = code.split('from ' + q + '../markdown' + q).join('from ' + JSON.stringify(MARKDOWN_TS_URL))
  }
  const dir = makeTempDir('safetrace-markdown-')
  writeFileSync(join(dir, 'package.json'), '{"type":"module"}', 'utf8')
  const file = join(dir, 'MarkdownBlock.ts')
  writeFileSync(file, code, 'utf8')
  const mod = await import(pathToFileURL(file).href)
  return {
    component: mod.default,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  }
}

const { component: MarkdownBlock, cleanup: cleanupComponent } = await loadMarkdownBlock()
const vue = await import(VUE_URL)
const { renderToString } = await import(SSR_URL)
const renderBlock = async (props) => renderToString(vue.createSSRApp(MarkdownBlock, props))

const COMPONENT_SOURCE = readFileSync(COMPONENT_PATH, 'utf8')

// ── 小工具 ─────────────────────────────────────────────────

const inlineText = (inlines) => inlines.map((i) => i.value).join('')
const blockText = (nodes) =>
  nodes
    .map((n) => {
      if (n.type === 'code') return n.text
      if (n.type === 'list') return n.items.map(inlineText).join('|')
      return inlineText(n.text)
    })
    .join('|')
/** 收集所有链接节点（遍历段落 / 标题 / 引用 / 列表项）。 */
function collectLinks(nodes) {
  const out = []
  for (const node of nodes) {
    if (node.type === 'heading' || node.type === 'paragraph' || node.type === 'quote') {
      for (const inline of node.text) if (inline.type === 'link') out.push(inline)
    } else if (node.type === 'list') {
      for (const item of node.items) for (const inline of item) if (inline.type === 'link') out.push(inline)
    }
  }
  return out
}
/** 断言一段源码不产出任何链接节点（恶意协议必须全部降级）。 */
function assertNoLink(source) {
  const nodes = renderMarkdown(source)
  A.deepStrictEqual(collectLinks(nodes), [], source + ' 不得产出链接节点')
  return nodes
}
/** 去掉 SSR 输出里的锚点注释，便于按“干净 HTML”断言结构。 */
const cleanHtml = (html) => html.replace(/<!--[\s\S]*?-->/g, '')
/** 去掉 JS / HTML 注释后再做“禁止什么”的检查，避免文档注释误伤。 */
function stripComments(source) {
  return source.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1')
}

const results = []
async function check(name, fn) {
  try {
    await fn()
    results.push('  [ OK ] ' + name)
  } catch (e) {
    results.push('  [FAIL] ' + name + NL + '         ' + e.message)
    process.exitCode = 1
  }
}

// ── 一、解析层：基础语法 ───────────────────────────────────

await check('空输入 / 纯空白输入 → []', () => {
  A.deepStrictEqual(renderMarkdown(''), [])
  A.deepStrictEqual(renderMarkdown('   ' + NL + NL + TAB + ' '), [])
  A.deepStrictEqual(renderMarkdown(String.fromCharCode(13) + NL + String.fromCharCode(13) + NL), [])
})

await check('ATX 标题 h1~h4：level 来自 # 个数，标题内可行内解析', () => {
  const nodes = renderMarkdown('# 一级' + NL + '## 二级 *斜体*' + NL + '### ' + BT + '码' + BT + NL + '#### **粗体**')
  A.deepStrictEqual(nodes.map((n) => n.type), ['heading', 'heading', 'heading', 'heading'])
  A.deepStrictEqual(nodes.map((n) => n.level), [1, 2, 3, 4])
  A.deepStrictEqual(nodes[0].text, [{ type: 'text', value: '一级' }])
  A.deepStrictEqual(nodes[1].text, [{ type: 'text', value: '二级 ' }, { type: 'em', value: '斜体' }])
  A.deepStrictEqual(nodes[2].text, [{ type: 'code', value: '码' }])
  A.deepStrictEqual(nodes[3].text, [{ type: 'strong', value: '粗体' }])
})

await check('标题降级：5 级 #、# 后无空格 → 段落（内容不丢）', () => {
  const nodes = renderMarkdown('##### 五级' + NL + '#无空格标题')
  A.deepStrictEqual(nodes.map((n) => n.type), ['paragraph'], '相邻行归为同一段落')
  A.equal(inlineText(nodes[0].text), '##### 五级' + NL + '#无空格标题')
  A.deepStrictEqual(nodes[0].text, [{ type: 'text', value: '##### 五级' + NL + '#无空格标题' }])
})

await check('标题闭合序列 "## 标题 ##" 被裁剪', () => {
  const nodes = renderMarkdown('## 漏洞影响 ##' + NL + '### 修复建议 ###   ')
  A.equal(nodes.length, 2)
  A.equal(inlineText(nodes[0].text), '漏洞影响')
  A.equal(inlineText(nodes[1].text), '修复建议')
})

await check('段落按空行拆分，段内软换行保留', () => {
  const nodes = renderMarkdown('第一段 第一行' + NL + '第一段 第二行' + NL + NL + '第二段')
  A.deepStrictEqual(nodes.map((n) => n.type), ['paragraph', 'paragraph'])
  A.equal(inlineText(nodes[0].text), '第一段 第一行' + NL + '第一段 第二行')
  A.equal(inlineText(nodes[1].text), '第二段')
})

await check('无序列表 - / * / + 三种标记，条目支持行内（粗体 / 代码 / 链接）', () => {
  const nodes = renderMarkdown('- 甲' + NL + '* 乙 **粗**' + NL + '+ 丙 ' + BT + '码' + BT + NL + '- 丁 [链](https://a.b/c)')
  A.deepStrictEqual(nodes.map((n) => n.type), ['list'])
  A.equal(nodes[0].ordered, false)
  A.equal(nodes[0].items.length, 4)
  A.deepStrictEqual(nodes[0].items[1], [{ type: 'text', value: '乙 ' }, { type: 'strong', value: '粗' }])
  A.deepStrictEqual(nodes[0].items[3][1], { type: 'link', value: '链', href: 'https://a.b/c' })
})

await check('有序列表支持 1. 与 1)，松散列表跨空行累积；与无序列表互不混淆', () => {
  const merged = renderMarkdown('1. 一' + NL + '2) 二' + NL + NL + '1. x' + NL + '2. y')
  A.deepStrictEqual(merged.map((n) => n.type), ['list'], '空行后的同类项仍属同一列表')
  A.equal(merged[0].ordered, true)
  A.equal(merged[0].items.length, 4)
  A.equal(inlineText(merged[0].items[3]), 'y')

  const mixed = renderMarkdown('- 甲' + NL + '1. 一' + NL + '- 乙')
  A.deepStrictEqual(mixed.map((n) => n.type), ['list', 'list', 'list'])
  A.deepStrictEqual(mixed.map((n) => n.ordered), [false, true, false])
  A.equal(inlineText(mixed[0].items[0]), '甲')
  A.equal(inlineText(mixed[2].items[0]), '乙')
})

await check('引用：多行合并、去 > 前缀、内部行内解析', () => {
  const nodes = renderMarkdown('> 第一行' + NL + '>第二行 **粗**' + NL + '> [来源](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)')
  A.deepStrictEqual(nodes.map((n) => n.type), ['quote'])
  A.equal(inlineText(nodes[0].text), '第一行' + NL + '第二行 粗' + NL + '来源')
  A.deepStrictEqual(nodes[0].text[1], { type: 'strong', value: '粗' })
  A.deepStrictEqual(nodes[0].text.find((i) => i.type === 'link'), { type: 'link', value: '来源', href: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' })
})

await check('代码块：lang 保留，内容原文不进词法解析（** 与 [ ] 保持字面）', () => {
  const nodes = renderMarkdown(FENCE + 'ts' + NL + 'const a = **1**' + NL + 'log4j(' + DQ + '[x](y)' + DQ + ')' + NL + FENCE)
  A.deepStrictEqual(nodes.map((n) => n.type), ['code'])
  A.equal(nodes[0].lang, 'ts')
  A.equal(nodes[0].text, 'const a = **1**' + NL + 'log4j(' + DQ + '[x](y)' + DQ + ')')
})

await check('未闭合围栏代码块吃到文末：内容不丢、不抛错', () => {
  const nodes = renderMarkdown(FENCE + 'json' + NL + '{"a": 1}' + NL + '**仍是代码**')
  A.equal(nodes.length, 1)
  A.equal(nodes[0].type, 'code')
  A.equal(nodes[0].lang, 'json')
  A.equal(nodes[0].text, '{"a": 1}' + NL + '**仍是代码**')
})

await check('分割线 --- / *** / - - -，且不与列表 / 强调混淆', () => {
  A.deepStrictEqual(renderMarkdown('---').map((n) => n.type), ['divider'])
  A.deepStrictEqual(renderMarkdown('***').map((n) => n.type), ['divider'])
  A.deepStrictEqual(renderMarkdown('- - -').map((n) => n.type), ['divider'])
  A.deepStrictEqual(renderMarkdown('**重点**').map((n) => n.type), ['paragraph'])
  A.deepStrictEqual(renderMarkdown('- 列表项').map((n) => n.type), ['list'])
})

await check('行内混合：粗体 / 斜体 / 行内代码 / 链接 / 纯文本', () => {
  const nodes = renderMarkdown('这是**粗体**、*斜体*、' + BT + 'code' + BT + ' 与 [链接](https://example.com/a_b?c=1)的混合文本。')
  A.equal(nodes.length, 1)
  A.deepStrictEqual(nodes[0].text.map((i) => i.type), ['text', 'strong', 'text', 'em', 'text', 'code', 'text', 'link', 'text'])
  A.deepStrictEqual(nodes[0].text[1], { type: 'strong', value: '粗体' })
  A.deepStrictEqual(nodes[0].text[3], { type: 'em', value: '斜体' })
  A.deepStrictEqual(nodes[0].text[5], { type: 'code', value: 'code' })
  A.deepStrictEqual(nodes[0].text[7], { type: 'link', value: '链接', href: 'https://example.com/a_b?c=1' })
})

await check('行内代码不再二次解析：**、[]、* 在 code span 内保持字面', () => {
  const nodes = renderMarkdown('前缀 ' + BT + '**不是粗体** [也不是链接](x) *也不是斜体*' + BT + ' 后缀')
  A.deepStrictEqual(nodes[0].text.map((i) => i.type), ['text', 'code', 'text'])
  A.equal(nodes[0].text[1].value, '**不是粗体** [也不是链接](x) *也不是斜体*')
})

await check('反斜杠转义：BS* BS BT BS[ 不触发语法，输出字面量', () => {
  const nodes = parseInline(BS + '*不是斜体' + BS + '* ' + BS + BT + '不是代码' + BS + BT + ' ' + BS + '[不是链接' + BS + '](x)')
  A.deepStrictEqual(nodes, [{ type: 'text', value: '*不是斜体* ' + BT + '不是代码' + BT + ' [不是链接](x)' }])
})

await check('链接文字与 href 分离存储（文字不是 URL，URL 不带文字）', () => {
  const [node] = renderMarkdown('[查看 NVD 详情](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)')
  const link = node.text[0]
  A.equal(link.type, 'link')
  A.equal(link.value, '查看 NVD 详情')
  A.equal(link.href, 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228')
  A.notEqual(link.value, link.href)
  A.ok(!link.value.includes('https://'), '文字部分不应夹带 URL')
})

await check('畸形语法按纯文本降级：不抛错、内容一个字符都不丢', () => {
  const source = '**未闭合粗体' + NL + BT + '未闭合行内代码' + NL + '[文字](url-未闭合' + NL + '[也没有括号]' + NL + '* 单个星号'
  let nodes
  A.doesNotThrow(() => {
    nodes = renderMarkdown(source)
  })
  A.ok(blockText(nodes).includes('**未闭合粗体'))
  A.ok(blockText(nodes).includes(BT + '未闭合行内代码'))
  A.ok(blockText(nodes).includes('[文字](url-未闭合'))
  A.ok(blockText(nodes).includes('[也没有括号]'))
  A.ok(blockText(nodes).includes('单个星号'), '* 开头会被解析成列表标记，但文字不能丢')
})

await check('原始 HTML 只当文本（<script> 不会成为节点，也不会被解析）', () => {
  const nodes = renderMarkdown('<script>alert(1)</script> & <b>加粗</b>')
  A.deepStrictEqual(nodes[0].text, [{ type: 'text', value: '<script>alert(1)</script> & <b>加粗</b>' }])
  A.equal(inlineToPlainText(nodes[0].text), '<script>alert(1)</script> & <b>加粗</b>')
})

// ── 二、解析层：体量上限 ───────────────────────────────────

await check('体量上限：source 超 200000 字符 → 截断并追加「（内容过长已截断）」', () => {
  A.equal(MARKDOWN_MAX_SOURCE_LENGTH, 200000)
  const nodes = renderMarkdown('y'.repeat(MARKDOWN_MAX_SOURCE_LENGTH + 1))
  A.equal(nodes.length, 2)
  A.equal(nodes[0].type, 'paragraph')
  A.equal(inlineText(nodes[0].text).split(NL).join('').length, MARKDOWN_MAX_SOURCE_LENGTH)
  A.deepStrictEqual(nodes[1], { type: 'paragraph', text: [{ type: 'text', value: MARKDOWN_TRUNCATION_NOTICE }] })
})

await check('体量上限：未超限时不截断、不加提示', () => {
  const exact = 'z'.repeat(MARKDOWN_MAX_SOURCE_LENGTH)
  const nodes = renderMarkdown(exact)
  A.equal(nodes.length, 1)
  A.equal(inlineText(nodes[0].text).split(NL).join(''), exact, '内容必须一字符不丢')
  A.equal(inlineText(nodes[0].text).split(NL).length, 50, '200000 字符应恰好切成 50 行')
})

await check('体量上限：单行超 4000 字符 → 按 4000 硬断行（段落与代码块都生效）', () => {
  const long = 'x'.repeat(10000)
  const para = renderMarkdown(long)
  A.equal(para.length, 1)
  A.equal(inlineText(para[0].text).split(NL).join(''), long, '内容必须一字符不丢')
  A.equal(inlineText(para[0].text).split(NL).length, 3, '应被切成 3 行')
  A.ok(inlineText(para[0].text).split(NL).every((l) => l.length <= MARKDOWN_MAX_LINE_LENGTH))

  const code = renderMarkdown(FENCE + NL + long + NL + FENCE)
  A.equal(code[0].type, 'code')
  A.equal(code[0].text.split(NL).length, 3, '代码块内同样硬断行')
  A.equal(code[0].text.split(NL)[0].length, MARKDOWN_MAX_LINE_LENGTH)
})

// ── 三、安全红线：链接协议白名单 ───────────────────────────

await check('白名单放行：http/https（含大写协议、括号 URL、带标题参数、编码路径）', () => {
  const ok = [
    ['[a](http://example.com/x)', 'http://example.com/x'],
    ['[a](https://example.com/x)', 'https://example.com/x'],
    ['[a](HTTPS://EXAMPLE.COM/X)', 'HTTPS://EXAMPLE.COM/X'],
    ['[a](https://en.wikipedia.org/wiki/Foo_(bar))', 'https://en.wikipedia.org/wiki/Foo_(bar)'],
    ['[a](https://example.com/x ' + DQ + '标题' + DQ + ')', 'https://example.com/x'],
    ['[a](https://example.com/a%20b?c=1&d=2#frag)', 'https://example.com/a%20b?c=1&d=2#frag'],
  ]
  for (const [source, expected] of ok) {
    const links = collectLinks(renderMarkdown(source))
    A.equal(links.length, 1, source)
    A.equal(links[0].href, expected, source)
  }
})

/** 去掉所有空白与控制 / 零宽 / BIDI 字符，用来核对“降级后原文仍在”。 */
const noWhitespace = (s) => {
  let out = ''
  for (const ch of s) {
    const code = ch.charCodeAt(0)
    if (code > 32 && code !== 0x200b && code !== 0x200e && code !== 0x200f && code !== 0x202e && code !== 0xfeff) out += ch
  }
  return out
}

await check('恶意协议拒绝：javascript: 及大小写 / 空白 / 控制字符 / 零宽混淆', () => {
  const cases = [
    '[a](javascript:alert(1))',
    '[a](JaVaScRiPt:alert(1))',
    '[a](JAVASCRIPT:alert(1))',
    '[a](java' + TAB + 'script:alert(1))',
    '[a](java' + NL + 'script:alert(1))',
    '[a](java script:alert(1))',
    '[a](' + SOH + 'javascript:alert(1))',
    '[a](java' + NUL + 'script:alert(1))',
    '[a](' + ZWSP + 'javascript:alert(1))',
    '[a](' + RLO + 'javascript:alert(1))',
    '[a](  javascript:alert(1)  )',
  ]
  for (const source of cases) {
    const nodes = assertNoLink(source)
    A.ok(noWhitespace(blockText(nodes)).toLowerCase().includes('javascript:'), source + ' 降级后原文必须仍在')
  }
})

await check('恶意协议拒绝：data: / vbscript: / file: / blob: / 协议相对地址 / mailto / tel', () => {
  const cases = [
    '[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
    '[a](vbscript:msgbox(1))',
    '[a](file:///etc/passwd)',
    '[a](blob:https://example.com/uuid)',
    '[a](mailto:someone@example.com)',
    '[a](tel:+8613800138000)',
    '[a](//evil.com/x)',
    '[a](' + BS + BS + 'evil.com/x)',
  ]
  for (const source of cases) {
    const nodes = assertNoLink(source)
    A.equal(nodes.length, 1, source)
    A.equal(nodes[0].type, 'paragraph', source)
  }
})

await check('反斜杠混淆不能绕过白名单（浏览器语义下仍只允许 http/https）', () => {
  const cases = [
    '[a](javascript:' + BS + BS + 'alert(1))',
    '[a](java' + BS + BS + 'script:alert(1))',
    '[a](https:/' + BS + '/' + '/evil.com' + BS + 'x)',
  ]
  for (const source of cases) {
    const links = collectLinks(renderMarkdown(source))
    A.ok(links.length <= 1, source)
    for (const link of links) {
      // 浏览器把特殊协议的反斜杠当斜杠解析，因此按“去反斜杠后的协议”判断
      const probe = link.href.split(BS).join('').toLowerCase()
      A.ok(probe.startsWith('https://'), source + ' 只允许 https 目标')
    }
  }
})

await check('sanitizeHref 单测：白名单之外一律 null', () => {
  A.equal(sanitizeHref('https://a.b'), 'https://a.b')
  A.equal(sanitizeHref('http://a.b/c?d=1'), 'http://a.b/c?d=1')
  A.equal(sanitizeHref('https://' + 'a'.repeat(300)), 'https://' + 'a'.repeat(300))
  for (const bad of [
    '',
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'java' + TAB + 'script:alert(1)',
    '' + SOH + 'javascript:alert(1)',
    'data:text/html,x',
    'vbscript:x',
    'file:///x',
    'blob:x',
    'mailto:a@b.c',
    '//evil.com',
    '/relative/path',
    '#fragment',
    'https://',
    'http://',
  ]) {
    A.equal(sanitizeHref(bad), null, bad + ' 必须被拒绝')
  }
})

// ── 四、组件层：真实 SSR 渲染 ──────────────────────────────

await check('组件源码（去注释后）不含 v-html / innerHTML / dangerouslySetInnerHTML', () => {
  const bare = stripComments(COMPONENT_SOURCE)
  A.ok(!bare.includes('v-html'), '禁止 v-html')
  A.ok(!bare.includes('innerHTML'), '禁止 innerHTML')
  A.ok(!bare.includes('dangerouslySetInnerHTML'), '禁止 dangerouslySetInnerHTML')
  A.ok(COMPONENT_SOURCE.includes('data-testid="markdown-block"'), '必须暴露 data-testid')
  A.ok(COMPONENT_SOURCE.includes('data-markdown-source-length'), '必须暴露 data-markdown-source-length')
})

await check('根元素：data-testid / data-markdown-source-length 与原文字长一致', async () => {
  const source = '# 标题' + NL + NL + '正文 **粗体**'
  const html = await renderBlock({ source })
  A.ok(html.includes('data-testid="markdown-block"'))
  A.ok(html.includes('data-markdown-source-length="' + source.length + '"'), '长度应为 ' + source.length)
  A.ok(html.includes('data-markdown-truncated="false"'))
})

await check('无内容时渲染空容器（仍有根元素，但没有任何块级子元素）', async () => {
  const html = await renderBlock({ source: '' })
  A.ok(html.includes('data-testid="markdown-block"'))
  A.ok(html.includes('markdown-block--empty'))
  A.ok(!html.includes('<h1') && !html.includes('<h2') && !html.includes('<h3') && !html.includes('<h4'), '空容器不应出现标题')
  A.ok(!html.includes('<p'), '空容器不应出现段落')
  A.ok(!html.includes('<ul') && !html.includes('<ol') && !html.includes('<pre') && !html.includes('<blockquote'), '空容器不应出现其它块')
})

await check('标题层级由节点 level 决定：h1~h4 一一对应', async () => {
  const html = cleanHtml(await renderBlock({ source: '# 一' + NL + '## 二' + NL + '### 三' + NL + '#### 四' + NL + '##### 五（降级为段落）' }))
  A.ok(html.includes('<h1 class="md-heading"><span>一</span></h1>'))
  A.ok(html.includes('<h2 class="md-heading"><span>二</span></h2>'))
  A.ok(html.includes('<h3 class="md-heading"><span>三</span></h3>'))
  A.ok(html.includes('<h4 class="md-heading"><span>四</span></h4>'))
  A.ok(!html.includes('<h5') && !html.includes('<h6'), '不得渲染 h5/h6')
  A.ok(html.includes('<p class="md-paragraph"><span>##### 五（降级为段落）</span></p>'))
})

await check('代码块渲染 <pre><code>，lang 走 data-lang（不进 class）', async () => {
  const html = await renderBlock({ source: FENCE + 'ts' + NL + 'const a = 1' + NL + '**仍是代码**' + NL + FENCE })
  A.ok(html.includes('<pre class="md-pre" data-lang="ts"><code class="md-code">'))
  A.ok(html.includes('**仍是代码**'))
  A.ok(!html.includes('<strong'), '代码块内不得出现粗体元素')
  A.ok(!html.includes('md-code--ts'), 'lang 不得拼进 class（可能是非法 CSS 标识符）')
})

await check('列表 → ul/ol + li，引用 → blockquote，分割线 → hr', async () => {
  const html = await renderBlock({ source: '- 甲' + NL + '- 乙' + NL + NL + '1. 一' + NL + NL + '> 引用 **粗**' + NL + NL + '---' })
  A.ok(html.includes('<ul class="md-list">'))
  A.ok(html.includes('<ol class="md-list">'))
  A.equal(html.split('<li>').length - 1, 3)
  A.ok(html.includes('<blockquote class="md-quote">'))
  A.ok(html.includes('<strong>粗</strong>'))
  A.ok(html.includes('<hr class="md-divider"'))
})

await check('行内语义标签：strong / em / code 与文本插值（插值自动转义）', async () => {
  const html = await renderBlock({ source: '**粗** *斜* ' + BT + '码' + BT + ' & <b>raw</b>' })
  A.ok(html.includes('<strong>粗</strong>'))
  A.ok(html.includes('<em>斜</em>'))
  A.ok(html.includes('<code>码</code>'))
  A.ok(html.includes('&lt;b&gt;raw&lt;/b&gt;'), '原始 HTML 必须被转义')
  A.ok(!html.includes('<b>raw</b>'), '不得产出真实 <b> 元素')
})

await check('链接渲染：<a target=_blank rel="noreferrer noopener"> + 域名以纯文本展示', async () => {
  const html = await renderBlock({ source: '参见 [NVD 详情](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)。' })
  A.ok(html.includes('<a class="md-link" href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228" target="_blank" rel="noreferrer noopener">NVD 详情</a>'), html)
  A.ok(html.includes('<span class="md-link-host" title="https://nvd.nist.gov/vuln/detail/CVE-2021-44228">nvd.nist.gov</span>'), '域名应以纯文本展示')
})

await check('恶意协议链接不渲染 <a>：降级为转义后的纯文本（无 XSS）', async () => {
  const html = await renderBlock({ source: '[a](javascript:alert(1)) 与 [b](data:text/html,<img src=x onerror=alert(1)>)' })
  A.ok(!html.includes('<a '), '不得出现任何 <a>')
  A.ok(!html.includes('href=' + DQ + 'javascript'), '不得出现 javascript href')
  A.ok(!html.includes('href=' + DQ + 'data:'), '不得出现 data href')
  A.ok(html.includes('[a](javascript:alert(1))'), '降级后原文必须仍在')
  A.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), '原始 HTML 必须被转义')
})

await check('<script> 载荷只以转义文本出现', async () => {
  const html = await renderBlock({ source: '<script>alert(1)</script>' })
  A.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'))
  A.ok(!html.includes('<script>alert'))
})

await check('compact 模式：类名生效且不再展示域名后缀', async () => {
  const html = await renderBlock({ source: '参见 [NVD](https://nvd.nist.gov/x)', compact: true })
  A.ok(html.includes('markdown-block--compact'))
  A.ok(!html.includes('md-link-host'), 'compact 下不展示域名')
})

await check('prefers-reduced-motion: reduce → 无入场动效类，data-motion="reduced"', async () => {
  globalThis.window = { matchMedia: () => ({ matches: true, addEventListener() {}, removeEventListener() {} }) }
  try {
    const html = await renderBlock({ source: '# 标题' + NL + NL + '正文' })
    A.ok(html.includes('data-motion="reduced"'))
    A.ok(!html.includes('markdown-block--enter'), 'reduce 时不得加入场动效类')
  } finally {
    delete globalThis.window
  }
})

await check('动效可用时：默认加入场类（起始不透明度 0.55，不会隐藏内容）', async () => {
  const html = await renderBlock({ source: '# 标题' })
  A.ok(html.includes('data-motion="full"'))
  A.ok(html.includes('markdown-block--enter'))
})

await check('CSS 侧仍保留 prefers-reduced-motion 守卫（与 JS 双保险）', () => {
  A.ok(COMPONENT_SOURCE.includes('@media (prefers-reduced-motion: reduce)'))
  A.ok(COMPONENT_SOURCE.includes('@media (prefers-reduced-motion: no-preference)'))
  A.ok(COMPONENT_SOURCE.includes('animation: none !important'))
})

await check('超长 source 在组件层标记 data-markdown-truncated="true" 并展示提示', async () => {
  const html = await renderBlock({ source: 'q'.repeat(MARKDOWN_MAX_SOURCE_LENGTH + 10) })
  A.ok(html.includes('data-markdown-truncated="true"'))
  A.ok(html.includes(MARKDOWN_TRUNCATION_NOTICE))
})

await check('无 matchMedia 的受限环境不抛错，且内容立即可见', async () => {
  const html = cleanHtml(await renderBlock({ source: '# t' }))
  A.ok(html.includes('<h1 class="md-heading"><span>t</span></h1>'))
})

// ── 汇总 ──────────────────────────────────────────────────

cleanupComponent()
console.log(results.join(NL))
console.log(
  process.exitCode
    ? NL + '安全 Markdown 渲染冒烟：有失败项（共 ' + results.length + ' 组 / ' + assertionCount + ' 项断言）'
    : NL + '安全 Markdown 渲染冒烟：全部通过（' + results.length + ' 组检查 / ' + assertionCount + ' 项断言，无浏览器、无后端）',
)

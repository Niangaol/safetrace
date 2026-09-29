/**
 * 答案高亮解析器验收（对着**真实 LLM 输出**跑，不靠肉眼看截图）。
 *
 * 为什么单独写这个：问答一次要 25–35s，浏览器无头截图很难等到流式结束；
 * 而"关键内容有没有被正确标注"是纯函数行为，完全可以直接断言。
 *
 * 用法：node scripts/check-answer-format.mjs
 */
import assert from 'node:assert/strict'
import { copyFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

// 本仓真实一次问答的答案（deepseek-v4-pro，CVE-2026-31001 怎么修复）
const REAL_ANSWER = `结论：
- 修复版本：将 vLLM 升级到 0.9.3 或更高版本 [S2]。
- 临时缓解措施：在反向代理层校验 chat_template 字段，拒绝包含双大括号且长度异常的请求 [S2]。
- 受影响范围：vLLM 0.9.2 及更早版本 [S1]。

依据：
- [S1] CVE-2026-31001：CVSS 9.8，EPSS 0.87，已被 CISA KEV 收录。
- [S2] 修复方式：0.9.3 起改用 SandboxedEnvironment 并禁用属性访问。

建议动作：
1. 立即确认 vLLM 版本；若为 0.9.2 或更早，升级到 0.9.3 或更高版本 [S1][S2]。
2. 升级前，在反向代理/WAF 增加规则 [S2]。`

// answerFormat.ts 是纯逻辑（无 import），Node 24 可直接执行 .ts，复制到临时目录再导入
const dir = mkdtempSync(join(tmpdir(), 'ansfmt-'))
copyFileSync(join(process.cwd(), 'src', 'answerFormat.ts'), join(dir, 'answerFormat.ts'))

const { parseAnswer } = await import(pathToFileURL(join(dir, 'answerFormat.ts')).href)

const blocks = parseAnswer(REAL_ANSWER)
const flat = blocks.flatMap((b) => [
  ...b.lines.flat(),
  ...(b.bullets ?? []).flat(),
])

const headings = blocks.map((b) => b.heading).filter(Boolean)
const allTokens = (kind) => flat.filter((t) => t.kind === kind).map((t) => t.text)
const citeRefs = flat.filter((t) => t.kind === 'citation').map((t) => t.ref)
const values = allTokens('value')
const dangers = allTokens('danger')
const actions = allTokens('action')

console.log('段落标题:', headings)
console.log('引用号  :', citeRefs.join(' '))
console.log('硬事实  :', [...new Set(values)].slice(0, 12).join(' | '))
console.log('风险词  :', [...new Set(dangers)].slice(0, 10).join(' | '))
console.log('动作词  :', [...new Set(actions)].slice(0, 10).join(' | '))
console.log()

const problems = []

// 1) 四段式标题必须被识别成 heading，而不是混在正文里
for (const h of ['结论', '依据', '建议动作']) {
  if (!headings.includes(h)) problems.push(`未识别出段落标题「${h}」`)
}

// 2) 引用号必须全部被识别为可点 chip，且编号正确
if (!citeRefs.includes('S1')) problems.push('未识别出 [S1]')
if (!citeRefs.includes('S2')) problems.push('未识别出 [S2]')
// 上面那段真实答案里共有 8 个 [Sn]（含末行连写的 [S1][S2] 要算两个）
if (citeRefs.length !== 8) problems.push(`引用号数量应为 8，实际 ${citeRefs.length}`)

// 3) 硬事实（CVE / 版本号 / CVSS / EPSS）必须被标注
for (const v of ['CVE-2026-31001', '0.9.3', '9.8', '0.87']) {
  if (!values.some((x) => x.includes(v))) problems.push(`未标注硬事实「${v}」`)
}

// 4) 风险词与动作词必须被标注
if (!dangers.length) problems.push('未标注任何风险词')
if (!actions.length) problems.push('未标注任何动作词')

// 5) 不许吞字：把 token 拼回去应当与原文一致（忽略 `**` 标记）
const rebuilt = blocks
  .map((b) => {
    const head = b.heading ? `${b.heading}：` : ''
    const lines = b.lines.map((l) => l.map((t) => t.text).join('')).join('\n')
    const bullets = (b.bullets ?? [])
      .map((l, i) => `${i + 1}. ${l.map((t) => t.text).join('')}`)
      .join('\n')
    return `${head}${lines}${bullets}`
  })
  .join('\n')
for (const probe of ['修复版本', 'SandboxedEnvironment', 'CISA KEV', '反向代理/WAF']) {
  if (!rebuilt.includes(probe)) problems.push(`重建文本丢失内容「${probe}」`)
}

if (problems.length) {
  console.log('发现问题：')
  for (const p of problems) console.log('  -', p)
  process.exitCode = 1
} else {
  console.log('OK：段落标题 / 引用号 / 硬事实 / 风险词 / 动作词 均正确标注，且未吞字')
}

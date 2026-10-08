// Offline regression tests: real store and compiled Vue report, no extra dependencies.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import ts from 'typescript'
import { parse, compileScript } from 'vue/compiler-sfc'
import { createRenderer, nextTick } from 'vue'
import { createPinia, setActivePinia } from 'pinia'

const root = fileURLToPath(new URL('../', import.meta.url))
const url = path => pathToFileURL(resolve(root, path)).href
const moduleUrl = code => 'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
const transpile = code => ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
function imports(code, map) {
  for (const [name, target] of Object.entries(map)) {
    code = code.replaceAll("from '" + name + "'", 'from ' + JSON.stringify(target)).replaceAll('from "' + name + '"', 'from ' + JSON.stringify(target))
  }
  return code
}
const vueUrl = url('node_modules/vue/index.mjs')
const markdownUrl = moduleUrl(transpile(readFileSync(resolve(root, 'src/markdown.ts'), 'utf8')))
function compileComponent(path, map) {
  const source = readFileSync(resolve(root, path), 'utf8')
  if (path.endsWith('AnswerReport.vue')) assert.doesNotMatch(source, /v-html|innerHTML/)
  const { descriptor } = parse(source, { filename: path })
  const compiled = compileScript(descriptor, { id: path, inlineTemplate: true })
  return moduleUrl(imports(transpile(compiled.content), { vue: vueUrl, ...map }))
}
const markdownBlockUrl = compileComponent('src/components/MarkdownBlock.vue', { '../markdown': markdownUrl })
const { default: AnswerReport } = await import(compileComponent('src/components/AnswerReport.vue', { './MarkdownBlock.vue': markdownBlockUrl, '../markdown': markdownUrl }))

// Minimal Vue host exercises actual event handlers and reactive DOM updates.
const node = (type, text = '') => ({ type, text, children: [], props: {}, parent: null })
const renderer = createRenderer({
  createElement: type => node(type), createText: text => node('#text', text), createComment: text => node('#comment', text),
  setText: (el, text) => { el.text = text }, setElementText: (el, text) => { el.children = []; el.text = text },
  parentNode: el => el.parent, nextSibling: el => el.parent?.children[el.parent.children.indexOf(el) + 1] ?? null,
  patchProp: (el, key, old, value) => { el.props[key] = value },
  insert: (el, parent, anchor = null) => {
    if (el.parent) el.parent.children.splice(el.parent.children.indexOf(el), 1)
    el.parent = parent
    const index = anchor ? parent.children.indexOf(anchor) : -1
    if (index < 0) parent.children.push(el); else parent.children.splice(index, 0, el)
  },
  remove: el => { if (el.parent) el.parent.children.splice(el.parent.children.indexOf(el), 1) },
})
const flatten = el => [el, ...el.children.flatMap(flatten)]
const textOf = el => el.type === '#comment' ? '' : el.text + el.children.map(textOf).join('')
const container = node('root')
const props = { answer: '# Real answer' + String.fromCharCode(10) + '<script>alert(1)</script>', citations: [{ id: 'c1', title: 'Source', url: 'https://example.com/proof', score: .5 }, { id: 'c2', title: 'Unsafe', url: 'javascript:alert(1)', score: NaN }], thinking: true, completed: false, abstained: null, finalReview: null, error: '' }
const app = renderer.createApp(AnswerReport, props)
app.mount(container)
assert.match(textOf(container), /生成中/)
assert.match(textOf(container), /等待最终回执/)
assert.equal(flatten(container).filter(el => el.type === 'script').length, 0)
assert.equal(flatten(container).filter(el => el.type === 'a').length, 1)
const link = flatten(container).find(el => el.type === 'a')
assert.equal(link.props.href, 'https://example.com/proof')
assert.equal(link.props.rel, 'noreferrer noopener')
const details = flatten(container).filter(el => el.type === 'details')
assert.equal(details.length, 2)
assert.equal(details[0].props.open, true)
details[0].props.onToggle({ target: { open: false } })
await nextTick()
assert.equal(details[0].props.open, false)
app._instance.props.answer += ' streamed update'
await nextTick()
assert.match(textOf(container), /streamed update/)
assert.equal(details[0].props.open, false)
props.answer = app._instance.props.answer
const button = label => flatten(container).find(el => el.type === 'button' && textOf(el).includes(label))
button('查看原文').props.onClick()
await nextTick()
assert.equal(flatten(container).find(el => el.type === 'pre').text, props.answer)
const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
try {
  let copied = ''
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { clipboard: { writeText: async text => { copied = text } } } })
  await button('复制回答原文').props.onClick()
  await nextTick()
  assert.equal(copied, props.answer)
  assert.match(textOf(container), /已复制回答原文/)
  globalThis.navigator.clipboard.writeText = async () => { throw new Error('denied') }
  await button('复制回答原文').props.onClick()
  await nextTick()
  assert.match(textOf(container), /复制失败/)
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {} })
  await button('复制回答原文').props.onClick()
  await nextTick()
  assert.match(textOf(container), /手动选择复制/)
} finally {
  if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor); else delete globalThis.navigator
  app.unmount()
}
for (const status of ['accepted', 'rejected', 'failed', 'skipped']) {
  const target = node('root')
  const instance = renderer.createApp(AnswerReport, { ...props, thinking: false, completed: true, abstained: true, finalReview: { status, reason: 'Review reason <img src=x>' } })
  instance.mount(target)
  assert.match(textOf(target), /已拒答（abstained=true）/)
  assert.match(textOf(target), /Review reason/)
  assert.match(textOf(target), new RegExp({ accepted: '已接受', rejected: '已拒绝', failed: '复核失败', skipped: '已跳过' }[status]))
  assert.equal(flatten(target).filter(el => el.type === 'img').length, 0)
  instance.unmount()
}

// API mock drives the genuine store with done, reset, stop and late events.
globalThis.__qaStreams = []
const apiMock = moduleUrl('export const getJson = async () => ({}); export function streamChat(body, event, error) { globalThis.__qaStreams.push({ event, error }); return () => {}; }')
const uiUrl = moduleUrl(transpile(readFileSync(resolve(root, 'src/qa-ui.ts'), 'utf8')))
const storeSource = readFileSync(resolve(root, 'src/stores/qa.ts'), 'utf8')
const { useQaStore } = await import(moduleUrl(imports(transpile(storeSource), { vue: vueUrl, pinia: url('node_modules/pinia/dist/pinia.mjs'), '../api': apiMock, '../qa-ui': uiUrl })))
setActivePinia(createPinia())
const qa = useQaStore()
qa.ask('first')
let stream = globalThis.__qaStreams.at(-1)
stream.event({ event: 'token', text: 'Refusal words do not decide state' })
stream.event({ event: 'stage', stage: 'check', abstained: true, final_review: { status: 'accepted', reason: 'not authoritative' } })
assert.equal(qa.abstained, null)
assert.equal(qa.finalReview, null)
for (const status of ['accepted', 'rejected', 'failed', 'skipped']) {
  qa.ask(status)
  stream = globalThis.__qaStreams.at(-1)
  stream.event({ event: 'done', abstained: status === 'rejected', final_review: { status, reason: 'backend reason' } })
  assert.equal(qa.completed, true)
  assert.equal(qa.thinking, false)
  assert.equal(qa.abstained, status === 'rejected')
  assert.deepEqual(qa.finalReview, { status, reason: 'backend reason' })
}
qa.ask('optional fields omitted')
assert.equal(qa.completed, false)
assert.equal(qa.abstained, null)
assert.equal(qa.finalReview, null)
stream = globalThis.__qaStreams.at(-1)
stream.event({ event: 'done' })
assert.equal(qa.abstained, null)
assert.equal(qa.finalReview, null)
qa.ask('malformed fields')
stream = globalThis.__qaStreams.at(-1)
stream.event({ event: 'done', abstained: 'false', final_review: { status: 'invented', reason: 'x' } })
assert.equal(qa.abstained, null)
assert.equal(qa.finalReview, null)
qa.ask('malformed review status array')
stream = globalThis.__qaStreams.at(-1)
stream.event({ event: 'done', final_review: { status: ['accepted'], reason: 'x' } })
assert.equal(qa.finalReview, null)
qa.ask('cancelled request')
const old = globalThis.__qaStreams.at(-1)
qa.stop()
old.event({ event: 'done', abstained: true, final_review: { status: 'accepted', reason: 'late' } })
assert.equal(qa.completed, false)
qa.ask('current request')
old.event({ event: 'token', text: 'stale answer' })
assert.equal(qa.answer, '')
stream = globalThis.__qaStreams.at(-1)
stream.error('network failed')
assert.equal(qa.completed, false)
assert.equal(qa.error, 'network failed')
assert.equal(qa.thinking, false)
delete globalThis.__qaStreams
console.log('PASS answer report: live rendering, collapse, raw source, clipboard success/failure, safe links, all review states, authoritative done/reset/late-event guards')

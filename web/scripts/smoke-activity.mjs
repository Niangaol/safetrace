/** Scoped SSE smoke: no server, no secrets, no repository mutations. */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const url = source => 'data:text/javascript;base64,' + Buffer.from(source).toString('base64')
const compile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText
const typesUrl = url(compile(readFileSync(new URL('../src/activity-types.ts', import.meta.url), 'utf8')))
const source = readFileSync(new URL('../src/activity-api.ts', import.meta.url), 'utf8').replaceAll("from './activity-types'", 'from ' + JSON.stringify(typesUrl))
const { consumeActivitySse, streamActivity, parseActivityEvent } = await import(url(compile(source)))
const encoder = new TextEncoder()
const body = text => new ReadableStream({ start(controller) { for (const byte of encoder.encode(text)) controller.enqueue(Uint8Array.of(byte)); controller.close() } })
const event = (sequence, origin = 'live') => ({ event: 'activity', id: 'activity-' + sequence, sequence, trace_id: 'trace', intel_id: null, stage: 'quality', status: 'review', at: '2026-01-01T00:00:00Z', label: '真实中文情报 🔎', origin, details: { reason: '待复核', elapsed_ms: 0 } })
const frame = value => 'event: ' + value.event + '\r\ndata: ' + JSON.stringify(value) + '\r\n\r\n'
let passed = 0
async function test(name, run) { await run(); console.log('PASS ' + name); passed++ }
await test('hello / recorded / live / heartbeat: single-byte UTF-8 + CRLF chunks', async () => {
 const values = [{ event: 'hello', live: true, cursor: 2, db_status: 'available' }, event(1, 'recorded'), event(2, 'recorded'), event(3), { event: 'heartbeat', at: 'now', cursor: 3 }]
 const got = []
 await consumeActivitySse(body(': comment\r\n\r\n' + values.map(frame).join('')), value => got.push(value))
 assert.deepEqual(got, values)
})
await test('multiline data and wire event fallback', async () => {
 const got = []
 await consumeActivitySse(body('event: error\ndata: {\ndata: "message": "中文错误"\ndata: }\n\n'), value => got.push(value))
 assert.deepEqual(got, [{ event: 'error', message: '中文错误' }])
})
await test('reset and error preserved without manufactured success', async () => {
 const values = [{ event: 'reset', reason: 'cursor expired', cursor: 100 }, { event: 'error', message: 'database unavailable' }], got = []
 await consumeActivitySse(body(values.map(frame).join('')), value => got.push(value)); assert.deepEqual(got, values)
})
await test('positive sequence and honest schema validation', () => {
 assert.throws(() => parseActivityEvent(event(0)), /schema/)
 assert.throws(() => parseActivityEvent({ ...event(1), details: { elapsed_ms: 'fake' } }))
 assert.equal(parseActivityEvent(event(1)).details.elapsed_ms, 0)
})
await test('truncated stream does not dispatch incomplete packet', async () => {
 const got = []
 await assert.rejects(consumeActivitySse(body('data: ' + JSON.stringify(event(1))), value => got.push(value)), /不完整/)
 assert.equal(got.length, 0)
})
await test('normal EOF is surfaced as disconnect by client', async () => {
 await assert.rejects(streamActivity({ signal: new AbortController().signal, onEvent() {}, fetchImpl: async () => new Response(body(frame(event(1))), { headers: { 'content-type': 'text/event-stream' } }) }), /断线/)
})
await test('GET auth and reconnect cursor passed without mutation', async () => {
 const previous = globalThis.localStorage
 globalThis.localStorage = { getItem: key => key === 'api_token' ? 'smoke-not-a-real-token' : null }
 try {
  await assert.rejects(streamActivity({ after: 42, signal: new AbortController().signal, onEvent() {}, fetchImpl: async (target, options) => {
   assert.equal(target, '/api/v1/activity/stream?after=42'); assert.equal(options.method, 'GET'); assert.equal(options.headers.Authorization, 'Bearer smoke-not-a-real-token'); assert.equal(options.body, undefined)
   return new Response(null, { status: 503 })
  } }), /503/)
 } finally { if (previous === undefined) delete globalThis.localStorage; else globalThis.localStorage = previous }
})
await test('abort cancels pending reader and dispatches no packets', async () => {
 let cancelled = false
 const controller = new AbortController(), got = []
 const promise = consumeActivitySse(new ReadableStream({ cancel() { cancelled = true } }), value => got.push(value), controller.signal)
 controller.abort()
 await assert.rejects(promise, { name: 'AbortError' }); assert.equal(cancelled, true); assert.equal(got.length, 0)
})
await test('callback failure is not swallowed as malformed JSON', async () => {
 await assert.rejects(consumeActivitySse(body(frame(event(1))), () => { throw new Error('callback failed') }), /callback failed/)
})
await test('invalid MIME and oversized unterminated frames rejected', async () => {
 await assert.rejects(streamActivity({ signal: new AbortController().signal, onEvent() {}, fetchImpl: async () => new Response('html') }), /SSE/)
 await assert.rejects(consumeActivitySse(new ReadableStream({ start(c) { c.enqueue(encoder.encode('data: ' + 'x'.repeat(262145))); c.close() } }), () => {}), /安全限制/)
})
await test('component aggregation / 500 history / eight-card flood / pause / resume / gaps / teardown', async () => {
 const { parse, compileScript, compileTemplate, compileStyle } = await import('@vue/compiler-sfc')
 const text = readFileSync(new URL('../src/components/ActivityBoard.vue', import.meta.url), 'utf8')
 const { descriptor, errors } = parse(text)
 assert.deepEqual(errors, [])
 assert.deepEqual(compileTemplate({ source: descriptor.template.content, filename: 'ActivityBoard.vue', id: 'activity-smoke' }).errors, [])
 assert.deepEqual(compileStyle({ source: descriptor.styles[0].content, filename: 'ActivityBoard.vue', id: 'activity-smoke', scoped: true }).errors, [])
 const hooks = { mounted: [], unmounted: [], receive: undefined }
 globalThis.__activitySmoke = hooks
 const runtime = url('const r=v=>({value:v}); export {r as ref,r as shallowRef}; export const computed=f=>({get value(){return f()}}); export const defineComponent=v=>v; export const onMounted=f=>globalThis.__activitySmoke.mounted.push(f); export const onBeforeUnmount=f=>globalThis.__activitySmoke.unmounted.push(f)')
 const api = url('export const IS_DEMO_MODE=false')
 const stream = url('export const streamActivity=o=>{globalThis.__activitySmoke.receive=o.onEvent;return new Promise((_,reject)=>o.signal.addEventListener("abort",()=>reject(new DOMException("Aborted","AbortError")),{once:true}))}')
 let script = compileScript(descriptor, { id: 'activity-smoke' }).content
 script = script.replaceAll("from './ParcelPipeline.vue'",'from '+JSON.stringify(url('export default {}')))
 assert.ok(!text.includes('class="paper-tray"'),'duplicate lower data cards removed')
 script = script.replaceAll("from 'vue'", 'from ' + JSON.stringify(runtime))
 script = script.replaceAll("from '../api'", 'from ' + JSON.stringify(api))
 script = script.replaceAll("from '../activity-api'", 'from ' + JSON.stringify(stream))
 script = script.replaceAll("from '../activity-types'", 'from ' + JSON.stringify(typesUrl))
 const frames = new Map(), previousRaf = globalThis.requestAnimationFrame, previousCancel = globalThis.cancelAnimationFrame
 let frameId = 0
 globalThis.requestAnimationFrame = callback => { frames.set(++frameId, callback); return frameId }
 globalThis.cancelAnimationFrame = id => frames.delete(id)
 const flush = () => { for (const [id, callback] of frames) { frames.delete(id); callback(0) } }
 try {
  const component = (await import(url(compile(script)))).default
  const state = component.setup({}, { expose() {} })
  for (const hook of hooks.mounted) hook()
  assert.equal(state.cards.value.length, 0, 'no events means no packets')
  hooks.receive({ event: 'hello', live: true, cursor: 0, db_status: 'available' })
  hooks.receive(event(1, 'recorded'))
  hooks.receive({ ...event(2), stage: 'review' })
  flush()
  assert.equal(state.cards.value.length, 1); assert.equal(state.cards.value[0].count, 2)
  assert.equal(state.cards.value[0].latest.intel_id, null)
  assert.equal(Object.keys(state.cards.value[0].stages).length, 2)
  state.togglePause()
  for (let sequence = 3; sequence <= 602; sequence++) hooks.receive({ ...event(sequence), intel_id: 'intel-' + sequence })
  flush()
  assert.equal(state.cards.value.length, 1, 'paused cards frozen')
  assert.equal(state.total.value, 602); assert.equal(state.pending.value, 600)
  state.togglePause()
  assert.equal(state.history.value.length, 500); assert.equal(state.trimmed.value, 102)
  assert.equal(state.cards.value.length, 500); assert.equal(state.archivedGroups.value, 101)
  assert.equal(state.pending.value, 0)
  hooks.receive(event(604)); flush(); assert.match(state.gap.value, /603/)
  const count = state.total.value
  hooks.receive(event(604)); assert.equal(state.total.value, count, 'replay duplicate not recounted')
  hooks.receive({ event: 'reset', reason: 'expired', cursor: 604 }); flush()
  assert.equal(state.cards.value.length, 0); assert.match(state.gap.value, /expired/)
  hooks.receive(event(605)); assert.equal(frames.size, 1)
  for (const hook of hooks.unmounted) hook()
  assert.equal(frames.size, 0, 'unmount cancels queued render')
  await Promise.resolve()
 } finally {
  delete globalThis.__activitySmoke
  if (previousRaf === undefined) delete globalThis.requestAnimationFrame; else globalThis.requestAnimationFrame = previousRaf
  if (previousCancel === undefined) delete globalThis.cancelAnimationFrame; else globalThis.cancelAnimationFrame = previousCancel
 }
})
console.log('Activity smoke: ' + passed + ' passed')
await import('./smoke-parcels.mjs')

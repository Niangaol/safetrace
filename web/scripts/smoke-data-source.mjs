/**
 * 前端数据来源 / SSE 解析逻辑烟测（无需浏览器/后端）。
 *
 * 为什么需要它：`web/src/api.ts` 的"演示模式开关"与"拿不到数据怎么办"是**诚实性红线**
 * 的落点——默认必须走真实后端，拿不到要如实报错，只有显式 VITE_DEMO_MODE=true
 * 才允许用预置数据；streamChat 的 SSE 逐行解析（多行帧不能丢事件）也只靠人眼看代码
 * 很容易改坏，所以用脚本钉住。
 *
 * 本脚本改编自 KKK9747human 的 aab1488（原作者为三态 VITE_USE_MOCK 口径；
 * main 采用等价但更简单的二值 VITE_DEMO_MODE 口径，故用例按 main 口径重写）。
 *
 * 用法：node scripts/smoke-data-source.mjs（在 web/ 目录下）
 */

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

// ── 最小环境桩 ───────────────────────────────────────────
const store = new Map()
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
}

/** 把 api.ts 复制到临时目录，脱掉 vue 依赖（只测数据来源判定，不测响应式）。 */
async function loadApi(importMetaEnv, fetchImpl) {
  const dir = mkdtempSync(join(tmpdir(), 'safetrace-api-'))
  const { readFileSync, writeFileSync } = await import('node:fs')
  let source = readFileSync(join(process.cwd(), 'src', 'api.ts'), 'utf8')
  // vue 的 ref 在 node 里不必真响应式：用一个带 .value 的对象顶替
  source = source.replace("import { ref } from 'vue'", 'const ref = (v) => ({ value: v })')
  // Node 的 TS loader 对相对导入要求显式扩展名（打包器会补，node 不会）
  source = source.replace("from './mock'", "from './mock.ts'")
  // 让 import.meta.env.VITE_DEMO_MODE 有确定取值（node 没有 vite 注入的 env）
  source = source.replace(
    'import.meta.env.VITE_DEMO_MODE',
    JSON.stringify(importMetaEnv.VITE_DEMO_MODE ?? ''),
  )
  const tmpFile = join(dir, 'api.ts')
  writeFileSync(tmpFile, source, 'utf8')
  writeFileSync(join(dir, 'package.json'), '{"type":"module"}', 'utf8')
  // api.ts 里 `import ... from './mock'` 是相对导入，把依赖一起带过去
  // （mock.ts 只 import type，运行时不需要额外文件）
  writeFileSync(join(dir, 'mock.ts'), readFileSync(join(process.cwd(), 'src', 'mock.ts'), 'utf8'), 'utf8')

  globalThis.fetch = fetchImpl
  const mod = await import(pathToFileURL(tmpFile).href)
  return { mod, cleanup: () => rmSync(dir, { recursive: true, force: true }) }
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
  }
}

/** 把若干 SSE 文本块包成 fake fetch 响应（ReadableStream）。 */
function sseResponse(chunks) {
  const encoder = new TextEncoder()
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    body: new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(encoder.encode(chunk))
        controller.close()
      },
    }),
  }
}

const results = []
async function check(name, fn) {
  try {
    await fn()
    results.push(`  [ OK ] ${name}`)
  } catch (e) {
    results.push(`  [FAIL] ${name}\n         ${e.message}`)
    process.exitCode = 1
  }
}

// ── 用例 ─────────────────────────────────────────────────

await check('默认（未设 VITE_DEMO_MODE）→ 请求真实后端，不用预置数据', async () => {
  let called = false
  const { mod, cleanup } = await loadApi({}, async () => {
    called = true
    return jsonResponse({ collect: { vulns: 7 }, enrich: {}, knowledge: {}, agents: {}, cost: {}, latency: {} })
  })
  try {
    assert.equal(mod.IS_DEMO_MODE, false)
    const data = await mod.getJson('/metrics/overview')
    assert.equal(data.collect.vulns, 7)
    assert.ok(called, '默认必须请求真实后端')
  } finally {
    cleanup()
  }
})

await check('VITE_DEMO_MODE=true → 始终预置数据，且不发起真实请求', async () => {
  const { mod, cleanup } = await loadApi(
    { VITE_DEMO_MODE: 'true' },
    async () => {
      throw new Error('演示模式不该发起真实请求')
    },
  )
  try {
    assert.equal(mod.IS_DEMO_MODE, true)
    const data = await mod.getJson('/metrics/overview')
    assert.equal(data.collect.vulns, 1284, '应返回预置指标（mockMetrics）')
  } finally {
    cleanup()
  }
})

await check('后端不可达（fetch 抛错）→ 如实抛错，不静默换成假数据', async () => {
  const { mod, cleanup } = await loadApi({}, async () => {
    throw new TypeError('fetch failed')
  })
  try {
    await assert.rejects(() => mod.getJson('/collect/status'), /fetch failed/)
  } finally {
    cleanup()
  }
})

await check('业务错误 401 → 如实抛错（带 message），不得替换成假数据', async () => {
  const { mod, cleanup } = await loadApi(
    {},
    async () => jsonResponse({ detail: { error: { message: 'token 无效' } } }, 401),
  )
  try {
    await assert.rejects(() => mod.getJson('/vulns'), /token 无效/)
  } finally {
    cleanup()
  }
})

await check('SSE 多行帧（event: + data: 同帧）→ 事件不丢', async () => {
  const events = []
  const { mod, cleanup } = await loadApi({}, async () =>
    sseResponse([
      ': 心跳注释帧\n\n',
      'data: {"event":"stage","stage":"plan"}\n\n',
      'event: citation\ndata: {"event":"citation","cve_id":"CVE-2026-12345"}\n\n',
    ]),
  )
  try {
    mod.streamChat({ question: 'Log4Shell 影响哪些版本？' }, (e) => events.push(e), () => {})
    await new Promise((r) => setTimeout(r, 100))
    assert.equal(events.length, 2, `应解析出 2 个事件，实际 ${events.length}`)
    assert.equal(events[0].event, 'stage')
    assert.equal(events[1].event, 'citation')
    assert.equal(events[1].cve_id, 'CVE-2026-12345', '多行帧的 data 载荷必须被解析')
  } finally {
    cleanup()
  }
})

console.log(results.join('\n'))
console.log(
  process.exitCode
    ? '\n前端数据来源 / SSE 逻辑烟测：有失败项'
    : '\n前端数据来源 / SSE 逻辑烟测：全部通过（默认真实后端 + 演示才用预置 + 如实报错 + 多行帧不丢）',
)

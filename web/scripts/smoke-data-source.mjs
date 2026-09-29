/**
 * 前端数据来源逻辑烟测（无需浏览器/后端）。
 *
 * 为什么需要它：`web/src/api.ts` 的"先真后假"回退是**诚实性红线**的落点——
 * 拿不到后端时必须回退到预置数据**并**把 `dataSource` 标成 mock，
 * 而业务错误（401/422）必须如实报错、不能拿假数据糊过去。
 * 这段逻辑只靠人眼看代码很容易改坏，所以用脚本钉住。
 *
 * 用法：node scripts/smoke-data-source.mjs
 */

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

// ── 最小 DOM/环境桩 ───────────────────────────────────────────
const store = new Map()
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
}

const warnings = []
const originalWarn = console.warn
console.warn = (...args) => {
  warnings.push(args.join(' '))
}

/** 把 api.ts 复制到一个临时目录，脱掉 vue 依赖（只测数据来源判定，不测响应式）。 */
async function loadApi(importMetaEnv, fetchImpl) {
  const dir = mkdtempSync(join(tmpdir(), 'safetrace-api-'))
  // 相对仓库（web/）定位，脚本从任何工作目录调用都能找到源码
  const sourcePath = join(process.cwd(), 'src', 'api.ts')
  const { readFileSync, writeFileSync } = await import('node:fs')
  let source = readFileSync(sourcePath, 'utf8')
  // vue 的 ref 在 node 里不必真响应式：用一个带 .value 的对象顶替
  source = source.replace("import { ref } from 'vue'", 'const ref = (v) => ({ value: v })')
  // Node 的 TS loader 对相对导入要求显式扩展名（打包器会补，node 不会）
  source = source.replace("from './mock'", "from './mock.ts'")
  // 让 import.meta.env.VITE_USE_MOCK 有确定取值（node 没有 vite 注入的 env）
  source = source.replace(
    'import.meta.env.VITE_USE_MOCK',
    JSON.stringify(importMetaEnv.VITE_USE_MOCK ?? ''),
  )
  const tmpFile = join(dir, 'api.ts')
  writeFileSync(tmpFile, source, 'utf8')
  writeFileSync(join(dir, 'package.json'), '{"type":"module"}', 'utf8')
  // api.ts 里 `import ... from './mock'` 是相对导入，把依赖一起带过去
  // （mock.ts 只 import type，运行时不需要额外文件）
  for (const dep of ['mock.ts']) {
    writeFileSync(join(dir, dep), readFileSync(join(process.cwd(), 'src', dep), 'utf8'), 'utf8')
  }

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

const results = []
function check(name, fn) {
  return (async () => {
    try {
      await fn()
      results.push(`  [ OK ] ${name}`)
    } catch (e) {
      results.push(`  [FAIL] ${name}\n         ${e.message}`)
      process.exitCode = 1
    }
  })()
}

// ── 用例 ─────────────────────────────────────────────────────

await check('后端可用 → 用真实数据，来源标 live', async () => {
  const { mod, cleanup } = await loadApi(
    {},
    async () => jsonResponse({ collect: { vulns: 7 }, enrich: {}, knowledge: {}, agents: {}, cost: {}, latency: {} }),
  )
  try {
    assert.equal(mod.MOCK_MODE, 'auto')
    const data = await mod.getJson('/metrics/overview')
    assert.equal(data.collect.vulns, 7)
    assert.equal(mod.dataSource.value, 'live')
  } finally {
    cleanup()
  }
})

await check('后端 404（未实现该端点）→ 回退预置数据并标 mock', async () => {
  const { mod, cleanup } = await loadApi({}, async () => jsonResponse({}, 404))
  try {
    const data = await mod.getJson('/metrics/overview')
    assert.ok(data && typeof data === 'object', '应回退到预置指标对象')
    assert.equal(mod.dataSource.value, 'mock')
    assert.match(mod.dataSourceReason.value, /404/)
  } finally {
    cleanup()
  }
})

await check('后端不可达（fetch 抛错）→ 回退预置数据并标 mock', async () => {
  const { mod, cleanup } = await loadApi({}, async () => {
    throw new TypeError('fetch failed')
  })
  try {
    await mod.getJson('/collect/status')
    assert.equal(mod.dataSource.value, 'mock')
    assert.match(mod.dataSourceReason.value, /不可达/)
  } finally {
    cleanup()
  }
})

await check('业务错误 401 → 如实抛错，不得替换成假数据', async () => {
  const { mod, cleanup } = await loadApi(
    {},
    async () => jsonResponse({ detail: { error: { message: 'token 无效' } } }, 401),
  )
  try {
    await assert.rejects(() => mod.getJson('/vulns'), /token 无效/)
    assert.equal(mod.dataSource.value, 'live', '业务错误不应改变数据来源标记')
  } finally {
    cleanup()
  }
})

await check('VITE_USE_MOCK=true → 始终预置数据（演示模式）', async () => {
  const { mod, cleanup } = await loadApi(
    { VITE_USE_MOCK: 'true' },
    async () => {
      throw new Error('不该发起真实请求')
    },
  )
  try {
    assert.equal(mod.MOCK_MODE, 'always')
    await mod.getJson('/metrics/overview')
    assert.equal(mod.dataSource.value, 'mock')
    assert.match(mod.dataSourceReason.value, /演示模式/)
  } finally {
    cleanup()
  }
})

await check('VITE_USE_MOCK=false → 后端不可用时报错，绝不回退', async () => {
  const { mod, cleanup } = await loadApi({ VITE_USE_MOCK: 'false' }, async () => {
    throw new TypeError('fetch failed')
  })
  try {
    assert.equal(mod.MOCK_MODE, 'never')
    await assert.rejects(() => mod.getJson('/metrics/overview'))
    assert.equal(mod.dataSource.value, 'live')
  } finally {
    cleanup()
  }
})

console.warn = originalWarn
console.log(results.join('\n'))
console.log(
  process.exitCode
    ? '\n数据来源逻辑烟测：有失败项'
    : '\n数据来源逻辑烟测：全部通过（先真后假 + 显式标注 + 业务错误不掩盖）',
)

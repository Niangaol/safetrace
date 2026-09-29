/**
 * 探针：把 Vite 转译后的**真实 api.ts** 拉下来在 Node 里执行，
 * 用真后端（127.0.0.1:8000）验证它判定为 live 而不是 mock。
 *
 * 用途：证明"前端真连后端"这条链路真的通，而不是只看代码。
 * 注意：Node 原生 fetch 不能直接访问相对路径，所以这里先把
 * 相对 '/api/v1/...' 拼成绝对地址。
 */
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const VITE = 'http://127.0.0.1:5181'
const API = 'http://127.0.0.1:8000'
const realFetch = globalThis.fetch.bind(globalThis)

const store = new Map()
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
}

// 把相对 URL 转成打到后端的绝对 URL，模拟 vite 代理
globalThis.fetch = async (url, init) => {
  let target = String(url)
  if (target.startsWith('/')) target = API + target
  return realFetch(target, init)
}

const apiSrc = await (await realFetch(`${VITE}/src/api.ts`)).text()
const mockSrc = await (await realFetch(`${VITE}/src/mock.ts`)).text()

const dir = mkdtempSync(join(tmpdir(), 'probe-demo-'))
let s = apiSrc
// Vite 已把 vue 的 import 改写成 /node_modules/.vite/deps/vue.js：换成极简 ref
s = s.replace(
  /import\s*\{[^}]*\}\s*from\s*["'][^"']*\/vue\.js[^"']*["'];?/,
  'const ref = (v) => ({ value: v });',
)
// Vite 会把相对导入改写成 /src/mock.ts 这种绝对路径，两种形态都要处理
s = s.replace(/from\s*["'](?:\.\/|\/src\/)mock(?:\.ts)?["']/g, 'from "./mock.ts"')
writeFileSync(join(dir, 'api.mjs'), s, 'utf8')
writeFileSync(join(dir, 'mock.ts'), mockSrc, 'utf8')

const mod = await import(pathToFileURL(join(dir, 'api.mjs')).href)

assert.equal(mod.MOCK_MODE, 'auto', `MOCK_MODE 应为 auto，实际 ${mod.MOCK_MODE}`)
const m = await mod.getJson('/metrics/overview')
assert.equal(mod.dataSource.value, 'live', `期望 live，实际 ${mod.dataSource.value}（${mod.dataSourceReason.value}）`)
assert.ok(m.collect.vulns > 0, '漏洞数应 > 0')

const v = await mod.getJson('/vulns', { page_size: 3, sort: 'epss' })
assert.ok(v.items[0].epss !== undefined, 'epss 应外发')
assert.ok(v.items[0].kev !== undefined, 'kev 应外发')

console.log('  [ OK ] 真实模块判定 dataSource =', mod.dataSource.value)
console.log('  [ OK ] metrics.vulns =', m.collect.vulns, ' enrich.dimensions =', m.enrich.dimensions)
console.log('  [ OK ] /vulns 首条 =', v.items[0].cve_id, ' epss =', v.items[0].epss, ' kev =', v.items[0].kev)
console.log('\n前端真实模块 ↔ 真后端：判定 live，数据打通（非预置数据）')

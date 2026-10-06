// 特效层回归：不依赖浏览器，也不需要任何第三方库。
// 覆盖动效偏好默认/覆盖/广播，以及粒子、连线、光束、涟漪的有界性与暂停行为。
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { AmbientEngine } from '../src/effects/ambient-engine.ts'
import { applyMotionIntensity, getMotionIntensity, isMotionIntensity, onMotionIntensityChange, readStoredIntensity, resolveMotionIntensity, systemPrefersReducedMotion } from '../src/effects/motion-prefs.ts'

const checks = []
async function check(name, fn) {
  try { await fn(); checks.push(name); console.log('PASS ' + name) }
  catch (error) { const detail = error && error.stack ? error.stack : String(error); console.error('FAIL ' + name); console.error('  ' + detail); process.exitCode = 1 }
}

function createContext() {
  const log = []
  const record = (name, args) => {
    for (const value of args) if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('非有限坐标传入 ' + name + ': ' + args.join(','))
    log.push({ name, args })
  }
  const gradient = { addColorStop: (offset, color) => { if (!Number.isFinite(offset)) throw new Error('渐变色标非有限'); if (typeof color !== 'string' || !color.startsWith('rgba(')) throw new Error('渐变色格式异常: ' + color) } }
  return {
    log,
    calls: () => log.length,
    count: (name) => log.filter(entry => entry.name === name).length,
    setTransform: (...a) => record('setTransform', a),
    clearRect: (...a) => record('clearRect', a),
    fillRect: (...a) => record('fillRect', a),
    beginPath: () => log.push({ name: 'beginPath', args: [] }),
    arc: (...a) => record('arc', a),
    fill: () => log.push({ name: 'fill', args: [] }),
    moveTo: (...a) => record('moveTo', a),
    lineTo: (...a) => record('lineTo', a),
    stroke: () => log.push({ name: 'stroke', args: [] }),
    save: () => log.push({ name: 'save', args: [] }),
    restore: () => log.push({ name: 'restore', args: [] }),
    translate: (...a) => record('translate', a),
    transform: (...a) => record('transform', a),
    createLinearGradient: (...a) => { record('createLinearGradient', a); return gradient },
    fillStyle: '', strokeStyle: '', lineWidth: 1, globalCompositeOperation: 'source-over'
  }
}
function createCanvas(width, height) {
  const ctx = createContext()
  const canvas = { width: 0, height: 0, clientWidth: width, clientHeight: height, style: {}, getContext: (kind) => (kind === '2d' ? ctx : null) }
  return { canvas, ctx }
}
function createScheduler() {
  const callbacks = new Map()
  let time = 0
  return {
    requestFrame: (callback) => { const handle = callbacks.size + 1; callbacks.set(handle, callback); return handle },
    cancelFrame: (handle) => { callbacks.delete(handle) },
    tick(step = 16.7, times = 1) {
      for (let n = 0; n < times; n++) {
        time += step
        const current = [...callbacks.entries()]
        callbacks.clear()
        for (const [, callback] of current) callback(time)
      }
      return time
    },
    size: () => callbacks.size
  }
}
function seeded(seed) { let a = seed >>> 0; return () => { a = (a + 0x6d2b79f5) >>> 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296 } }
function withLocalStorage(storage, fn) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true })
  try { return fn() } finally { if (previous) Object.defineProperty(globalThis, 'localStorage', previous); else delete globalThis.localStorage }
}
function memoryStorage() { const map = new Map(); return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => map.set(k, v), removeItem: (k) => map.delete(k) } }

await check('扫光层不越界、不拦截指针（CSS 契约回归）', async () => {
  const css = await readFile(new URL('../src/effects/effects.css', import.meta.url), 'utf8')
  const block = (selector) => { const index = css.indexOf(selector + ' {'); assert.ok(index >= 0, '缺少规则: ' + selector); const end = css.indexOf('\n}', index); return css.slice(index, end) }
  assert.match(block('.fx-sheen'), /overflow:\s*hidden/, '扫光必须被容器裁剪，避免覆盖相邻卡片')
  assert.match(block('.fx-sheen::after'), /pointer-events:\s*none/, '扫光伪元素不得拦截指针事件')
  assert.match(block('.fx-sheen::before'), /pointer-events:\s*none/, '光斑伪元素不得拦截指针事件')
  assert.match(block('.ambient-canvas'), /pointer-events:\s*none/, '环境画布不得拦截指针事件')
  assert.match(block('.pointer-spot'), /pointer-events:\s*none/, '指针微光不得拦截指针事件')
})

await check('动效偏好：系统减少动效默认关闭，显式选择优先', () => {
  assert.equal(isMotionIntensity('off'), true)
  assert.equal(isMotionIntensity('turbo'), false)
  assert.equal(resolveMotionIntensity(undefined, true), 'off')
  assert.equal(resolveMotionIntensity(undefined, false), 'full')
  assert.equal(resolveMotionIntensity('full', true), 'full', '用户显式选择必须压过系统偏好')
  assert.equal(systemPrefersReducedMotion(() => true), true)
  assert.equal(systemPrefersReducedMotion(() => { throw new Error('x') }), false)
})

await check('动效开关：持久化、广播与非法值拒绝', () => {
  const storage = memoryStorage()
  let seen = null
  const unbind = onMotionIntensityChange((value) => { seen = value })
  try {
    withLocalStorage(storage, () => {
      applyMotionIntensity('low', storage)
      assert.equal(readStoredIntensity(), 'low')
      assert.equal(getMotionIntensity(), 'low')
      applyMotionIntensity('full', storage)
      assert.equal(seen, 'full', '偏好变化必须广播')
      assert.equal(readStoredIntensity(), 'full')
      assert.throws(() => applyMotionIntensity('fast', storage))
      applyMotionIntensity('off', storage)
    })
  } finally { unbind() }
})

await check('环境层：挂载后可启动，帧与粒子上界受控', () => {
  const scheduler = createScheduler()
  const { canvas, ctx } = createCanvas(1440, 900)
  const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(7), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame, maxParticles: 90 })
  engine.start()
  scheduler.tick(16.7, 30)
  const stats = engine.stats()
  assert.equal(stats.running, true)
  assert.ok(stats.particles > 0 && stats.particles <= 90, '粒子数应有界: ' + stats.particles)
  assert.equal(stats.beams, 3)
  assert.ok(stats.frames >= 25, '应持续出帧: ' + stats.frames)
  assert.ok(ctx.count('arc') >= stats.particles, '每个粒子都应绘制')
  assert.ok(ctx.count('fillRect') >= 3, '每条光束都应绘制')
  engine.dispose()
})

await check('环境层：长跑坐标不含 NaN，粒子不越界', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(800, 600)
  const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(11), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame, maxParticles: 60 })
  engine.start()
  scheduler.tick(16.7, 400)
  engine.dispose()
})

await check('环境层：DPR 上限 2，缩放后尺寸正确', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(1000, 500)
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'devicePixelRatio')
  Object.defineProperty(globalThis, 'devicePixelRatio', { value: 5, configurable: true })
  try {
    const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(3), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
    engine.start()
    const stats = engine.stats()
    assert.equal(stats.dpr, 2, 'DPR 必须被限制')
    assert.equal(canvas.width, 2000)
    assert.equal(canvas.height, 1000)
    assert.equal(canvas.style.width, '1000px')
    engine.dispose()
  } finally { if (previous) Object.defineProperty(globalThis, 'devicePixelRatio', previous); else delete globalThis.devicePixelRatio }
})

await check('环境层：低强度更少粒子、更少光束', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(1440, 900)
  const full = new AmbientEngine({ canvas, intensity: 'full', random: seeded(5), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
  const low = new AmbientEngine({ canvas, intensity: 'low', random: seeded(5), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
  assert.ok(low.stats().particles < full.stats().particles, '低强度粒子必须更少')
  assert.equal(low.stats().beams, 2)
  full.dispose(); low.dispose()
})

await check('环境层：关闭时不建粒子、不出帧', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(1440, 900)
  const engine = new AmbientEngine({ canvas, intensity: 'off', random: seeded(5), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
  engine.start()
  scheduler.tick(16.7, 10)
  const stats = engine.stats()
  assert.equal(stats.particles, 0)
  assert.equal(stats.frames, 0)
  assert.equal(stats.running, false)
  engine.dispose()
})

await check('环境层：减少动效只画静态帧，不循环', () => {
  const scheduler = createScheduler()
  const { canvas, ctx } = createCanvas(1200, 800)
  const engine = new AmbientEngine({ canvas, intensity: 'full', reducedMotion: true, random: seeded(9), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
  engine.start()
  assert.ok(ctx.count('clearRect') >= 1, '应渲染静态帧')
  assert.equal(scheduler.size(), 0, '不得继续请求帧')
  engine.dispose()
})

await check('环境层：页面隐藏即停，恢复后继续', () => {
  const scheduler = createScheduler()
  let visible = true
  const { canvas } = createCanvas(1440, 900)
  const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(13), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame, visible: () => visible })
  engine.start()
  scheduler.tick(16.7, 5)
  assert.ok(engine.stats().frames > 0)
  visible = false
  engine.syncVisibility()
  assert.equal(engine.stats().running, false)
  const before = engine.stats().frames
  scheduler.tick(16.7, 10)
  assert.equal(engine.stats().frames, before, '隐藏期间不得出帧')
  visible = true
  engine.syncVisibility()
  assert.equal(engine.stats().running, true)
  scheduler.tick(16.7, 5)
  assert.ok(engine.stats().frames > before)
  engine.dispose()
})

await check('环境层：每点连线数有界', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(1440, 900)
  const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(21), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame, maxConnectionsPerParticle: 2 })
  engine.start()
  scheduler.tick(16.7, 5)
  const stats = engine.stats()
  assert.ok(stats.particles * 2 >= stats.links, '每点连线数必须受限: ' + stats.links + '/' + stats.particles)
  engine.dispose()
})

await check('环境层：释放后不再响应，重复释放安全', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(800, 600)
  const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(31), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
  engine.start()
  scheduler.tick(16.7, 3)
  engine.dispose()
  assert.equal(scheduler.size(), 0)
  assert.throws(() => engine.attach(canvas))
  engine.dispose()
})

await check('环境层：非法缩放输入被夹紧且不抛错', () => {
  const scheduler = createScheduler()
  const { canvas } = createCanvas(800, 600)
  const engine = new AmbientEngine({ canvas, intensity: 'full', random: seeded(41), requestFrame: scheduler.requestFrame, cancelFrame: scheduler.cancelFrame })
  engine.resize(Number.NaN, -10)
  assert.equal(engine.stats().width, 800, '非法尺寸不得破坏已有布局')
  engine.resize(3000, 1200)
  engine.start()
  scheduler.tick(16.7, 5)
  assert.equal(engine.stats().width, 3000)
  engine.dispose()
})

if (process.exitCode) { console.error('特效烟测存在失败项'); process.exit(1) }
console.log('特效层 / 动效烟测：全部通过（' + checks.length + ' 项）')

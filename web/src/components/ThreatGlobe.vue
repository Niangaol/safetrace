<script setup lang="ts">
/**
 * ThreatGlobe：卡巴斯基威胁地图风格的线框地球，作为 hero 背景装饰。
 *
 * 实现要点：
 * - Canvas 2D + 正交投影（yaw/pitch 旋转），**完整球体**（经纬网覆盖 -90°~90° 全纬度），
 *   半径按容器取 `min(w,h)/2` 并留 3% 余量，保证球体完整不裁切；
 * - **纯装饰、零交互**：不响应鼠标/触摸，不拖动、不点击跳转（避免"拖完松手"或
 *   "选中文字"误触发导航）。`pointer-events: none` 从根上杜绝误触；
 * - 攻击点为**确定性示意数据**（非实时采集），前端不轮询、不伪造"实时"；
 * - 性能：极慢自转 + **30fps 限帧**（不是每帧重绘）；元素不可见 / 标签页隐藏时
 *   完全停帧；`prefers-reduced-motion` 下静止。
 */
import { onBeforeUnmount, onMounted, ref } from 'vue'

const SPIN = 0.055 // 自转速度 rad/s
const FPS = 30 // 限帧：30fps 足够，CPU 约为 60fps 的一半
const PITCH = 0.22 // 固定俯仰：略微俯视，让赤道与回归线都能看见

interface V3 {
  /** 单位向量 */
  x: number
  y: number
  z: number
  kind: number // 0 中性 1 防御 2 攻击
  r: number
}

/** 确定性生成的示意点位（Fibonacci 球面分布，覆盖全球） */
function buildNodes(): V3[] {
  const out: V3[] = []
  const N = 190
  for (let i = 0; i < N; i++) {
    const latDeg = ((i * 0.6180339887) % 1) * 172 - 86
    const lon = ((i * 2.3999632297) % 1) * 360 - 180
    const lat = (latDeg * Math.PI) / 180
    const p = (lon * Math.PI) / 180
    const ct = Math.cos(lat)
    out.push({
      x: ct * Math.sin(p),
      y: Math.sin(lat),
      z: ct * Math.cos(p),
      kind: i % 9 === 0 ? 2 : i % 4 === 0 ? 1 : 0,
      r: i % 9 === 0 ? 2.4 : i % 4 === 0 ? 1.8 : 1.3,
    })
  }
  return out
}

const NODES = buildNodes()

/** 确定性示意攻击弧（全球两点之间的抬升贝塞尔） */
const ARCS: { a: number; b: number; kind: number }[] = (() => {
  const out: { a: number; b: number; kind: number }[] = []
  for (let k = 0; k < 14; k++) {
    const a = Math.floor(((k * 0.6180339887) % 1) * NODES.length)
    const b = Math.floor(((k * 0.7548776662 + 0.31) % 1) * NODES.length)
    if (a === b) continue
    out.push({ a, b, kind: k % 5 === 0 ? 1 : 2 })
  }
  return out
})()

/** 经纬网：经线每 30°、纬线按纬度分层（覆盖全纬度），采样点提前算好 */
const MERIDIANS: V3[][] = []
const PARALLELS: V3[][] = []
for (let m = 0; m < 12; m++) {
  const lon = (m * Math.PI) / 6
  const pts: V3[] = []
  for (let latDeg = -90; latDeg <= 90; latDeg += 3) {
    const lat = (latDeg * Math.PI) / 180
    const ct = Math.cos(lat)
    pts.push({ x: ct * Math.sin(lon), y: Math.sin(lat), z: ct * Math.cos(lon), kind: 0, r: 0 })
  }
  MERIDIANS.push(pts)
}
for (const latDeg of [-60, -30, 0, 30, 60]) {
  const lat = (latDeg * Math.PI) / 180
  const y = Math.sin(lat)
  const rr = Math.cos(lat)
  const pts: V3[] = []
  for (let lon = -180; lon <= 180; lon += 5) {
    const p = (lon * Math.PI) / 180
    pts.push({ x: rr * Math.sin(p), y, z: rr * Math.cos(p), kind: 0, r: 0 })
  }
  PARALLELS.push(pts)
}

const cv = ref<HTMLCanvasElement | null>(null)
let yaw = -0.6
let raf = 0
let last = 0
let acc = 0
let visible = true
let reduceMotion = false
let w = 0
let h = 0
let ctx: CanvasRenderingContext2D | null = null
/** 球半径：由容器尺寸决定，保证整个球完整落在画布内 */
let radius = 1
let cx = 0
let cy = 0

function rot(p: V3): [number, number, number] {
  const x0 = p.x * radius
  const y0 = p.y * radius
  const z0 = p.z * radius
  const c = Math.cos(yaw)
  const s = Math.sin(yaw)
  const x1 = x0 * c + z0 * s
  const z1 = -x0 * s + z0 * c
  const cp = Math.cos(PITCH)
  const sp = Math.sin(PITCH)
  return [x1, y0 * cp - z1 * sp, y0 * sp + z1 * cp]
}

function draw() {
  if (!ctx) return
  ctx.clearRect(0, 0, w, h)

  // 经纬网：只画前半球，按深度衰减透明度
  ctx.lineWidth = 1
  for (const group of [MERIDIANS, PARALLELS]) {
    for (const line of group) {
      let drawing = false
      ctx.beginPath()
      for (const p of line) {
        const [x1, y1, z1] = rot(p)
        if (z1 <= 0) {
          drawing = false
          continue
        }
        if (drawing) ctx.lineTo(cx + x1, cy - y1)
        else {
          ctx.moveTo(cx + x1, cy - y1)
          drawing = true
        }
      }
      ctx.strokeStyle = 'rgba(148,197,255,0.16)'
      ctx.stroke()
    }
  }

  // 赤道：稍亮一点，作为"地面"参考线
  ctx.beginPath()
  let started = false
  for (const p of PARALLELS[2]) {
    const [x1, , z1] = rot(p)
    if (z1 <= 0) {
      started = false
      continue
    }
    if (started) ctx.lineTo(cx + x1, cy - 0)
    else {
      ctx.moveTo(cx + x1, cy)
      started = true
    }
  }
  ctx.strokeStyle = 'rgba(148,197,255,0.42)'
  ctx.lineWidth = 1.4
  ctx.stroke()

  // 攻击弧
  for (const a of ARCS) {
    const [ax, ay, az] = rot(NODES[a.a])
    const [bx, by, bz] = rot(NODES[a.b])
    if (az <= 0 || bz <= 0) continue
    const mx = (ax + bx) / 2
    const my = (ay + by) / 2
    const mz = (az + bz) / 2
    const len = Math.hypot(mx, my, mz) || 1
    ctx.beginPath()
    ctx.moveTo(cx + ax, cy - ay)
    ctx.quadraticCurveTo(cx + (mx / len) * len * 1.3, cy - (my / len) * len * 1.3, cx + bx, cy - by)
    ctx.strokeStyle = a.kind === 1 ? 'rgba(52,211,153,0.3)' : 'rgba(148,197,255,0.26)'
    ctx.lineWidth = 1.1
    ctx.stroke()
  }

  // 地表点位：按深度定透明度/半径，背面不画
  for (const p of NODES) {
    const [x1, y1, z1] = rot(p)
    if (z1 <= 0) continue
    const depth = z1 / radius
    const alpha = 0.16 + depth * 0.44
    ctx.beginPath()
    ctx.arc(cx + x1, cy - y1, p.r * (0.7 + depth * 0.5), 0, Math.PI * 2)
    if (p.kind === 2) ctx.fillStyle = `rgba(251,113,133,${alpha})`
    else if (p.kind === 1) ctx.fillStyle = `rgba(52,211,153,${alpha})`
    else ctx.fillStyle = `rgba(125,211,252,${alpha * 0.7})`
    ctx.fill()
  }
}

function loop(now: number) {
  raf = requestAnimationFrame(loop)
  const dt = Math.min((now - last) / 1000, 0.1)
  last = now
  if (!visible || document.hidden || reduceMotion) return

  yaw += SPIN * dt
  // 限帧：不足 1/FPS 秒就不重绘
  acc += dt
  if (acc < 1 / FPS) return
  acc = 0
  draw()
}

function resize() {
  const c = cv.value
  if (!c) return
  const rect = c.getBoundingClientRect()
  const dpr = Math.min(window.devicePixelRatio || 1, 2)
  w = rect.width
  h = rect.height
  // 完整球体：宽高都等于 2×半径 → 取两者较小值再留 3% 余量
  radius = Math.max(40, Math.min(w, h) / 2 * 0.97)
  cx = w / 2
  cy = h / 2
  c.width = Math.round(w * dpr)
  c.height = Math.round(h * dpr)
  ctx = c.getContext('2d')
  ctx?.scale(dpr, dpr)
  draw()
}

let io: IntersectionObserver | null = null

onMounted(() => {
  reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  resize()
  window.addEventListener('resize', resize)
  io = new IntersectionObserver(
    (es) => {
      visible = es[0]?.isIntersecting ?? true
    },
    { threshold: 0 },
  )
  if (cv.value) io.observe(cv.value)
  last = performance.now()
  raf = requestAnimationFrame(loop)
})

onBeforeUnmount(() => {
  cancelAnimationFrame(raf)
  window.removeEventListener('resize', resize)
  io?.disconnect()
})
</script>

<template>
  <canvas
    ref="cv"
    class="threat-globe"
    role="img"
    aria-label="全球威胁分布示意地球"
  ></canvas>
</template>

<style scoped>
.threat-globe {
  display: block;
  width: 100%;
  height: 100%;
  /* 纯装饰：不接收任何指针事件，避免拖动/选字误触发导航 */
  pointer-events: none;
  /* 配角：压低存在感，不喧宾夺主压过标题 */
  opacity: 0.62;
}
</style>
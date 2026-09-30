<script setup lang="ts">
/**
 * ThreatGlobe：卡巴斯基威胁地图风格的线框地球，作为 hero 背景装饰。
 *
 * 实现要点：
 * - Canvas 2D + 正交投影（yaw 自转 + pitch 俯视），**完整球体**（经纬网覆盖 -90°~90°），
 *   半径按容器取 `min(w,h)/2 * 0.97`，整球完整不裁切；
 * - **球体要"成团"而不是"碎片"**：先铺一层极淡的球面径向渐变给出体积与轮廓，
 *   再画**整圈**经纬网（背面线只降透明度、不剔除，否则背面缺口会让球看起来破碎），
 *   最后补一条亮轮廓线 + 真实赤道，点位和攻击弧画在最上层；
 * - **纯装饰、零交互**：不响应鼠标/触摸，不拖动、不点击跳转（避免"拖完松手"或
 *   "选中文字"误触发导航）。`pointer-events: none` 从根上杜绝误触；
 * - 攻击点为**确定性示意数据**（非实时采集），前端不轮询、不伪造"实时"；
 * - 性能：**45fps 限帧**（不是 60fps 每帧重绘）；元素不可见 / 标签页隐藏时完全停帧。
 */
import { onBeforeUnmount, onMounted, ref } from 'vue'

const SPIN = 0.16 // 自转速度 rad/s（约 39 秒转一圈，看得出在转又不晃眼）
const FPS = 45 // 限帧：45fps 兼顾流畅与 CPU
const PITCH = 0.22 // 固定俯视：略微俯视，能同时看到赤道南北

interface V3 {
  /** 单位向量 */
  x: number
  y: number
  z: number
  kind: number // 0 中性 1 防御 2 攻击
  r: number
}

/**
 * 确定性示意点位。
 * 用标准 Fibonacci 球面分布（黄金角 137.5°）铺满全球 —— 早先用的
 * `((i*0.618)%1)` 一维等分会把点挤成条带，看着零碎不均匀。
 */
function buildNodes(): V3[] {
  const out: V3[] = []
  const N = 200
  const GOLDEN = Math.PI * (3 - Math.sqrt(5))
  for (let i = 0; i < N; i++) {
    // y 从 +1 到 -1 均匀分层，theta 按黄金角递增 → 球面上均匀无堆叠
    const y = 1 - (2 * (i + 0.5)) / N
    const rr = Math.sqrt(Math.max(0, 1 - y * y))
    const theta = i * GOLDEN
    out.push({
      x: rr * Math.cos(theta),
      y,
      z: rr * Math.sin(theta),
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

/** 经纬网：经线每 30°、纬线每 30°（含赤道），采样点提前算好 */
const MERIDIANS: V3[][] = []
const PARALLELS: V3[][] = []
for (let m = 0; m < 12; m++) {
  const lon = (m * Math.PI) / 6
  const pts: V3[] = []
  for (let latDeg = -90; latDeg <= 90; latDeg += 2) {
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
  for (let lon = -180; lon <= 180; lon += 4) {
    const p = (lon * Math.PI) / 180
    pts.push({ x: rr * Math.sin(p), y, z: rr * Math.cos(p), kind: 0, r: 0 })
  }
  PARALLELS.push(pts)
}
/** 赤道在 PARALLELS 里的下标（lat = 0） */
const EQUATOR = 2

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

/**
 * 把一组经纬线画成**两条** Path2D：正面一条、背面一条，各自只 stroke 一次。
 *
 * 之前是逐段 beginPath+stroke（1600+ 次/帧），CPU 压力大；逐段剔除背面又会让球面
 * 出现缺口、看着破碎。这里既批量绘制又保留背面（只降透明度），球面连续且便宜。
 */
function buildPaths(lines: V3[][]): { front: Path2D; back: Path2D } {
  const front = new Path2D()
  const back = new Path2D()
  for (const line of lines) {
    let prev: [number, number, number] | null = null
    for (const p of line) {
      const cur = rot(p)
      if (prev) {
        // 段中任一点在正面就算正面段
        const path = prev[2] > 0 || cur[2] > 0 ? front : back
        path.moveTo(cx + prev[0], cy - prev[1])
        path.lineTo(cx + cur[0], cy - cur[1])
      }
      prev = cur
    }
  }
  return { front, back }
}

function draw() {
  if (!ctx) return
  ctx.clearRect(0, 0, w, h)

  // 1) 球面体积：极淡的径向渐变，让球有"实体感"，而不是一堆漂浮的线
  const g = ctx.createRadialGradient(
    cx - radius * 0.3,
    cy - radius * 0.35,
    radius * 0.1,
    cx,
    cy,
    radius,
  )
  g.addColorStop(0, 'rgba(56,189,248,0.13)')
  g.addColorStop(0.55, 'rgba(30,90,170,0.07)')
  g.addColorStop(1, 'rgba(10,25,60,0.02)')
  ctx.beginPath()
  ctx.arc(cx, cy, radius, 0, Math.PI * 2)
  ctx.fillStyle = g
  ctx.fill()

  // 2) 经纬网：整圈都画（背面只降透明度，不剔除 → 球面连续不破碎），批量两次 stroke
  ctx.lineWidth = 1
  const grid = buildPaths([...MERIDIANS, ...PARALLELS])
  ctx.strokeStyle = 'rgba(148,197,255,0.06)'
  ctx.stroke(grid.back)
  ctx.strokeStyle = 'rgba(148,197,255,0.2)'
  ctx.stroke(grid.front)

  // 3) 赤道：稍亮，作为"地面"参考线（用真实投影 y，不是画一条水平直线）
  ctx.lineWidth = 1.4
  const eq = buildPaths([PARALLELS[EQUATOR]])
  ctx.strokeStyle = 'rgba(148,197,255,0.08)'
  ctx.stroke(eq.back)
  ctx.strokeStyle = 'rgba(160,210,255,0.42)'
  ctx.stroke(eq.front)

  // 4) 轮廓线：闭合圆，勾出球的外沿 —— 这一笔最能让球"完整"
  ctx.beginPath()
  ctx.arc(cx, cy, radius, 0, Math.PI * 2)
  ctx.strokeStyle = 'rgba(148,197,255,0.34)'
  ctx.lineWidth = 1.2
  ctx.stroke()

  // 5) 攻击弧：两端都在正面才画
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
    ctx.strokeStyle = a.kind === 1 ? 'rgba(52,211,153,0.34)' : 'rgba(148,197,255,0.3)'
    ctx.lineWidth = 1.1
    ctx.stroke()
  }

  // 6) 地表点位：背面不画，正面按深度定透明度/半径
  for (const p of NODES) {
    const [x1, y1, z1] = rot(p)
    if (z1 <= 0) continue
    const depth = z1 / radius
    const alpha = 0.24 + depth * 0.5
    ctx.beginPath()
    ctx.arc(cx + x1, cy - y1, p.r * (0.7 + depth * 0.5), 0, Math.PI * 2)
    if (p.kind === 2) ctx.fillStyle = `rgba(251,113,133,${alpha})`
    else if (p.kind === 1) ctx.fillStyle = `rgba(52,211,153,${alpha})`
    else ctx.fillStyle = `rgba(125,211,252,${alpha * 0.8})`
    ctx.fill()
  }
}

function loop(now: number) {
  raf = requestAnimationFrame(loop)
  const dt = Math.min((now - last) / 1000, 0.1)
  last = now
  // 不可见 / 标签页隐藏时停帧；可见时**始终**缓慢自转
  // （系统"关闭动画"时只把速度减半，不再完全冻结 —— 冻结会被误认为"坏了不动"）
  if (!visible || document.hidden) return

  yaw += (reduceMotion ? SPIN * 0.45 : SPIN) * dt
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
  // 系统"关闭动画"（prefers-reduced-motion）时把自转减速一半，而不是完全静止
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
  opacity: 0.7;
}
</style>
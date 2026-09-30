<script setup lang="ts">
/**
 * ThreatGlobe：卡巴斯基威胁地图风格的线框地球。
 *
 * 实现要点：
 * - Canvas 2D + 正交投影（yaw/pitch 旋转），只画朝向观察者的半边（z>0）；
 * - 鼠标/触摸拖拽可自由转动，松手有惯性；无操作时极慢自转；
 * - 攻击点为**确定性示意数据**（非实时采集），前端不轮询、不伪造"实时"；
 * - 性能：不操作时 rAF 里不做任何重绘（idle 时直接 return），且元素不可见 /
 *   标签页隐藏时完全停帧；`prefers-reduced-motion` 下不自转。
 */
import { onBeforeUnmount, onMounted, ref } from 'vue'

const emit = defineEmits<{ (e: 'enter'): void }>()

const R = 620 // 球半径（大于半屏宽 → 只露顶部球冠）
const CY_OFF = 40 // 球心距容器顶部：负值越大露出的球冠越多
const DRAG_SENS = 0.005
const SPIN = 0.05 // 自转速度 rad/s
const INERTIA = 0.94

interface Node3 {
  x: number
  y: number
  z: number
  kind: number // 0 中性 1 防御 2 攻击
  r: number
}

/** 确定性生成的示意点位（Fibonacci 球面分布，只保留北半球可见冠区） */
function buildNodes(): Node3[] {
  const out: Node3[] = []
  const N = 150
  for (let i = 0; i < N; i++) {
    // 纬度 6°..86°（赤道以下不画，省一半绘制量）
    const lat = ((i * 0.6180339887) % 1) * 80 + 6
    const lon = ((i * 2.3999632297) % 1) * 360 - 180
    const t = (lat * Math.PI) / 180
    const p = (lon * Math.PI) / 180
    const ct = Math.cos(t)
    out.push({
      x: R * ct * Math.sin(p),
      y: R * Math.sin(t),
      z: R * ct * Math.cos(p),
      kind: i % 9 === 0 ? 2 : i % 4 === 0 ? 1 : 0,
      r: i % 9 === 0 ? 2.6 : i % 4 === 0 ? 2 : 1.4,
    })
  }
  return out
}

const NODES = buildNodes()

/** 确定性示意攻击弧（球面两点之间的抬升贝塞尔） */
const ARCS: { a: number; b: number; kind: number }[] = (() => {
  const out: { a: number; b: number; kind: number }[] = []
  for (let k = 0; k < 16; k++) {
    const a = Math.floor(((k * 0.6180339887) % 1) * NODES.length)
    const b = Math.floor(((k * 0.7548776662 + 0.31) % 1) * NODES.length)
    if (a === b) continue
    out.push({ a, b, kind: k % 5 === 0 ? 1 : 2 })
  }
  return out
})()

/** 经纬网：经线每 30°、纬线按纬度分层，采样点提前算好 */
const MERIDIANS: Node3[][] = []
const PARALLELS: Node3[][] = []
for (let m = 0; m < 12; m++) {
  const lon = (m * Math.PI) / 6
  const pts: Node3[] = []
  for (let lat = -80; lat <= 80; lat += 4) {
    const t = (lat * Math.PI) / 180
    const ct = Math.cos(t)
    pts.push({ x: R * ct * Math.sin(lon), y: R * Math.sin(t), z: R * ct * Math.cos(lon), kind: 0, r: 0 })
  }
  MERIDIANS.push(pts)
}
for (const lat of [-60, -30, 0, 30, 45, 60, 75]) {
  const t = (lat * Math.PI) / 180
  const y = R * Math.sin(t)
  const rr = R * Math.cos(t)
  const pts: Node3[] = []
  for (let lon = -180; lon <= 180; lon += 5) {
    const p = (lon * Math.PI) / 180
    pts.push({ x: rr * Math.sin(p), y, z: rr * Math.cos(p), kind: 0, r: 0 })
  }
  PARALLELS.push(pts)
}

const cv = ref<HTMLCanvasElement | null>(null)
let yaw = -0.6
let pitch = 0.34
let velYaw = 0
let velPitch = 0
let dragging = false
let lastX = 0
let lastY = 0
let raf = 0
let last = 0
let visible = true
let reduceMotion = false
let w = 0
let h = 0
let dpr = 1

function rot(p: Node3): [number, number, number] {
  const cy = Math.cos(yaw)
  const sy = Math.sin(yaw)
  const x1 = p.x * cy + p.z * sy
  const z1 = -p.x * sy + p.z * cy
  const cp = Math.cos(pitch)
  const sp = Math.sin(pitch)
  const y1 = p.y * cp - z1 * sp
  const z2 = p.y * sp + z1 * cp
  return [x1, y1, z2]
}

function draw() {
  const c = cv.value
  if (!c) return
  const ctx = c.getContext('2d')
  if (!ctx) return
  ctx.clearRect(0, 0, w, h)

  const cx = w / 2
  const cy = h - CY_OFF
  const inBand = (y: number) => y >= -20 && y <= h + 20

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
        const sx = cx + x1
        const sy = cy - y1
        if (!inBand(sy)) {
          drawing = false
          continue
        }
        if (drawing) ctx.lineTo(sx, sy)
        else {
          ctx.moveTo(sx, sy)
          drawing = true
        }
      }
      ctx.strokeStyle = 'rgba(148,197,255,0.16)'
      ctx.stroke()
    }
  }

  // 地平弧：球冠那条最亮的边线（唯一一根高亮线，做出球感）
  ctx.beginPath()
  let started = false
  for (let lon = -180; lon <= 180; lon += 4) {
    const p = (lon * Math.PI) / 180
    const q: Node3 = { x: R * Math.sin(p), y: 0, z: R * Math.cos(p), kind: 0, r: 0 }
    const [x1, y1, z1] = rot(q)
    if (z1 <= 0) {
      started = false
      continue
    }
    const sx = cx + x1
    const sy = cy - y1
    if (!inBand(sy)) {
      started = false
      continue
    }
    if (started) ctx.lineTo(sx, sy)
    else {
      ctx.moveTo(sx, sy)
      started = true
    }
  }
  ctx.strokeStyle = 'rgba(148,197,255,0.42)'
  ctx.lineWidth = 1.4
  ctx.stroke()

  // 攻击弧
  for (const a of ARCS) {
    const pa = NODES[a.a]
    const pb = NODES[a.b]
    const [ax, ay, az] = rot(pa)
    const [bx, by, bz] = rot(pb)
    if (az <= 0 || bz <= 0) continue
    const mx = (ax + bx) / 2
    const my = (ay + by) / 2
    const mz = (az + bz) / 2
    // 控制点沿中点法向抬离球心 → 视觉上"飞越"球面
    const len = Math.hypot(mx, my, mz) || 1
    const lift = 1.34
    const qx = cx + (mx / len) * len * lift
    const qy = cy - (my / len) * len * lift
    const sx = cx + ax
    const sy = cy - ay
    const ex2 = cx + bx
    const ey2 = cy - by
    if (!inBand(sy) && !inBand(ey2)) continue
    ctx.beginPath()
    ctx.moveTo(sx, sy)
    ctx.quadraticCurveTo(qx, qy, ex2, ey2)
    ctx.strokeStyle = a.kind === 1 ? 'rgba(52,211,153,0.34)' : 'rgba(148,197,255,0.28)'
    ctx.lineWidth = 1.1
    ctx.stroke()
  }

  // 地表点位：按深度定透明度/半径，背面不画
  for (const p of NODES) {
    const [x1, y1, z1] = rot(p)
    if (z1 <= 0) continue
    const sy = cy - y1
    if (!inBand(sy)) continue
    const depth = z1 / R
    const alpha = 0.18 + depth * 0.55
    const sx = cx + x1
    ctx.beginPath()
    ctx.arc(sx, sy, p.r * (0.7 + depth * 0.5), 0, Math.PI * 2)
    if (p.kind === 2) ctx.fillStyle = `rgba(251,113,133,${alpha})`
    else if (p.kind === 1) ctx.fillStyle = `rgba(52,211,153,${alpha})`
    else ctx.fillStyle = `rgba(125,211,252,${alpha * 0.75})`
    ctx.fill()
  }
}

function loop(now: number) {
  raf = requestAnimationFrame(loop)
  const dt = Math.min((now - last) / 1000, 0.05)
  last = now
  if (!visible || document.hidden) return

  let moved = false
  if (dragging) {
    moved = true
  } else {
    if (Math.abs(velYaw) > 1e-4 || Math.abs(velPitch) > 1e-4) {
      yaw += velYaw * dt * 60
      pitch = Math.max(-1.2, Math.min(1.2, pitch + velPitch * dt * 60))
      velYaw *= INERTIA
      velPitch *= INERTIA
      moved = true
    } else if (!reduceMotion) {
      yaw += SPIN * dt
      moved = true
    }
  }
  // 静止时直接跳过绘制，这是省 CPU 的关键
  if (moved) draw()
}

function resize() {
  const c = cv.value
  if (!c) return
  const rect = c.getBoundingClientRect()
  dpr = Math.min(window.devicePixelRatio || 1, 2)
  w = rect.width
  h = rect.height
  c.width = Math.round(w * dpr)
  c.height = Math.round(h * dpr)
  const ctx = c.getContext('2d')
  if (ctx) ctx.scale(dpr, dpr)
  draw()
}

function down(e: PointerEvent) {
  dragging = true
  velYaw = 0
  velPitch = 0
  lastX = e.clientX
  lastY = e.clientY
  cv.value?.setPointerCapture(e.pointerId)
}
function move(e: PointerEvent) {
  if (!dragging) return
  const dx = e.clientX - lastX
  const dy = e.clientY - lastY
  lastX = e.clientX
  lastY = e.clientY
  yaw += dx * DRAG_SENS
  pitch = Math.max(-1.2, Math.min(1.2, pitch + dy * DRAG_SENS * 0.6))
  velYaw = dx * DRAG_SENS
  velPitch = dy * DRAG_SENS * 0.6
}
function up(e: PointerEvent) {
  dragging = false
  cv.value?.releasePointerCapture(e.pointerId)
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
    aria-label="全球威胁分布示意地球，可拖动旋转"
    title="拖动可旋转 · 点击进入态势大屏"
    @pointerdown="down"
    @pointermove="move"
    @pointerup="up"
    @pointercancel="up"
    @click="emit('enter')"
  ></canvas>
</template>

<style scoped>
.threat-globe {
  display: block;
  width: 100%;
  height: 100%;
  cursor: grab;
  touch-action: none;
}
.threat-globe:active {
  cursor: grabbing;
}
</style>
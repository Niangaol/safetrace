<script setup lang="ts">
/**
 * ThreatGlobe：卡巴斯基威胁地图风格的线框地球。
 *
 * 实现要点：
 * - Canvas 2D + 正交投影（yaw/pitch 旋转），**只画北半球**（模型空间纬度 >= 0），
 *   所以看到的是一个完整的上半球穹顶，而不是被容器裁掉一半的球；
 * - 鼠标/触摸拖拽可自由转动，松手有惯性；无操作时极慢自转；
 * - 攻击点为**确定性示意数据**（非实时采集），前端不轮询、不伪造"实时"；
 * - 性能：不操作时 rAF 里不做任何重绘（idle 时直接 return），且元素不可见 /
 *   标签页隐藏时完全停帧；`prefers-reduced-motion` 下不自转。
 */
import { onBeforeUnmount, onMounted, ref } from 'vue'

const emit = defineEmits<{ (e: 'enter'): void }>()

const DRAG_SENS = 0.005
const SPIN = 0.05 // 自转速度 rad/s
const INERTIA = 0.94
const PITCH_MIN = -0.25
const PITCH_MAX = 0.5

interface V3 {
  /** 单位向量 */
  x: number
  y: number
  z: number
  /** 模型空间纬度（弧度），>= 0 即北半球 */
  lat: number
  kind: number // 0 中性 1 防御 2 攻击
  r: number
}

/** 确定性生成的示意点位（Fibonacci 球面分布，只取北半球） */
function buildNodes(): V3[] {
  const out: V3[] = []
  const N = 170
  for (let i = 0; i < N; i++) {
    // 纬度 1°..89°（赤道与南半球不画）
    const latDeg = ((i * 0.6180339887) % 1) * 88 + 1
    const lon = ((i * 2.3999632297) % 1) * 360 - 180
    const lat = (latDeg * Math.PI) / 180
    const p = (lon * Math.PI) / 180
    const ct = Math.cos(lat)
    out.push({
      x: ct * Math.sin(p),
      y: Math.sin(lat),
      z: ct * Math.cos(p),
      lat,
      kind: i % 9 === 0 ? 2 : i % 4 === 0 ? 1 : 0,
      r: i % 9 === 0 ? 2.6 : i % 4 === 0 ? 2 : 1.4,
    })
  }
  return out
}

const NODES = buildNodes()

/** 确定性示意攻击弧（北半球内两点之间的抬升贝塞尔） */
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

/** 经纬网：经线每 30°、纬线按纬度分层，全部只取北半球，采样点提前算好 */
const MERIDIANS: V3[][] = []
const PARALLELS: V3[][] = []
for (let m = 0; m < 12; m++) {
  const lon = (m * Math.PI) / 6
  const pts: V3[] = []
  for (let latDeg = 0; latDeg <= 90; latDeg += 3) {
    const lat = (latDeg * Math.PI) / 180
    const ct = Math.cos(lat)
    pts.push({ x: ct * Math.sin(lon), y: Math.sin(lat), z: ct * Math.cos(lon), lat, kind: 0, r: 0 })
  }
  MERIDIANS.push(pts)
}
for (const latDeg of [0, 15, 30, 45, 60, 75]) {
  const lat = (latDeg * Math.PI) / 180
  const y = Math.sin(lat)
  const rr = Math.cos(lat)
  const pts: V3[] = []
  for (let lon = -180; lon <= 180; lon += 5) {
    const p = (lon * Math.PI) / 180
    pts.push({ x: rr * Math.sin(p), y, z: rr * Math.cos(p), lat, kind: 0, r: 0 })
  }
  PARALLELS.push(pts)
}

const cv = ref<HTMLCanvasElement | null>(null)
let yaw = -0.6
let pitch = 0.28
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
let ctx: CanvasRenderingContext2D | null = null
/** 球半径：由容器尺寸决定，保证整个上半球完整落在画布内 */
let radius = 1

function rot(p: V3): [number, number, number] {
  const x0 = p.x * radius
  const y0 = p.y * radius
  const z0 = p.z * radius
  const cy = Math.cos(yaw)
  const sy = Math.sin(yaw)
  const x1 = x0 * cy + z0 * sy
  const z1 = -x0 * sy + z0 * cy
  const cp = Math.cos(pitch)
  const sp = Math.sin(pitch)
  const y1 = y0 * cp - z1 * sp
  const z2 = y0 * sp + z1 * cp
  return [x1, y1, z2]
}

function draw() {
  if (!ctx) return
  ctx.clearRect(0, 0, w, h)

  const cx = w / 2
  const cy = radius + (h - 2 * radius) / 2

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
      ctx.strokeStyle = 'rgba(148,197,255,0.17)'
      ctx.stroke()
    }
  }

  // 地平弧（赤道）：上半球最下面那条边线，最亮，画出穹顶的"地面"
  ctx.beginPath()
  let started = false
  for (const p of PARALLELS[0]) {
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
  ctx.strokeStyle = 'rgba(148,197,255,0.5)'
  ctx.lineWidth = 1.5
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
    // 控制点沿中点径向抬离球心 → 视觉上"飞越"球面
    const len = Math.hypot(mx, my, mz) || 1
    const lift = 1.3
    ctx.beginPath()
    ctx.moveTo(cx + ax, cy - ay)
    ctx.quadraticCurveTo(cx + (mx / len) * len * lift, cy - (my / len) * len * lift, cx + bx, cy - by)
    ctx.strokeStyle = a.kind === 1 ? 'rgba(52,211,153,0.36)' : 'rgba(148,197,255,0.3)'
    ctx.lineWidth = 1.1
    ctx.stroke()
  }

  // 地表点位：按深度定透明度/半径，背面不画
  for (const p of NODES) {
    const [x1, y1, z1] = rot(p)
    if (z1 <= 0) continue
    const depth = z1 / radius
    const alpha = 0.2 + depth * 0.55
    ctx.beginPath()
    ctx.arc(cx + x1, cy - y1, p.r * (0.7 + depth * 0.5), 0, Math.PI * 2)
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
  } else if (Math.abs(velYaw) > 1e-4 || Math.abs(velPitch) > 1e-4) {
    yaw += velYaw * dt * 60
    pitch = Math.max(PITCH_MIN, Math.min(PITCH_MAX, pitch + velPitch * dt * 60))
    velYaw *= INERTIA
    velPitch *= INERTIA
    moved = true
  } else if (!reduceMotion) {
    yaw += SPIN * dt
    moved = true
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
  // 上半球穹顶：高 = 2×半径，宽 = 2×半径 → 取两者较小值，完整不裁切
  radius = Math.max(40, Math.min(h, w / 2))
  c.width = Math.round(w * dpr)
  c.height = Math.round(h * dpr)
  ctx = c.getContext('2d')
  ctx?.scale(dpr, dpr)
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
  pitch = Math.max(PITCH_MIN, Math.min(PITCH_MAX, pitch + dy * DRAG_SENS * 0.5))
  velYaw = dx * DRAG_SENS
  velPitch = dy * DRAG_SENS * 0.5
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
    aria-label="全球威胁分布示意地球（北半球），可拖动旋转"
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
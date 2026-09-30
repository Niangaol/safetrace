<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'

export type DimState3D = {
  id: string
  label: string
  short: string
  status: 'real' | 'mock' | 'degraded' | 'conflict'
  confidence: number
  degraded_to?: string | null
}

const props = defineProps<{
  dims: DimState3D[]
  centralLabel?: string
  centralSub?: string
}>()

const tick = ref(0)
const rotY = ref(0)
const rotX = ref(-12)
const autoRotate = ref(true)
let raf = 0
let lastTime = 0

// Inertia
const velX = ref(0)
const velY = ref(0)
const DAMPING = 0.94

const isDragging = ref(false)
let dragStartX = 0
let dragStartY = 0
let dragStartRotX = 0
let dragStartRotY = 0
let lastDragX = 0
let lastDragY = 0
let lastDragTime = 0
let hasDragged = false

const selected = ref<string | null>(null)
const hovered = ref<string | null>(null)

/** 视口可见性 + 观察器：不可见时动画循环直接跳过计算与渲染 */
const wrapRef = ref<SVGSVGElement | HTMLElement | null>(null)
const inView = ref(true)
let viewObserver: IntersectionObserver | null = null

// Morph: per-node control-point offset for line curvature
const morph = ref<Record<string, { x: number; y: number; z: number }>>({})

const W = 580
const H = 400
const PERSPECTIVE = 900
const CX = W / 2
const CY = H / 2

onMounted(() => {
  lastTime = performance.now()
  // init morph state
  for (const d of props.dims) {
    morph.value[d.id] = { x: 0, y: 0, z: 0 }
  }
  const loop = (now: number) => {
    const dt = Math.min((now - lastTime) / 1000, 0.05)
    lastTime = now
    raf = requestAnimationFrame(loop)

    // 不可见 / 标签页隐藏时直接空转返回，不做任何计算与渲染（省 CPU）
    if (!inView.value || document.hidden) return

    let moved = false
    // Apply inertia
    if (!isDragging.value) {
      if (Math.abs(velX.value) > 0.01 || Math.abs(velY.value) > 0.01) {
        rotY.value += velY.value * dt * 60
        rotX.value = Math.max(-80, Math.min(80, rotX.value + velX.value * dt * 60))
        velX.value *= DAMPING
        velY.value *= DAMPING
        moved = true
      } else if (autoRotate.value && !hovered.value) {
        rotY.value += dt * 8
        moved = true
      }
    } else {
      moved = true
    }

    // Morph: line curvature control points drift slowly (not node jitter)
    const t = tick.value
    if (moved) tick.value += dt
    for (const d of props.dims) {
      const m = morph.value[d.id]
      if (!m) continue
      // slow sinusoidal drift of bezier control point offset
      const phase = d.id.length * 1.3
      m.x = Math.sin(t * 0.5 + phase) * 12
      m.y = Math.cos(t * 0.4 + phase) * 8
      m.z = Math.sin(t * 0.6 + phase * 0.7) * 10
    }
  }
  raf = requestAnimationFrame(loop)

  // 元素滚出视口就停帧（配合 loop 里的 document.hidden 判断）
  if (wrapRef.value) {
    viewObserver = new IntersectionObserver((es) => {
      inView.value = es[0]?.isIntersecting ?? true
    })
    viewObserver.observe(wrapRef.value)
  }
})
onUnmounted(() => {
  cancelAnimationFrame(raf)
  viewObserver?.disconnect()
})

const RADIUS = 135

const nodes3D = computed(() => {
  const n = props.dims.length
  return props.dims.map((dim, i) => {
    const phi = Math.acos(1 - 2 * (i + 0.5) / n)
    const theta = Math.PI * (1 + Math.sqrt(5)) * (i + 0.5)
    const bx = RADIUS * Math.sin(phi) * Math.cos(theta)
    const by = RADIUS * Math.cos(phi)
    const bz = RADIUS * Math.sin(phi) * Math.sin(theta)
    const m = morph.value[dim.id] ?? { x: 0, y: 0, z: 0 }
    // node stays on sphere; morph is the bezier control point offset
    return { ...dim, x: bx, y: by, z: bz, bx, by, bz, morph: m, idx: i }
  })
})

const stateColor: Record<string, string> = {
  real: '#22c55e',
  mock: '#eab308',
  degraded: '#ff8800',
  conflict: '#ff2d55',
}
function flowColor(s: string) { return stateColor[s] ?? '#64748b' }

function rotate3D(x: number, y: number, z: number, rx: number, ry: number) {
  const ryR = ry * Math.PI / 180
  const x1 = x * Math.cos(ryR) + z * Math.sin(ryR)
  const y1 = y
  const z1 = -x * Math.sin(ryR) + z * Math.cos(ryR)
  const rxR = rx * Math.PI / 180
  const x2 = x1
  const y2 = y1 * Math.cos(rxR) - z1 * Math.sin(rxR)
  const z2 = y1 * Math.sin(rxR) + z1 * Math.cos(rxR)
  return { x: x2, y: y2, z: z2 }
}

function project(x: number, y: number, z: number) {
  const denom = PERSPECTIVE + z
  if (denom <= 1) return { x: CX, y: CY, scale: 0, visible: false }
  const scale = PERSPECTIVE / denom
  return { x: CX + x * scale, y: CY + y * scale, scale, visible: true }
}

const projected = computed(() => {
  return nodes3D.value.map(node => {
    const r = rotate3D(node.x, node.y, node.z, rotX.value, rotY.value)
    const p = project(r.x, r.y, r.z)
    return { ...node, px: p.x, py: p.y, scale: p.scale, visible: p.visible, depth: r.z }
  })
})

// Bezier control points: midpoint between center and node, offset by morph
const controlPoints = computed(() => {
  return projected.value.map(node => {
    // Control point in 3D: midpoint of center→node, plus morph offset
    const cx3 = node.bx / 2 + node.morph.x
    const cy3 = node.by / 2 + node.morph.y
    const cz3 = node.bz / 2 + node.morph.z
    const r = rotate3D(cx3, cy3, cz3, rotX.value, rotY.value)
    const p = project(r.x, r.y, r.z)
    return { id: node.id, x: p.x, y: p.y, scale: p.scale, visible: node.visible }
  })
})

const centerProj = computed(() => {
  const r = rotate3D(0, 0, 0, rotX.value, rotY.value)
  const p = project(r.x, r.y, r.z)
  return { x: p.x, y: p.y, scale: p.scale }
})

const centralPulse = computed(() => 0.5 + Math.sin(tick.value * 2) * 0.25)

const conflictPairs = computed(() => {
  const cp: { n1: typeof projected.value[0]; n2: typeof projected.value[0] }[] = []
  const cn = projected.value.filter(n => n.status === 'conflict')
  for (let i = 0; i < cn.length; i++) {
    for (let j = i + 1; j < cn.length; j++) {
      cp.push({ n1: cn[i], n2: cn[j] })
    }
  }
  return cp
})

function particle(t: number, x1: number, y1: number, x2: number, y2: number) {
  const f = t - Math.floor(t)
  return { x: x1 + (x2 - x1) * f, y: y1 + (y2 - y1) * f }
}

function lineParticles(x1: number, y1: number, x2: number, y2: number, count: number, speed: number) {
  const arr: { x: number; y: number; opacity: number }[] = []
  for (let i = 0; i < count; i++) {
    const t = (tick.value * speed + i / count) % 1
    const pos = particle(t, x1, y1, x2, y2)
    const fade = Math.sin(t * Math.PI)
    arr.push({ x: pos.x, y: pos.y, opacity: fade })
  }
  return arr
}

const sortedProjected = computed(() => {
  return [...projected.value].sort((a, b) => b.depth - a.depth)
})

const selectedNode = computed(() => {
  if (!selected.value) return null
  return projected.value.find(n => n.id === selected.value) ?? null
})

function startDrag(e: MouseEvent | TouchEvent) {
  isDragging.value = true
  hasDragged = false
  autoRotate.value = false
  velX.value = 0
  velY.value = 0
  const pt = 'touches' in e ? e.touches[0] : e
  dragStartX = pt.clientX
  dragStartY = pt.clientY
  lastDragX = pt.clientX
  lastDragY = pt.clientY
  lastDragTime = performance.now()
  dragStartRotX = rotX.value
  dragStartRotY = rotY.value
}

function onDrag(e: MouseEvent | TouchEvent) {
  if (!isDragging.value) return
  const pt = 'touches' in e ? e.touches[0] : e
  const dx = pt.clientX - dragStartX
  const dy = pt.clientY - dragStartY
  if (Math.abs(dx) > 3 || Math.abs(dy) > 3) hasDragged = true
  rotY.value = dragStartRotY + dx * 0.5
  rotX.value = Math.max(-80, Math.min(80, dragStartRotX - dy * 0.5))
  // Track velocity for inertia
  const now = performance.now()
  const dtMs = now - lastDragTime
  if (dtMs > 0) {
    velY.value = (pt.clientX - lastDragX) / dtMs * 0.5
    velX.value = -(pt.clientY - lastDragY) / dtMs * 0.5
  }
  lastDragX = pt.clientX
  lastDragY = pt.clientY
  lastDragTime = now
}

function endDrag() {
  isDragging.value = false
  // If barely moved, it was a click — don't let inertia spin
  if (!hasDragged) {
    velX.value = 0
    velY.value = 0
  }
}

function resetView() {
  rotX.value = -12
  rotY.value = 0
  velX.value = 0
  velY.value = 0
  autoRotate.value = true
  selected.value = null
}

function toggleSelect(id: string) {
  // If we just finished dragging, don't select
  if (hasDragged) {
    hasDragged = false
    return
  }
  selected.value = selected.value === id ? null : id
}

const legendItems = [
  { color: '#22c55e', label: 'Real', desc: '数据顺畅' },
  { color: '#eab308', label: 'Mock', desc: '虚线/模拟' },
  { color: '#ff8800', label: 'Degraded', desc: '降级警示' },
  { color: '#ff2d55', label: 'Conflict', desc: '冲突闪烁' },
]
</script>

<template>
  <div class="df3d-container" ref="wrapRef">
    <div class="df3d-toolbar">
      <button class="df3d-btn" :class="{ active: autoRotate }" @click="autoRotate = !autoRotate">
        {{ autoRotate ? '暂停旋转' : '自动旋转' }}
      </button>
      <button class="df3d-btn" @click="resetView">重置视角</button>
    </div>

    <div
      class="df3d-scene"
      @mousedown="startDrag"
      @touchstart.prevent="startDrag"
      @mousemove="onDrag"
      @touchmove.prevent="onDrag"
      @mouseup="endDrag"
      @mouseleave="endDrag"
      @touchend="endDrag"
    >
      <svg :viewBox="`0 0 ${W} ${H}`" class="df3d-svg" preserveAspectRatio="xMidYMid meet">
        <defs>
          <filter id="glow3d" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glowStrong3d" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="5" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <radialGradient id="coreGrad3d" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.9" />
            <stop offset="50%" stop-color="#0284c7" stop-opacity="0.5" />
            <stop offset="100%" stop-color="#0284c7" stop-opacity="0" />
          </radialGradient>
        </defs>

        <!-- orbit rings -->
        <ellipse :cx="CX" :cy="CY" :rx="RADIUS * (centerProj.scale || 1)" :ry="RADIUS * 0.28 * (centerProj.scale || 1)"
          fill="none" stroke="rgba(56,189,248,0.05)" stroke-width="1" stroke-dasharray="2 6" />

        <!-- connection lines: curved bezier paths -->
        <g v-for="(node, ni) in projected" :key="'l' + node.id">
          <path
            v-if="node.visible && controlPoints[ni]"
            :d="`M ${centerProj.x},${centerProj.y} Q ${controlPoints[ni].x},${controlPoints[ni].y} ${node.px},${node.py}`"
            :stroke="flowColor(node.status)"
            :stroke-width="node.status === 'mock' ? 1 : 1.5"
            :stroke-dasharray="node.status === 'mock' ? '4 3' : 'none'"
            fill="none"
            :opacity="0.3 + node.scale * 0.1"
          />
        </g>

        <!-- flowing particles -->
        <g v-for="node in projected" :key="'p' + node.id">
          <template v-if="node.visible && node.status !== 'conflict'">
            <circle
              v-for="(p, idx) in lineParticles(centerProj.x, centerProj.y, node.px, node.py, 2, node.status === 'degraded' ? 0.15 : 0.4)"
              :key="idx"
              :cx="p.x" :cy="p.y" :r="1.8 * node.scale"
              :fill="flowColor(node.status)"
              :opacity="p.opacity * 0.8"
              filter="url(#glow3d)"
            />
          </template>
          <template v-if="node.visible && node.status === 'real'">
            <circle
              v-for="(p, idx) in lineParticles(node.px, node.py, centerProj.x, centerProj.y, 1, 0.25)"
              :key="'r' + idx"
              :cx="p.x" :cy="p.y" :r="1.3 * node.scale"
              fill="#818cf8"
              :opacity="p.opacity * 0.5"
            />
          </template>
        </g>

        <!-- conflict cross-lines -->
        <g v-for="(pair, idx) in conflictPairs" :key="'cl' + idx">
          <line
            v-if="pair.n1.visible && pair.n2.visible"
            :x1="pair.n1.px" :y1="pair.n1.py"
            :x2="pair.n2.px" :y2="pair.n2.py"
            stroke="#ff2d55" stroke-width="1.2"
            :opacity="0.3 + Math.abs(Math.sin(tick * 4)) * 0.4"
            filter="url(#glowStrong3d)"
          />
        </g>

        <!-- center node -->
        <g>
          <circle :cx="centerProj.x" :cy="centerProj.y" :r="42 * centerProj.scale"
            fill="url(#coreGrad3d)" :opacity="centralPulse * 0.25 + 0.15" />
          <circle :cx="centerProj.x" :cy="centerProj.y" :r="22 * centerProj.scale"
            fill="#0a0f1a" stroke="#38bdf8" :stroke-width="1.5" filter="url(#glow3d)" />
          <circle :cx="centerProj.x" :cy="centerProj.y" :r="27 * centerProj.scale"
            fill="none" stroke="#38bdf8" :stroke-width="0.8" :opacity="centralPulse * 0.25" />
          <text :x="centerProj.x" :y="centerProj.y - 1 * centerProj.scale" text-anchor="middle"
            fill="#f1f5f9" :font-size="9 * centerProj.scale" font-weight="700" font-family="JetBrains Mono, monospace">
            {{ centralLabel || 'CVE' }}
          </text>
          <text :x="centerProj.x" :y="centerProj.y + 8 * centerProj.scale" text-anchor="middle"
            fill="#64748b" :font-size="6 * centerProj.scale" font-family="Inter, sans-serif">
            {{ centralSub || 'IntelItem' }}
          </text>
        </g>

        <!-- satellite nodes (depth sorted) -->
        <g v-for="node in sortedProjected" :key="'n' + node.id"
          :style="{ cursor: 'pointer', opacity: node.visible ? 1 : 0.15 }"
          @click.stop="toggleSelect(node.id)"
          @mouseenter="hovered = node.id"
          @mouseleave="hovered = null"
        >
          <!-- hit area -->
          <circle
            :cx="node.px" :cy="node.py" :r="24 * node.scale"
            fill="transparent"
            :style="{ pointerEvents: 'all' }"
          />
          <!-- hover ring -->
          <circle v-if="hovered === node.id && selected !== node.id"
            :cx="node.px" :cy="node.py" :r="22 * node.scale"
            fill="none" :stroke="flowColor(node.status)" stroke-width="1"
            :opacity="0.4" />
          <!-- selected ring -->
          <circle v-if="selected === node.id"
            :cx="node.px" :cy="node.py" :r="26 * node.scale"
            fill="none" :stroke="flowColor(node.status)" stroke-width="1.5"
            :opacity="0.5" filter="url(#glow3d)" />

          <!-- degraded pulse -->
          <circle v-if="node.status === 'degraded'"
            :cx="node.px" :cy="node.py" :r="22 * node.scale"
            fill="none" stroke="#ff8800" stroke-width="1"
            :opacity="0.2 + Math.sin(tick * 3) * 0.2" />
          <!-- conflict pulse -->
          <circle v-if="node.status === 'conflict'"
            :cx="node.px" :cy="node.py" :r="22 * node.scale"
            fill="none" stroke="#ff2d55" stroke-width="1.5"
            :opacity="0.2 + Math.sin(tick * 5) * 0.3" />

          <!-- node body -->
          <circle
            :cx="node.px" :cy="node.py" :r="16 * node.scale"
            fill="#0f1623"
            :stroke="flowColor(node.status)"
            :stroke-width="selected === node.id ? 2 : 1.5"
            :filter="node.scale > 0.65 ? 'url(#glow3d)' : ''"
          />
          <text
            :x="node.px" :y="node.py + 3 * node.scale"
            text-anchor="middle"
            :fill="flowColor(node.status)"
            :font-size="8 * node.scale" font-weight="700"
            font-family="JetBrains Mono, monospace"
          >{{ node.short }}</text>

          <text
            :x="node.px" :y="node.py + 28 * node.scale"
            text-anchor="middle"
            fill="#94a3b8"
            :font-size="7 * node.scale"
            font-family="Inter, sans-serif"
          >{{ node.label }}</text>

          <text
            :x="node.px" :y="node.py + 36 * node.scale"
            text-anchor="middle"
            :fill="flowColor(node.status)"
            :font-size="7 * node.scale" font-weight="500"
            font-family="JetBrains Mono, monospace"
            opacity="0.6"
          >{{ (node.confidence * 100).toFixed(0) }}%</text>

          <text
            v-if="node.degraded_to"
            :x="node.px" :y="node.py - 22 * node.scale"
            text-anchor="middle"
            fill="#ff8800" :font-size="6 * node.scale" font-weight="600"
            font-family="Inter, sans-serif"
          >⚠ {{ node.degraded_to }}</text>
          <text
            v-if="node.status === 'mock'"
            :x="node.px" :y="node.py - 22 * node.scale"
            text-anchor="middle"
            fill="#eab308" :font-size="6 * node.scale" font-weight="600"
            font-family="Inter, sans-serif"
          >◇ mock</text>
        </g>
      </svg>

      <!-- detail panel -->
      <Transition name="slide-up">
        <div v-if="selectedNode" class="df3d-detail" @click.stop>
          <div class="df3d-detail-header" :style="{ '--accent': flowColor(selectedNode.status) }">
            <span class="df3d-detail-badge" :style="{ background: flowColor(selectedNode.status) }">
              {{ selectedNode.short }}
            </span>
            <span class="df3d-detail-title">{{ selectedNode.label }}</span>
            <button class="df3d-detail-close" @click="selected = null">✕</button>
          </div>
          <div class="df3d-detail-body">
            <div class="df3d-detail-row">
              <span class="df3d-detail-key">状态</span>
              <span class="df3d-detail-val" :style="{ color: flowColor(selectedNode.status) }">
                {{ selectedNode.status === 'real' ? 'Real · 数据真实' :
                   selectedNode.status === 'mock' ? 'Mock · 模拟数据' :
                   selectedNode.status === 'degraded' ? 'Degraded · 已降级' :
                   'Conflict · 冲突检出' }}
              </span>
            </div>
            <div class="df3d-detail-row">
              <span class="df3d-detail-key">置信度</span>
              <span class="df3d-detail-val mono">{{ (selectedNode.confidence * 100).toFixed(1) }}%</span>
            </div>
            <div class="df3d-detail-row" v-if="selectedNode.degraded_to">
              <span class="df3d-detail-key">降级至</span>
              <span class="df3d-detail-val" style="color: #ff8800">{{ selectedNode.degraded_to }}</span>
            </div>
            <div class="df3d-detail-row">
              <span class="df3d-detail-key">维度 ID</span>
              <span class="df3d-detail-val mono">{{ selectedNode.id }}</span>
            </div>
            <div class="df3d-detail-bar-wrap">
              <div class="df3d-detail-bar-label">置信度</div>
              <div class="df3d-detail-bar">
                <div class="df3d-detail-bar-fill"
                  :style="{ width: (selectedNode.confidence * 100) + '%', background: flowColor(selectedNode.status) }">
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </div>

    <div class="df3d-legend">
      <div v-for="item in legendItems" :key="item.label" class="df3d-legend-item">
        <span class="df3d-legend-dot" :style="{ background: item.color, boxShadow: `0 0 6px ${item.color}` }"></span>
        <span class="df3d-legend-label">{{ item.label }}</span>
        <span class="df3d-legend-desc">{{ item.desc }}</span>
      </div>
    </div>
    <div class="df3d-hint">点击节点查看详情 · 拖拽旋转（松手有惯性）</div>
  </div>
</template>

<style scoped>
.df3d-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  user-select: none;
}

.df3d-toolbar {
  display: flex;
  gap: 8px;
}

.df3d-btn {
  background: rgba(15, 22, 35, 0.9);
  border: 1px solid #1e2d44;
  border-radius: 6px;
  color: #94a3b8;
  font-size: 11px;
  font-weight: 500;
  padding: 5px 14px;
  cursor: pointer;
  transition: all 0.2s;
  font-family: inherit;
  box-shadow: none;
  transform: none;
}
.df3d-btn:hover {
  border-color: #2a4060;
  color: #e2e8f0;
  background: #182339;
  box-shadow: none;
  transform: none;
}
.df3d-btn.active {
  border-color: #38bdf8;
  color: #38bdf8;
}

.df3d-scene {
  width: 100%;
  max-width: 580px;
  height: 400px;
  position: relative;
  cursor: grab;
}
.df3d-scene:active { cursor: grabbing; }

.df3d-svg {
  width: 100%;
  height: 100%;
}

.df3d-detail {
  position: absolute;
  bottom: 8px;
  left: 50%;
  transform: translateX(-50%);
  width: 280px;
  background: rgba(10, 15, 26, 0.97);
  border: 1px solid var(--accent, #38bdf8);
  border-radius: 10px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5), 0 0 16px var(--accent, rgba(56,189,248,0.2));
  backdrop-filter: blur(12px);
  z-index: 10;
}
.df3d-detail-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-bottom: 1px solid #1e2d44;
}
.df3d-detail-badge {
  width: 22px; height: 22px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 9px;
  font-weight: 700;
  color: #0a0f1a;
  font-family: 'JetBrains Mono', monospace;
}
.df3d-detail-title {
  font-size: 13px;
  font-weight: 600;
  color: #f1f5f9;
  flex: 1;
}
.df3d-detail-close {
  background: none;
  border: none;
  color: #64748b;
  cursor: pointer;
  font-size: 14px;
  padding: 0 4px;
  box-shadow: none;
  transform: none;
}
.df3d-detail-close:hover {
  color: #ff2d55;
  box-shadow: none;
  transform: none;
}
.df3d-detail-body {
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.df3d-detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.df3d-detail-key {
  font-size: 11px;
  color: #64748b;
}
.df3d-detail-val {
  font-size: 12px;
  color: #e2e8f0;
  font-weight: 500;
}
.df3d-detail-val.mono {
  font-family: 'JetBrains Mono', monospace;
}
.df3d-detail-bar-wrap {
  margin-top: 4px;
}
.df3d-detail-bar-label {
  font-size: 10px;
  color: #64748b;
  margin-bottom: 4px;
}
.df3d-detail-bar {
  height: 6px;
  background: #1e2d44;
  border-radius: 3px;
  overflow: hidden;
}
.df3d-detail-bar-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.3s ease;
  box-shadow: 0 0 8px currentColor;
}

.slide-up-enter-active, .slide-up-leave-active {
  transition: all 0.25s ease;
}
.slide-up-enter-from, .slide-up-leave-to {
  opacity: 0;
  transform: translateX(-50%) translateY(20px);
}

.df3d-legend {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  justify-content: center;
}
.df3d-legend-item {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
}
.df3d-legend-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.df3d-legend-label {
  color: #e2e8f0;
  font-weight: 600;
}
.df3d-legend-desc {
  color: #64748b;
}
.df3d-hint {
  font-size: 10px;
  color: #475569;
}
</style>

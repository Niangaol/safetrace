<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue'

export type DimState = {
  id: string
  label: string
  short: string
  status: 'real' | 'mock' | 'degraded' | 'conflict'
  confidence: number
  degraded_to?: string | null
}

const props = defineProps<{
  dims: DimState[]
  centralLabel?: string
  centralSub?: string
}>()

const W = 520
const H = 520
const CX = W / 2
const CY = H / 2
const RADIUS = 180

const tick = ref(0)
let raf = 0
let lastTime = 0

onMounted(() => {
  lastTime = performance.now()
  const loop = (now: number) => {
    const dt = Math.min((now - lastTime) / 1000, 0.05)
    lastTime = now
    tick.value += dt
    raf = requestAnimationFrame(loop)
  }
  raf = requestAnimationFrame(loop)
  measure()
  window.addEventListener('resize', measure)
})
onUnmounted(() => {
  cancelAnimationFrame(raf)
  window.removeEventListener('resize', measure)
})

// ── 悬停工具提示：点位坐标按容器宽度换算（SVG viewBox 520 → 实际像素）──
const wrapRef = ref<HTMLElement | null>(null)
const svgScale = ref(W / 560)
function measure() {
  const el = wrapRef.value
  svgScale.value = el ? el.clientWidth / W : W / 560
}
const hovered = ref<DimState | null>(null)

const nodePos = computed(() => {
  const m = new Map<string, { x: number; y: number }>()
  for (const node of nodes.value) m.set(node.id, { x: node.x, y: node.y })
  return m
})

const tooltipStyle = computed(() => {
  if (!hovered.value) return {}
  const p = nodePos.value.get(hovered.value.id)
  const s = svgScale.value
  const wrapW = wrapRef.value?.clientWidth ?? 340
  let left = (p?.x ?? 0) * s + 14
  let top = (p?.y ?? 0) * s - 92
  if (left + 200 > wrapW) left = wrapW - 208
  if (left < 8) left = 8
  if (top < 8) top = 8
  return { left: `${left}px`, top: `${top}px` }
})

function statusText(s: DimState['status']): string {
  return { real: '数据顺畅', mock: 'mock 模拟', degraded: '降级为规则', conflict: '一致性冲突' }[s] ?? s
}

const nodes = computed(() => {
  const n = props.dims.length
  return props.dims.map((dim, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2
    const x = CX + Math.cos(angle) * RADIUS
    const y = CY + Math.sin(angle) * RADIUS
    return { ...dim, x, y, angle }
  })
})

const stateColor: Record<string, string> = {
  real: '#22c55e',
  mock: '#eab308',
  degraded: '#ff8800',
  conflict: '#ff2d55',
}

function flowColor(s: string) { return stateColor[s] ?? '#64748b' }

function dashOffset(status: string) {
  if (status === 'mock') return `${(tick.value * 8) % 6}`
  return '0'
}

function particlePos(t: number, x1: number, y1: number, x2: number, y2: number) {
  const f = t - Math.floor(t)
  return { x: x1 + (x2 - x1) * f, y: y1 + (y2 - y1) * f }
}

function particlesOnLine(x1: number, y1: number, x2: number, y2: number, count = 3, speed = 0.3) {
  const arr: { x: number; y: number; opacity: number }[] = []
  for (let i = 0; i < count; i++) {
    const t = (tick.value * speed + i / count) % 1
    const pos = particlePos(t, x1, y1, x2, y2)
    const fade = Math.sin(t * Math.PI)
    arr.push({ x: pos.x, y: pos.y, opacity: fade })
  }
  return arr
}

const centralPulse = computed(() => 0.5 + Math.sin(tick.value * 2) * 0.25)

const conflictPairs = computed(() => {
  const cp: { x1: number; y1: number; x2: number; y2: number }[] = []
  const conflictNodes = nodes.value.filter(n => n.status === 'conflict')
  for (let i = 0; i < conflictNodes.length; i++) {
    for (let j = i + 1; j < conflictNodes.length; j++) {
      cp.push({ x1: conflictNodes[i].x, y1: conflictNodes[i].y, x2: conflictNodes[j].x, y2: conflictNodes[j].y })
    }
  }
  return cp
})

const legendItems = [
  { color: '#22c55e', label: 'Real', desc: '数据顺畅' },
  { color: '#eab308', label: 'Mock', desc: '虚线/模拟' },
  { color: '#ff8800', label: 'Degraded', desc: '降级警示' },
  { color: '#ff2d55', label: 'Conflict', desc: '冲突闪烁' },
]
</script>

<template>
  <div ref="wrapRef" class="dataflow-container">
    <svg :viewBox="`0 0 ${W} ${H}`" class="dataflow-svg" preserveAspectRatio="xMidYMid meet">
      <defs>
        <radialGradient id="coreGrad" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="#38bdf8" stop-opacity="1" />
          <stop offset="40%" stop-color="#0284c7" stop-opacity="0.8" />
          <stop offset="100%" stop-color="#0284c7" stop-opacity="0" />
        </radialGradient>
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="4" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="glowStrong" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="8" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      <!-- outer ring -->
      <circle :cx="CX" :cy="CY" :r="RADIUS" fill="none" stroke="#1e2d44" stroke-width="1" stroke-dasharray="2 4" opacity="0.4" />
      <circle :cx="CX" :cy="CY" :r="RADIUS + 30" fill="none" stroke="#1e2d44" stroke-width="1" opacity="0.15" />

      <!-- center → satellite lines -->
      <g v-for="node in nodes" :key="node.id">
        <line
          :x1="CX" :y1="CY" :x2="node.x" :y2="node.y"
          :stroke="flowColor(node.status)"
          :stroke-width="node.status === 'mock' ? 1.5 : 2"
          :stroke-dasharray="node.status === 'mock' ? '6 4' : 'none'"
          :stroke-dashoffset="node.status === 'mock' ? dashOffset(node.status) : '0'"
          :opacity="node.status === 'degraded' ? 0.6 : 0.3"
          filter="url(#glow)"
        />
        <!-- flowing particles -->
        <g v-if="node.status !== 'conflict'">
          <circle
            v-for="(p, idx) in particlesOnLine(CX, CY, node.x, node.y, 3, node.status === 'degraded' ? 0.15 : 0.35)"
            :key="idx"
            :cx="p.x" :cy="p.y" :r="2.5"
            :fill="flowColor(node.status)"
            :opacity="p.opacity * 0.9"
            filter="url(#glow)"
          />
        </g>
        <!-- return particles (satellite → center) -->
        <g v-if="node.status === 'real'">
          <circle
            v-for="(p, idx) in particlesOnLine(node.x, node.y, CX, CY, 2, 0.25)"
            :key="'r' + idx"
            :cx="p.x" :cy="p.y" :r="1.8"
            fill="#818cf8"
            :opacity="p.opacity * 0.6"
          />
        </g>
      </g>

      <!-- conflict cross-lines (red blinking) -->
      <g v-for="(pair, idx) in conflictPairs" :key="'conflict' + idx">
        <line
          :x1="pair.x1" :y1="pair.y1" :x2="pair.x2" :y2="pair.y2"
          stroke="#ff2d55" stroke-width="2"
          :opacity="0.4 + Math.sin(tick * 4) * 0.4"
          filter="url(#glowStrong)"
        />
      </g>

      <!-- central node -->
      <g>
        <circle :cx="CX" :cy="CY" :r="50" fill="url(#coreGrad)" :opacity="centralPulse * 0.3 + 0.3" />
        <circle :cx="CX" :cy="CY" :r="34" fill="#0a0f1a" stroke="#38bdf8" :stroke-width="2" filter="url(#glow)" />
        <circle :cx="CX" :cy="CY" :r="40" fill="none" stroke="#38bdf8" :stroke-width="1.5" :opacity="centralPulse * 0.4" />
        <!-- 中心仅保留必要信息，放大字号（缩小后唯一仍可读的文字） -->
        <text :x="CX" :y="CY - 5" text-anchor="middle" fill="#f1f5f9" font-size="17" font-weight="800" font-family="JetBrains Mono, monospace">
          {{ centralLabel || 'CVE' }}
        </text>
        <text :x="CX" :y="CY + 13" text-anchor="middle" fill="#94a3b8" font-size="11" font-family="JetBrains Mono, monospace">
          {{ centralSub || '' }}
        </text>
      </g>

      <!-- satellite nodes：只保留色点，完整内容在悬停浮层展示 -->
      <g
        v-for="node in nodes"
        :key="'node' + node.id"
        @mouseenter="hovered = node"
        @mouseleave="hovered = null"
        style="cursor: pointer"
      >
        <!-- 悬停高亮环 -->
        <circle
          v-if="hovered?.id === node.id"
          :cx="node.x" :cy="node.y" :r="30"
          fill="none" :stroke="flowColor(node.status)" stroke-width="2"
          :opacity="0.5 + Math.sin(tick * 4) * 0.2"
        />
        <!-- degraded pulse ring -->
        <circle
          v-if="node.status === 'degraded'"
          :cx="node.x" :cy="node.y" :r="26"
          fill="none" stroke="#ff8800" stroke-width="1.5"
          :opacity="0.3 + Math.sin(tick * 3) * 0.3"
        />
        <!-- conflict pulse ring -->
        <circle
          v-if="node.status === 'conflict'"
          :cx="node.x" :cy="node.y" :r="26"
          fill="none" stroke="#ff2d55" stroke-width="2"
          :opacity="0.3 + Math.sin(tick * 5) * 0.4"
        />
        <!-- node body -->
        <circle
          :cx="node.x" :cy="node.y" :r="22"
          :fill="hovered?.id === node.id ? flowColor(node.status) : '#0f1623'"
          :stroke="flowColor(node.status)"
          :stroke-width="2"
          filter="url(#glow)"
        />
        <!-- short code（放大、悬停时高对比） -->
        <text
          :x="node.x" :y="node.y + 5"
          text-anchor="middle"
          :fill="hovered?.id === node.id ? '#06121f' : flowColor(node.status)"
          font-size="12" font-weight="700"
          font-family="JetBrains Mono, monospace"
        >
          {{ node.short }}
        </text>
      </g>

      <!-- 悬停浮层：完整内容只在悬停时展示 -->
    </svg>

    <div v-if="hovered" class="df-tooltip" :style="tooltipStyle">
      <div class="tt-title" :style="{ color: flowColor(hovered.status) }">{{ hovered.label }}</div>
      <div class="tt-line">状态：{{ statusText(hovered.status) }}</div>
      <div class="tt-line">置信度：{{ (hovered.confidence * 100).toFixed(0) }}%</div>
      <div v-if="hovered.degraded_to" class="tt-line tt-warn">⚠ 降级为 {{ hovered.degraded_to }}</div>
      <div v-if="hovered.status === 'mock'" class="tt-line tt-warn">◇ mock（预置）</div>
      <div v-if="hovered.status === 'conflict'" class="tt-line tt-crit">! 与其它维度冲突</div>
    </div>

    <!-- legend -->
    <div class="df-legend">
      <div v-for="item in legendItems" :key="item.label" class="df-legend-item">
        <span class="df-legend-dot" :style="{ background: item.color, boxShadow: `0 0 6px ${item.color}` }"></span>
        <span class="df-legend-label">{{ item.label }}</span>
        <span class="df-legend-desc">{{ item.desc }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dataflow-container {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}
.dataflow-svg {
  width: 100%;
  max-width: 520px;
  height: auto;
}
.df-legend {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  justify-content: center;
}
.df-legend-item {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
}
.df-legend-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.df-legend-label {
  color: #e2e8f0;
  font-weight: 600;
}
.df-legend-desc {
  color: #64748b;
}

/* 悬停浮层：完整内容只在悬停时展示 */
.df-tooltip {
  position: absolute;
  min-width: 190px;
  max-width: 200px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-bright);
  border-radius: var(--radius);
  padding: 10px 12px;
  box-shadow: var(--shadow), var(--shadow-glow);
  pointer-events: none;
  z-index: 30;
  animation: ttIn 0.15s ease-out;
}
@keyframes ttIn {
  from { opacity: 0; transform: translateY(-3px); }
  to { opacity: 1; transform: none; }
}
.tt-title {
  font-size: 13px;
  font-weight: 700;
  margin-bottom: 4px;
  font-family: 'JetBrains Mono', monospace;
}
.tt-line {
  font-size: 12px;
  color: var(--text);
  margin: 3px 0;
}
.tt-warn { color: var(--high); }
.tt-crit { color: var(--critical); }
</style>

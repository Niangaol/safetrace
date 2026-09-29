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
})
onUnmounted(() => cancelAnimationFrame(raf))

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
  <div class="dataflow-container">
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
        <circle :cx="CX" :cy="CY" :r="30" fill="#0a0f1a" stroke="#38bdf8" :stroke-width="2" filter="url(#glow)" />
        <circle :cx="CX" :cy="CY" :r="36" fill="none" stroke="#38bdf8" :stroke-width="1.5" :opacity="centralPulse * 0.4" />
        <text :x="CX" :y="CY - 4" text-anchor="middle" fill="#f1f5f9" font-size="11" font-weight="700" font-family="JetBrains Mono, monospace">
          {{ centralLabel || 'CVE' }}
        </text>
        <text :x="CX" :y="CY + 10" text-anchor="middle" fill="#64748b" font-size="9" font-family="Inter, sans-serif">
          {{ centralSub || 'IntelItem' }}
        </text>
      </g>

      <!-- satellite nodes -->
      <g v-for="node in nodes" :key="'node' + node.id">
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
          fill="#0f1623"
          :stroke="flowColor(node.status)"
          :stroke-width="2"
          filter="url(#glow)"
        />
        <!-- node icon (short label) -->
        <text
          :x="node.x" :y="node.y + 4"
          text-anchor="middle"
          :fill="flowColor(node.status)"
          font-size="10" font-weight="700"
          font-family="JetBrains Mono, monospace"
        >
          {{ node.short }}
        </text>
        <!-- node full label -->
        <text
          :x="node.x" :y="node.y + 38"
          text-anchor="middle"
          fill="#94a3b8"
          font-size="9"
          font-family="Inter, sans-serif"
        >
          {{ node.label }}
        </text>
        <!-- confidence -->
        <text
          :x="node.x" :y="node.y + 50"
          text-anchor="middle"
          :fill="flowColor(node.status)"
          font-size="9" font-weight="500"
          font-family="JetBrains Mono, monospace"
          opacity="0.7"
        >
          {{ (node.confidence * 100).toFixed(0) }}%
        </text>
        <!-- degraded indicator -->
        <text
          v-if="node.degraded_to"
          :x="node.x" :y="node.y - 30"
          text-anchor="middle"
          fill="#ff8800" font-size="8" font-weight="600"
          font-family="Inter, sans-serif"
        >
          ⚠ {{ node.degraded_to }}
        </text>
        <!-- mock indicator -->
        <text
          v-if="node.status === 'mock'"
          :x="node.x" :y="node.y - 30"
          text-anchor="middle"
          fill="#eab308" font-size="8" font-weight="600"
          font-family="Inter, sans-serif"
        >
          ◇ mock
        </text>
      </g>
    </svg>

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
</style>

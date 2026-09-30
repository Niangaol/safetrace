<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'

const props = defineProps<{
  items: {
    label: string
    value: string | number | null
    hint?: string
    icon?: string
    variant?: string
    /** 点击展开后展示的明细行（真实数据），不提供则提示“无更多明细” */
    detail?: string[]
  }[]
}>()

const ICON_PATHS: Record<string, string> = {
  shield: 'M12 2L2 7v10l10 5 10-5V7L12 2z M12 22V12 M2 7l10 5 10-5',
  docs: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8',
  spark: 'M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z M12 6v6l4 2',
  zap: 'M13 2L3 14h9l-1 8 10-12h-9z',
  box: 'M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z M3.27 6.96L12 12.01l8.73-5.05 M12 22.08V12',
  yen: 'M5 3l7 8 7-8 M12 11v10 M8 14h8 M8 17h8',
  refresh: 'M23 4v6h-6 M1 20v-6h6 M3.51 9a9 9 0 0 1 14.85-3.36L23 10 M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
}

const expandedLabel = ref<string | null>(null)

function ripple(e: PointerEvent): void {
  const card = e.currentTarget as HTMLElement
  const layer = card.querySelector('.ripple-layer') as HTMLElement | null
  if (!layer) return
  const rect = card.getBoundingClientRect()
  const size = Math.max(rect.width, rect.height) * 1.4
  const span = document.createElement('span')
  span.className = 'ripple-ink'
  span.style.width = `${size}px`
  span.style.height = `${size}px`
  span.style.left = `${e.clientX - rect.left - size / 2}px`
  span.style.top = `${e.clientY - rect.top - size / 2}px`
  layer.appendChild(span)
  window.setTimeout(() => span.remove(), 650)
}

function toggle(label: string): void {
  expandedLabel.value = expandedLabel.value === label ? null : label
}

function onDocClick(e: MouseEvent): void {
  if (expandedLabel.value) {
    const t = e.target as HTMLElement
    if (!t.closest('.card')) expandedLabel.value = null
  }
}
onMounted(() => document.addEventListener('click', onDocClick))
onUnmounted(() => document.removeEventListener('click', onDocClick))
</script>

<template>
  <div class="cards">
    <div
      v-for="item in props.items"
      :key="item.label"
      class="card fade-in"
      :class="[item.variant || '', { expanded: expandedLabel === item.label }]"
      @pointerdown="ripple"
      @click="toggle(item.label)"
    >
      <div class="ripple-layer"></div>
      <div class="card-body">
        <div class="label">{{ item.label }}</div>
        <div class="value">{{ item.value ?? '—' }}</div>
        <div v-if="item.hint" class="hint">{{ item.hint }}</div>
        <div v-if="item.icon" class="icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path :d="ICON_PATHS[item.icon] || item.icon" />
          </svg>
        </div>
      </div>

      <div v-if="expandedLabel === item.label" class="card-detail">
        <template v-if="item.detail?.length">
          <div v-for="(line, i) in item.detail" :key="i" class="detail-row">
            <span class="detail-dot"></span>
            <span>{{ line }}</span>
          </div>
        </template>
        <div v-else class="detail-none">该指标暂无更多明细</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.card {
  cursor: pointer;
  /* 只过渡合成属性，避免 hover 时触发 layout/paint 重排 */
  transition: transform 0.18s ease, border-color 0.18s ease;
}
.ripple-layer {
  position: absolute;
  inset: 0;
  overflow: hidden;
  border-radius: inherit;
  pointer-events: none;
  z-index: 1;
}
.ripple-ink {
  position: absolute;
  border-radius: 50%;
  background: rgba(56, 189, 248, 0.3);
  transform: scale(0);
  pointer-events: none;
  animation: ripple 0.65s ease-out forwards;
}
@keyframes ripple {
  to { transform: scale(2); opacity: 0; }
}

/* 展开：原地放大 + 浮在页面图层之上 */
.card.expanded {
  transform: translateY(-3px) scale(1.06);
  border-color: var(--border-bright);
  box-shadow: var(--shadow), var(--shadow-glow);
  z-index: 60;
  overflow: visible;
}
.card.expanded:hover {
  transform: translateY(-3px) scale(1.06);
}
.card.expanded::before { opacity: 1; }
.card.expanded .icon { transform: scale(1.15); }

.card-detail {
  position: absolute;
  top: calc(100% + 10px);
  left: 0;
  min-width: 230px;
  z-index: 61;
  background: var(--bg-elevated);
  border: 1px solid var(--border-bright);
  border-radius: var(--radius);
  padding: 12px 16px;
  box-shadow: var(--shadow), var(--shadow-glow);
  animation: detailIn 0.18s ease-out;
  cursor: default;
}
.card-detail::before {
  content: '';
  position: absolute;
  top: -6px;
  left: 20px;
  width: 10px;
  height: 10px;
  background: var(--bg-elevated);
  border-left: 1px solid var(--border-bright);
  border-top: 1px solid var(--border-bright);
  transform: rotate(45deg);
}
@keyframes detailIn {
  from { opacity: 0; transform: translateY(-4px); }
  to { opacity: 1; transform: none; }
}
.detail-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--text);
  margin: 6px 0;
  white-space: nowrap;
  font-family: 'JetBrains Mono', monospace;
}
.detail-row:first-child { margin-top: 2px; }
.detail-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 6px var(--accent);
  flex-shrink: 0;
}
.detail-none {
  font-size: 12px;
  color: var(--muted);
}

/* 卡片主体内容盖在涟漪层之上 */
.card-body {
  position: relative;
  z-index: 2;
}
</style>
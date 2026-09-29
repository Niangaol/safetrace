<script setup lang="ts">
defineProps<{
  items: { label: string; value: string | number | null; hint?: string; icon?: string; variant?: string }[]
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
</script>

<template>
  <div class="cards">
    <div
      v-for="item in items"
      :key="item.label"
      class="card fade-in"
      :class="item.variant || ''"
    >
      <div class="label">{{ item.label }}</div>
      <div class="value">{{ item.value ?? '—' }}</div>
      <div v-if="item.hint" class="hint">{{ item.hint }}</div>
      <div v-if="item.icon" class="icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path :d="ICON_PATHS[item.icon] || item.icon" />
        </svg>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

import { MOCK_MODE, dataSource, dataSourceReason } from '../api'

/**
 * 数据来源横幅（诚实标识）。
 *
 * 赛题红线（README:14）：「Mock 要说出口」—— 演示时明示"此处为预置数据"。
 * 所以只要当前展示的是预置数据，这里就必须visible，不允许静默。
 */
const isMock = computed(() => dataSource.value === 'mock')
const modeHint = computed(() => (MOCK_MODE === 'always' ? '演示模式' : '后端不可用，已回退'))
</script>

<template>
  <div v-if="isMock" class="mock-banner" role="status" aria-live="polite">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <path d="M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
    </svg>
    <span>
      <strong>当前展示为预置数据（非实时采集）</strong>
      <span class="mock-banner-detail">{{ modeHint }}：{{ dataSourceReason }}</span>
    </span>
  </div>
</template>

<style scoped>
.mock-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 0 24px 12px;
  padding: 10px 14px;
  border: 1px solid color-mix(in srgb, var(--warn, #f59e0b) 45%, transparent);
  border-radius: 8px;
  background: color-mix(in srgb, var(--warn, #f59e0b) 12%, transparent);
  color: var(--warn, #f59e0b);
  font-size: 13px;
  line-height: 1.5;
}

.mock-banner strong {
  color: inherit;
  font-weight: 600;
}

.mock-banner-detail {
  margin-left: 8px;
  opacity: 0.85;
}
</style>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import { dataSource } from '../api'

const links = [
  { to: '/', label: '总览', icon: 'M3 10.5 12 3l9 7.5V21H3V10.5z' },
  { to: '/dashboard', label: '态势大屏', icon: 'M3 3h7v7H3V3zm0 11h7v7H3v-7zm11-11h7v7h-7V3zm0 11h7v7h-7v-7z' },
  { to: '/intel', label: '情报列表', icon: 'M12 2l9 4v6c0 5.5-3.8 10.7-9 12-5.2-1.3-9-6.5-9-12V6l9-4z' },
  { to: '/qa', label: '情报问答', icon: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.6 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.6-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z' },
]

/**
 * 状态标签必须反映**实际数据来源**。
 * 原来无论后端通不通都显示绿色「系统运行中」，那是把"界面能打开"说成"系统在跑"，
 * 属于团队红线⑤「Mock 要说出口」与红线③「禁止静默兜底」都不允许的静默假象。
 */
const status = computed(() =>
  dataSource.value === 'live'
    ? { text: '实时数据', className: 'ok' }
    : { text: '预置数据', className: 'mock' },
)
</script>

<template>
  <nav class="top">
    <span class="brand">
      <span class="logo">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#06121f" stroke-width="2.5">
          <path d="M12 2L2 7v10l10 5 10-5V7L12 2z M12 22V12 M2 7l10 5 10-5"/>
        </svg>
      </span>
      AI 安全情报系统
    </span>
    <div class="nav-links">
      <RouterLink
        v-for="link in links"
        :key="link.to"
        :to="link.to"
        active-class="active"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 6px;">
          <path :d="link.icon" />
        </svg>
        {{ link.label }}
      </RouterLink>
    </div>
    <div class="nav-status" :class="status.className" :title="status.text">
      <span class="dot"></span>
      {{ status.text }}
    </div>
  </nav>
</template>

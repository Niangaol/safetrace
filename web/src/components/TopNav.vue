<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { IS_DEMO_MODE, BACKEND_DATA_MODE } from '../api'

const links = [
  { to: '/dashboard', label: '工作台', icon: 'M3 3h7v7H3V3zm0 11h7v7H3v-7zm11-11h7v7h-7V3zm0 11h7v7h-7v-7z' },
  { to: '/intel', label: '富化与证据', icon: 'M12 2l9 4v6c0 5.5-3.8 10.7-9 12-5.2-1.3-9-6.5-9-12V6l9-4z' },
  { to: '/ingest-diagnostics', label: '多源采集', icon: 'M3 3v18h18 M7 14l4-4 3 3 6-7' },
  { to: '/qa', label: '证据问答', icon: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.6 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.6-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z' },
  { to: '/settings', label: '设置', icon: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3' },
]
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
      <!-- 悬停光泽 + 指针微光：fx-sheen + data-sheen（effects 层提供，纯装饰，不改链接文字与路由）。
           当前项下划线生长：fx-underline 配 is-active，isActive 与 active-class 的 "active" 同源派生。 -->
      <RouterLink
        v-for="link in links"
        :key="link.to"
        :to="link.to"
        active-class="active"
        class="fx-sheen"
        data-sheen
        v-slot="{ isActive }"
      >
        <span class="fx-underline" :class="{ 'is-active': isActive }">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 6px;">
            <path :d="link.icon" />
          </svg>
          {{ link.label }}
        </span>
      </RouterLink>
    </div>
    <div class="nav-status" :class="{ demo: IS_DEMO_MODE || BACKEND_DATA_MODE !== 'live' }">
      <span class="dot"></span>
      {{ IS_DEMO_MODE ? '静态演示' : BACKEND_DATA_MODE === 'live' ? '正式库 · 只读' : BACKEND_DATA_MODE === 'fixture' ? '本地实链 · fixture' : '后端待核验' }}
    </div>
  </nav>
</template>
<style scoped>
.top{flex-wrap:wrap;gap:12px}.nav-links{flex-wrap:wrap}.nav-status{white-space:nowrap}@media(max-width:800px){.top{padding:14px}.nav-links{order:3;width:100%;gap:4px}.nav-links a{padding:8px;font-size:12px}.brand{font-size:14px}.nav-status{margin-left:auto;font-size:10px}}
</style>

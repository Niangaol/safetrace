<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { IS_DEMO_MODE, BACKEND_DATA_MODE, getAssetsOverview } from '../api'

const links = [
  { to: '/dashboard', label: '工作台', icon: 'M3 3h7v7H3V3zm0 11h7v7H3v-7zm11-11h7v7h-7V3zm0 11h7v7h-7v-7z' },
  { to: '/intel', label: '富化与证据', icon: 'M12 2l9 4v6c0 5.5-3.8 10.7-9 12-5.2-1.3-9-6.5-9-12V6l9-4z' },
  { to: '/ingest-diagnostics', label: '多源采集', icon: 'M3 3v18h18 M7 14l4-4 3 3 6-7' },
  { to: '/assets', label: '本地资产', icon: 'M12 2l9 5v10l-9 5-9-5V7l9-5z M12 12l9-5 M12 12v10 M12 12L3 7' },
  { to: '/qa', label: '证据问答', icon: 'M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.6 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.6-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z' },
  { to: '/settings', label: '设置', icon: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3' },
]

// 资产漏洞提醒铃铛：轮询 /api/v1/assets/overview 的未读数（demo 模式走前端样本）
const router = useRouter()
const unread = ref(0)
let timer: ReturnType<typeof setInterval> | undefined

async function pollUnread(): Promise<void> {
  try {
    const overview = await getAssetsOverview()
    unread.value = overview.unread_count
  } catch {
    // 资产库不可读时不显示角标；不弹错误打扰主界面
  }
}

onMounted(() => {
  void pollUnread()
  timer = setInterval(() => void pollUnread(), 15000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
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
      <button class="bell" :class="{ ringing: unread > 0 }" title="本地资产漏洞提醒" @click="router.push('/assets')">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9"/>
          <path d="M13.7 21a2 2 0 01-3.4 0"/>
        </svg>
        <span v-if="unread > 0" class="badge">{{ unread > 99 ? '99+' : unread }}</span>
      </button>
      <span class="dot"></span>
      {{ IS_DEMO_MODE ? '静态演示' : BACKEND_DATA_MODE === 'live' ? '正式库 · 只读' : BACKEND_DATA_MODE === 'fixture' ? '本地实链 · fixture' : '后端待核验' }}
    </div>
  </nav>
</template>

<style scoped>
.top{flex-wrap:wrap;gap:12px}.nav-links{flex-wrap:wrap}.nav-status{white-space:nowrap;display:flex;align-items:center;gap:8px}
.bell{position:relative;display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text-muted);cursor:pointer}
.bell.ringing{color:#facc15;border-color:rgba(234,179,8,.5)}
.bell .badge{position:absolute;top:-7px;right:-8px;min-width:17px;height:17px;padding:0 4px;border-radius:999px;background:#fb7185;color:#06121f;font:700 10px/17px 'JetBrains Mono',monospace;text-align:center}
@media(max-width:800px){.top{padding:14px}.nav-links{order:3;width:100%;gap:4px}.nav-links a{padding:8px;font-size:12px}.brand{font-size:14px}.nav-status{margin-left:auto;font-size:10px}}
</style>

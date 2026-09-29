<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'

import TopNav from './components/TopNav.vue'
import { IS_DEMO_MODE } from './api'

onMounted(() => {
  // 令牌只存在 localStorage，开发期留空即可免鉴权
  const saved = localStorage.getItem('api_token')
  if (saved === null) localStorage.setItem('api_token', '')
})
</script>

<template>
  <TopNav />
  <main>
    <div v-if="IS_DEMO_MODE" class="demo-banner" role="status">
      <strong>演示模式</strong>｜来源状态、统计、漏洞、引用和问答均为预置样例，不能用于实际风险判断。
    </div>
    <RouterView />
  </main>
</template>

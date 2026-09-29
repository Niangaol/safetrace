<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'

import TopNav from './components/TopNav.vue'

onMounted(() => {
  // 令牌只存在 localStorage，开发期留空即可免鉴权
  const saved = localStorage.getItem('api_token')
  if (saved === null) localStorage.setItem('api_token', '')
})
</script>

<template>
  <TopNav />
  <main>
    <RouterView />
  </main>
</template>

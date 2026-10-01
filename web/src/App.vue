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
      <strong>静态演示模式</strong>｜所有页面和问答均来自前端预置样例，不请求后端。
    </div>
    <div v-else class="demo-banner" role="status">
      <strong>本地模式（fixture）</strong>｜采集与检索证据来自仓库 fixture，不代表实时态势；Q1 低置信、Q2 低召回时可按需调用 StepPlan，Q4 生成答案；各层失败均回规则/模板。StepPlan 会接收问题/查询改写，Q4 还会发送公开检索证据，请勿输入敏感数据；采集原文不发云。
    </div>
    <RouterView />
  </main>
</template>

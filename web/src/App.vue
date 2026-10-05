<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { RouterView } from 'vue-router'

import TopNav from './components/TopNav.vue'
import { IS_DEMO_MODE, BACKEND_DATA_MODE, BACKEND_QA_MODE, getJson } from './api'
const backendError = ref('')
const modeChanged = (event: Event) => { const mode = (event as CustomEvent).detail; if (['template','cloud','local'].includes(mode)) BACKEND_QA_MODE.value = mode }
onBeforeUnmount(() => window.removeEventListener('safetrace-model-mode', modeChanged))

onMounted(() => {
  window.addEventListener('safetrace-model-mode', modeChanged)
  // 令牌只存在 localStorage，开发期留空即可免鉴权
  const saved = localStorage.getItem('api_token')
  if (saved === null) localStorage.setItem('api_token', '')
  if (!IS_DEMO_MODE) getJson('/health').catch(error => { backendError.value = (error as Error).message })
})
</script>

<template>
  <TopNav />
  <main>
    <div v-if="IS_DEMO_MODE" class="demo-banner" role="status">
      <strong>静态演示模式</strong>｜所有页面和问答均来自前端预置样例，不请求后端。
    </div>
    <div v-else-if="BACKEND_DATA_MODE === 'live'" class="demo-banner" role="status">
      <strong>正式情报库 · 只读视图</strong>｜列表与问答读取当前已放行情报及有来源证明的富化工件；历史未验证记录不算成功。当前检索 BM25，问答模式：{{ BACKEND_QA_MODE === 'cloud' ? '显式启用云端' : BACKEND_QA_MODE === 'local' ? '本地模型' : BACKEND_QA_MODE === 'template_fallback' ? '模型失败 → 规则模板' : '规则模板 / 待核验' }}。不自动采集、补跑或更换向量模型，不代表实时 SLA。
    </div>
    <div v-else-if="BACKEND_DATA_MODE === 'fixture'" class="demo-banner" role="status">
      <strong>本地模式（fixture）</strong>｜采集与检索证据来自仓库 fixture，不代表实时态势；Q1 低置信、Q2 低召回时可按需调用 StepPlan，Q4 生成答案；各层失败均回规则/模板。StepPlan 会接收问题/查询改写，Q4 还会发送公开检索证据，请勿输入敏感数据；采集原文不发云。
    </div>
    <div v-else class="demo-banner" role="status"><strong>后端数据模式待核验</strong>｜{{ backendError || '正在检查后端；不会回退预置数据。' }}</div>
    <RouterView />
  </main>
</template>

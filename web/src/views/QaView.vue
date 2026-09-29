<script setup lang="ts">
import { onMounted, ref, nextTick, watch } from 'vue'

import { getJson } from '../api'
import { useQaStore } from '../stores/qa'
import type { MetricsOverview } from '../types'

const qa = useQaStore()
const question = ref('')
const chatScroll = ref<HTMLElement | null>(null)

const STAGE_LABEL: Record<string, string> = {
  plan: '拆解问题',
  rewrite: '改写检索式',
  retrieve: '混合检索',
  generate: '规则合成答案',
  check: '自检',
}

const SUGGESTIONS = [
  'Log4Shell 影响哪些版本？怎么修复？',
  'CVE-2021-44228 有哪些证据来源？',
  'CVE-2099-4321 影响哪些版本？',
  '嗯',
]

async function submit(q?: string) {
  const text = (q ?? question.value).trim()
  if (!text || qa.thinking) return
  qa.ask(text)
  question.value = ''
  await nextTick()
  chatScroll.value?.scrollTo({ top: chatScroll.value.scrollHeight, behavior: 'smooth' })
}

function scrollToBottom() {
  nextTick(() => {
    chatScroll.value?.scrollTo({ top: chatScroll.value.scrollHeight, behavior: 'smooth' })
  })
}

onMounted(async () => {
  try {
    const m = await getJson<MetricsOverview>('/metrics/overview')
    qa.metrics = m
  } catch { /* 不阻塞问答 */ }
})

watch(() => qa.answer, scrollToBottom)
watch(() => qa.citations.length, scrollToBottom)
</script>

<template>
  <h1 class="page-title">情报问答</h1>
  <p class="page-subtitle">Q1 意图识别 → Q2（独立 fixture 证据索引）→ Q4 规则合成；显示实际检索引用，索引外 CVE 会拒答。</p>

  <div v-if="qa.metrics" class="muted" style="margin-bottom: 12px; font-size: 12px; display: flex; align-items: center; gap: 12px">
    <span>离线采集 fixture：{{ qa.metrics.collect.vulns }} 条情报 / {{ qa.metrics.knowledge.chunks }} 个检索块</span>
    <span>问答使用 Q1→Q2→Q4 规则与本地检索；不调用 LLM，不产生模型费用。</span>
  </div>

  <div class="panel" style="min-height: 400px; display: flex; flex-direction: column">
    <div ref="chatScroll" style="flex: 1; overflow-y: auto; max-height: 520px; padding-right: 8px">
      <!-- 阶段进度 -->
      <div v-if="qa.stage" style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px">
        <span class="spinner"></span>
        <span class="muted" style="font-size: 12px">当前阶段：{{ STAGE_LABEL[qa.stage] ?? qa.stage }}</span>
      </div>

      <!-- 回答 -->
      <div v-if="qa.answer" class="answer" style="background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 16px; margin-bottom: 12px">
        {{ qa.answer }}
      </div>
      <div v-else-if="qa.thinking && !qa.stage" class="muted" style="padding: 24px; text-align: center">
        <span class="spinner" style="margin-right: 8px"></span>
        等待开始…
      </div>

      <!-- 空状态 -->
      <div v-if="!qa.answer && !qa.thinking && !qa.error" style="text-align: center; padding: 32px 16px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width: 40px; height: 40px; color: var(--muted); margin-bottom: 8px">
          <circle cx="11" cy="11" r="8" />
          <path d="M21 21l-4.35-4.35" />
        </svg>
        <p class="muted" style="margin-bottom: 16px">提出一个 AI 安全相关的问题试试</p>
        <div style="display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; max-width: 600px; margin: 0 auto">
          <button
            v-for="s in SUGGESTIONS"
            :key="s"
            class="secondary"
            style="font-size: 12px; padding: 6px 14px"
            @click="submit(s)"
          >
            {{ s }}
          </button>
        </div>
      </div>

      <!-- 降级提示 -->
      <div v-if="qa.degraded" class="degraded-flag" style="margin-bottom: 8px; padding: 8px 12px; background: rgba(251, 191, 36, 0.08); border-radius: var(--radius-sm); border: 1px solid rgba(251, 191, 36, 0.2); display: flex; align-items: center; gap: 8px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 14px; height: 14px; flex-shrink: 0">
          <path d="M12 9v4 M12 17h.01 M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
        </svg>
        本次答案由本地规则模板根据检索证据生成；输入为 fixture，不调用外部模型。
      </div>

      <!-- 错误 -->
      <div v-if="qa.error" style="color: var(--critical); font-size: 13px; padding: 12px; background: rgba(244, 63, 94, 0.08); border-radius: var(--radius-sm); border: 1px solid rgba(244, 63, 94, 0.2)">
        {{ qa.error }}
      </div>

      <!-- 引用 -->
      <div v-if="qa.citations.length" style="margin-top: 16px">
        <div class="label" style="margin-bottom: 8px">引用来源</div>
        <div v-for="(c, i) in qa.citations" :key="c.id" class="evidence" style="margin-bottom: 6px">
          <div style="display: flex; align-items: center; gap: 8px">
            <span class="badge info" style="min-width: 28px; text-align: center">[{{ i + 1 }}]</span>
            <a :href="c.url" target="_blank" rel="noreferrer" style="font-size: 12px">{{ c.title }}</a>
          </div>
          <div class="snippet" style="margin-top: 4px">检索得分 {{ c.score?.toFixed(4) ?? '—' }}</div>
        </div>
      </div>

      <!-- 成本 -->
      <div v-if="qa.lastCost !== null" class="muted" style="font-size: 11px; margin-top: 8px; text-align: right">
        本次调用成本 ¥{{ qa.lastCost.toFixed(4) }}
      </div>
    </div>

    <!-- 历史 -->
    <div v-if="qa.history.length > 1" style="border-top: 1px solid var(--border); padding-top: 12px; margin-top: 12px">
      <div class="label" style="margin-bottom: 8px">历史提问</div>
      <div v-for="(h, i) in qa.history.slice().reverse().slice(0, 3)" :key="i" class="evidence" style="margin-bottom: 6px">
        <strong style="font-size: 12px">{{ h.question }}</strong>
        <div class="snippet" style="margin-top: 4px">{{ h.answer.slice(0, 120) }}{{ h.answer.length > 120 ? '…' : '' }}</div>
      </div>
    </div>
  </div>

  <div class="toolbar" style="margin-top: 16px">
    <input
      v-model="question"
      placeholder="输入问题后回车…"
      style="flex: 1"
      @keyup.enter="submit()"
    />
    <button :disabled="!question.trim() || qa.thinking" @click="submit()">
      {{ qa.thinking ? '生成中…' : '提问' }}
    </button>
    <button class="secondary" :disabled="!qa.thinking" @click="qa.stop()">中断</button>
  </div>
</template>

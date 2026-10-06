<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, nextTick, watch } from 'vue'

import { getJson, BACKEND_DATA_MODE, IS_DEMO_MODE } from '../api'
import CompetitionFocus from '../components/CompetitionFocus.vue'
import MarkdownBlock from '../components/MarkdownBlock.vue'
import CountUpNumber from '../effects/CountUpNumber.vue'
import { useQaStore } from '../stores/qa'
import type { MetricsOverview } from '../types'

const qa = useQaStore()
const question = ref('')
type QaRuntime = { qa_mode?: string; qa_model?: string; retrieval_mode?: string; model_calls_enabled?: boolean }
const runtime = ref<QaRuntime | null>(null)
const configuredMode = computed(() => runtime.value?.qa_mode ?? (qa.metrics as (MetricsOverview & QaRuntime) | null)?.qa_mode ?? '')
const dataLabel = computed(() => IS_DEMO_MODE ? '静态演示样例' : BACKEND_DATA_MODE.value === 'live' ? '正式库只读' : BACKEND_DATA_MODE.value === 'fixture' ? '本地 fixture 样例' : '数据模式待核验')
const chatScroll = ref<HTMLElement | null>(null)

const STAGE_LABEL: Record<string, string> = {
  plan: '拆解问题',
  rewrite: '改写检索式',
  retrieve: '混合检索',
  generate: 'StepPlan / 模板生成',
  check: '自检',
}

const LLM_LAYER_LABEL: Record<string, string> = {
  q1_intent: "Q1 意图补判/澄清",
  q2_query_rewrite: "Q2 查询改写",
  q4_answer: "Q4 结论生成",
}

const SUGGESTIONS = [
  'CVE-2021-44228 影响哪些产品和版本？请给出处。',
  'CVE-2021-44228 应如何修复？哪些只是建议、尚未验证？',
  'CVE-2021-44228 有哪些已核验的相关论文？没有就明确说明。',
  '比较 CVE-2021-44228 与 CVE-2021-45046 的影响和修复，分别引用证据。',
  'CVE-2099-4321 影响哪些版本？（拒答检查样例）',
]

function hostOf(url: string): string {
  try { return new URL(url).host } catch { return '本地证据' }
}

function answerModeLabel(mode: string): string {
  if (mode === "cloud") return "已启用云端模型"
  if (mode === "local") return "本地模型"
  if (mode === "stepfun") return "StepPlan LLM"
  if (mode === "template_fallback") return "模型未可用 → 规则模板兜底"
  if (mode === "template") return "BM25 / 规则模板"
  return mode || "未返回模式（待核验）"
}

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
  } catch { /* 不阻塞问答，不补造指标 */ }
  if (!IS_DEMO_MODE) {
    try { runtime.value = await getJson<QaRuntime>('/health') } catch { /* 保留未知模式 */ }
  }
})
onUnmounted(() => qa.stop())

watch(() => qa.answer, scrollToBottom)
watch(() => qa.citations.length, scrollToBottom)
</script>

<template>
  <CompetitionFocus compact />
  <h1 class="page-title">证据驱动问答</h1>
  <p class="page-subtitle">围绕影响范围、修复指引、论文关联和漏洞比较提问。先检索证据，再给结论；没有充分来源时应明确拒答或说明限制。</p>
  <section class="runtime-panel" aria-label="问答运行模式">
    <div><strong>{{ dataLabel }}</strong><span>服务模式：{{ answerModeLabel(configuredMode) }}{{ runtime?.qa_model ? ' · ' + runtime.qa_model : '' }}</span><span v-if="runtime?.retrieval_mode">检索：{{ runtime.retrieval_mode }}</span></div>
    <div><strong>本轮回答</strong><span>{{ qa.answerMode ? answerModeLabel(qa.answerMode) : '尚未返回执行模式' }}{{ qa.answerModelId ? ' · ' + qa.answerModelId : '' }}</span></div>
    <p>正式库当前默认使用 BM25 与规则模板；若后端启用模型，以服务模式和本轮回执为准。云模型会发送问题 / 查询内容，请勿输入敏感信息。历史提问仅供回看，不代表多轮语义已完成。</p>
    <p v-if="qa.metrics">当前接口范围：<CountUpNumber :value="qa.metrics.collect.vulns" /> 条情报 / <CountUpNumber :value="qa.metrics.knowledge.chunks" /> 个检索块。结果数、检索得分和置信分都不是准确率。</p>
    <p v-if="qa.llmLayers.length">本轮模型层：{{ qa.llmLayers.map((layer) => LLM_LAYER_LABEL[layer] ?? layer).join('、') }}</p>
    <p v-if="qa.layerFallbacks.length">层内兜底：{{ qa.layerFallbacks.join('；') }}</p>
  </section>
  <!-- 阶段高亮完全由 store 真实返回的 qa.stage 驱动：当前阶段常驻下划线生长（fx-underline + is-active），
       生成进行中（qa.thinking）额外加 fx-beam 光束；未进入的阶段保持普通样式，不编造进度。 -->
  <div class="process-strip" aria-label="处理阶段"><span v-for="(label, key) in STAGE_LABEL" :key="key" :class="{ current: qa.stage === key, 'fx-underline': qa.stage === key, 'is-active': qa.stage === key, 'fx-beam': qa.stage === key && qa.thinking }">{{ label }}</span></div>

  <div class="panel" style="min-height: 400px; display: flex; flex-direction: column">
    <div ref="chatScroll" style="flex: 1; overflow-y: auto; max-height: 520px; padding-right: 8px">
      <!-- 阶段进度 -->
      <div v-if="qa.stage" style="margin-bottom: 12px; display: flex; align-items: center; gap: 8px">
        <span v-if="qa.thinking" class="spinner"></span>
        <span class="muted" style="font-size: 12px">{{ qa.thinking ? '当前阶段' : '最后返回阶段' }}：{{ STAGE_LABEL[qa.stage] ?? qa.stage }}</span>
      </div>

      <!-- 回答 -->
      <div v-if="qa.answer" class="answer markdown-answer fx-in" style="background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 16px; margin-bottom: 12px">
        <MarkdownBlock :source="qa.answer" />
        <span v-if="qa.thinking" class="fx-type-cursor generating-caret" aria-hidden="true"></span>
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
        <!-- 问题建议按钮组：错落入场（fx-in-scale + --fx-delay 逐个错开），纯装饰不影响点击 -->
        <div style="display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; max-width: 600px; margin: 0 auto">
          <button
            v-for="(s, i) in SUGGESTIONS"
            :key="s"
            class="secondary fx-in-scale"
            :style="{ '--fx-delay': i * 80 + 'ms', 'font-size': '12px', padding: '6px 14px' }"
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
        <span>本轮存在降级 / 证据限制：{{ answerModeLabel(qa.answerMode) }}。{{ qa.fallbackReason || '请核对回答中的限制与引用。' }} 数据来自{{ dataLabel }}；降级不算成功，缺少论文不能用漏洞摘要替代。</span>
      </div>

      <!-- 错误 -->
      <div v-if="qa.error" style="color: var(--critical); font-size: 13px; padding: 12px; background: rgba(244, 63, 94, 0.08); border-radius: var(--radius-sm); border: 1px solid rgba(244, 63, 94, 0.2)">
        {{ qa.error }}
      </div>

      <!-- 引用 -->
      <div v-if="qa.citations.length" style="margin-top: 16px">
        <div class="label" style="margin-bottom: 8px">引用来源 · 检索匹配不等于结论已证实</div>
        <div v-for="(c, i) in qa.citations" :key="c.id" class="evidence fx-in-left" :style="{ '--fx-delay': i * 70 + 'ms', marginBottom: '6px' }">
          <div style="display: flex; align-items: center; gap: 8px">
            <span class="badge info" style="min-width: 28px; text-align: center">[{{ i + 1 }}]</span>
            <a :href="c.url" target="_blank" rel="noreferrer noopener" style="font-size: 12px">{{ c.title }}<span class="link-host">{{ hostOf(c.url) }} ↗</span></a>
          </div>
          <div class="snippet" style="margin-top: 4px">检索得分（非准确率） {{ c.score?.toFixed(4) ?? '—' }}</div>
        </div>
      </div>

      <p v-if="qa.answer && !qa.thinking && !qa.citations.length" class="muted refusal-note">本轮没有引用。若回答是拒答 / 澄清，这是证据不足的边界；不要把无引用结论当作已验证事实。</p>

      <!-- 成本 -->
      <div v-if="qa.lastCost !== null" class="muted" style="font-size: 11px; margin-top: 8px; text-align: right">
        本次调用成本 ¥{{ qa.lastCost.toFixed(4) }}
      </div>
    </div>

    <!-- 历史 -->
    <div v-if="qa.history.length > 1" style="border-top: 1px solid var(--border); padding-top: 12px; margin-top: 12px">
      <div class="label" style="margin-bottom: 8px">历史提问（独立请求回看，非多轮语义验收）</div>
      <div v-for="(h, i) in qa.history.slice().reverse().slice(0, 3)" :key="i" class="evidence" style="margin-bottom: 6px">
        <strong style="font-size: 12px">{{ h.question }}</strong>
        <div class="snippet" style="margin-top: 4px">{{ h.answer.slice(0, 120) }}{{ h.answer.length > 120 ? '…' : '' }}</div>
      </div>
    </div>
  </div>

  <div class="toolbar" style="margin-top: 16px">
    <input
      v-model="question"
      placeholder="输入 CVE、产品 / 版本与想核对的影响或修复…"
      style="flex: 1"
      @keyup.enter="submit()"
    />
    <button :disabled="!question.trim() || qa.thinking" @click="submit()">
      {{ qa.thinking ? '生成中…' : '提问' }}
    </button>
    <button class="secondary" :disabled="!qa.thinking" @click="qa.stop()">中断</button>
  </div>
</template>
<style scoped>
/* Markdown 回答区：层级、链接与生成中光标。链接强制新窗口 + noopener，域名明文供人工核对。 */
.markdown-answer :deep(h1),.markdown-answer :deep(h2),.markdown-answer :deep(h3),.markdown-answer :deep(h4){margin:14px 0 8px;line-height:1.5}
.markdown-answer :deep(h1){font-size:19px}.markdown-answer :deep(h2){font-size:17px}.markdown-answer :deep(h3){font-size:15px}.markdown-answer :deep(h4){font-size:14px}
.markdown-answer :deep(p){margin:8px 0;line-height:1.85}
.markdown-answer :deep(ul),.markdown-answer :deep(ol){margin:8px 0;padding-left:22px;line-height:1.85}
.markdown-answer :deep(blockquote){margin:10px 0;padding:6px 12px;border-left:3px solid var(--accent);background:rgba(56,189,248,.06);color:var(--muted-light)}
.markdown-answer :deep(pre){margin:10px 0;padding:12px;background:#0a1221;border:1px solid var(--border);border-radius:var(--radius-sm);overflow:auto}
.markdown-answer :deep(code){font-family:'JetBrains Mono',monospace;font-size:12px}
.markdown-answer :deep(a){color:var(--accent);text-decoration:underline;text-underline-offset:3px;overflow-wrap:anywhere}
.markdown-answer :deep(a:hover){color:#7dd3fc}
.markdown-answer :deep(hr){border:0;border-top:1px solid var(--border);margin:14px 0}
.generating-caret{margin-left:2px;color:var(--accent)}
.link-host{display:block;font-size:10px;color:var(--muted);margin-top:2px}
@media(prefers-reduced-motion:reduce){.markdown-answer{animation:none}.evidence{animation:none}}
.runtime-panel{border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:14px;background:var(--bg-elevated)}.runtime-panel>div{display:flex;flex-wrap:wrap;gap:10px 16px;margin-bottom:8px;font-size:12px}.runtime-panel p,.refusal-note{font-size:12px;color:var(--muted);line-height:1.8;margin:8px 0}.process-strip{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}.process-strip span{padding:6px 12px;font-size:12px;border:1px solid var(--border);border-radius:20px;color:var(--muted)}.process-strip .current{color:var(--accent);border-color:var(--accent)}.toolbar{flex-wrap:wrap}.toolbar input{min-width:200px}.evidence a{overflow-wrap:anywhere}@media(max-width:600px){.toolbar input{width:100%;flex-basis:100%!important}.runtime-panel{padding:12px}}
</style>

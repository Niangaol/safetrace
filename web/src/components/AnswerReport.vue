<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import MarkdownBlock from './MarkdownBlock.vue'
import { sanitizeHref } from '../markdown'
import type { Citation } from '../types'
import type { FinalReview } from '../stores/qa'

const props = defineProps<{
  answer: string
  citations: Citation[]
  thinking: boolean
  completed: boolean
  abstained: boolean | null
  finalReview: FinalReview | null
  error: string
}>()
const rawSource = ref(false)
const copying = ref(false)
const copyMessage = ref('')
const contentOpen = ref(true)
const evidenceOpen = ref(true)
let copyAttempt = 0
watch(() => props.answer, () => { copyAttempt += 1; copying.value = false; copyMessage.value = '' })
const reviewLabels: Record<FinalReview['status'], string> = {
  accepted: '已接受', rejected: '已拒绝', failed: '复核失败', skipped: '已跳过',
}
const progressLabel = computed(() => props.thinking ? '生成中 · 尚未收到最终回执'
  : props.completed ? '已收到最终回执' : props.error ? '请求失败 · 未完成' : '已停止 · 未完成')
const abstainedLabel = computed(() => !props.completed ? '等待最终回执'
  : props.abstained === true ? '已拒答（abstained=true）'
    : props.abstained === false ? '未拒答（abstained=false）' : '后端未返回')
function hostOf(url: string): string {
  try { return new URL(url).host } catch { return '本地证据' }
}
function scoreLabel(score: number): string {
  return typeof score === 'number' && Number.isFinite(score) ? score.toFixed(4) : '—'
}
async function copyAnswer() {
  const attempt = ++copyAttempt
  const source = props.answer
  copying.value = true
  copyMessage.value = ''
  try {
    if (typeof navigator === 'undefined' || !navigator.clipboard?.writeText) {
      throw new Error('clipboard unavailable')
    }
    await navigator.clipboard.writeText(source)
    if (attempt === copyAttempt) copyMessage.value = '已复制回答原文。'
  } catch {
    if (attempt === copyAttempt) copyMessage.value = '复制失败：请切换原文后手动选择复制，或允许剪贴板访问。'
  } finally {
    if (attempt === copyAttempt) copying.value = false
  }
}
</script>

<template>
  <section class="answer-report" aria-label="问答报告" :aria-busy="thinking" data-testid="answer-report">
    <header class="report-header">
      <div><p class="report-eyebrow">SAFETRACE / QA</p><h2>证据问答报告</h2></div>
      <p class="report-progress" role="status">{{ progressLabel }}</p>
    </header>
    <dl class="report-state">
      <div><dt>拒答状态 · 后端回执</dt><dd>{{ abstainedLabel }}</dd></div>
      <div><dt>最终复核 · 后端回执</dt><dd>{{ !completed ? '等待最终回执' : finalReview ? reviewLabels[finalReview.status] : '后端未返回' }}</dd></div>
    </dl>
    <div v-if="completed && finalReview" class="review-reason">
      <strong>复核原因</strong>
      <MarkdownBlock v-if="finalReview.reason" :source="finalReview.reason" compact />
      <p v-else class="muted">后端未提供原因。</p>
    </div>
    <p class="report-note">回执状态不代表事实准确率；请结合引用和证据限制核对结论。</p>
    <div class="report-actions">
      <button type="button" class="secondary" :aria-pressed="rawSource" @click="rawSource = !rawSource">{{ rawSource ? '显示排版' : '查看原文' }}</button>
      <button type="button" class="secondary" :disabled="!answer || copying" @click="copyAnswer">{{ copying ? '复制中…' : '复制回答原文' }}</button>
      <p class="copy-message" role="status" aria-live="polite">{{ copyMessage }}</p>
    </div>
    <details :open="contentOpen" class="report-section" @toggle="contentOpen = ($event.target as HTMLDetailsElement).open">
      <summary>回答内容<span>{{ thinking ? '持续接收中' : 'Markdown / 原文' }}</span></summary>
      <div class="report-content">
        <pre v-if="rawSource && answer" class="raw-source" tabindex="0" aria-label="回答原文">{{ answer }}</pre>
        <MarkdownBlock v-else-if="answer" :source="answer" />
        <p v-else class="muted">{{ thinking ? '等待回答内容…' : '本轮没有返回回答内容。' }}</p>
        <p v-if="thinking" class="streaming-note">回答仍在生成，拒答和复核状态以最终回执为准。</p>
      </div>
    </details>
    <details :open="evidenceOpen" class="report-section" @toggle="evidenceOpen = ($event.target as HTMLDetailsElement).open">
      <summary>引用证据<span>{{ citations.length }} 条 · 检索匹配不等于结论已证实</span></summary>
      <ol v-if="citations.length" class="report-evidence">
        <li v-for="(citation, index) in citations" :key="citation.id + ':' + index" class="evidence">
          <div class="citation-title"><span class="badge info">[{{ index + 1 }}]</span>
            <a v-if="sanitizeHref(citation.url)" :href="sanitizeHref(citation.url)!" target="_blank" rel="noreferrer noopener">{{ citation.title }}<span class="link-host">{{ hostOf(citation.url) }} ↗</span></a>
            <span v-else>{{ citation.title }} <span class="muted">（来源链接不可用）</span></span>
          </div>
          <p class="snippet">检索得分（非准确率） {{ scoreLabel(citation.score) }}</p>
        </li>
      </ol>
      <p v-else class="report-content muted">{{ thinking ? '等待引用来源…' : '本轮没有引用；不要把无引用结论当作已验证事实。' }}</p>
    </details>
  </section>
</template>

<style scoped>
.answer-report { min-width: 0; margin-bottom: 12px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-elevated); overflow-wrap: anywhere; }
.report-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; padding: 18px; border-bottom: 1px solid var(--border); }
.report-eyebrow { margin: 0 0 4px; font-size: 10px; letter-spacing: .12em; color: var(--muted); }
h2 { margin: 0; font-size: 18px; }
.report-progress, .report-note, .streaming-note { font-size: 12px; color: var(--muted); }
.report-progress { margin: 0; }
.report-state { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; margin: 0; padding: 16px 18px; }
dt { color: var(--muted); font-size: 11px; margin-bottom: 6px; }
dd { margin: 0; font-size: 13px; font-weight: 600; }
.review-reason { margin: 0 18px; padding: 12px; border-left: 3px solid var(--border); font-size: 12px; }
.report-note { margin: 10px 18px; }
.report-actions { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; padding: 8px 18px 16px; }
.report-actions button { min-height: 40px; font-size: 12px; }
.copy-message { flex-basis: 100%; margin: 0; font-size: 12px; }
.copy-message:empty { display: none; }
.report-section { border-top: 1px solid var(--border); }
summary { cursor: pointer; padding: 14px 18px; font-weight: 600; font-size: 13px; min-height: 44px; box-sizing: border-box; }
summary span { margin-left: 12px; font-size: 11px; font-weight: 400; color: var(--muted); }
.report-content { padding: 0 18px 16px; }
.raw-source { margin: 0; max-height: 420px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; line-height: 1.7; font-family: var(--font-mono, monospace); }
.report-evidence { list-style: none; padding: 0 18px 16px; margin: 0; display: grid; gap: 8px; }
.citation-title { display: flex; align-items: baseline; gap: 8px; font-size: 12px; }
.citation-title a { min-width: 0; }
.snippet { margin: 6px 0 0; }
summary:focus-visible, button:focus-visible, a:focus-visible, pre:focus-visible { outline: 2px solid var(--accent, #60a5fa); outline-offset: -2px; }
@media (max-width: 600px) {
  .report-state { grid-template-columns: 1fr; }
  summary span { display: block; margin: 6px 0 0 16px; }
  .report-actions button { flex: 1 1 auto; }
}
@media (prefers-reduced-motion: reduce) {
  .answer-report, .answer-report :deep(*) { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
</style>

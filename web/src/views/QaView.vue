<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { getJson, BACKEND_DATA_MODE, IS_DEMO_MODE } from '../api'
import AdaptiveAnswer from '../components/AdaptiveAnswer.vue'
import AnswerReport from '../components/AnswerReport.vue'
import MarkdownBlock from '../components/MarkdownBlock.vue'
import { sanitizeHref } from '../markdown'
import { isNearBottom, shouldSendOnEnter } from '../qa-ui'
import { useQaStore } from '../stores/qa'
import type { QaTurn } from '../stores/qa'
const qa = useQaStore()
const question = ref('')
const composing = ref(false)
const composer = ref<HTMLTextAreaElement | null>(null)
const chatScroll = ref<HTMLElement | null>(null)
const following = ref(true)
const unread = ref(false)
type QaRuntime = { qa_mode?: string; qa_model?: string; retrieval_mode?: string }
const runtime = ref<QaRuntime | null>(null)
const dataLabel = computed(() => IS_DEMO_MODE ? '静态演示样例' : BACKEND_DATA_MODE.value === 'live' ? '正式库只读' : BACKEND_DATA_MODE.value === 'fixture' ? '本地 fixture 样例' : '数据模式待核验')
const STAGE_LABEL: Record<string, string> = { plan: '拆解问题', rewrite: '改写检索式', retrieve: '证据检索', generate: '结论生成', check: '引用校验 / 模型复核' }
const REVIEW_LABEL = { accepted: '已接受', rejected: '已拒绝', failed: '复核失败', skipped: '已跳过' }
const SUGGESTIONS = [
  { label: '核对影响范围', question: 'CVE-2021-44228 影响哪些产品和版本？请给出处。' },
  { label: '阅读修复证据', question: 'CVE-2021-44228 应如何修复？哪些只是建议、尚未验证？' },
  { label: '比较两个漏洞', question: '比较 CVE-2021-44228 与 CVE-2021-45046 的影响和修复，分别引用证据。' },
  { label: '查找论文关联', question: 'CVE-2021-44228 有哪些已核验的相关论文？没有就明确说明。' },
]
function modeLabel(mode: string) { return ({ cloud: '云端模型', local: '本地模型', stepfun: 'StepPlan LLM', template: 'BM25 / 规则模板', template_fallback: '模型不可用 · 规则兜底' } as Record<string, string>)[mode] ?? (mode || '模式待回执') }
function status(turn: QaTurn) { return turn.thinking ? '接收中 · 待最终回执' : turn.completed ? '已完成 · 收到回执' : turn.error ? '请求失败 · 未完成' : '已停止 · 未完成' }
function gap(turn: QaTurn) { return !!(turn.degraded || turn.fallbackReason || /缺口|过期|陈旧|stale/i.test(turn.answer) || (turn.completed && !turn.citations.length)) }
function onScroll() {
  if (!chatScroll.value) return
  following.value = isNearBottom(chatScroll.value)
  if (following.value) unread.value = false
}
async function followBottom() {
  await nextTick()
  if (following.value && chatScroll.value) chatScroll.value.scrollTo({ top: chatScroll.value.scrollHeight, behavior: 'auto' })
}
function jumpToLatest() { following.value = true; unread.value = false; void followBottom() }
function resizeComposer() { const el = composer.value; if (el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 180) + 'px' } }
function onComposerInput(event: Event) { question.value = (event.target as HTMLTextAreaElement).value; resizeComposer() }
async function submit(q?: string) {
  const text = (q ?? question.value).trim()
  if (!text || qa.thinking || composing.value) return
  qa.ask(text)
  question.value = ''
  await nextTick()
  resizeComposer()
  if (following.value) void followBottom(); else unread.value = true
  composer.value?.focus({ preventScroll: true })
}
function onComposerKey(event: KeyboardEvent) {
  if (shouldSendOnEnter(event, composing.value)) { event.preventDefault(); void submit() }
}
function newConversation() { qa.newConversation(); question.value = ''; following.value = true; unread.value = false; nextTick(() => { resizeComposer(); composer.value?.focus({ preventScroll: true }) }) }
watch(() => [qa.answer, qa.citations.length, qa.stage, qa.thinking, qa.ui, qa.error], () => {
  if (following.value) void followBottom(); else unread.value = true
}, { flush: 'post' })
onMounted(async () => {
  if (!IS_DEMO_MODE) { try { runtime.value = await getJson<QaRuntime>('/health') } catch { /* Do not invent a mode. */ } }
})
onUnmounted(() => qa.stop())
</script>

<template>
  <section class="qa-workspace" aria-label="SafeTrace 证据对话工作区">
    <header class="workspace-header">
      <div class="workspace-brand"><span class="brand-mark" aria-hidden="true">S</span><div><h1>SafeTrace <span>证据问答</span></h1><p>{{ dataLabel }} · 每个问题独立检索</p></div></div>
      <button type="button" class="secondary new-conversation" @click="newConversation">＋ 新对话</button>
    </header>
    <details class="workspace-context"><summary>使用边界与服务模式</summary><p>历史仅供回看，不代表语义多轮；每次请求只发送当前问题。问答历史与证据仅存于本页内存，不写入本地存储。云模型可能接收问题及查询内容，请勿输入敏感信息。回执、检索分数与勾选均不代表事实准确率或修复成功。</p><p>服务模式：{{ modeLabel(runtime?.qa_mode ?? '') }}{{ runtime?.qa_model ? ' · ' + runtime.qa_model : '' }}<span v-if="runtime?.retrieval_mode"> · 检索：{{ runtime.retrieval_mode }}</span></p></details>
    <div ref="chatScroll" class="conversation-scroll" tabindex="0" aria-label="独立问答历史" @scroll="onScroll">
      <div v-if="!qa.turns.length" class="welcome">
        <span class="welcome-eyebrow">FOLLOW THE EVIDENCE</span><h2>从一个问题，找到可信的依据。</h2><p>核对影响、阅读来源、比较漏洞。<br />证据不足时，保留拒答与缺口，不替你猜测。</p>
        <div class="suggestions"><button v-for="suggestion in SUGGESTIONS" :key="suggestion.label" type="button" @click="submit(suggestion.question)"><span>{{ suggestion.label }}</span><small>{{ suggestion.question }}</small><span aria-hidden="true">↗</span></button></div>
      </div>
      <div v-else class="conversation-thread">
        <article v-for="turn in qa.turns" :key="turn.id" class="conversation-turn" :data-turn-id="turn.id">
          <div class="user-message"><span class="message-label">你</span><p>{{ turn.question }}</p></div>
          <section class="assistant-message" :aria-busy="turn.thinking" aria-label="SafeTrace 回答">
            <header class="assistant-header"><span class="assistant-symbol" aria-hidden="true">S</span><strong>SafeTrace</strong><span class="turn-status" role="status">{{ status(turn) }}</span></header>
            <div v-if="turn.abstained === true || gap(turn) || turn.error || turn.stopped || turn.finalReview?.status === 'rejected' || turn.finalReview?.status === 'failed'" class="answer-caution">
              <strong v-if="turn.abstained === true">已拒答 · 后端最终回执</strong>
              <p v-if="gap(turn)">存在降级、证据缺口或时效限制，请完整阅读下方限制与来源。{{ turn.fallbackReason }}</p>
              <p v-if="turn.finalReview?.status === 'rejected' || turn.finalReview?.status === 'failed'">最终复核：{{ REVIEW_LABEL[turn.finalReview.status] }}。{{ turn.finalReview.reason }}</p>
              <p v-if="turn.error" role="alert">{{ turn.error }}</p><p v-if="turn.stopped">已停止接收：当前内容不完整，拒答与复核尚未最终确认。</p>
            </div>
            <details class="execution-panel"><summary><span v-if="turn.thinking" class="live-dot" aria-hidden="true"></span>执行记录 <span>{{ turn.stages.length }} 个真实阶段事件{{ turn.stage ? ' · ' + (STAGE_LABEL[turn.stage] ?? turn.stage) : '' }}</span></summary><p>这里只展示服务返回的阶段事件，不是模型思维链。回答文本流式接收；证据组件在完整 UI 事件抵达后一次呈现。</p><ol v-if="turn.stages.length"><li v-for="(entry, index) in turn.stages" :key="index">{{ STAGE_LABEL[entry.stage] ?? entry.stage }} <code>{{ entry.stage }}</code></li></ol><p v-else>尚未收到阶段事件。</p></details>
            <div class="natural-answer"><MarkdownBlock v-if="turn.answer" :source="turn.answer" /><p v-else class="quiet-note">{{ turn.thinking ? '正在等待来源与回答…' : '本轮未返回回答正文。' }}</p></div>
            <p v-if="turn.thinking" class="quiet-note">回答仍在生成，拒答和复核状态以最终回执为准。</p>
            <div v-if="turn.citations.length" class="citation-pills" aria-label="回答引用"><template v-for="(citation, index) in turn.citations" :key="citation.id + ':' + index"><a v-if="sanitizeHref(citation.url)" :href="sanitizeHref(citation.url)!" target="_blank" rel="noreferrer noopener">[{{ index + 1 }}] {{ citation.title }} ↗</a><span v-else>[{{ index + 1 }}] {{ citation.title }} · 链接不可用</span></template></div>
            <p v-if="turn.uiError" class="quiet-note">{{ turn.uiError }}</p>
            <AdaptiveAnswer v-if="turn.ui && turn.abstained !== true" :document="turn.ui" />
            <footer class="answer-receipt"><span>{{ modeLabel(turn.answerMode) }}{{ turn.answerModelId ? ' · ' + turn.answerModelId : '' }}</span><span v-if="turn.completed">拒答：{{ turn.abstained === true ? '是' : turn.abstained === false ? '否' : '未返回' }} · 复核：{{ turn.finalReview ? REVIEW_LABEL[turn.finalReview.status] : '未返回' }}</span><span v-if="turn.lastCost !== null">¥{{ turn.lastCost.toFixed(4) }}</span></footer>
            <details class="audit-details"><summary>详细审计 / 回答原文 / 全部引用</summary><p v-if="turn.llmLayers.length">模型层：{{ turn.llmLayers.join('、') }}</p><p v-if="turn.layerFallbacks.length">层内兜底：{{ turn.layerFallbacks.join('；') }}</p><p v-if="turn.uiStatus">UI 回执：{{ turn.uiStatus.status }} · {{ turn.uiStatus.reason }}</p><AnswerReport :answer="turn.answer" :citations="turn.citations" :thinking="turn.thinking" :completed="turn.completed" :abstained="turn.abstained" :final-review="turn.finalReview" :error="turn.error" /></details>
          </section>
        </article>
      </div>
    </div>
    <div class="composer-dock">
      <button v-if="!following" type="button" class="latest-button secondary" @click="jumpToLatest">↓ {{ unread ? '有新内容 · ' : '' }}回到最新</button>
      <form class="composer-shell" @submit.prevent="submit()">
        <label for="qa-question" class="composer-label">提出一个独立问题</label>
        <textarea id="qa-question" ref="composer" :value="question" rows="2" placeholder="输入 CVE、产品 / 版本，以及你想核对的问题…" aria-describedby="composer-help" @input="onComposerInput" @keydown="onComposerKey" @compositionstart="composing = true" @compositionend="composing = false"></textarea>
        <div class="composer-controls"><span id="composer-help">Enter 发送 · Shift + Enter 换行</span><button v-if="qa.thinking" type="button" class="stop-button" @click="qa.stop()">■ 停止</button><button v-else type="submit" class="send-button" :disabled="!question.trim() || composing" aria-label="发送问题">↑</button></div>
      </form>
      <p class="composer-disclaimer">独立问题 · 历史不参与推理 · 仅显示真实事件与来源 · 请核对证据</p>
    </div>
  </section>
</template>

<style scoped>
.qa-workspace{width:min(100%,1060px);margin:0 auto;height:calc(100dvh - 142px);min-height:560px;display:flex;flex-direction:column;color:var(--text);background:var(--bg);position:relative}.workspace-header{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:8px 12px 18px;border-bottom:1px solid var(--border)}.workspace-brand{display:flex;gap:12px;align-items:center}.brand-mark,.assistant-symbol{display:grid;place-items:center;border:1px solid color-mix(in srgb,var(--accent) 35%,var(--border));background:color-mix(in srgb,var(--accent) 8%,var(--panel));border-radius:12px;color:var(--accent);width:36px;height:36px;font-weight:750}.workspace-brand h1{font-size:18px;letter-spacing:-.4px;margin:0}.workspace-brand h1 span{font-size:12px;font-weight:400;color:var(--muted);margin-left:9px}.workspace-brand p{font-size:11px;color:var(--muted);margin:5px 0 0}.new-conversation{font-size:12px;border-radius:20px;padding:8px 14px}.workspace-context{font-size:11px;color:var(--muted);padding:10px 14px}.workspace-context summary{cursor:pointer;width:fit-content}.workspace-context p{line-height:1.8;max-width:780px}.conversation-scroll{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;scrollbar-gutter:stable;padding:0 22px;scroll-behavior:auto}.conversation-thread{max-width:780px;margin:0 auto;padding:24px 0 20px}.welcome{max-width:680px;margin:auto;padding:clamp(28px,6vh,74px) 0 36px}.welcome-eyebrow{font-size:10px;letter-spacing:2px;color:var(--accent)}.welcome h2{font-size:clamp(22px,3vw,32px);font-weight:550;line-height:1.4;letter-spacing:-.8px;margin:14px 0}.welcome>p{font-size:13px;line-height:1.9;color:var(--muted)}.suggestions{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:28px}.suggestions button{text-align:left;background:transparent;border:1px solid var(--border);color:var(--text);padding:16px;border-radius:14px;display:grid;grid-template-columns:1fr auto;gap:8px;transition:border-color .15s}.suggestions button:hover{border-color:var(--accent)}.suggestions small{grid-column:1/-1;font-size:11px;font-weight:400;color:var(--muted);line-height:1.6}.conversation-turn{margin-bottom:42px}.user-message{margin:0 0 25px auto;width:fit-content;max-width:85%;border-radius:20px 20px 4px 20px;background:color-mix(in srgb,var(--muted) 10%,var(--panel));padding:12px 18px;overflow-wrap:anywhere}.message-label{font-size:10px;color:var(--muted)}.user-message p{white-space:pre-wrap;font-size:14px;line-height:1.8;margin:4px 0}.assistant-message{min-width:0}.assistant-header{display:flex;align-items:center;gap:10px;margin-bottom:15px}.assistant-symbol{width:26px;height:26px;border-radius:9px;font-size:12px}.assistant-header strong{font-size:12px}.turn-status{margin-left:auto;font-size:10px;color:var(--muted)}.answer-caution{padding:12px 15px;margin:12px 0 16px;border:1px solid rgba(185,148,84,.3);border-left:3px solid #b99454;border-radius:8px;background:rgba(185,148,84,.06);font-size:12px;line-height:1.8;overflow-wrap:anywhere}.answer-caution p{margin:3px 0}.execution-panel{font-size:11px;color:var(--muted);margin-bottom:18px}.execution-panel summary{cursor:pointer;display:flex;align-items:center;gap:8px;flex-wrap:wrap}.execution-panel summary>span:last-child{font-size:10px}.execution-panel p{line-height:1.8}.execution-panel ol{padding-left:20px;line-height:2}.execution-panel code{margin-left:10px;font-size:10px}.live-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 12%,transparent)}.natural-answer{font-size:14px;line-height:1.9}.quiet-note{font-size:11px;color:var(--muted);line-height:1.7}.citation-pills{display:flex;flex-wrap:wrap;gap:7px;margin:18px 0}.citation-pills a,.citation-pills>span{font-size:10px;color:var(--muted);border:1px solid var(--border);padding:5px 9px;border-radius:20px;max-width:100%;overflow-wrap:anywhere}.citation-pills a:hover{color:var(--accent);border-color:var(--accent)}.answer-receipt{display:flex;gap:12px;flex-wrap:wrap;font-size:10px;color:var(--muted);margin:18px 0 12px}.audit-details{font-size:11px;color:var(--muted)}.audit-details>summary{cursor:pointer;padding:8px 0}.audit-details :deep(.answer-report){margin-top:12px}.composer-dock{position:sticky;bottom:0;padding:12px 22px 5px;background:var(--bg);border-top:1px solid var(--border)}.composer-shell{max-width:780px;margin:auto;border:1px solid color-mix(in srgb,var(--muted) 30%,var(--border));border-radius:22px;background:var(--panel);padding:12px 16px;box-shadow:0 6px 26px rgba(0,0,0,.05)}.composer-shell:focus-within{border-color:color-mix(in srgb,var(--accent) 65%,var(--border))}.composer-label{font-size:10px;color:var(--muted)}.composer-shell textarea{display:block;width:100%;min-height:52px;max-height:180px;resize:none;border:0;outline:none;background:transparent;color:var(--text);font:inherit;font-size:13px;line-height:1.8;padding:8px 0;box-shadow:none}.composer-controls{display:flex;align-items:center;justify-content:space-between;gap:12px}.composer-controls>span{font-size:10px;color:var(--muted)}.send-button{border-radius:50%;width:32px;height:32px;padding:0;font-size:20px}.stop-button{font-size:11px;border-radius:18px}.composer-disclaimer{font-size:10px;color:var(--muted);text-align:center;margin:10px 0 2px}.latest-button{display:block;margin:-32px auto 10px;position:relative;font-size:11px;border-radius:20px;box-shadow:0 2px 12px rgba(0,0,0,.12)}button:focus-visible,summary:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:3px}@media(max-width:600px){.qa-workspace{height:calc(100dvh - 125px);min-height:510px}.workspace-header{padding:6px 0 14px}.conversation-scroll{padding:0 8px}.composer-dock{padding:10px 2px 3px}.suggestions{grid-template-columns:1fr}.welcome{padding:26px 6px}.suggestions button{padding:12px}.workspace-brand h1 span{display:block;margin:4px 0 0}.new-conversation{padding:7px 10px}.turn-status{max-width:52%;text-align:right}.user-message{max-width:92%}}@media(prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
</style>

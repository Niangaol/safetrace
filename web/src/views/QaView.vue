<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { getJson } from '../api'
import { useQaStore } from '../stores/qa'
import type { MetricsOverview } from '../types'

const qa = useQaStore()
const route = useRoute()
const question = ref('')

/**
 * 「一次完整问答」演示页（TEAM-PLAN.md §3.4 的答辩核心）。
 *
 * 目标：**一屏看完** 提问 → 检索证据 → 推理链（可展开）→ 带引用答案。
 *
 * 三条诚实性约束（都来自团队红线，不是可选项）：
 *   1. 后端没有 LLM 凭据时会返回 `【演示模式】…` 占位答案 —— 必须在页面上显式说明，
 *      不能让人误以为这是模型真实分析结果；
 *   2. 检索得分（`score`）为 0 是真实值（当前是词法兜底排序），要如实展示而不是藏起来；
 *   3. 成本恒为 ¥0（cache provider 占位），也不涂改。
 */

const STAGE_ORDER = ['rewrite', 'retrieve', 'reasoning', 'generate', 'check'] as const
const STAGE_LABEL: Record<string, string> = {
  plan: '拆解问题',
  rewrite: '改写检索式',
  retrieve: '混合检索',
  reasoning: '推理链',
  generate: '生成答案',
  check: '自检',
}

/** 预置问题：优先选库里真实有切片的 CVE，保证能检索到证据、演示不空转 */
const SUGGESTIONS = [
  'CVE-2026-31001 怎么修复？',
  'CVE-2026-28114 的攻击条件是什么？',
  'vLLM 存在哪些高危漏洞？',
  'PyTorch torch.load 的安全风险如何缓解？',
]

const showReasoning = ref(true)

const hasAnswer = computed(() => qa.answer.trim().length > 0)
/** 后端在无 LLM 凭据时会给出这个前缀 */
const isPlaceholderAnswer = computed(() => qa.answer.includes('【演示模式】'))
const evidenceCount = computed(() => qa.citations.length)

/** 已走过的阶段（用于进度条高亮） */
const reachedStages = computed(() => new Set(qa.stages.map((s) => s.stage)))

function stageState(name: string): 'done' | 'active' | 'idle' {
  if (qa.thinking && qa.stage === name) return 'active'
  if (reachedStages.value.has(name)) return 'done'
  return 'idle'
}

/** retrieve 阶段的实际轮次与命中数，作为"多轮检索真的发生过"的证据 */
const retrieveRounds = computed(() => qa.stages.filter((s) => s.stage === 'retrieve'))

async function submit(q?: string) {
  const text = (q ?? question.value).trim()
  if (!text || qa.thinking) return
  qa.ask(text)
  question.value = ''
}

onMounted(async () => {
  try {
    qa.metrics = await getJson<MetricsOverview>('/metrics/overview')
  } catch {
    /* 不阻塞问答 */
  }
  // 支持深链：/qa?q=... 直接跑一遍（便于把某个问题固定进演示脚本/书签，
  // 也便于无头截图验证整条问答链路）
  const deepLink = String(route.query.q ?? '').trim()
  if (deepLink) submit(deepLink)
})
</script>

<template>
  <h1 class="page-title">情报问答 · 一次完整问答</h1>
  <p class="page-subtitle">
    提问 → 检索证据 → 推理链 → 带引用答案，一屏看完（每一步都可展开核对）
  </p>

  <!-- 提问区 -->
  <div class="toolbar">
    <input
      v-model="question"
      placeholder="输入问题后回车，例如：CVE-2026-31001 怎么修复？"
      style="flex: 1; min-width: 320px"
      @keyup.enter="submit()"
    />
    <button :disabled="!question.trim() || qa.thinking" @click="submit()">
      <span v-if="qa.thinking" class="spinner" style="margin-right: 6px"></span>
      {{ qa.thinking ? '生成中…' : '提问' }}
    </button>
    <button class="secondary" :disabled="!qa.thinking" @click="qa.stop()">中断</button>
  </div>

  <div style="display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 16px">
    <button
      v-for="s in SUGGESTIONS"
      :key="s"
      class="secondary"
      style="font-size: 12px; padding: 5px 12px"
      :disabled="qa.thinking"
      @click="submit(s)"
    >
      {{ s }}
    </button>
  </div>

  <!-- 流水线进度 -->
  <div class="panel fade-in" style="margin-bottom: 14px">
    <div class="panel-header">
      <h3>检索流水线</h3>
      <span class="badge-count">
        {{ retrieveRounds.length ? `检索 ${retrieveRounds.length} 轮` : '待运行' }}
        <template v-if="retrieveRounds.length">
          · 命中 {{ retrieveRounds[retrieveRounds.length - 1]?.hit ?? 0 }}
        </template>
      </span>
    </div>
    <div class="pipeline">
      <div v-for="(name, i) in STAGE_ORDER" :key="name" class="pipeline-step" :class="stageState(name)">
        <span class="pipeline-index">{{ i + 1 }}</span>
        <span class="pipeline-name">{{ STAGE_LABEL[name] }}</span>
      </div>
    </div>
    <p v-if="qa.stages.length" class="muted" style="font-size: 11px; margin: 8px 0 0">
      实际到达的阶段：
      {{ qa.stages.map((s) => STAGE_LABEL[s.stage] ?? s.stage).join(' → ') }}
      <template v-if="retrieveRounds.length">
        （检索轮次：{{ retrieveRounds.map((r) => `${r.round}轮命中${r.hit}`).join('，') }}）
      </template>
    </p>
  </div>

  <!-- 答案占位/降级说明：必须在最显眼处 -->
  <div v-if="isPlaceholderAnswer" class="notice warn" style="margin-bottom: 14px">
    <strong>当前为演示占位答案，不是模型分析结果。</strong>
    后端未配置 LLM 凭据（<code>LLM_API_KEY</code>），走 cache provider 占位，
    因此 <code>cost_cny = 0</code>。检索、引用、推理链都是真实的；只有最终文字是占位。
  </div>
  <div v-else-if="qa.degraded" class="notice warn" style="margin-bottom: 14px">
    <strong>本次回答处于降级状态</strong>（后端 <code>degraded=true</code>），请对照下方证据判断可信度。
  </div>
  <div v-if="qa.error" class="notice error" style="margin-bottom: 14px">{{ qa.error }}</div>

  <!-- 三栏：证据 / 推理链 / 答案 -->
  <div class="qa-grid">
    <!-- 证据 -->
    <div class="panel fade-in">
      <div class="panel-header">
        <h3>检索证据</h3>
        <span class="badge-count">{{ evidenceCount }} 条</span>
      </div>
      <div v-if="!evidenceCount" class="muted" style="padding: 16px; font-size: 12px">
        {{ qa.thinking ? '检索中…' : '暂无证据（提出一个问题后显示）' }}
      </div>
      <div
        v-for="c in qa.citations"
        :key="c.id"
        class="evidence"
        style="margin-bottom: 8px"
      >
        <div style="display: flex; align-items: center; gap: 8px">
          <span class="badge info" style="min-width: 34px; text-align: center">{{ c.id }}</span>
          <strong style="font-size: 12px">{{ c.title }}</strong>
        </div>
        <div class="muted" style="font-size: 11px; margin-top: 4px">
          检索得分 <code>{{ c.score != null ? c.score.toFixed(4) : '—' }}</code>
          <span v-if="c.score === 0">（词法兜底排序，语义排序需向量模型）</span>
        </div>
      </div>
    </div>

    <!-- 推理链 -->
    <div class="panel fade-in">
      <div class="panel-header">
        <h3>推理链</h3>
        <button class="secondary" style="font-size: 11px; padding: 3px 10px" @click="showReasoning = !showReasoning">
          {{ showReasoning ? '收起' : '展开' }}
        </button>
      </div>
      <div v-if="!qa.reasoning.length" class="muted" style="padding: 16px; font-size: 12px">
        暂无推理步骤
      </div>
      <template v-else>
        <div v-if="showReasoning">
          <div v-for="r in qa.reasoning" :key="r.step" class="reason-step">
            <div class="reason-head">
              <span class="badge info" style="min-width: 34px; text-align: center">步骤 {{ r.step }}</span>
              <span style="font-size: 12px">{{ r.sub_question }}</span>
            </div>
            <div class="reason-finding" :class="{ empty: !r.finding }">
              <template v-if="r.finding">
                <span class="muted" style="font-size: 11px">自检结论：</span>{{ r.finding }}
              </template>
              <template v-else>
                <span class="muted" style="font-size: 11px">
                  （后端在生成答案后才补发自检结论；若此处长期为空，说明该步未执行到自检）
                </span>
              </template>
            </div>
          </div>
        </div>
        <p v-else class="muted" style="font-size: 12px; margin: 0">
          已收起 {{ qa.reasoning.length }} 步（点右上角展开）
        </p>
      </template>
    </div>

    <!-- 答案 -->
    <div class="panel fade-in">
      <div class="panel-header">
        <h3>四段式答案</h3>
        <span v-if="qa.meta" class="badge-count">
          {{ qa.meta.model }} · {{ qa.meta.elapsedMs }}ms
        </span>
      </div>
      <div v-if="hasAnswer" class="answer-body">{{ qa.answer }}</div>
      <div v-else class="muted" style="padding: 16px; font-size: 12px">
        {{ qa.thinking ? '生成中…' : '暂无答案' }}
      </div>

      <!-- 引用回指：答案里的 [Sn] 与证据编号一一对应 -->
      <div v-if="evidenceCount" style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 10px">
        <div class="label" style="margin-bottom: 6px">引用来源（可点开核对）</div>
        <div v-for="c in qa.citations" :key="`f-${c.id}`" style="font-size: 12px; margin-bottom: 4px">
          <span class="badge info" style="min-width: 34px; text-align: center">{{ c.id }}</span>
          <code style="margin-left: 6px">{{ c.url }}</code>
        </div>
      </div>
    </div>
  </div>

  <!-- 运行元信息 -->
  <div v-if="qa.meta" class="panel fade-in" style="margin-top: 14px">
    <div class="panel-header"><h3>本次运行</h3></div>
    <div class="meta-grid">
      <div><span class="label">耗时</span><strong>{{ qa.meta.elapsedMs }} ms</strong></div>
      <div><span class="label">模型</span><strong>{{ qa.meta.model }}</strong></div>
      <div><span class="label">引用数</span><strong>{{ qa.meta.citationCount }}</strong></div>
      <div>
        <span class="label">成本</span>
        <strong>¥{{ (qa.meta.costCny ?? 0).toFixed(4) }}</strong>
        <span v-if="qa.meta.costCny === 0" class="muted" style="font-size: 11px">（cache 占位，未真实调用）</span>
      </div>
      <div><span class="label">降级</span><strong>{{ qa.meta.degraded ? '是' : '否' }}</strong></div>
      <div><span class="label">会话</span><code style="font-size: 11px">{{ qa.meta.sessionId }}</code></div>
    </div>
    <p v-if="qa.metrics" class="muted" style="font-size: 11px; margin: 10px 0 0">
      今日累计 LLM 花费 ¥{{ qa.metrics.cost.total_cny.toFixed(2) }} / 预算 ¥{{ qa.metrics.cost.daily_budget_cny }}
    </p>
  </div>
</template>

<style scoped>
.pipeline {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.pipeline-step {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 12px;
  color: var(--muted);
}
.pipeline-step.done {
  border-color: rgba(34, 197, 94, 0.4);
  color: var(--text);
  background: rgba(34, 197, 94, 0.08);
}
.pipeline-step.active {
  border-color: rgba(56, 189, 248, 0.6);
  color: var(--text);
  background: rgba(56, 189, 248, 0.12);
}
.pipeline-index {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  opacity: 0.7;
}

.qa-grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1.2fr;
  gap: 14px;
}
@media (max-width: 1200px) {
  .qa-grid { grid-template-columns: 1fr; }
}

.reason-step {
  border-left: 2px solid var(--border);
  padding: 0 0 10px 10px;
  margin-bottom: 10px;
}
.reason-head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.reason-finding {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text);
}
.reason-finding.empty { color: var(--muted); }

.answer-body {
  white-space: pre-wrap;
  font-size: 13px;
  line-height: 1.7;
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}
.meta-grid > div { display: flex; flex-direction: column; gap: 2px; }
.meta-grid .label { font-size: 11px; }

.notice {
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  line-height: 1.6;
}
.notice.warn {
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
}
.notice.error {
  background: rgba(244, 63, 94, 0.1);
  border: 1px solid rgba(244, 63, 94, 0.3);
  color: var(--critical);
}
.notice code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
}
</style>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { getJson } from '../api'
import TerminalWindow from '../components/TerminalWindow.vue'
import { parseAnswer, type InlineToken } from '../answerFormat'
import {
  SAMPLE_ANSWER,
  SAMPLE_CITATIONS,
  SAMPLE_META,
  SAMPLE_INJECTION_GUARD,
  SAMPLE_STALE_WARNING,
  SAMPLE_QUESTION,
  SAMPLE_REASONING,
  SAMPLE_STAGES,
  SAMPLE_TRACES,
} from '../qaSample'
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
 *   3. 成本恒为 ¥0（cache provider 占位）时也要如实写，不涂改。
 */

/**
 * 流水线步骤**必须与后端实际发出的 stage 一一对应**。
 * 早先这里画了「改写检索式/混合检索/推理链/生成答案/自检」五步，
 * 但后端当时只发 `rewrite` 与 `retrieve` —— 于是进度条永远停在第 2 步"走不到头"。
 * 现在后端补齐了 `generate`/`reasoning`/`check`/`done`，两侧对齐。
 */

const STAGE_ORDER = ['rewrite', 'retrieve', 'generate', 'reasoning', 'check'] as const
const STAGE_LABEL: Record<string, string> = {
  plan: '拆解问题',
  rewrite: '改写检索式',
  retrieve: '混合检索',
  reasoning: '推理链',
  generate: '生成答案',
  check: '自检',
  done: '完成',
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

/**
 * 把 ISO 时间显示成日期（只取到"天"）。
 *
 * 只显示日期而非精确时刻：这个值的用途是让用户判断**证据是否过时**，
 * 精确到秒反而会让人误以为它是"采集时刻"（其实是上游首次发布时间）。
 * 解析失败时原样返回，不显示 Invalid Date。
 */
function formatDate(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso)
  return m ? `${m[1]}-${m[2]}-${m[3]}` : iso
}

/** 整条流水线是否跑完（后端发过 `done` 阶段） */
const finished = computed(() => reachedStages.value.has('done'))

/** 结构化后的答案块：用于突出关键内容（标题/引用号/硬事实/动作词） */
const answerBlocks = computed(() => parseAnswer(qa.answer))

/**
 * 折叠状态（模仿 opencode 的"次要内容默认收起"）。
 * - 答案段落：只默认展开「结论 / 建议动作」这类先要看的，其余收起；
 * - 执行轨迹：默认收起成一行摘要（展开才看每一步）。
 * 用 Set 记录"被手动切换过"的段落，避免重渲染时丢掉用户的选择。
 */
const expandedSections = ref<Set<number>>(new Set())
const toggledSections = ref<Set<number>>(new Set())

function isSectionOpen(index: number, collapsedByDefault: boolean): boolean {
  if (toggledSections.value.has(index)) return expandedSections.value.has(index)
  return !collapsedByDefault
}
function toggleSection(index: number, collapsedByDefault: boolean) {
  const nextExpanded = new Set(expandedSections.value)
  const nextToggled = new Set(toggledSections.value)
  const currentlyOpen = isSectionOpen(index, collapsedByDefault)
  if (currentlyOpen) nextExpanded.delete(index)
  else nextExpanded.add(index)
  nextToggled.add(index)
  expandedSections.value = nextExpanded
  toggledSections.value = nextToggled
}
/** 答案换新时清空折叠选择（否则新答案会继承旧答案的开关状态） */
function resetSectionState() {
  expandedSections.value = new Set()
  toggledSections.value = new Set()
}

/** 当前被点中的引用编号，用于把对应证据也高亮出来 */
const activeRef = ref<string | null>(null)

/** 是否处于「样例渲染」模式（`/qa?demo=1`），页面上要如实标注 */
const isSample = ref(false)

/**
 * 轨迹（trajectory）：把后端的 `trace` 事件渲染成"过程可视化"。
 *
 * 设计取向与 agent 工具链的轨迹视图一致：
 *   - **干到哪一步就显示到哪一步**（先有什么发什么），没有"等全部完成再展开"；
 *   - 每步显示 工具名 / 入参摘要 / 结果 / **该步耗时**（由相邻两步时间差算出）；
 *   - 正在执行的那步有活动指示，失败的步标红，不隐藏。
 */
const showTrace = ref(false)

/** 每步耗时：用"下一步开始"或"自身结束"减去"自身开始" */
const traceRows = computed(() =>
  qa.traces.map((t, i) => {
    const next = qa.traces[i + 1]
    const end = t.finishedAt ?? next?.startedAt ?? null
    return {
      ...t,
      durationMs: end != null ? Math.max(0, end - t.startedAt) : null,
      running: t.finishedAt == null && t.ok == null,
    }
  }),
)

/** 轨迹里入参过长时截断展示（完整内容放在 title 里） */
function inputSummary(input?: Record<string, unknown>): string {
  if (!input) return ''
  const parts: string[] = []
  for (const [k, v] of Object.entries(input)) {
    if (Array.isArray(v)) {
      parts.push(`${k}=[${v.length} 项]`)
    } else if (typeof v === 'string') {
      parts.push(`${k}=${v.length > 40 ? `${v.slice(0, 40)}…` : v}`)
    } else {
      parts.push(`${k}=${String(v)}`)
    }
  }
  return parts.join(' · ')
}

/** 轨迹步骤的中文标签（未知步骤原样显示，不猜） */
const TRACE_LABEL: Record<string, string> = {
  recv: '收到问题',
  plan: '规划子问题与检索式',
  citations: '整理可引用证据',
  generate: '生成答案',
  reasoning: '汇总推理链',
  check: '自检',
  regenerate: '自检未通过，重生成',
  no_evidence: '无证据，如实告知',
  failed: '失败',
}
function traceLabel(step: string): string {
  if (TRACE_LABEL[step]) return TRACE_LABEL[step]
  const m = /^retrieve\.(\d+)$/.exec(step)
  if (m) return `第 ${m[1]} 轮检索`
  return step
}

/** 轨迹行内展开：显示完整入参/出参 JSON，供逐行追溯 */
const openTrace = ref(new Set<number>())
function toggleTrace(i: number) {
  const next = new Set(openTrace.value)
  if (next.has(i)) next.delete(i)
  else next.add(i)
  openTrace.value = next
}
function traceJson(t: { input?: Record<string, unknown>; output?: string }): string {
  const parts: string[] = []
  if (t.input) parts.push(JSON.stringify(t.input, null, 2))
  if (t.output) parts.push(t.output)
  return parts.join('\n')
}

function focusRef(ref: string) {
  activeRef.value = activeRef.value === ref ? null : ref
  document.getElementById(`evidence-${ref}`)?.scrollIntoView({
    behavior: 'smooth',
    block: 'center',
  })
}

/** token 的展示类名：颜色与字重由 CSS 的 .hl-* 决定 */
function tokenClass(t: InlineToken): string {
  return t.kind ? `hl hl-${t.kind}` : ''
}

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
  resetSectionState()
  qa.ask(text)
  question.value = ''
}

onMounted(async () => {
  try {
    qa.metrics = await getJson<MetricsOverview>('/metrics/overview')
  } catch {
    /* 不阻塞问答 */
  }

  // `/qa?demo=1`：用固定样例把整页渲染立即可见（不等 25–35s 的真实问答）。
  // 用途是**渲染验收**与讲解时的静态展示；页面会标注"演示样例"，
  // 不会被当成真实运行结果（红线⑤）。
  if (String(route.query.demo ?? '') === '1') {
    isSample.value = true
    qa.question = SAMPLE_QUESTION
    qa.answer = SAMPLE_ANSWER
    qa.citations = SAMPLE_CITATIONS
    qa.reasoning = SAMPLE_REASONING
    qa.stages = SAMPLE_STAGES
    qa.traces = SAMPLE_TRACES
    qa.started = true
    qa.stage = 'done'
    qa.meta = SAMPLE_META
    qa.thinking = false
    qa.degraded = false
    // C-04：样例也带上时效与注入筛查状态，否则验收时看不到这两条提示
    qa.staleWarning = SAMPLE_STALE_WARNING
    qa.injectionGuard = SAMPLE_INJECTION_GUARD
    // 样例内容是公开域一次真实问答的产出，如实显示"公开域"（不覆盖用户已选的数据域）
    qa.setDomain('public', false)
    return
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
      style="flex: 1 1 260px; min-width: 0"
      @keyup.enter="submit()"
    />
    <button :disabled="!question.trim() || qa.thinking" @click="submit()">
      <span v-if="qa.thinking" class="spinner" style="margin-right: 6px"></span>
      {{ qa.thinking ? '生成中…' : '提问' }}
    </button>
    <button class="secondary" :disabled="!qa.thinking" @click="qa.stop()">中断</button>
    <!-- C-05 数据域：public/private 由后端强制隔离与出网，前端只如实把选择发过去。
         私有态按钮区的 title 说清语义，避免"选了私有=数据绝对安全"的误解。 -->
    <div class="domain-switch" :class="{ private: qa.domain === 'private' }" role="group" aria-label="数据域">
      <button
        v-for="d in (['public', 'private'] as const)"
        :key="d"
        type="button"
        :class="{ active: qa.domain === d }"
        :disabled="isSample"
        :title="
          d === 'public'
            ? '公开域：检索全部公开情报源（默认）'
            : '私有域：仅检索本地边界/内部数据；后端按 C-05 隔离、出网策略拒绝（A-03），前端不做安全承诺'
        "
        @click="qa.setDomain(d)"
      >
        {{ d === 'public' ? '公开域' : '私有域' }}
      </button>
    </div>
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
        <template v-if="finished">✓ 已跑完</template>
        <template v-else-if="retrieveRounds.length">运行中</template>
        <template v-else>待运行</template>
        <template v-if="retrieveRounds.length">
          · 检索 {{ retrieveRounds.length }} 轮 · 命中
          {{ retrieveRounds[retrieveRounds.length - 1]?.hit ?? 0 }}
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
  <div v-if="isSample" class="notice warn" style="margin-bottom: 14px">
    <strong>当前为渲染样例（`/qa?demo=1`）。</strong>
    内容取自本仓一次真实问答的实测输出，用于快速验收排版与高亮；
    <strong>不代表系统此刻的运行状态</strong>。
  </div>
  <div v-if="isPlaceholderAnswer" class="notice warn" style="margin-bottom: 14px">
    <strong>当前为演示占位答案，不是模型分析结果。</strong>
    后端未配置 LLM 凭据（<code>LLM_API_KEY</code>），走 cache provider 占位，
    因此 <code>cost_cny = 0</code>。检索、引用、推理链都是真实的；只有最终文字是占位。
  </div>
  <div v-else-if="qa.degraded" class="notice warn" style="margin-bottom: 14px">
    <strong>{{ qa.llmDegraded ? '本次回答由降级模型生成' : '本次回答处于降级状态' }}</strong>
    <!-- 必须说清"降级"是哪种：模型降级（云端不可用/预算耗尽，答案不是云端模型产出的）
         与"自检质量分偏低"（答案本身支撑不足）对读者的含义完全不同。 -->
    <span v-if="qa.degradedReason">：{{ qa.degradedReason }}</span>
    <span v-else>（后端 <code>degraded=true</code>）</span>
    ，请对照下方证据判断可信度。
  </div>
  <div v-if="qa.error" class="notice error" style="margin-bottom: 14px">{{ qa.error }}</div>
  <!-- C-05 私有域意图提示：只要本次处于 private，就常驻说明"只查本地边界"，
       后端策略拒绝时会由上面的 qa.error 如实透出（4xx 业务错误不做 mock 回退）。 -->
  <div v-if="qa.domain === 'private'" class="notice warn" style="margin-bottom: 14px">
    <strong>私有域问答（仅本地边界）。</strong>
    本轮以 <code>data_domain=private</code> 提交：只检索本地索引/内部数据，不访问外部源；
    输出可能更稀疏，若查询超出本地可用证据会被如实说明，不会用公开数据顶替。
  </div>
  <!-- C-04 时效提示：契约要求"过龄或未知必须显式可见"。
       stale_warning 为 null 表示证据新鲜且时效全已知——那是唯一不用提示的情况。 -->
  <div v-if="qa.staleWarning" class="notice warn" style="margin-bottom: 14px">
    {{ qa.staleWarning.note }}
  </div>
  <!-- C-04 注入筛查状态（契约 v1.1.3；A-04 已落地，本仓有检测器）：
       screened=true = 本轮做过规则筛查（筛出危险时也是 true，含义是"筛过"而非"干净"，
       检出时 note 写"检出 N/total…"并给出 flags）；
       screened=false 只在"无引用"时出现（没有输入就没有筛查动作），必须显式说"未筛查"。
       note 结尾如实声明"不保证覆盖全部注入手法"——界面不得替后端把"没检出"读成"一定安全"。 -->
  <div
    v-if="qa.injectionGuard"
    class="notice"
    :class="{ warn: (qa.injectionGuard.flags?.length ?? 0) > 0 }"
    style="margin-bottom: 14px"
  >
    <strong>{{
      qa.injectionGuard.screened ? '注入筛查：已执行' : '注入筛查：未执行'
    }}</strong>
    <span v-if="qa.injectionGuard.screened === false">（本轮无引用证据，无筛查动作）</span>
    <template v-if="(qa.injectionGuard.flags?.length ?? 0) > 0">
      <span class="inject-flags">
        <span v-for="f in qa.injectionGuard.flags" :key="f" class="badge warn">{{ f }}</span>
      </span>
    </template>
    <div style="margin-top: 4px">{{ qa.injectionGuard.note }}</div>
  </div>

  <!-- 轨迹：过程可视化（干到哪一步显示到哪一步） -->
  <div v-if="qa.traces.length" class="panel fade-in" style="margin-bottom: 14px">
    <div class="panel-header">
      <h3>执行轨迹</h3>
      <div style="display: flex; align-items: center; gap: 8px">
        <span class="badge-count">
          {{ traceRows.length }} 步
          <template v-if="qa.meta?.elapsedMs != null"> · 共 {{ qa.meta.elapsedMs }}ms</template>
        </span>
        <button
          class="secondary"
          style="font-size: 11px; padding: 3px 10px"
          @click="showTrace = !showTrace"
        >
          {{ showTrace ? '收起' : '展开' }}
        </button>
      </div>
    </div>
<TerminalWindow
        v-if="showTrace"
        title="safe_trace@qa: ~/trace --follow"
        :status="`▮ ${traceRows.length} 步 · 点「完整 JSON」可展开入参/出参 · ⤢ 放大 / Esc 还原`"
      >
        <div
          v-for="(t, i) in traceRows"
          :key="`${t.step}-${i}`"
          class="trace-row"
          :class="{ running: t.running, failed: t.ok === false }"
        >
          <span class="trace-icon">
            <span v-if="t.running" class="spinner"></span>
            <span v-else-if="t.ok === false">✕</span>
            <span v-else>✓</span>
          </span>
          <span class="trace-main">
            <span class="trace-title">
              {{ traceLabel(t.step) }}
              <code class="trace-tool">{{ t.tool }}</code>
            </span>
            <span v-if="t.output" class="trace-output">{{ t.output }}</span>
            <span v-else-if="t.input" class="trace-input" :title="JSON.stringify(t.input)">
              {{ inputSummary(t.input) }}
            </span>
            <!-- 可展开：完整入参/出参 JSON，终端行内追溯到底 -->
            <button
              v-if="t.input || t.output"
              class="trace-expand"
              :title="openTrace.has(i) ? '收起完整内容' : '展开完整入参/出参'"
              @click="toggleTrace(i)"
            >{{ openTrace.has(i) ? '▾ 收起' : '▸ 完整 JSON' }}</button>
            <pre v-if="openTrace.has(i)" class="trace-json">{{ traceJson(t) }}</pre>
          </span>
          <span class="trace-time">
            <template v-if="t.durationMs != null">{{ t.durationMs }}ms</template>
            <template v-else>…</template>
            <span class="trace-at">@{{ t.startedAt }}ms</span>
          </span>
        </div>
      </TerminalWindow>
    <p v-else class="muted" style="font-size: 12px; margin: 0">
      已收起 {{ traceRows.length }} 步（点右上角展开）
    </p>
  </div>

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
        :id="`evidence-${c.id}`"
        class="evidence"
        :class="{ 'evidence-active': activeRef === c.id }"
        style="margin-bottom: 8px"
      >
        <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap">
          <span class="badge info" style="min-width: 34px; text-align: center">{{ c.id }}</span>
          <strong style="font-size: 12px">{{ c.title }}</strong>
          <!-- 原始出处必须可点开核对；取不到链接时如实说明，而不是给个点不开的假链接 -->
          <a
            v-if="c.url"
            :href="c.url"
            target="_blank"
            rel="noreferrer"
            class="src-link"
            :title="c.url"
          >
            打开出处 ↗
          </a>
          <span v-else class="muted" style="font-size: 11px">仅内部切片，无外部链接</span>
        </div>
        <div class="muted" style="font-size: 11px; margin-top: 4px">
          检索得分 <code>{{ c.score != null ? c.score.toFixed(4) : '—' }}</code>
          <span v-if="c.score === 0">（词法兜底排序，语义排序需向量模型）</span>
        </div>
        <!-- 证据可信度：契约 v1.1.1 的 trust / published_at。
             **缺省 = 未知**，所以没值时必须显示"未评估"，不能留空让人以为没问题。 -->
        <div class="muted" style="font-size: 11px; margin-top: 3px; display: flex; gap: 8px; flex-wrap: wrap">
          <span>
            来源可信度
            <span
              v-if="c.trust === 'trusted'"
              class="badge ok"
              style="font-size: 10px"
              title="结构化权威源 API 直读（NVD/KEV/GHSA/arXiv 等）或本系统由其派生"
            >权威源</span>
            <span
              v-else-if="c.trust === 'untrusted'"
              class="badge warn"
              style="font-size: 10px"
              title="网页/文档类外部文本（厂商公告页、社区、博客、PoC），未经权威确认"
            >外部文本</span>
            <span v-else class="badge" style="font-size: 10px" title="未做可信度评估，不得当作已验证">未评估</span>
          </span>
          <span>
            发布时间
            <code v-if="c.published_at">{{ formatDate(c.published_at) }}</code>
            <span v-else title="发布时间未知，不得假定新鲜">未知</span>
          </span>
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

      <!--
        关键内容突出：段落标题用色块、[Sn] 做成可点徽标、
        CVE/版本号/评分等硬事实与危险动作词分别着色加粗。
        解析是保守的（见 answerFormat.ts），不认识的行原样输出，不吞字。
      -->
      <div v-if="hasAnswer" class="answer-body">
        <div v-for="(block, bi) in answerBlocks" :key="bi" class="ans-block">
          <!-- 段落标题可点击折叠：次要段落默认收起，只留结论/建议动作展开 -->
          <button
            v-if="block.heading"
            class="ans-heading"
            :class="{ collapsed: !isSectionOpen(bi, block.collapsedByDefault) }"
            :title="isSectionOpen(bi, block.collapsedByDefault) ? '点击收起' : '点击展开'"
            @click="toggleSection(bi, block.collapsedByDefault)"
          >
            <span class="ans-caret">{{ isSectionOpen(bi, block.collapsedByDefault) ? '▾' : '▸' }}</span>
            {{ block.heading }}
            <span v-if="!isSectionOpen(bi, block.collapsedByDefault)" class="ans-count">
              {{ block.lineCount }} 行 · 点击展开
            </span>
          </button>

          <template v-if="isSectionOpen(bi, block.collapsedByDefault)">
            <p v-for="(line, li) in block.lines" :key="`l-${li}`" class="ans-line">
              <template v-for="(t, ti) in line" :key="`t-${ti}`">
                <button
                  v-if="t.kind === 'citation'"
                  class="cite-chip"
                  :class="{ active: activeRef === t.ref }"
                  :title="`跳到证据 ${t.ref}`"
                  @click="focusRef(t.ref!)"
                >
                  {{ t.text }}
                </button>
                <span v-else :class="tokenClass(t)">{{ t.text }}</span>
              </template>
            </p>
            <ul v-if="block.bullets?.length" class="ans-bullets">
              <li v-for="(b, li) in block.bullets" :key="`b-${li}`">
                <template v-for="(t, ti) in b" :key="`bt-${ti}`">
                  <button
                    v-if="t.kind === 'citation'"
                    class="cite-chip"
                    :class="{ active: activeRef === t.ref }"
                    @click="focusRef(t.ref!)"
                  >
                    {{ t.text }}
                  </button>
                  <span v-else :class="tokenClass(t)">{{ t.text }}</span>
                </template>
              </li>
            </ul>
          </template>
        </div>
      </div>
      <div v-else class="muted" style="padding: 16px; font-size: 12px">
        {{ qa.thinking ? '生成中…' : '暂无答案' }}
      </div>

      <!-- 引用回指：答案里的 [Sn] 与证据编号一一对应，链接可点 -->
      <div v-if="evidenceCount" style="margin-top: 12px; border-top: 1px solid var(--border); padding-top: 10px">
        <div class="label" style="margin-bottom: 6px">引用来源（点开核对）</div>
        <div v-for="c in qa.citations" :key="`f-${c.id}`" style="font-size: 12px; margin-bottom: 5px">
          <span class="badge info" style="min-width: 34px; text-align: center">{{ c.id }}</span>
          <a
            v-if="c.url"
            :href="c.url"
            target="_blank"
            rel="noreferrer"
            class="src-link"
            style="margin-left: 6px"
          >
            {{ c.url }}
          </a>
          <span v-else class="muted" style="margin-left: 6px">{{ c.title }}（无外部链接）</span>
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
      <div>
        <span class="label">数据域</span>
        <strong>{{ qa.domain === 'private' ? '私有域' : '公开域' }}</strong>
      </div>
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

/* ── 关键内容突出 ─────────────────────────────────────────── */

.ans-block { margin-bottom: 12px; }
.ans-block:last-child { margin-bottom: 0; }

/* 段落标题：结论 / 依据 / 推理链 / 建议动作。可点击折叠 */
.ans-heading {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  margin-bottom: 4px;
  padding: 1px 8px;
  border-radius: 5px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.02em;
  color: #7dd3fc;
  background: rgba(56, 189, 248, 0.12);
  border: 1px solid rgba(56, 189, 248, 0.28);
  cursor: pointer;
  transition: background 0.15s;
}
.ans-heading:hover { background: rgba(56, 189, 248, 0.22); }
/* 收起的段落弱化，让展开的结论更突出 */
.ans-heading.collapsed {
  color: #94a3b8;
  background: rgba(100, 116, 139, 0.12);
  border-color: rgba(100, 116, 139, 0.3);
}
.ans-caret { font-size: 10px; opacity: 0.85; }
.ans-count { font-weight: 400; font-size: 10px; opacity: 0.7; }

.ans-line { margin: 0 0 4px; }
.ans-bullets { margin: 2px 0 6px; padding-left: 18px; }
.ans-bullets li { margin-bottom: 3px; }

/* 硬事实：CVE / 版本号 / CVSS / EPSS —— 深色底 + 等宽，便于扫读 */
.hl-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 700;
  color: #fbbf24;
  background: rgba(251, 191, 36, 0.12);
  border-radius: 4px;
  padding: 0 4px;
}

/* 风险/危险动作词：红色 + 加粗 */
.hl-danger {
  color: #fb7185;
  font-weight: 700;
}

/* 建议动作词：绿色 + 加粗 */
.hl-action {
  color: #4ade80;
  font-weight: 700;
}

/* [S1] 引用号：做成可点徽标，点一下把对应证据高亮并滚到可见处 */
.inject-flags {
  display: inline-flex;
  gap: 4px;
  margin-left: 8px;
}

.cite-chip {
  display: inline-block;
  margin: 0 2px;
  padding: 0 6px;
  border-radius: 5px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  font-weight: 700;
  line-height: 18px;
  color: #93c5fd;
  background: rgba(59, 130, 246, 0.14);
  border: 1px solid rgba(59, 130, 246, 0.35);
  cursor: pointer;
  transition: all 0.15s;
}
.cite-chip:hover { background: rgba(59, 130, 246, 0.28); }
.cite-chip.active {
  color: #0b1220;
  background: #93c5fd;
  border-color: #93c5fd;
}

/* 证据卡片被引用号点中时同步高亮 */
.evidence-active {
  border-color: rgba(147, 197, 253, 0.7) !important;
  box-shadow: 0 0 0 1px rgba(147, 197, 253, 0.35);
}

/* 原始出处链接 */
.src-link {
  font-size: 11px;
  color: #7dd3fc;
  text-decoration: none;
  border-bottom: 1px dashed rgba(125, 211, 252, 0.5);
  word-break: break-all;
}
.src-link:hover { color: #bae6fd; border-bottom-style: solid; }

/* ── 执行轨迹（过程可视化）────────────────────────────────── */

/* 轨迹已改用 TerminalWindow 承载（Linux 终端风 + 滚轮 + ⤢ 放大） */
.trace-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 6px 10px;
  border-bottom: 1px dashed rgba(42, 64, 96, 0.3);
  font-size: 12px;
  position: relative;
}
.trace-row:hover { background: rgba(56, 189, 248, 0.06); }
/* 展开完整入参/出参：终端内逐行追溯 */
.trace-expand {
  margin-top: 3px;
  background: none;
  border: none;
  padding: 0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: #7dd3fc;
  cursor: pointer;
}
.trace-expand:hover { color: #bae6fd; text-decoration: underline; }
.trace-json {
  margin: 4px 0 2px;
  padding: 6px 8px;
  background: rgba(2, 6, 14, 0.7);
  border-left: 2px solid rgba(56, 189, 248, 0.35);
  font-family: 'JetBrains Mono', monospace;
  font-size: 10.5px;
  line-height: 1.5;
  color: #9cc8f2;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 220px;
  overflow-y: auto;
}
.trace-row.running { background: rgba(56, 189, 248, 0.08); }
.trace-row.failed { background: rgba(244, 63, 94, 0.08); }

/* 时间线节点 */
.trace-icon {
  flex-shrink: 0;
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  color: #4ade80;
  background: #0f1623;
  border: 1px solid rgba(74, 222, 128, 0.4);
  border-radius: 50%;
  margin-left: -11px;
}
.trace-row.running .trace-icon {
  color: #38bdf8;
  border-color: rgba(56, 189, 248, 0.5);
}
.trace-row.failed .trace-icon {
  color: #fb7185;
  border-color: rgba(251, 113, 133, 0.5);
}

.trace-main { display: flex; flex-direction: column; gap: 1px; flex: 1; min-width: 0; }
.trace-title { color: var(--text); }
.trace-tool {
  margin-left: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  color: #64748b;
}
.trace-output { color: #94a3b8; font-size: 11px; }
.trace-input {
  color: #64748b;
  font-size: 11px;
  font-family: 'JetBrains Mono', monospace;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.trace-time {
  flex-shrink: 0;
  text-align: right;
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: #7dd3fc;
  display: flex;
  flex-direction: column;
}
.trace-at { color: #475569; font-size: 10px; }

.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}
.meta-grid > div { display: flex; flex-direction: column; gap: 2px; }
.meta-grid .label { font-size: 11px; }

/* ── C-05 数据域切换 ───────────────────────────────────── */

.domain-switch {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: rgba(100, 116, 139, 0.08);
}
.domain-switch button {
  border: none;
  background: transparent;
  color: var(--muted);
  font-size: 12px;
  padding: 5px 12px;
  border-radius: calc(var(--radius-sm) - 3px);
  cursor: pointer;
  transition: all 0.15s;
}
.domain-switch button.active {
  color: var(--text);
  background: rgba(56, 189, 248, 0.18);
}
.domain-switch.private button.active {
  color: #fbbf24;
  background: rgba(251, 191, 36, 0.16);
}
.domain-switch button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

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

import { defineStore } from 'pinia'
import { ref } from 'vue'

import { getJson, streamChat } from '../api'
import type { Citation, MetricsOverview } from '../types'

/** 一次检索的中间阶段（后端 `stage` 事件），用于展示流水线走到哪一步 */
export interface StageStep {
  stage: string
  message?: string
  round?: number
  hit?: number
}

/** 一条推理链步骤（后端 `reasoning` 事件）。
 *  后端在答案生成**之后**才补发 finding（自检结论），所以这里会先收到空 finding。 */
export interface ReasoningStep {
  step: number
  sub_question: string
  finding: string
}

/** 一次问答的完整元信息（后端 `done` 事件） */
export interface RunMeta {
  sessionId: string | null
  elapsedMs: number | null
  model: string | null
  costCny: number | null
  degraded: boolean
  citationCount: number
}

/**
 * 一条轨迹（后端 `trace` 事件）—— 对应"正在做什么 / 用什么 / 拿到什么 / 花了多久"。
 *
 * 后端对**每个关键步骤发两条**：开始（只有 `input`）与结束（带 `ok`/`output`）。
 * 这里按 `step` 合并成一条，保留 `startedAt` 与 `finishedAt`，
 * 于是界面上能看出"哪一步最慢"，而不是只看到一个总耗时。
 */
export interface TraceStep {
  step: string
  tool: string
  /** 工具入参（开始帧） */
  input?: Record<string, unknown>
  /** 是否成功（结束帧；未结束为 undefined） */
  ok?: boolean
  /** 结果摘要（结束帧） */
  output?: string
  /** 开始/结束时的累计耗时（毫秒），来自后端，便于判断哪一步耗时最长 */
  startedAt: number
  finishedAt?: number
  /** 结束帧可能带的补充字段（新增条数、模型名、自检分数等） */
  extra?: Record<string, unknown>
}

export const useQaStore = defineStore('qa', () => {
  const answer = ref('')
  const citations = ref<Citation[]>([])
  const stage = ref('')
  /** 阶段轨迹（按到达顺序累积）——"这条流水线真的走过哪些步骤"的证据 */
  const stages = ref<StageStep[]>([])
  /** 推理链。**原实现把 `reasoning` 事件丢掉了**，等于把后端唯一的可解释性输出浪费掉 */
  const reasoning = ref<ReasoningStep[]>([])
  /** 轨迹：每一步在做什么、拿到什么、花了多久（后端的 trace 事件） */
  const traces = ref<TraceStep[]>([])
  /** 是否已经收到第一帧（用于"先有什么显示什么"：立刻给出可见反馈） */
  const started = ref(false)
  const thinking = ref(false)
  const degraded = ref(false)
  /** 降级原因（人话文案，来自后端 done.degraded_reason） */
  const degradedReason = ref('')
  /** 是否属于**模型降级**（而非仅自检质量低）——用于区分徽标文案 */
  const llmDegraded = ref(false)
  /**
   * C-04 时效提示（`stale_warning`）。契约：缺省不得被当作"证据新鲜"，
   * 而过龄/未知必须**显式可见**，所以原样保留后端给的 note。
   * `null` = 证据新鲜且时效全已知（唯一不用提示的情况）。
   */
  const staleWarning = ref<{ threshold_days: number; note: string } | null>(null)
  /**
   * C-04 注入筛查状态（A-04 已落地：screened=true 表示本轮做过规则筛查，检出危险时也是 true；
   * 仅无引用时为 false）。字段原样保留，不补默认值——会把"未知"伪装成"没问题"。
   */
  const injectionGuard = ref<{
    screened: boolean
    max_score?: number
    flags?: string[]
    untrusted_evidence: number
    note: string
  } | null>(null)
  const error = ref('')
  const history = ref<{ question: string; answer: string }[]>([])
  const lastCost = ref<number | null>(null)
  const meta = ref<RunMeta | null>(null)
  /** 最近一次提问，供演示页回显 */
  const question = ref('')
  /**
   * C-05 数据域（public/private）：后端 `/qa/chat` 的 `data_domain` 字段。
   * `private` 只会检索本地边界/内部数据——隔离与出网由后端 C-05/A-03 强制，
   * 前端只是**把选择如实发过去**，不做任何"保证私有"的承诺（红线：禁止静默兜底）。
   * 默认 public（与后端缺省一致）；跟随 `sessionStorage`，刷新后保留用户上一次选择。
   */
  const domain = ref<'public' | 'private'>(
    sessionStorage.getItem('qa_domain') === 'private' ? 'private' : 'public',
  )
  let abort: (() => void) | null = null

  function setDomain(d: 'public' | 'private', persist = true) {
    domain.value = d
    if (persist) sessionStorage.setItem('qa_domain', d)
  }

  function reset() {
    answer.value = ''
    citations.value = []
    stage.value = ''
    stages.value = []
    reasoning.value = []
    traces.value = []
    started.value = false
    thinking.value = true
    degraded.value = false
    degradedReason.value = ''
    llmDegraded.value = false
    staleWarning.value = null
    injectionGuard.value = null
    error.value = ''
    lastCost.value = null
    meta.value = null
  }

  function ask(q: string, dataDomain?: 'public' | 'private') {
    stop()
    reset()
    question.value = q
    const asked = q
    if (dataDomain) setDomain(dataDomain)
    abort = streamChat(
      { question: q, stream: true, data_domain: domain.value },
      (event) => {
        // 收到任何一帧就说明请求已被受理：立刻结束"纯空白等待"
        started.value = true
        switch (event.event) {
          case 'trace': {
            // 同一步的发/收两帧合并：开始帧带 input，结束帧带 ok/output
            const step = String(event.step ?? '')
            const at = Number(event.elapsed_ms ?? 0)
            const idx = traces.value.findIndex((t) => t.step === step)
            const base: TraceStep =
              idx >= 0
                ? traces.value[idx]
                : { step, tool: String(event.tool ?? ''), startedAt: at }
            const merged: TraceStep = {
              ...base,
              tool: String(event.tool ?? base.tool),
              input: (event.input as Record<string, unknown>) ?? base.input,
              startedAt: base.startedAt ?? at,
            }
            if (event.ok !== undefined || event.output !== undefined) {
              merged.ok = Boolean(event.ok)
              merged.output = event.output ? String(event.output) : merged.output
              merged.finishedAt = at
            }
            // 其余字段（新增条数 / 模型名 / 自检分数…）原样保留，便于展开查看
            const skip = new Set([
              'event',
              'step',
              'tool',
              'input',
              'ok',
              'output',
              'elapsed_ms',
            ])
            const extra: Record<string, unknown> = { ...(base.extra ?? {}) }
            for (const [k, v] of Object.entries(event)) {
              if (!skip.has(k)) extra[k] = v
            }
            if (Object.keys(extra).length) merged.extra = extra

            traces.value =
              idx >= 0
                ? traces.value.map((t, i) => (i === idx ? merged : t))
                : [...traces.value, merged]
            break
          }
          case 'stage':
            stage.value = event.stage
            stages.value = [
              ...stages.value,
              {
                stage: event.stage,
                message: event.message,
                round: event.round,
                hit: event.hit,
              },
            ]
            break
          case 'citation':
            citations.value = [...citations.value, event as unknown as Citation]
            break
          case 'reasoning':
            // 同一步可能先收到空 finding、后收到自检结论：按 step 覆盖而不是重复追加
            reasoning.value = [
              ...reasoning.value.filter((r) => r.step !== event.step),
              {
                step: Number(event.step),
                sub_question: String(event.sub_question ?? ''),
                finding: String(event.finding ?? ''),
              },
            ].sort((a, b) => a.step - b.step)
            break
          case 'token':
            answer.value += event.text ?? ''
            break
          case 'done':
            thinking.value = false
            degraded.value = Boolean(event.degraded)
            // 后端现在会给出**降级原因**（模型降级 / 自检质量低，两者可同时成立）。
            // 只显示一个"降级"徽标而不说原因，用户无法判断该不该信这个答案。
            degradedReason.value = String(event.degraded_reason ?? '')
            llmDegraded.value = Boolean(event.llm_degraded)
            // C-04：时效与注入筛查。**原样保留**（含 null），
            // 不在这里"补默认值"——那会把"未知"伪装成"没问题"。
            staleWarning.value = (event.stale_warning as typeof staleWarning.value) ?? null
            injectionGuard.value =
              (event.injection_guard as typeof injectionGuard.value) ?? null
            lastCost.value = event.cost_cny ?? null
            meta.value = {
              sessionId: event.session_id ?? null,
              elapsedMs: event.elapsed_ms ?? null,
              model: event.model ?? null,
              costCny: event.cost_cny ?? null,
              degraded: Boolean(event.degraded),
              citationCount: Number(event.citation_count ?? citations.value.length),
            }
            // done 帧里也带 reasoning（含已补全的 finding），以它为准做最终覆盖
            if (Array.isArray(event.reasoning) && event.reasoning.length) {
              reasoning.value = event.reasoning
                .map((r: Record<string, unknown>) => ({
                  step: Number(r.step),
                  sub_question: String(r.sub_question ?? ''),
                  finding: String(r.finding ?? ''),
                }))
                .sort((a: ReasoningStep, b: ReasoningStep) => a.step - b.step)
            }
            history.value = [...history.value, { question: asked, answer: answer.value }]
            break
          case 'error':
            thinking.value = false
            error.value = event.message ?? '问答失败'
            break
          default:
            break
        }
      },
      (message) => {
        // 流中断也要把状态收干净，避免界面永远停在"思考中"
        error.value = message
        thinking.value = false
      },
    )
  }

  function stop() {
    abort?.()
    abort = null
    thinking.value = false
  }

  const metrics = ref<MetricsOverview | null>(null)
  async function loadMetrics() {
    metrics.value = await getJson<MetricsOverview>('/metrics/overview')
  }

  return {
    answer,
    citations,
    stage,
    stages,
    reasoning,
    traces,
    started,
    thinking,
    degraded,
    degradedReason,
    llmDegraded,
    staleWarning,
    injectionGuard,
    error,
    history,
    lastCost,
    meta,
    question,
    domain,
    setDomain,
    metrics,
    ask,
    stop,
    loadMetrics,
    reset,
  }
})

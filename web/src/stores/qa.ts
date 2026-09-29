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

export const useQaStore = defineStore('qa', () => {
  const answer = ref('')
  const citations = ref<Citation[]>([])
  const stage = ref('')
  /** 阶段轨迹（按到达顺序累积）——"这条流水线真的走过哪些步骤"的证据 */
  const stages = ref<StageStep[]>([])
  /** 推理链。**原实现把 `reasoning` 事件丢掉了**，等于把后端唯一的可解释性输出浪费掉 */
  const reasoning = ref<ReasoningStep[]>([])
  const thinking = ref(false)
  const degraded = ref(false)
  const error = ref('')
  const history = ref<{ question: string; answer: string }[]>([])
  const lastCost = ref<number | null>(null)
  const meta = ref<RunMeta | null>(null)
  /** 最近一次提问，供演示页回显 */
  const question = ref('')
  let abort: (() => void) | null = null

  function reset() {
    answer.value = ''
    citations.value = []
    stage.value = ''
    stages.value = []
    reasoning.value = []
    thinking.value = true
    degraded.value = false
    error.value = ''
    lastCost.value = null
    meta.value = null
  }

  function ask(q: string) {
    stop()
    reset()
    question.value = q
    const asked = q
    abort = streamChat(
      { question: q, stream: true },
      (event) => {
        switch (event.event) {
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
    thinking,
    degraded,
    error,
    history,
    lastCost,
    meta,
    question,
    metrics,
    ask,
    stop,
    loadMetrics,
    reset,
  }
})

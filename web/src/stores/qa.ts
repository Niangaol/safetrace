import { defineStore } from 'pinia'
import { ref } from 'vue'

import { getJson, streamChat } from '../api'
import type { Citation, MetricsOverview } from '../types'
import { readUiEvent, readUiStatus } from '../qa-ui'
import type { UiDocument, UiStatus } from '../qa-ui'

export interface FinalReview {
  status: 'accepted' | 'rejected' | 'failed' | 'skipped'
  reason: string
}

function readFinalReview(value: unknown): FinalReview | null {
  if (!value || typeof value !== 'object') return null
  const review = value as Record<string, unknown>
  if (typeof review.status !== 'string' || !['accepted', 'rejected', 'failed', 'skipped'].includes(review.status) || typeof review.reason !== 'string') return null
  return { status: review.status as FinalReview['status'], reason: review.reason }
}

export interface QaTurn {
  id: number; question: string; answer: string; citations: Citation[]; stage: string
  stages: { stage: string; receivedAt: number }[]; thinking: boolean; completed: boolean; stopped: boolean
  degraded: boolean; abstained: boolean | null; finalReview: FinalReview | null; error: string
  answerMode: string; answerModelId: string; fallbackReason: string; llmLayers: string[]; layerFallbacks: string[]
  lastCost: number | null; ui: UiDocument | null; uiStatus: UiStatus | null; uiError: string
}

export const useQaStore = defineStore('qa', () => {
  const answer = ref('')
  const citations = ref<Citation[]>([])
  const stage = ref('')
  const thinking = ref(false)
  const degraded = ref(false)
  const completed = ref(false)
  const abstained = ref<boolean | null>(null)
  const finalReview = ref<FinalReview | null>(null)
  const requestId = ref(0)
  const answerMode = ref<'stepfun' | 'cloud' | 'local' | 'template' | 'template_fallback' | ''>('')
  const answerModelId = ref('')
  const fallbackReason = ref('')
  const llmLayers = ref<string[]>([])
  const layerFallbacks = ref<string[]>([])
  const error = ref('')
  const history = ref<{ question: string; answer: string }[]>([])
  const lastCost = ref<number | null>(null)
  const turns = ref<QaTurn[]>([])
  const stopped = ref(false)
  const stages = ref<QaTurn['stages']>([])
  const ui = ref<UiDocument | null>(null)
  const uiStatus = ref<UiStatus | null>(null)
  const uiError = ref('')
  let uiReceived = false
  let activeTurnId: number | null = null
  function syncTurn() {
    const turn = turns.value.find(turn => turn.id === activeTurnId)
    if (!turn) return
    Object.assign(turn, { answer: answer.value, citations: [...citations.value], stage: stage.value,
      stages: [...stages.value], thinking: thinking.value, completed: completed.value, stopped: stopped.value,
      degraded: degraded.value, abstained: abstained.value, finalReview: finalReview.value, error: error.value,
      answerMode: answerMode.value, answerModelId: answerModelId.value, fallbackReason: fallbackReason.value,
      llmLayers: [...llmLayers.value], layerFallbacks: [...layerFallbacks.value], lastCost: lastCost.value,
      ui: ui.value, uiStatus: uiStatus.value, uiError: uiError.value })
  }
  let abort: (() => void) | null = null

  function reset() {
    ui.value = null
    uiStatus.value = null
    uiError.value = ''
    uiReceived = false
    stopped.value = false
    stages.value = []
    answer.value = ''
    citations.value = []
    stage.value = ''
    thinking.value = true
    degraded.value = false
    completed.value = false
    abstained.value = null
    finalReview.value = null
    answerMode.value = ''
    answerModelId.value = ''
    fallbackReason.value = ''
    llmLayers.value = []
    layerFallbacks.value = []
    error.value = ''
    lastCost.value = null
  }

  function ask(question: string) {
    if (!question.trim()) return
    stop()
    reset()
    const asked = question
    const activeRequest = requestId.value
    activeTurnId = activeRequest
    turns.value.push({ id: activeRequest, question: asked } as QaTurn)
    syncTurn()
    abort = streamChat(
      { question, stream: true },
      (event) => {
        if (activeRequest !== requestId.value || completed.value || !thinking.value) return
        switch (event.event) {
          case 'stage':
            if (typeof event.stage === 'string' && event.stage.length <= 160) {
              stage.value = event.stage
              stages.value.push({ stage: event.stage, receivedAt: Date.now() })
            }
            if (['stepfun', 'cloud', 'local', 'template', 'template_fallback'].includes(event.answer_mode)) answerMode.value = event.answer_mode
            break
          case 'citation':
            citations.value = [...citations.value, event as unknown as Citation]
            break
          case 'token':
            answer.value += event.text ?? ''
            break
          case 'ui': {
            const document = readUiEvent(event)
            if (uiReceived || !document) {
              ui.value = null
              uiError.value = '自适应证据文档未通过校验，已退回完整文字回答。'
            } else if (!uiError.value) ui.value = document
            uiReceived = true
            break
          }
          case 'done':
            uiStatus.value = readUiStatus(event.ui_status)
            // 只有 accepted（模型选型）与 fallback+source=rules（服务端规则选型）保留卡片；其余一律撤回为文字回答。
            const keepUi = uiStatus.value?.status === 'accepted' || (uiStatus.value?.status === 'fallback' && ui.value?.source === 'rules')
            if (!keepUi) {
              ui.value = null
              if (uiReceived && !uiError.value && uiStatus.value?.status !== 'skipped') uiError.value = '自适应证据未获最终回执确认，已退回完整文字回答。'
            }
            completed.value = true
            abstained.value = typeof event.abstained === 'boolean' ? event.abstained : null
            finalReview.value = readFinalReview(event.final_review)
            thinking.value = false
            degraded.value = Boolean(event.degraded)
            answerMode.value = ['stepfun', 'cloud', 'local', 'template', 'template_fallback'].includes(event.answer_mode) ? event.answer_mode : 'template'
            answerModelId.value = event.answer_model_id ?? ''
            fallbackReason.value = event.fallback_reason ?? ''
            llmLayers.value = Array.isArray(event.llm_layers) ? event.llm_layers.filter((value: unknown): value is string => typeof value === 'string') : []
            layerFallbacks.value = Array.isArray(event.layer_fallbacks) ? event.layer_fallbacks.filter((value: unknown): value is string => typeof value === 'string') : []
            lastCost.value = typeof event.cost_cny === 'number' && Number.isFinite(event.cost_cny) ? event.cost_cny : null
            history.value = [...history.value, { question: asked, answer: answer.value }]
            break
          case 'error':
            thinking.value = false
            error.value = event.message ?? '问答失败'
            break
          default:
            break
        }
        syncTurn()
      },
      (message) => {
        if (activeRequest !== requestId.value || completed.value || !thinking.value) return
        error.value = message
        thinking.value = false
        syncTurn()
      },
    )
  }

  function stop() {
    if (thinking.value && activeTurnId !== null) {
      stopped.value = true
      thinking.value = false
      syncTurn()
    }
    requestId.value += 1
    abort?.()
    abort = null
    thinking.value = false
  }

  function newConversation() {
    stop()
    activeTurnId = null
    turns.value = []
    history.value = []
    reset()
    thinking.value = false
  }

  const metrics = ref<MetricsOverview | null>(null)
  async function loadMetrics() {
    metrics.value = await getJson<MetricsOverview>('/metrics/overview')
  }

  return { turns, stopped, stages, ui, uiStatus, uiError, newConversation, answer, citations, stage, thinking, degraded, completed, abstained, finalReview, requestId, answerMode, answerModelId, fallbackReason, llmLayers, layerFallbacks, error, history, lastCost, metrics, ask, stop, loadMetrics, reset }
})

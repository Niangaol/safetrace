import { defineStore } from 'pinia'
import { ref } from 'vue'

import { getJson, streamChat } from '../api'
import type { Citation, MetricsOverview } from '../types'

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
  let abort: (() => void) | null = null

  function reset() {
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
    stop()
    reset()
    const asked = question
    const activeRequest = requestId.value
    abort = streamChat(
      { question, stream: true },
      (event) => {
        if (activeRequest !== requestId.value || completed.value) return
        switch (event.event) {
          case 'stage':
            stage.value = event.stage
            if (['stepfun', 'cloud', 'local', 'template', 'template_fallback'].includes(event.answer_mode)) answerMode.value = event.answer_mode
            break
          case 'citation':
            citations.value = [...citations.value, event as unknown as Citation]
            break
          case 'token':
            answer.value += event.text ?? ''
            break
          case 'done':
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
            lastCost.value = event.cost_cny ?? null
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
        if (activeRequest !== requestId.value || completed.value) return
        error.value = message
        thinking.value = false
      },
    )
  }

  function stop() {
    requestId.value += 1
    abort?.()
    abort = null
    thinking.value = false
  }

  const metrics = ref<MetricsOverview | null>(null)
  async function loadMetrics() {
    metrics.value = await getJson<MetricsOverview>('/metrics/overview')
  }

  return { answer, citations, stage, thinking, degraded, completed, abstained, finalReview, requestId, answerMode, answerModelId, fallbackReason, llmLayers, layerFallbacks, error, history, lastCost, metrics, ask, stop, loadMetrics, reset }
})

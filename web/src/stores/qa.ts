import { defineStore } from 'pinia'
import { ref } from 'vue'

import { getJson, streamChat } from '../api'
import type { Citation, MetricsOverview } from '../types'

export const useQaStore = defineStore('qa', () => {
  const answer = ref('')
  const citations = ref<Citation[]>([])
  const stage = ref('')
  const thinking = ref(false)
  const degraded = ref(false)
  const answerMode = ref<'stepfun' | 'template' | 'template_fallback' | ''>('')
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
    abort = streamChat(
      { question, stream: true },
      (event) => {
        switch (event.event) {
          case 'stage':
            stage.value = event.stage
            if (['stepfun', 'template', 'template_fallback'].includes(event.answer_mode)) answerMode.value = event.answer_mode
            break
          case 'citation':
            citations.value = [...citations.value, event as unknown as Citation]
            break
          case 'token':
            answer.value += event.text ?? ''
            break
          case 'done':
            thinking.value = false
            degraded.value = Boolean(event.degraded)
            answerMode.value = ['stepfun', 'template', 'template_fallback'].includes(event.answer_mode) ? event.answer_mode : 'template'
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

  return { answer, citations, stage, thinking, degraded, answerMode, answerModelId, fallbackReason, llmLayers, layerFallbacks, error, history, lastCost, metrics, ask, stop, loadMetrics, reset }
})

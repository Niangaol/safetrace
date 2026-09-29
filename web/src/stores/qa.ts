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

  return { answer, citations, stage, thinking, degraded, error, history, lastCost, metrics, ask, stop, loadMetrics, reset }
})

import { ref } from 'vue'
import { mockCollectStatus, mockEvidence, mockMetrics, mockVuln, mockVulnsPage, mockQaResponse } from './mock'

const BASE = '/api/v1'
// VITE_DEMO_MODE=true 时才使用前端内置静态 mock；默认请求本地实链 API。
export const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'
export const BACKEND_DATA_MODE = ref<'fixture' | 'live' | 'unknown'>(IS_DEMO_MODE ? 'fixture' : 'unknown')
function recordDataMode(value: any) {
  if (value?.data_mode === 'fixture' || value?.data_mode === 'live') BACKEND_DATA_MODE.value = value.data_mode
}

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('api_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function unwrap<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const err = body?.detail?.error ?? body?.error
    throw new Error(err?.message ?? `${res.status} ${res.statusText}`)
  }
  const value = await res.json()
  recordDataMode(value)
  return value as T
}

export function getJson<T>(path: string, params?: Record<string, string | number | boolean | undefined>) {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== '') qs.set(k, String(v))
  }
  const url = `${BASE}${path}${qs.toString() ? `?${qs}` : ''}`

  if (IS_DEMO_MODE) {
    return mockGet<T>(path, params)
  }

  return fetch(url, { headers: authHeaders() }).then((r) => unwrap<T>(r))
}

export function postJson<T>(path: string, body: unknown) {
  if (IS_DEMO_MODE) return mockPost<T>(path, body)
  return fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  }).then((r) => unwrap<T>(r))
}

export function streamChat(
  body: unknown,
  onEvent: (event: Record<string, any>) => void,
  onError: (message: string) => void,
): () => void {
  if (IS_DEMO_MODE) {
    return mockStreamChat(body as { question?: string }, onEvent)
  }

  const controller = new AbortController()
  const token = localStorage.getItem('api_token')

  ;(async () => {
    try {
      const res = await fetch(`${BASE}/qa/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ ...(body as object), stream: true }),
        signal: controller.signal,
      })
      if (!res.ok || !res.body) throw new Error(`${res.status} ${res.statusText}`)

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let terminal = false
      const dispatch = (frame: string) => {
        const raw = frame.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n').trim()
        if (!raw || raw === 'ping') return
        let value: Record<string, any>
        try { value = JSON.parse(raw) } catch { throw new Error('后端返回了无效的 SSE 数据') }
        recordDataMode(value)
        if (value.event === 'done' || value.event === 'error') terminal = true
        onEvent(value) // callback errors must not be mistaken for ignorable JSON heartbeats
      }
      try {
        for (;;) {
          const { done, value } = await reader.read()
          buffer += done ? decoder.decode() : decoder.decode(value, { stream: true })
          buffer = buffer.replace(/\r\n/g, '\n')
          const frames = buffer.split('\n\n')
          buffer = frames.pop() ?? ''
          for (const frame of frames) dispatch(frame)
          if (done) {
            if (buffer.trim()) dispatch(buffer)
            if (!terminal) throw new Error('问答连接已结束，但后端没有发送完成状态')
            break
          }
        }
      } finally { reader.releaseLock() }
    } catch (e) {
      if ((e as Error).name !== 'AbortError') onError((e as Error).message)
    }
  })()

  return () => controller.abort()
}

// ── mock 实现 ──────────────────────────────────────

function mockGet<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (path === '/metrics/overview') resolve(mockMetrics as T)
      else if (path === '/collect/status') resolve(mockCollectStatus as T)
      else if (path.startsWith('/vulns/') && path.includes('/evidence')) resolve(mockEvidence(path.split('/')[2]) as T)
      else if (path.startsWith('/vulns/')) resolve(mockVuln(path.split('/')[2]) as T)
      else if (path === '/vulns') resolve(mockVulnsPage(params) as T)
      else resolve({} as T)
    }, 300 + Math.random() * 200)
  })
}

function mockPost<T>(path: string, body: unknown): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve({} as T), 200)
  })
}

function mockStreamChat(
  body: { question?: string },
  onEvent: (event: Record<string, any>) => void,
): () => void {
  let stopped = false
  const stages = [
    { event: 'stage', stage: 'plan', message: '正在理解问题意图…' },
    { event: 'stage', stage: 'rewrite', message: '正在改写检索式…' },
    { event: 'stage', stage: 'retrieve', round: 1, hit: 8 },
  ]
  const citations = mockQaResponse.citations
  const answer = mockQaResponse.answer
  let i = 0

  function nextStage() {
    if (stopped) return
    if (i < stages.length) {
      onEvent(stages[i])
      i++
      setTimeout(nextStage, 400)
    } else {
      onCitations()
    }
  }

  let ci = 0
  function onCitations() {
    if (stopped) return
    if (ci < citations.length) {
      onEvent({ event: 'citation', ...citations[ci] })
      ci++
      setTimeout(onCitations, 250)
    } else {
      streamAnswer()
    }
  }

  let ai = 0
  const chunkSize = 3
  function streamAnswer() {
    if (stopped) return
    if (ai < answer.length) {
      onEvent({ event: 'token', text: answer.slice(ai, ai + chunkSize) })
      ai += chunkSize
      setTimeout(streamAnswer, 30)
    } else {
      onEvent({ event: 'done', cost_cny: mockQaResponse.cost_cny, degraded: mockQaResponse.degraded })
    }
  }

  setTimeout(nextStage, 200)
  return () => { stopped = true }
}

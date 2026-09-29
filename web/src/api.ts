import { ref } from 'vue'

import {
  mockCollectStatus,
  mockEvidence,
  mockMetrics,
  mockQaResponse,
  mockVuln,
  mockVulnsPage,
} from './mock'

const BASE = '/api/v1'

/**
 * 数据来源开关（原来这里是硬编码 `const USE_MOCK = true`，导致**界面从不请求后端**）。
 *
 * 现在的规则，按优先级：
 *  1. `VITE_USE_MOCK=true` → 只用预置数据（离线演示/无后端时用）；
 *  2. `VITE_USE_MOCK=false` → 只用真实后端，失败就报错（**不静默替换成假数据**）；
 *  3. 未设置（默认）→ **先请求真实后端**；只有连不上（网络错误）或后端明确不可用
 *     （404/5xx，例如没实现该端点）时才回退到预置数据，并把来源标为 mock。
 *
 * 为什么默认要"先真后假"：离线演示需要能跑，但**静默展示假数据是红线**
 * （README:14「Mock 要说出口」）。所以回退必须伴随用户可见的标识 —— 见 `dataSource`。
 */
type MockMode = 'auto' | 'always' | 'never'

function resolveMockMode(): MockMode {
  const raw = String(import.meta.env.VITE_USE_MOCK ?? '').trim().toLowerCase()
  if (raw === 'true' || raw === '1') return 'always'
  if (raw === 'false' || raw === '0') return 'never'
  return 'auto'
}

export const MOCK_MODE: MockMode = resolveMockMode()

/** 当前数据来源。界面必须据此显示「预置数据」标识，不允许静默。 */
export const dataSource = ref<'live' | 'mock'>('live')
/** 回退到预置数据的原因（用于向用户说明为什么看到的是示例数据）。 */
export const dataSourceReason = ref('')

function markMock(reason: string) {
  if (dataSource.value !== 'mock') {
    dataSource.value = 'mock'
    dataSourceReason.value = reason
    // 演示时也留一条控制台线索，方便排查"为什么数字不动"
    console.warn(`[SafeTrace] 已回退到预置数据：${reason}`)
  }
}

function markLive() {
  dataSource.value = 'live'
  dataSourceReason.value = ''
}

/** 只有"拿不到数据"才回退；4xx 业务错误（如 401/422）应当如实报错，不能拿假数据糊过去。 */
function isBackendUnavailable(status: number): boolean {
  return status === 0 || status === 404 || status >= 500
}

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('api_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function unwrap<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const err = body?.detail?.error ?? body?.error
    const error = new Error(err?.message ?? `${res.status} ${res.statusText}`)
    ;(error as Error & { status?: number }).status = res.status
    throw error
  }
  return res.json() as Promise<T>
}

async function fetchJson<T>(path: string, url: string): Promise<T> {
  const res = await fetch(url, { headers: authHeaders() })
  return unwrap<T>(res)
}

export async function getJson<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
): Promise<T> {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v !== undefined && v !== '') qs.set(k, String(v))
  }
  const url = `${BASE}${path}${qs.toString() ? `?${qs}` : ''}`

  if (MOCK_MODE === 'always') {
    markMock('VITE_USE_MOCK=true（演示模式）')
    return mockGet<T>(path, params)
  }

  try {
    const data = await fetchJson<T>(path, url)
    markLive()
    return data
  } catch (e) {
    const status = (e as Error & { status?: number }).status ?? 0
    if (MOCK_MODE === 'auto' && isBackendUnavailable(status)) {
      markMock(
        status === 0
          ? // 说清"谁"连不上：这里指**本项目的 API 服务**（默认 127.0.0.1:8000），不是数据库。
            // 原先写"后端不可达"容易被读成"数据库挂了"（实测确实产生过误解）。
            'API 服务未启动或不可达（默认 127.0.0.1:8000）'
          : `API 未提供该数据（HTTP ${status}）`,
      )
      return mockGet<T>(path, params)
    }
    throw e
  }
}

export async function postJson<T>(path: string, body: unknown): Promise<T> {
  if (MOCK_MODE === 'always') {
    markMock('VITE_USE_MOCK=true（演示模式）')
    return mockPost<T>()
  }
  try {
    const res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify(body),
    })
    const data = await unwrap<T>(res)
    markLive()
    return data
  } catch (e) {
    const status = (e as Error & { status?: number }).status ?? 0
    if (MOCK_MODE === 'auto' && isBackendUnavailable(status)) {
      markMock(
        status === 0
          ? 'API 服务未启动或不可达（默认 127.0.0.1:8000）'
          : `API 未提供该接口（HTTP ${status}）`,
      )
      return mockPost<T>()
    }
    throw e
  }
}

export function streamChat(
  body: unknown,
  onEvent: (event: Record<string, any>) => void,
  onError: (message: string) => void,
): () => void {
  if (MOCK_MODE === 'always') {
    markMock('VITE_USE_MOCK=true（演示模式）')
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
      if (!res.ok || !res.body) {
        // 后端没实现问答端点时回退到预置回答（同样显式标注来源）
        if (MOCK_MODE === 'auto' && isBackendUnavailable(res.status)) {
          markMock(`API 未提供问答接口（HTTP ${res.status}）`)
          mockStreamChat(body as { question?: string }, onEvent)
          return
        }
        throw new Error(`${res.status} ${res.statusText}`)
      }
      markLive()

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const frames = buffer.split('\n\n')
        buffer = frames.pop() ?? ''
        for (const frame of frames) {
          // SSE 帧可能同时带 `event:` 与 `data:` 行，逐行找出 data 载荷即可
          // （原来只取整帧的第一行，遇到多行帧会丢事件）
          for (const line of frame.split('\n')) {
            const trimmed = line.trim()
            if (!trimmed.startsWith('data:')) continue
            const raw = trimmed.slice(5).trim()
            if (!raw) continue
            try {
              onEvent(JSON.parse(raw))
            } catch {
              // 非 JSON 的心跳/注释帧直接忽略
            }
          }
        }
      }
    } catch (e) {
      if ((e as Error).name === 'AbortError') return
      const status = (e as Error & { status?: number }).status ?? 0
      if (MOCK_MODE === 'auto' && status === 0) {
        markMock('API 服务不可达（问答流失败），已改用预置回答')
        mockStreamChat(body as { question?: string }, onEvent)
        return
      }
      onError((e as Error).message)
    }
  })()

  return () => controller.abort()
}

// ── 预置数据（仅在上面判定为"后端不可用"或显式演示模式时使用）────────

function mockGet<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (path === '/metrics/overview') resolve(mockMetrics as T)
      else if (path === '/collect/status') resolve(mockCollectStatus as T)
      else if (path.startsWith('/vulns/') && path.includes('/evidence'))
        resolve(mockEvidence(path.split('/')[2]) as T)
      else if (path.startsWith('/vulns/')) resolve(mockVuln(path.split('/')[2]) as T)
      else if (path === '/vulns') resolve(mockVulnsPage(params) as T)
      else resolve({} as T)
    }, 200 + Math.random() * 150)
  })
}

function mockPost<T>(): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve({} as T), 150)
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
  return () => {
    stopped = true
  }
}

import { ACTIVITY_STAGES, ACTIVITY_STATUSES } from './activity-types'
import type { ActivityStreamEvent } from './activity-types'

/** Validate wire data rather than inventing missing quality/latency fields. */
export function parseActivityEvent(value: unknown, wireEvent?: string): ActivityStreamEvent {
  if (!value || typeof value !== 'object') throw new Error('活动流数据不是对象')
  const v = value as Record<string, unknown>
  const event = v.event ?? wireEvent
  const cursor = () => Number.isSafeInteger(v.cursor) && Number(v.cursor) >= 0
  if (event === 'activity') {
    if (typeof v.id !== 'string' || !Number.isSafeInteger(v.sequence) || Number(v.sequence) <= 0
      || typeof v.trace_id !== 'string' || !(v.intel_id === null || typeof v.intel_id === 'string')
      || !ACTIVITY_STAGES.includes(v.stage as never) || !ACTIVITY_STATUSES.includes(v.status as never)
      || typeof v.at !== 'string' || typeof v.label !== 'string' || !['live', 'recorded'].includes(String(v.origin))
      || !v.details || typeof v.details !== 'object' || Array.isArray(v.details)) throw new Error('活动流 schema 无效')
    const details = v.details as Record<string, unknown>
    for (const key of ['source_id', 'source_type', 'reason']) {
      if (details[key] !== undefined && typeof details[key] !== 'string') throw new Error('活动详情字段无效')
    }
    for (const key of ['elapsed_ms', 'artifact_count']) {
      if (details[key] !== undefined && (typeof details[key] !== 'number' || !Number.isFinite(details[key]) || Number(details[key]) < 0)) throw new Error('活动详情数值无效')
    }
  } else if (event === 'hello') {
    if (v.live !== true || !cursor()) throw new Error('hello schema 无效')
  } else if (event === 'heartbeat') {
    if (typeof v.at !== 'string' || !cursor()) throw new Error('heartbeat schema 无效')
  } else if (event === 'reset') {
    if (typeof v.reason !== 'string' || !cursor()) throw new Error('reset schema 无效')
  } else if (event === 'error') {
    if (typeof v.message !== 'string') throw new Error('error schema 无效')
  } else throw new Error('未知活动流事件')
  return { ...v, event } as unknown as ActivityStreamEvent
}

/** Streaming UTF-8 decoder; CRLF may be split between any two network chunks. */
export async function consumeActivitySse(body: ReadableStream<Uint8Array>, onEvent: (event: ActivityStreamEvent) => void, signal?: AbortSignal): Promise<void> {
  const reader = body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let buffer = '', lines: string[] = []
  let frameSize = 0
  const abort = () => { void reader.cancel().catch(() => {}) }
  signal?.addEventListener('abort', abort, { once: true })
  const dispatch = () => {
    const data = lines.filter(line => line.startsWith('data:')).map(line => line.slice(5).replace(/^ /, '')).join('\n')
    const event = lines.find(line => line.startsWith('event:'))?.slice(6).trim()
    lines = []; frameSize = 0
    if (data) onEvent(parseActivityEvent(JSON.parse(data), event))
  }
  try {
    for (;;) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      const { done, value } = await reader.read()
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      buffer += done ? decoder.decode() : decoder.decode(value, { stream: true })
      for (;;) {
        const match = /\r\n|\r|\n/.exec(buffer)
        if (!match || (!done && match[0] === '\r' && match.index === buffer.length - 1)) break
        const line = buffer.slice(0, match.index)
        buffer = buffer.slice(match.index + match[0].length)
        frameSize += line.length
        if (frameSize > 262144) throw new Error('活动流帧超过安全限制')
        if (line === '') dispatch()
        else if (!line.startsWith(':')) lines.push(line)
      }
      if (buffer.length + frameSize > 262144) throw new Error('活动流帧超过安全限制')
      if (done) {
        // SSE requires a blank-line terminator; do not manufacture a truncated event.
        if (buffer.trim() || lines.length) throw new Error('活动流中断：末尾事件不完整')
        return
      }
    }
  } finally {
    signal?.removeEventListener('abort', abort)
    await reader.cancel().catch(() => {})
    reader.releaseLock()
  }
}

export async function streamActivity(options: {
  after?: number; signal: AbortSignal; onEvent: (event: ActivityStreamEvent) => void
  fetchImpl?: typeof fetch
}): Promise<void> {
  const token = typeof localStorage === 'undefined' ? null : localStorage.getItem('api_token')
  const query = options.after === undefined ? '' : '?after=' + encodeURIComponent(options.after)
  const response = await (options.fetchImpl ?? fetch)('/api/v1/activity/stream' + query, {
    method: 'GET', signal: options.signal,
    headers: { Accept: 'text/event-stream', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
  })
  if (!response.ok) throw new Error('活动流 HTTP ' + response.status)
  if (!response.body || !response.headers.get('content-type')?.includes('text/event-stream')) throw new Error('活动流未返回 SSE')
  await consumeActivitySse(response.body, options.onEvent, options.signal)
  throw new Error('活动流已断线；等待重连')
}

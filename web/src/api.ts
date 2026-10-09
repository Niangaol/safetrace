import { ref } from 'vue'
import { mockCollectStatus, mockEvidence, mockMetrics, mockVuln, mockVulnsPage, mockQaResponse, mockAssetsOverview, mockAssetsRepos, mockAssetsComponents, mockAssetsAlerts, mockAssetsScanResult, mockAssetsGroups } from './mock'

const BASE = '/api/v1'
// VITE_DEMO_MODE=true 时才使用前端内置静态 mock；默认请求本地实链 API。
export const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'
export const BACKEND_DATA_MODE = ref<'fixture' | 'live' | 'unknown'>(IS_DEMO_MODE ? 'fixture' : 'unknown')
export const BACKEND_QA_MODE = ref('unknown')
function recordDataMode(value: any) {
  if (typeof value?.qa_mode === 'string') BACKEND_QA_MODE.value = value.qa_mode
  if (typeof value?.answer_mode === 'string') BACKEND_QA_MODE.value = value.answer_mode
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

// ── 本地资产扫描（A 线） ──────────────────────────────

export interface AssetAlert {
  alert_id: string
  created_at: string
  name: string
  version: string
  repo_path: string
  group_id: string
  cve_id: string
  intel_id: string
  severity: string | null
  title: string | null
  matched_rule: string
  matched_ranges: string[]
  reason: string
  vendor_unverified: boolean
  status: 'new' | 'seen'
}

export interface AssetGroup {
  group_id: string
  name: string
  roots: string[]
  enabled: boolean
  note: string | null
  created_at: string
}

export interface AssetGroupStats extends AssetGroup {
  last_finished_at: string | null
  repo_count: number
  component_count: number
  unread_count: number
  alert_count: number
}

export interface AssetsOverview {
  scope: string
  data_mode: string
  group_id: string | null
  group_name: string | null
  last_run: {
    run_id: string
    finished_at: string
    repo_count: number
    component_count: number
    status: string
    degraded_to: string | null
    note: string | null
    roots: string[]
  } | null
  repo_count: number
  component_count: number
  alert_count: number
  unread_count: number
  by_ecosystem: Record<string, number>
  by_group: Array<{ group_id: string; group_name: string; repo_count: number; component_count: number; unread_count: number; last_finished_at: string | null }>
  alerts: AssetAlert[]
}

export interface AssetRepo {
  repo_id: string
  group_id: string
  path: string
  remote_url: string | null
  branch: string | null
  head_commit: string | null
  head_commit_at: string | null
  is_git: boolean
  git_note: string | null
  languages: string[]
  frameworks: string[]
  manifests: string[]
  component_count: number
}

export interface AssetComponent {
  ecosystem: string
  name: string
  version: string
  constraint_raw: string
  version_is_range_floor: boolean
  source_file: string
  repo_path: string
  group_id: string
}

export interface AssetsScanResult {
  scope: string
  groups: Array<{ group_id: string; run_id: string; status: string; degraded_to: string | null; note: string | null; repo_count: number; component_count: number; skipped: number; affected: number; new_alerts: number }>
  repo_count: number
  component_count: number
  new_alerts: number
  unread_count: number
}

export function getAssetsGroups() {
  return getJson<{ groups: AssetGroupStats[] }>('/assets/groups')
}

export function getAssetsOverview(groupId?: string) {
  return getJson<AssetsOverview>('/assets/overview', groupId ? { group_id: groupId } : undefined)
}

export function getAssetsRepos(groupId?: string) {
  return getJson<{ run_id: string | null; repos: AssetRepo[] }>('/assets/repos', groupId ? { group_id: groupId } : undefined)
}

export function getAssetsComponents(groupId?: string, params?: Record<string, string | number | undefined>) {
  return getJson<{ total: number; rows: AssetComponent[] }>('/assets/components', { ...(groupId ? { group_id: groupId } : {}), ...(params ?? {}) })
}

export function getAssetsAlerts(groupId?: string, status?: 'new' | 'seen') {
  return getJson<{ alerts: AssetAlert[]; unread_count: number }>('/assets/alerts', { ...(groupId ? { group_id: groupId } : {}), ...(status ? { status } : {}) })
}

export function postAssetsScan(groupId?: string) {
  return postJson<AssetsScanResult>('/assets/scan', groupId ? { group_id: groupId } : {})
}

export function postAssetsGroup(group: { group_id: string; name: string; roots: string[]; enabled?: boolean; note?: string }) {
  return postJson<{ action: 'created' | 'updated'; group: AssetGroup }>('/assets/groups', group)
}

export function postAssetsGroupDelete(groupId: string) {
  return postJson<{ deleted: string; groups: AssetGroup[] }>('/assets/groups/delete', { group_id: groupId })
}

export function postAlertsRead(options?: { ids?: string[]; group_id?: string }) {
  return postJson<{ updated: number; unread_count: number }>('/assets/alerts/read', options ?? {})
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
      else if (path === '/assets/overview') resolve((params?.group_id ? { ...mockAssetsOverview, group_id: params.group_id as string, group_name: mockAssetsGroups.groups.find((g) => g.group_id === params.group_id)?.name ?? null } : mockAssetsOverview) as T)
      else if (path === '/assets/repos') resolve((params?.group_id ? { run_id: 'run_demo', repos: mockAssetsRepos.repos.filter((r) => r.group_id === params.group_id) } : mockAssetsRepos) as T)
      else if (path === '/assets/components') resolve((params?.group_id ? { total: mockAssetsComponents.rows.filter((c) => c.group_id === params.group_id).length, rows: mockAssetsComponents.rows.filter((c) => c.group_id === params.group_id) } : mockAssetsComponents) as T)
      else if (path === '/assets/groups') resolve(mockAssetsGroups as T)
      else if (path === '/assets/alerts') resolve((params?.group_id ? { alerts: mockAssetsAlerts.filter((a) => a.group_id === params.group_id && (!params.status || a.status === params.status)), unread_count: mockAssetsAlerts.filter((a) => a.group_id === params.group_id && a.status === 'new').length } : { alerts: params?.status ? mockAssetsAlerts.filter((a) => a.status === params.status) : mockAssetsAlerts, unread_count: mockAssetsOverview.unread_count }) as T)
      else resolve({} as T)
    }, 300 + Math.random() * 200)
  })
}

function mockPost<T>(path: string, body: unknown): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (path === '/assets/scan') resolve(mockAssetsScanResult as T)
      else if (path === '/assets/groups') resolve({ action: 'created', group: mockAssetsGroups.groups[0] } as T)
      else if (path === '/assets/groups/delete') resolve({ deleted: (body as { group_id?: string })?.group_id ?? '', groups: mockAssetsGroups.groups } as T)
      else if (path === '/assets/alerts/read') resolve({ updated: 1, unread_count: 0 } as T)
      else resolve({} as T)
    }, 200)
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

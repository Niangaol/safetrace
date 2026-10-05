export const ACTIVITY_STAGES = ['collect', 'normalize', 'dedupe', 'quality', 'paper', 'score', 'knowledge', 'answer', 'review', 'fallback'] as const
export const ACTIVITY_STATUSES = ['success', 'degraded', 'failed', 'review', 'rejected', 'running'] as const
export type ActivityStage = typeof ACTIVITY_STAGES[number]
export type ActivityStatus = typeof ACTIVITY_STATUSES[number]
export interface ActivityDetails {
  source_id?: string
  source_type?: string
  elapsed_ms?: number
  artifact_count?: number
  reason?: string
}
export interface ActivityEvent {
  event: 'activity'
  id: string
  sequence: number
  trace_id: string
  intel_id: string | null
  stage: ActivityStage
  status: ActivityStatus
  at: string
  label: string
  origin: 'live' | 'recorded'
  details: ActivityDetails
}
export type ActivityStreamEvent = ActivityEvent
  | { event: 'hello'; live: true; cursor: number; db_status: unknown }
  | { event: 'heartbeat'; at: string; cursor: number }
  | { event: 'reset'; reason: string; cursor: number }
  | { event: 'error'; message: string }
export interface ActivityCard { key: string; latest: ActivityEvent; count: number; stages: Partial<Record<ActivityStage, ActivityEvent>> }

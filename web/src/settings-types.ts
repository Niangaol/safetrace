export type ModelMode = 'template' | 'cloud' | 'local'
export interface CloudSettings { base_url: string; model_id: string; key_configured: boolean }
export interface LocalSettings {
  connection: 'managed' | 'existing'
  base_url: string
  model_id: string
  selected_file_id: string | null
  context_size: number
  gpu_layers: number
}
export interface ModelRuntime {
  state: 'stopped' | 'loading' | 'ready' | 'failed' | 'external'
  managed: boolean
  model_file_id: string | null
  model_id: string | null
  pid: number | null
  error: string | null
  base_url: string | null
}
export interface ModelFile { id: string; name: string; size_bytes: number; kind: 'chat' | 'embedding' | 'unknown' }
export interface ModelSettings {
  revision: number
  active_mode: ModelMode
  cloud: CloudSettings
  local: LocalSettings
  runtime: ModelRuntime
  catalog: ModelFile[]
  csrf_token: string
  capabilities: { cloud_protocol: string; local_format: string; embedding_policy: string }
}
export interface SaveModelSettings {
  expected_revision: number
  cloud: { base_url: string; model_id: string; api_key?: string; clear_api_key?: boolean }
  local: LocalSettings
}
export interface ModelTestResult { ok: boolean; models: string[]; message: string }
export interface ApplyModelSettings { expected_revision: number; mode: ModelMode; confirm_cloud_usage?: true }
export interface LoadLocalModel { expected_revision: number; model_file_id: string; context_size: number; gpu_layers: number }

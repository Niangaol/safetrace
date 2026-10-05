import type { ApplyModelSettings, LoadLocalModel, ModelRuntime, ModelSettings, ModelTestResult, SaveModelSettings } from './settings-types'

const BASE = '/api/v1/settings/models'
export const SETTINGS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'
export class SettingsApiError extends Error {
  constructor(message: string, public readonly status: number, public readonly refreshRequired = false) { super(message) }
}
// A page owns this client; the token never leaves memory and is discarded on unmount.
export function createSettingsApi() {
  let token = ''
  let getVersion = 0
  const controllers = new Set<AbortController>()
  async function request<T>(suffix = '', method = 'GET', body?: unknown): Promise<T> {
    if (SETTINGS_DEMO_MODE) throw new SettingsApiError('静态演示模式不提供模型设置服务。', 0)
    if (method !== 'GET' && !token) throw new SettingsApiError('设置令牌缺失，请刷新设置后重试。', 403, true)
    const controller = new AbortController()
    controllers.add(controller)
    const timeout = window.setTimeout(() => controller.abort(), 15000)
    try {
      const response = await fetch(BASE + suffix, {
        method, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', 'x-safetrace-settings-token': token },
        ...(method !== 'GET' ? { body: JSON.stringify(body ?? {}) } : {}),
      })
      // Never echo arbitrary backend error bodies: they can contain submitted credentials.
      if (response.status === 409) throw new SettingsApiError('设置版本已变化（409），请刷新设置后重新检查并保存。', 409, true)
      if (response.status === 403) throw new SettingsApiError('设置安全令牌校验失败（CSRF/403），请刷新设置后重试。', 403, true)
      if ([404, 405, 501, 503].includes(response.status)) throw new SettingsApiError('模型设置服务不可用；操作已禁用，请启动支持此接口的本地后端后刷新。', response.status)
      if (!response.ok) throw new SettingsApiError('模型设置请求失败（HTTP ' + response.status + '），请检查配置和本地后端。', response.status)
      if (response.status === 204) return undefined as T
      if (!response.headers.get('content-type')?.includes('application/json')) throw new SettingsApiError('未收到模型设置 API 数据（可能是静态页面）；操作已禁用。', 404)
      return await response.json() as T
    } catch (err) {
      if (err instanceof SettingsApiError) throw err
      throw new SettingsApiError('无法连接模型设置服务或请求超时；请检查本地后端后刷新。', 0)
    } finally { window.clearTimeout(timeout); controllers.delete(controller) }
  }
  return {
    async get(): Promise<ModelSettings> {
      const version = ++getVersion
      const value = await request<ModelSettings>()
      if (!value || !Number.isInteger(value.revision) || !value.csrf_token || !value.cloud || !value.local || !value.runtime || !Array.isArray(value.catalog) || !value.capabilities) {
        token = ''
        throw new SettingsApiError('模型设置接口返回的协议不完整；操作已禁用，请检查后端。', 404)
      }
      if (version === getVersion) { token = value.csrf_token; window.dispatchEvent(new CustomEvent('safetrace-model-mode', { detail: value.active_mode })) }
      return value
    },
    save: (body: SaveModelSettings) => request<unknown>('', 'PUT', body),
    test: (target: 'cloud' | 'local') => request<ModelTestResult>('/test', 'POST', { target }),
    apply: (body: ApplyModelSettings) => request<unknown>('/apply', 'POST', body),
    load: (body: LoadLocalModel) => request<ModelRuntime>('/local/load', 'POST', body),
    stop: () => request<ModelRuntime>('/local/stop', 'POST', {}),
    dispose() { getVersion++; token = ''; for (const controller of controllers) controller.abort(); controllers.clear() },
  }
}

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { createSettingsApi, SETTINGS_DEMO_MODE, SettingsApiError } from '../settings-api'
import type { LocalSettings, ModelMode, ModelSettings, ModelTestResult } from '../settings-types'
import { applyMotionIntensity, getMotionIntensity, type MotionIntensity } from '../effects/motion-prefs'

const api = createSettingsApi()
const settings = ref<ModelSettings | null>(null)
// 动效强度只是本机装饰偏好，与模型配置无关，也不参与任何数据语义。
const motion = ref<MotionIntensity>(getMotionIntensity())
const motionHint = computed(() => motion.value === 'off' ? '关闭：粒子、光束、入场、滚动数字全部停用（系统偏好减少动效时默认关闭）' : motion.value === 'low' ? '低：保留粒子与光束，数量减半、去掉涟漪和连线' : '完整：粒子、连线、光束、雷达涟漪与全部动效')
function changeMotion(value: string) {
  if (value === 'full' || value === 'low' || value === 'off') { motion.value = applyMotionIntensity(value) }
}
const cloud = reactive({ base_url: '', model_id: '' })
const local = reactive<LocalSettings>({ connection: 'existing', base_url: 'http://127.0.0.1:8080/v1', model_id: '', selected_file_id: null, context_size: 4096, gpu_layers: 0 })
const apiKey = ref('')
const clearKey = ref(false)
const mode = ref<ModelMode>('template')
const cloudConsent = ref(false)
const busy = ref(false)
const available = ref(false)
const refreshRequired = ref(false)
const error = ref('')
const notice = ref('')
const testResult = ref<ModelTestResult | null>(null)
const testedTarget = ref('')
const baseline = ref('')
const draftRevision = ref(0)
let disposed = false
let interval: ReturnType<typeof setInterval> | undefined
let pollCount = 0
let polling = false
let operationVersion = 0
const fingerprint = () => JSON.stringify({ cloud, local })
const dirty = computed(() => !!settings.value && (fingerprint() !== baseline.value || !!apiKey.value || clearKey.value))
const blocked = computed(() => SETTINGS_DEMO_MODE || !available.value || busy.value || refreshRequired.value)
const selectedFile = computed(() => settings.value?.catalog.find(file => file.id === local.selected_file_id))
const canLoad = computed(() => !blocked.value && !dirty.value && local.connection === 'managed' && !!selectedFile.value && selectedFile.value.kind !== 'embedding' && settings.value?.runtime.state !== 'loading')
const canApply = computed(() => !blocked.value && !dirty.value && (mode.value !== 'cloud' || cloudConsent.value) && (mode.value !== 'local' || local.connection === 'existing' || (selectedFile.value?.kind !== 'embedding' && settings.value?.runtime.state === 'ready' && settings.value.runtime.model_file_id === local.selected_file_id)))
const modeLabel = (value: ModelMode) => ({ template: '离线模板', cloud: '云端模型', local: '本地模型' })[value]
const stateLabel = (value: string) => ({ stopped: '已停止', loading: '加载中', ready: '已就绪', failed: '加载失败', external: '外部服务' } as Record<string, string>)[value] ?? '未知'
const fileSize = (value: number) => value >= 1073741824 ? (value / 1073741824).toFixed(2) + ' GiB' : (value / 1048576).toFixed(1) + ' MiB'
function stopPolling() { if (interval !== undefined) clearInterval(interval); interval = undefined }
function fail(err: unknown) {
  if (disposed) return
  error.value = err instanceof Error ? err.message : '模型设置操作失败。'
  if (err instanceof SettingsApiError) {
    refreshRequired.value = err.refreshRequired
    if (err.status === 0 || [404, 405, 501, 503].includes(err.status)) available.value = false
  }
  stopPolling()
}
function accept(value: ModelSettings, replaceDraft: boolean) {
  settings.value = value
  available.value = true
  if (replaceDraft) {
    Object.assign(cloud, { base_url: value.cloud.base_url, model_id: value.cloud.model_id })
    Object.assign(local, value.local)
    apiKey.value = ''; clearKey.value = false
    baseline.value = fingerprint(); draftRevision.value = value.revision
  }
}
function startPolling() {
  if (interval !== undefined || settings.value?.runtime.state !== 'loading') return
  pollCount = 0
  interval = setInterval(async () => {
    if (polling || busy.value || disposed) return
    if (++pollCount > 60) { stopPolling(); notice.value = '加载状态轮询已达 2 分钟上限；请手动刷新查看结果。'; return }
    polling = true
    const version = operationVersion
    try {
      const value = await api.get()
      if (disposed || busy.value || version !== operationVersion) return
      accept(value, !dirty.value)
      if (value.runtime.state !== 'loading') stopPolling()
    } catch (err) { if (!busy.value && version === operationVersion) fail(err) } finally { polling = false }
  }, 2000)
}
async function refresh() {
  if (busy.value || SETTINGS_DEMO_MODE) return
  if (dirty.value && !window.confirm('刷新会丢弃未保存的模型设置和输入的 API Key，是否继续？')) return
  operationVersion++; stopPolling(); busy.value = true; error.value = ''; notice.value = ''
  try {
    const value = await api.get()
    if (disposed) return
    accept(value, true); mode.value = value.active_mode; cloudConsent.value = false
    testResult.value = null; refreshRequired.value = false; startPolling()
  } catch (err) { fail(err) } finally { busy.value = false }
}
async function run(action: () => Promise<void>) {
  if (blocked.value) return
  operationVersion++; busy.value = true; error.value = ''; notice.value = ''; testResult.value = null
  try { await action(); if (!disposed) startPolling() } catch (err) { fail(err) } finally { busy.value = false }
}
function confirmClear(event: Event) {
  const checkbox = event.target as HTMLInputElement
  clearKey.value = checkbox.checked && window.confirm('确认清除后端已保存的云端 API Key？需要点击「保存草稿」才生效。')
  checkbox.checked = clearKey.value
  if (clearKey.value) apiKey.value = ''
}
function validDraft() {
  if (!Number.isInteger(local.context_size) || local.context_size < 1 || !Number.isInteger(local.gpu_layers) || local.gpu_layers < -1) {
    error.value = '上下文长度须为正整数，GPU 层数须为 -1 或非负整数。'; return false
  }
  if (local.connection === 'managed' && selectedFile.value?.kind === 'embedding') {
    error.value = 'Embedding 模型不能用作聊天模型。'; return false
  }
  return true
}
async function save() {
  if (!validDraft()) return
  await run(async () => {
    await api.save({ expected_revision: draftRevision.value, cloud: { ...cloud, ...(apiKey.value ? { api_key: apiKey.value } : {}), ...(clearKey.value ? { clear_api_key: true } : {}) }, local: { ...local } })
    apiKey.value = ''; clearKey.value = false
    const value = await api.get()
    if (disposed) return
    accept(value, true); notice.value = '草稿已保存，当前启用模式没有改变。'
  })
}
async function test(target: 'cloud' | 'local') {
  if (dirty.value) return
  await run(async () => { const result = await api.test(target); if (!disposed) { testResult.value = result; testedTarget.value = target } })
}
async function apply() {
  if (!canApply.value || !settings.value) return
  if (mode.value === 'cloud' && !window.confirm('启用云端模型后，未来问答可能产生计费；仅允许发送公开且已验证资料。确认明确启用？')) return
  await run(async () => {
    await api.apply({ expected_revision: draftRevision.value, mode: mode.value, ...(mode.value === 'cloud' ? { confirm_cloud_usage: true as const } : {}) })
    const value = await api.get(); if (disposed) return
    accept(value, true); notice.value = '已明确应用：' + modeLabel(value.active_mode)
  })
}
async function load() {
  if (!canLoad.value || !local.selected_file_id) return
  const model_file_id = local.selected_file_id
  await run(async () => {
    const runtime = await api.load({ expected_revision: draftRevision.value, model_file_id, context_size: local.context_size, gpu_layers: local.gpu_layers })
    if (!disposed && settings.value) { settings.value.runtime = runtime; notice.value = '已请求加载本地模型；运行状态以后端回报为准。' }
  })
}
async function stop() {
  if (!settings.value?.runtime.managed || !window.confirm('确认停止 SafeTrace 管理的本地模型？正在使用它的请求可能中断。')) return
  await run(async () => {
    const runtime = await api.stop()
    if (disposed || !settings.value) return
    settings.value.runtime = runtime; stopPolling()
    const value = await api.get(); if (disposed) return
    accept(value, !dirty.value); notice.value = '停止请求已完成；请以运行状态为准。'
  })
}
onMounted(refresh)
onBeforeUnmount(() => { disposed = true; stopPolling(); apiKey.value = ''; api.dispose() })
</script>

<template>
  <div class="settings-page" :aria-busy="busy">
    <header class="page-head">
      <div><div class="eyebrow">SETTINGS · MODEL CONTROL</div><h1>模型设置</h1><p>保存草稿、测试连接、明确启用各自独立。默认离线模板，不会自动生成、下载或上传模型。</p></div>
      <button type="button" :disabled="busy || SETTINGS_DEMO_MODE" aria-label="刷新模型设置" @click="refresh">{{ busy ? '操作中…' : '刷新设置' }}</button>
    </header>
    <section v-if="SETTINGS_DEMO_MODE" class="notice warning" role="status">静态演示模式：模型设置服务未连接，所有操作禁用，不提供模拟成功结果。</section>
    <section v-if="error" class="notice danger" role="alert">{{ error }}<strong v-if="refreshRequired"> 请点击「刷新设置」获取最新版本与安全令牌。</strong></section>
    <section v-if="notice" class="notice" role="status" aria-live="polite">{{ notice }}</section>
    <div class="status-strip"><span>当前启用 <strong>{{ settings ? modeLabel(settings.active_mode) : '未连接' }}</strong></span><span>后端版本 <strong>{{ settings?.revision ?? '—' }}</strong></span><span>草稿 <strong>{{ dirty ? '未保存（测试 / 启用已禁用）' : '无未保存修改' }}</strong></span></div>
    <form @submit.prevent="save">
      <fieldset :disabled="blocked" class="config-grid">
        <section class="panel" aria-labelledby="cloud-title">
          <div class="panel-head"><h2 id="cloud-title">云端模型</h2><span>OpenAI 兼容</span></div>
          <label for="cloud-url">云端 Base URL</label><input id="cloud-url" v-model="cloud.base_url" type="url" placeholder="https://provider.example/v1" autocomplete="off" />
          <label for="cloud-model">云端模型 ID</label><input id="cloud-model" v-model="cloud.model_id" placeholder="填写供应商模型 ID" autocomplete="off" />
          <label for="cloud-key">API Key <span class="hint">{{ settings?.cloud.key_configured ? '后端已配置（不回显）' : '后端未配置' }}</span></label>
          <input id="cloud-key" v-model="apiKey" type="password" :disabled="clearKey" placeholder="留空保留旧密钥" autocomplete="new-password" spellcheck="false" aria-describedby="key-help" />
          <p id="key-help" class="help">密钥仅在当前页内存中保存，成功保存后清空；不写入浏览器存储、地址或日志。</p>
          <label class="check"><input type="checkbox" :checked="clearKey" @change="confirmClear" />清除已保存的 API Key（需确认并保存）</label>
          <button type="button" :disabled="dirty" aria-label="测试云端模型连接" @click="test('cloud')">测试云端连接</button>
        </section>
        <section class="panel" aria-labelledby="local-title">
          <div class="panel-head"><h2 id="local-title">本地模型</h2><span>GGUF · 不上传 / 不自动下载</span></div>
          <label for="local-connection">连接方式</label><select id="local-connection" v-model="local.connection"><option value="existing">连接已有本地服务</option><option value="managed">SafeTrace 管理已有 GGUF</option></select>
          <template v-if="local.connection === 'existing'">
            <label for="local-url">本地 Base URL</label><input id="local-url" v-model="local.base_url" type="url" placeholder="http://127.0.0.1:8080/v1" autocomplete="off" />
            <label for="local-model">本地模型 ID</label><input id="local-model" v-model="local.model_id" placeholder="与已有服务 /models 中的 ID 一致" autocomplete="off" />
            <p class="help">连接你已启动的兼容服务，不启动或停止外部进程。</p>
          </template>
          <template v-else>
            <label for="local-file">已有 GGUF 模型文件</label><select id="local-file" v-model="local.selected_file_id"><option :value="null">请选择已有文件</option><option v-for="file in settings?.catalog ?? []" :key="file.id" :value="file.id" :disabled="file.kind === 'embedding'">{{ file.name }} · {{ fileSize(file.size_bytes) }} · {{ file.kind === 'embedding' ? 'Embedding（不可用于聊天）' : file.kind === 'unknown' ? '类型未知，后端须校验' : '聊天' }}</option></select>
            <p v-if="!settings?.catalog.length" class="help">没有已发现的 GGUF 文件；本页不提供上传或下载。</p>
            <div class="number-grid"><div><label for="context-size">上下文长度</label><input id="context-size" v-model.number="local.context_size" type="number" min="1" step="1" /></div><div><label for="gpu-layers">GPU 层数</label><input id="gpu-layers" v-model.number="local.gpu_layers" type="number" min="-1" step="1" /></div></div>
            <p class="help">GPU 层数：0 为 CPU，-1 为全部层；实际可用资源由后端校验。</p>
            <button type="button" :disabled="!canLoad" aria-label="加载选中的本地 GGUF 模型" @click="load">加载选中模型</button>
          </template>
          <button type="button" :disabled="dirty || settings?.runtime.state === 'loading'" aria-label="测试本地模型连接" @click="test('local')">测试本地连接</button>
        </section>
      </fieldset>
      <div class="save-bar"><span>保存只更新草稿；测试仅访问 /models，不生成回答。先保存再测试 / 启用。</span><button class="primary" type="submit" :disabled="blocked || !dirty" aria-label="保存模型设置草稿">保存草稿</button></div>
    </form>
    <section v-if="testResult" class="notice" :class="{ warning: !testResult.ok }" role="status" aria-live="polite"><strong>{{ testedTarget === 'cloud' ? '云端' : '本地' }}连接测试：{{ testResult.ok ? '成功' : '失败' }}</strong><span>{{ testResult.message }}</span><span>发现模型：{{ testResult.models.length ? testResult.models.join('、') : '无' }}</span><small>连接成功不代表已经启用模型。</small></section>
    <section class="panel runtime" aria-labelledby="runtime-title"><div class="panel-head"><h2 id="runtime-title">本地运行状态</h2><span :class="{ loading: settings?.runtime.state === 'loading' }">{{ settings ? stateLabel(settings.runtime.state) : '未连接' }}</span></div><div class="runtime-grid"><span>管理方式<strong>{{ settings ? (settings.runtime.managed ? 'SafeTrace 托管' : '外部 / 未托管') : '—' }}</strong></span><span>模型<strong>{{ settings?.runtime.model_id || settings?.runtime.model_file_id || '—' }}</strong></span><span>PID<strong>{{ settings?.runtime.pid ?? '—' }}</strong></span><span>服务地址<strong>{{ settings?.runtime.base_url || '—' }}</strong></span></div><p v-if="settings?.runtime.error" class="runtime-error" role="alert">{{ settings.runtime.error }}</p><p v-if="settings?.runtime.state === 'loading'" class="help">每 2 秒读取真实后端状态，最多 60 次；轮询不会覆盖未保存草稿。</p><button type="button" class="danger-button" :disabled="blocked || !settings?.runtime.managed || settings?.runtime.state === 'stopped'" aria-label="停止 SafeTrace 托管本地模型" @click="stop">停止托管模型（需确认）</button></section>
    <section class="panel apply-panel" aria-labelledby="apply-title"><div class="panel-head"><h2 id="apply-title">明确启用</h2><span>不会随保存自动切换</span></div><label for="apply-mode">要启用的模式</label><select id="apply-mode" v-model="mode" :disabled="blocked"><option value="template">离线模板（不调用模型）</option><option value="cloud">云端模型</option><option value="local">本地模型</option></select><label v-if="mode === 'cloud'" class="check cloud-warning"><input v-model="cloudConsent" type="checkbox" :disabled="blocked" />我确认：未来云端问答可能计费，仅可发送公开且已验证资料。</label><p v-if="mode === 'local' && local.connection === 'managed'" class="help">托管模型须先保存并加载到 ready 状态，才能启用。</p><button class="primary" type="button" :disabled="!canApply" aria-label="明确启用所选模型模式" @click="apply">启用所选模式</button></section>
    <section class="panel motion-panel" aria-labelledby="motion-title"><div class="panel-head"><h2 id="motion-title">界面动效</h2><span>本机偏好 · 立即生效</span></div><label for="motion-intensity">动效强度</label><select id="motion-intensity" :value="motion" :disabled="SETTINGS_DEMO_MODE" @change="changeMotion(($event.target as HTMLSelectElement).value)"><option value="full">完整（粒子 + 连线 + 光束 + 涟漪）</option><option value="low">低（粒子 + 光束，减半）</option><option value="off">关闭（静态界面）</option></select><p class="help">{{ motionHint }}</p><p class="help">纯装饰层：不改变任何情报、富化证据或问答结果；关闭后页面内容与可访问性不受影响。系统设置为“减少动态效果”时默认关闭。</p></section>
    <footer class="capabilities"><span>云协议：{{ settings?.capabilities.cloud_protocol ?? '未读取' }}</span><span>本地格式：{{ settings?.capabilities.local_format ?? '未读取' }}</span><span>Embedding 策略：{{ settings?.capabilities.embedding_policy ?? '未读取（本页不修改向量模型）' }}</span></footer>
  </div>
</template>

<style scoped>
.settings-page{max-width:1280px;margin:auto;padding:28px;color:var(--text,#e2e8f0)}.page-head,.panel-head,.save-bar{display:flex;justify-content:space-between;align-items:center;gap:16px}.page-head{margin-bottom:24px}.eyebrow{color:var(--accent,#38bdf8);font-size:11px;letter-spacing:2px}h1{font-size:28px;margin:8px 0}h2{font-size:17px;margin:0}.page-head p,.help,.hint,.panel-head span,.save-bar span,.capabilities{color:var(--muted-light,#94a3b8)}.page-head p{margin:0}.status-strip{display:flex;flex-wrap:wrap;gap:24px;margin:20px 0;padding:16px;border:1px solid var(--border,#1e2d44);border-radius:10px;background:#0b1424}.status-strip strong{margin-left:10px;color:#7dd3fc}.config-grid{border:0;padding:0;margin:0;display:grid;grid-template-columns:1fr 1fr;gap:20px;min-width:0}.panel{padding:22px;background:var(--panel,#131c2e);border:1px solid var(--border,#1e2d44);border-radius:12px;min-width:0}.panel-head{margin-bottom:18px}.panel-head span{font-size:12px}label{display:block;margin:14px 0 7px;font-size:13px}input:not([type=checkbox]),select{width:100%;padding:10px 12px;background:#0a1221;border:1px solid #2a4060;border-radius:7px;color:#e2e8f0;min-width:0}.hint{font-size:12px;margin-left:6px}.help{font-size:12px;line-height:1.7;margin:10px 0 16px}.check{display:flex;align-items:flex-start;gap:9px;line-height:1.7;margin:16px 0}.check input{margin-top:5px;accent-color:#38bdf8}.number-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}button{border:1px solid #2a4060;border-radius:7px;background:#172b44;color:#dbeafe;padding:10px 16px;cursor:pointer;font:inherit;white-space:normal}button:hover:not(:disabled){border-color:#38bdf8}button:disabled,input:disabled,select:disabled{opacity:.45;cursor:not-allowed}.panel button+button{margin-left:8px}.primary{background:#075985;border-color:#0284c7;color:#f0f9ff}.save-bar{padding:18px 0;font-size:13px}.notice{padding:15px 18px;background:#0b2636;border:1px solid #155e75;border-radius:9px;margin-bottom:16px;overflow-wrap:anywhere}.notice span,.notice small{display:block;margin-top:6px}.warning{background:#2c2413;border-color:#7c5a20;color:#fde68a}.danger{background:#301622;border-color:#7f2941;color:#fda4af}.runtime,.apply-panel{margin-top:18px}.runtime-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}.runtime-grid span{color:#94a3b8;font-size:12px}.runtime-grid strong{display:block;margin-top:6px;color:#e2e8f0;overflow-wrap:anywhere;font-size:13px}.runtime-error{color:#fda4af;overflow-wrap:anywhere}.runtime button{margin-top:18px}.danger-button{border-color:#7f2941;background:#301622;color:#fda4af}.loading{color:#fbbf24!important}.apply-panel select{max-width:360px;margin-bottom:16px}.apply-panel>button{display:block}.cloud-warning{color:#fde68a}.motion-panel{margin-top:18px}.motion-panel select{max-width:360px}.capabilities{display:flex;flex-wrap:wrap;gap:20px;padding:20px 0;font-size:12px;overflow-wrap:anywhere}input:focus-visible,select:focus-visible,button:focus-visible{outline:2px solid #38bdf8;outline-offset:3px}@media(max-width:850px){.config-grid{grid-template-columns:1fr}.runtime-grid{grid-template-columns:1fr 1fr}.page-head,.save-bar{align-items:flex-start;flex-direction:column}.settings-page{padding:18px}}@media(max-width:480px){.runtime-grid,.number-grid{grid-template-columns:1fr}.panel-head{align-items:flex-start;flex-direction:column}}
</style>

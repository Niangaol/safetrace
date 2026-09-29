<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { getJson, postJson, putJson } from '../api'

/** 单个配置项（后端 /config 的字段视图） */
interface FieldView {
  value?: unknown
  env_var?: string
  editable?: boolean
  requires_restart?: boolean
  restart_reason?: string
  secret?: boolean
  configured?: boolean
  preview?: string
  driver?: string
  host?: string | null
  database?: string | null
}

interface ConfigResponse {
  llm: Record<string, FieldView>
  cost: Record<string, FieldView>
  runtime: Record<string, FieldView>
  env_file: string
  env_file_exists: boolean
  note: string
}

const cfg = ref<ConfigResponse | null>(null)
const error = ref('')
const loading = ref(true)
const saving = ref(false)
const savedMsg = ref('')
const testing = ref(false)
const testResult = ref<Record<string, unknown> | null>(null)

/** 表单：只放可编辑字段。密钥留空表示"不改动"。 */
const form = ref({
  llm_provider: '',
  llm_flash_model: '',
  llm_pro_model: '',
  llm_base_url: '',
  llm_local_enabled: false,
  llm_local_base_url: '',
  llm_local_model: '',
  llm_thinking_deep: false,
  llm_cache_enabled: true,
  cost_daily_budget_cny: 20,
  cost_warn_ratio: 0.8,
  demo_mode: false,
})
/** 密钥单独放：留空 = 不改；填了就覆盖 */
const apiKeyInput = ref('')

const LABELS: Record<string, string> = {
  llm_provider: '提供方',
  llm_flash_model: 'Flash 档模型',
  llm_pro_model: 'Pro 档模型',
  llm_base_url: 'API Base URL',
  llm_local_enabled: '启用本地兜底（Ollama）',
  llm_local_base_url: '本地 Base URL',
  llm_local_model: '本地模型',
  llm_thinking_deep: '思考模式（抽取/分类类任务建议关闭：思维 token 按输出计费）',
  llm_cache_enabled: '启用前缀缓存',
  cost_daily_budget_cny: '每日预算（元）',
  cost_warn_ratio: '告警阈值（占比）',
  demo_mode: 'DEMO_MODE（无凭据时用占位回答）',
}

const EDITABLE_LLM = [
  'llm_provider',
  'llm_flash_model',
  'llm_pro_model',
  'llm_base_url',
  'llm_local_enabled',
  'llm_local_base_url',
  'llm_local_model',
  'llm_thinking_deep',
  'llm_cache_enabled',
] as const

/** 是否为复选框字段（显式列布尔字段，避免对 form 做动态索引而丢类型） */
const BOOLEAN_FIELDS = new Set(['llm_local_enabled', 'llm_thinking_deep', 'llm_cache_enabled', 'demo_mode'])
function isBool(name: string): boolean {
  return BOOLEAN_FIELDS.has(name)
}

const keyField = computed(() => cfg.value?.llm.llm_api_key)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await getJson<ConfigResponse>('/config')
    cfg.value = data
    form.value = {
      llm_provider: String(data.llm.llm_provider?.value ?? ''),
      llm_flash_model: String(data.llm.llm_flash_model?.value ?? ''),
      llm_pro_model: String(data.llm.llm_pro_model?.value ?? ''),
      llm_base_url: String(data.llm.llm_base_url?.value ?? ''),
      llm_local_enabled: Boolean(data.llm.llm_local_enabled?.value),
      llm_local_base_url: String(data.llm.llm_local_base_url?.value ?? ''),
      llm_local_model: String(data.llm.llm_local_model?.value ?? ''),
      llm_thinking_deep: Boolean(data.llm.llm_thinking_deep?.value),
      llm_cache_enabled: Boolean(data.llm.llm_cache_enabled?.value),
      cost_daily_budget_cny: Number(data.cost.cost_daily_budget_cny?.value ?? 20),
      cost_warn_ratio: Number(data.cost.cost_warn_ratio?.value ?? 0.8),
      demo_mode: Boolean(data.runtime.demo_mode?.value),
    }
    apiKeyInput.value = ''
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  savedMsg.value = ''
  error.value = ''
  try {
    const payload: Record<string, unknown> = { ...form.value }
    // 密钥：只有用户真填了才提交，避免"空串把已配置的密钥清掉"
    if (apiKeyInput.value.trim()) payload.llm_api_key = apiKeyInput.value.trim()
    const res = await putJson<{ updated: string[]; note: string }>('/config', payload)
    savedMsg.value = `已保存并生效：${res.updated.join(', ')}`
    await load()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    saving.value = false
  }
}

async function clearKey() {
  if (!confirm('确定要清空 LLM_API_KEY 吗？清空后会走 DEMO_MODE 占位或本地兜底。')) return
  saving.value = true
  try {
    await putJson('/config', { llm_api_key: '' })
    savedMsg.value = '已清空 LLM_API_KEY'
    await load()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    saving.value = false
  }
}

async function testConnection() {
  testing.value = true
  testResult.value = null
  try {
    testResult.value = await postJson<Record<string, unknown>>('/config/test-llm', {})
  } catch (e) {
    testResult.value = { ok: false, reason: (e as Error).message }
  } finally {
    testing.value = false
  }
}

onMounted(load)
</script>

<template>
  <h1 class="page-title">配置管理</h1>
  <p class="page-subtitle">
    修改后写入 <code>.env</code> 并立即生效（无需重启）——实现方式是把改动写进 .env 后清除
    <code>get_settings</code> 的缓存。
  </p>

  <div v-if="loading" class="muted" style="padding: 24px"><span class="spinner"></span> 加载中…</div>
  <p v-else-if="error" class="notice error" style="margin-bottom: 12px">{{ error }}</p>

  <template v-if="cfg">
    <!-- 生效位置提示 -->
    <div class="notice info" style="margin-bottom: 14px">
      配置文件：<code>{{ cfg.env_file }}</code>
      <span v-if="!cfg.env_file_exists" class="bad">（不存在，保存时会创建）</span>
      <div class="muted" style="margin-top: 4px; font-size: 11px">{{ cfg.note }}</div>
    </div>

    <!-- LLM -->
    <div class="panel fade-in" style="margin-bottom: 14px">
      <div class="panel-header">
        <h3>LLM 路由</h3>
        <button class="secondary" style="font-size: 12px" :disabled="testing" @click="testConnection">
          <span v-if="testing" class="spinner" style="margin-right: 6px"></span>
          {{ testing ? '测试中…' : '测试连接' }}
        </button>
      </div>

      <!-- 连接测试结果 -->
      <div v-if="testResult" class="notice" :class="testResult.ok ? 'ok' : 'error'" style="margin-bottom: 12px">
        <template v-if="testResult.ok">
          <strong>连接成功</strong>：模型 <code>{{ testResult.model }}</code> 回复
          「{{ testResult.reply }}」，耗时 {{ testResult.elapsed_ms }}ms，
          本次花费 ¥{{ Number(testResult.cost_cny ?? 0).toFixed(6) }}
          <span class="muted">（思维 token {{ testResult.reasoning_tokens }}）</span>
        </template>
        <template v-else>
          <strong>连接失败</strong>：{{ testResult.reason }}
        </template>
      </div>

      <!-- 密钥 -->
      <div class="cfg-row">
        <label>LLM_API_KEY</label>
        <div class="cfg-ctrl">
          <input
            v-model="apiKeyInput"
            type="password"
            :placeholder="keyField?.configured ? `已配置（${keyField.preview}），留空则不修改` : '未配置，请输入'"
            autocomplete="off"
          />
          <span class="badge" :class="keyField?.configured ? 'low' : 'critical'">
            {{ keyField?.configured ? '已配置' : '未配置' }}
          </span>
          <button v-if="keyField?.configured" class="secondary" style="font-size: 11px" @click="clearKey">
            清空
          </button>
        </div>
        <p class="cfg-hint">
          密钥<strong>永不回传明文</strong>，这里只显示脱敏预览；留空保存不会改动它。
        </p>
      </div>

      <div v-for="name in EDITABLE_LLM" :key="name" class="cfg-row">
        <label :for="`cfg-${name}`">{{ LABELS[name] ?? name }}</label>
        <div class="cfg-ctrl">
          <input
            v-if="isBool(name)"
            :id="`cfg-${name}`"
            v-model="form[name]"
            type="checkbox"
            style="width: auto"
          />
          <input
            v-else
            :id="`cfg-${name}`"
            v-model="form[name]"
            type="text"
          />
        </div>
        <p class="cfg-hint">
          <code>{{ cfg.llm[name]?.env_var }}</code>
          <span v-if="cfg.llm[name]?.requires_restart" class="bad"> · 需要重启才生效</span>
        </p>
      </div>
    </div>

    <!-- 成本 -->
    <div class="panel fade-in" style="margin-bottom: 14px">
      <div class="panel-header"><h3>成本闸门</h3></div>

      <div class="cfg-row">
        <label for="cfg-cost_daily_budget_cny">{{ LABELS.cost_daily_budget_cny }}</label>
        <div class="cfg-ctrl">
          <input
            id="cfg-cost_daily_budget_cny"
            v-model="form.cost_daily_budget_cny"
            type="number"
            step="0.5"
            min="0.5"
          />
        </div>
        <p class="cfg-hint"><code>{{ cfg.cost.cost_daily_budget_cny?.env_var }}</code></p>
      </div>

      <div class="cfg-row">
        <label for="cfg-cost_warn_ratio">{{ LABELS.cost_warn_ratio }}</label>
        <div class="cfg-ctrl">
          <input
            id="cfg-cost_warn_ratio"
            v-model="form.cost_warn_ratio"
            type="number"
            step="0.05"
            min="0.05"
            max="1"
          />
        </div>
        <p class="cfg-hint"><code>{{ cfg.cost.cost_warn_ratio?.env_var }}</code></p>
      </div>

      <div class="cfg-row">
        <label for="cfg-demo_mode">{{ LABELS.demo_mode }}</label>
        <div class="cfg-ctrl">
          <input id="cfg-demo_mode" v-model="form.demo_mode" type="checkbox" style="width: auto" />
        </div>
        <p class="cfg-hint">
          <code>{{ cfg.runtime.demo_mode?.env_var }}</code> ·
          开启后无凭据时返回占位回答（页面上会标注「演示模式」）
        </p>
      </div>

      <p class="cfg-hint">
        成本流水落盘在 <code>{{ cfg.cost.cost_tracker_path?.value }}</code>。
      </p>
    </div>

    <!-- 只读 / 需重启 -->
    <div class="panel fade-in" style="margin-bottom: 14px">
      <div class="panel-header">
        <h3>基础设施（只读）</h3>
        <span class="badge-count">改了要重启，所以不放在可编辑区</span>
      </div>
      <div v-for="name in ['postgres_dsn', 'redis_url']" :key="name" class="cfg-row">
        <label>{{ name === 'postgres_dsn' ? 'POSTGRES_DSN' : 'REDIS_URL' }}</label>
        <div class="cfg-ctrl">
          <input :value="String(cfg.runtime[name]?.value ?? '')" disabled />
          <span class="badge medium">需重启</span>
        </div>
        <p class="cfg-hint bad">{{ cfg.runtime[name]?.restart_reason }}</p>
      </div>
    </div>

    <!-- 保存 -->
    <div class="toolbar">
      <button :disabled="saving" @click="save">
        <span v-if="saving" class="spinner" style="margin-right: 6px"></span>
        {{ saving ? '保存中…' : '保存并生效' }}
      </button>
      <button class="secondary" :disabled="saving" @click="load">重新加载</button>
      <span v-if="savedMsg" class="badge low">{{ savedMsg }}</span>
    </div>
  </template>
</template>

<style scoped>
.cfg-row {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
}
.cfg-row:last-child { border-bottom: none; }
.cfg-row > label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
}
.cfg-ctrl {
  display: flex;
  align-items: center;
  gap: 8px;
}
.cfg-ctrl input[type='text'],
.cfg-ctrl input[type='password'],
.cfg-ctrl input[type='number'] {
  flex: 1;
  min-width: 0;
  max-width: 520px;
}
.cfg-ctrl input:disabled {
  opacity: 0.65;
  cursor: not-allowed;
}
.cfg-hint {
  margin: 0;
  font-size: 11px;
  color: var(--muted);
}
.cfg-hint code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
}
.cfg-hint .bad, .bad { color: var(--critical); }

.notice {
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  line-height: 1.6;
}
.notice.info {
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.25);
}
.notice.ok {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
}
.notice.error {
  background: rgba(244, 63, 94, 0.1);
  border: 1px solid rgba(244, 63, 94, 0.3);
  color: var(--critical);
}
.notice code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
}
</style>

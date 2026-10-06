<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref, shallowRef } from 'vue'
import { IS_DEMO_MODE } from '../api'
import { streamActivity } from '../activity-api'
import ParcelPipeline from './ParcelPipeline.vue'
import { ACTIVITY_STAGES, ACTIVITY_STATUSES } from '../activity-types'
import type { ActivityCard, ActivityEvent, ActivityStage, ActivityStreamEvent } from '../activity-types'

const stageNames: Record<ActivityStage, string> = { collect: '来源接收', normalize: '规范整理', dedupe: '去重分流', quality: '质量盖章', paper: '论文关联', score: '证据评分', knowledge: '结果 / 索引发布', answer: '问答出站', review: '人工复核', fallback: '降级旁路' }
const rules: Record<ActivityStage, string> = {
 collect: 'source_id / source_type 标识来源；intel_id=null 为来源批次，不代表已产生情报。',
 normalize: 'trace_id 追踪同一处理链；intel_id 绑定具体情报。仅展示后端真实规范化状态。',
 dedupe: 'stage=dedupe 表示去重工位；status 与 reason 决定处理结果，不推断新增数量。',
 quality: 'success=通过本阶段，review=待复核，rejected=拒收；degraded/failed 不盖通过章。不是整条情报最终质量。',
 paper: 'artifact_count 为后端报告的产物数；缺失时不补造论文或证据。',
 score: '仅显示真实 status / reason；协议不含分数，不虚构评分。',
 knowledge: '知识投影结果以 status 为准；success 不等于所有前序阶段成功。',
 answer: '真实 QA 活动共享 sequence 与 trace_id；elapsed_ms 只表示后端报告的本阶段耗时。',
 review: '人工复核分支为只读展示；本工作台不提交审批、不触发 mutation。',
 fallback: '降级旁路不是成功捷径；展示 reason，保留失败与拒收印章。',
}
const statusNames = { success: '本阶段通过', degraded: '降级', failed: '失败', review: '待复核', rejected: '拒收', running: '处理中' }
const connection = ref<'waiting' | 'connected' | 'disconnected'>('waiting')
const error = ref(''), gap = ref(''), heartbeat = ref(''), dbStatus = ref('未握手')
const paused = ref(false), pending = ref(0), total = ref(0), live = ref(0), recorded = ref(0), trimmed = ref(0), archivedGroups = ref(0)
const statusCounts = ref(Object.fromEntries(ACTIVITY_STATUSES.map(s => [s, 0])) as Record<ActivityEvent['status'], number>)
const cards = shallowRef<ActivityCard[]>([]), history = shallowRef<ActivityEvent[]>([])
const groups = new Map<string, ActivityCard>()
let retained: ActivityEvent[] = [], attempts = 0, stopped = false
const lastSequence = ref<number | undefined>(), reconnects = ref(0)
// 实时事件一次性反馈：仅当真实 SSE 事件 origin==='live' 时点亮，键含卡片 key 与 sequence，
// 两秒后自动熄灭（刚够一次光束 / 涟漪周期）。不用定时器伪造事件，也不做循环动画冒充实时。
const liveFlash = shallowRef<Record<string, number>>({})
const flashTimers = new Set<ReturnType<typeof setTimeout>>()
function flashOnce(key: string, sequence: number) {
  liveFlash.value = { ...liveFlash.value, [key]: sequence }
  let handle: ReturnType<typeof setTimeout> | undefined
  handle = setTimeout(() => {
    if (handle !== undefined) flashTimers.delete(handle)
    const current = liveFlash.value
    if (current[key] === sequence) {
      const next = { ...current }
      delete next[key]
      liveFlash.value = next
    }
  }, 2000)
  flashTimers.add(handle)
}
let controller: AbortController | undefined, retry: ReturnType<typeof setTimeout> | undefined
let renderFrame: number | undefined

const title = computed(() => IS_DEMO_MODE ? '历史 / 示例工作台' : connection.value === 'waiting' ? '等待连接 · 情报工作台' : connection.value === 'disconnected' ? '断线 · 情报工作台' : live.value === 0 && recorded.value > 0 ? '已连接 · 历史回放' : '已连接 · 实时情报工作台')
function publish() {
 cards.value = [...groups.values()].reverse()
 history.value = [...retained].reverse()

}
function schedulePublish() {
 if (renderFrame !== undefined) return
 renderFrame = requestAnimationFrame(() => { renderFrame = undefined; if (!paused.value && !stopped) publish() })
}
function receive(event: ActivityStreamEvent) {
 if (event.event === 'hello') { connection.value = 'connected'; dbStatus.value = JSON.stringify(event.db_status) ?? '未报告'; attempts = 0; error.value = ''; return }
 if (event.event === 'heartbeat') { heartbeat.value = event.at; return }
 if (event.event === 'reset') { gap.value = '流重置 / 数据缺口：' + event.reason + '（服务端游标 ' + event.cursor + '）'; lastSequence.value = undefined; trimmed.value += retained.length; archivedGroups.value += groups.size; groups.clear(); retained = []; if (!paused.value) schedulePublish(); return }
 if (event.event === 'error') throw new Error(event.message)
 if (lastSequence.value !== undefined && event.sequence <= lastSequence.value!) return
 if (lastSequence.value !== undefined && event.sequence > lastSequence.value! + 1) gap.value = '序列缺口：#' + (lastSequence.value! + 1) + '–#' + (event.sequence - 1) + ' 未收到；不推断其处理结果。'
 lastSequence.value = event.sequence
 total.value++; statusCounts.value[event.status]++
 if (event.origin === 'live') live.value++; else recorded.value++
 retained.push(event)
 if (retained.length > 500) { retained.shift(); trimmed.value++ }
 const key = JSON.stringify([event.trace_id, event.intel_id])
 const old = groups.get(key)
 groups.delete(key)
 groups.set(key, { key, latest: event, count: (old?.count ?? 0) + 1, stages: { ...old?.stages, [event.stage]: event } })
 if (groups.size > 500) { const first = groups.keys().next().value; if (first !== undefined) groups.delete(first); archivedGroups.value++ }
 if (event.origin === 'live') { flashOnce('card:' + key, event.sequence); flashOnce('stage:' + event.stage, event.sequence) }
 if (paused.value) pending.value++; else schedulePublish()
}
function togglePause() { paused.value = !paused.value; if (!paused.value) { pending.value = 0; publish() } }
async function connect() {
 if (stopped || IS_DEMO_MODE) return
 const current = new AbortController()
 controller = current
 connection.value = attempts ? 'disconnected' : 'waiting'
 try { await streamActivity({ after: lastSequence.value, signal: current.signal, onEvent: receive }) }
 catch (cause) {
  if (stopped || current.signal.aborted) return
  connection.value = 'disconnected'; error.value = cause instanceof Error ? cause.message : String(cause)
  attempts++; reconnects.value++
  retry = setTimeout(() => { retry = undefined; void connect() }, Math.min(30000, 1000 * 2 ** Math.min(attempts, 5)))
 }
}
function reconnect() { if (retry) clearTimeout(retry); controller?.abort(); attempts++; reconnects.value++; void connect() }
function detail(event: ActivityEvent) { return JSON.stringify(event, null, 2) }
onMounted(() => {
 if (IS_DEMO_MODE) {
  const base = { event: 'activity' as const, trace_id: 'example-trace', intel_id: 'EXAMPLE-ONLY', at: '2026-01-01T00:00:00Z', origin: 'recorded' as const }
  receive({ ...base, id: 'example-1', sequence: 1, stage: 'quality', status: 'review', label: '示例：证据不足，转人工复核', details: { reason: '仅用于展示卡片，不是真实运行记录' } })
  receive({ ...base, id: 'example-2', sequence: 2, stage: 'review', status: 'review', label: '示例：等待人工复核', details: {} })
 } else void connect()
})
onBeforeUnmount(() => { stopped = true; controller?.abort(); if (retry) clearTimeout(retry); if (renderFrame !== undefined) cancelAnimationFrame(renderFrame); for (const handle of flashTimers) clearTimeout(handle); flashTimers.clear() })
</script>

<template>
 <section class="activity-board" aria-label="实时情报工作台">
  <header class="board-header">
   <div><p class="eyebrow">SAFETRACE / INTELLIGENCE OPERATIONS</p><h2>{{ title }}</h2><p class="subtitle">只读传送工位 · 每枚印章都有真实事件依据</p></div>
   <div class="controls"><span class="connection" :class="connection" role="status">{{ IS_DEMO_MODE ? '示例 · 无真实请求' : connection === 'connected' ? 'SSE 已连接' : connection === 'waiting' ? '等待后端 hello' : '断线 · 自动重连' }}</span><button type="button" :aria-pressed="paused" aria-label="暂停或恢复工作台渲染" @click="togglePause">{{ paused ? '恢复渲染' : '暂停渲染' }}</button><button v-if="!IS_DEMO_MODE" type="button" aria-label="重新连接活动流" @click="reconnect">重新连接</button></div>
  </header>
  <p v-if="IS_DEMO_MODE" class="notice">历史 / 示例模式：以下卡片为静态示例，不连接真实活动接口，不代表实时成功。</p>
  <p v-if="error" class="notice warning" role="status">{{ error }} · 重连使用最后收到的 sequence：{{ lastSequence ?? '无' }}；断线期间事件完整性未确认。</p>
  <p v-if="reconnects && connection === 'connected'" class="notice" role="status">已重连 {{ reconnects }} 次 · 从已收序列续传；如有缺口会单独告警，历史与实时来源按后端 origin 标记。</p>
  <p v-if="gap" class="notice warning" role="status">{{ gap }}</p>
  <p v-if="paused" class="notice" role="status">仅暂停卡片与历史渲染，流仍持续接收：新增 {{ pending }} 条；恢复后按真实事件聚合（详细历史最多 500 条）。</p>
  <div class="telemetry" aria-label="活动累计计数"><span>已接收 <strong>{{ total }}</strong></span><span>实时 <strong>{{ live }}</strong></span><span>历史 <strong>{{ recorded }}</strong></span><span v-for="status in ACTIVITY_STATUSES" :key="status">{{ statusNames[status] }} <strong>{{ statusCounts[status] }}</strong></span></div>
  <!-- 工位光束：仅当收到该 stage 的真实 origin==='live' 事件时点亮一次（脚本 liveFlash 驱动），历史回放不点亮 -->
  <details class="architecture-help"><summary>各阶段协议与规则说明</summary><div class="station-track" aria-label="处理工位与规则说明">
   <details v-for="(stage, index) in ACTIVITY_STAGES" :key="stage" class="station" :class="{ 'fx-beam': liveFlash['stage:' + stage] !== undefined }"><summary :aria-label="stageNames[stage] + '工位帮助'"><span class="station-index">{{ String(index + 1).padStart(2, '0') }}</span>{{ stageNames[stage] }}<span class="help-sign">?</span></summary><p>{{ rules[stage] }}</p><code>stage: {{ stage }}</code></details>
  </div>
  </details>
  <ParcelPipeline :events="history" :paused="paused" />
  <footer class="board-footer"><span>详细历史 {{ history.length }}/500 · 已压缩 {{ trimmed }} 条旧详情，累计计数保留；{{ archivedGroups }} 次旧聚合移出托盘。</span><span>心跳 {{ heartbeat || '尚未收到' }} · DB {{ dbStatus }}</span><span>装饰层：环境粒子与光束，强度可在设置页调整；不传达任何情报语义</span></footer>
  <details class="history"><summary aria-label="展开活动详细历史">活动登记簿 · 最近 {{ history.length }} 条真实记录</summary><ol><li v-for="event in history" :key="event.id + ':' + event.sequence"><details><summary>#{{ event.sequence }} · {{ event.origin === 'live' ? '实时' : '历史 / 示例' }} · {{ stageNames[event.stage] }} · {{ statusNames[event.status] }} · {{ event.label }}</summary><pre>{{ detail(event) }}</pre></details></li></ol></details>
 </section>
</template>

<style scoped>
.activity-board{background:#111e30;color:#e0eaf7;border:1px solid #405572;border-radius:16px;padding:26px;box-shadow:0 18px 40px #09122135;min-width:0}.board-header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.eyebrow{letter-spacing:.18em;font-size:10px;color:#9fb8d5;margin:0 0 8px}.board-header h2{font-size:23px;font-weight:650;margin:0}.subtitle{font-size:12px;color:#91a7bf;margin:9px 0 0}.controls{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;align-items:center}.activity-board button{background:#253b53;color:#e6edf7;border:1px solid #526981;border-radius:6px;padding:7px 11px;cursor:pointer;font:inherit;font-size:12px}.activity-board :focus-visible{outline:3px solid #e2b969;outline-offset:3px}.connection{font-size:11px;color:#b2c4d9}.connection.connected{color:#8fdbbd}.connection.disconnected{color:#ffbf97}.notice{padding:11px 14px;border:1px solid #507597;background:#1e3851;border-radius:7px;font-size:12px;line-height:1.7}.notice.warning{border-color:#ac784c;background:#3a302a;color:#ffdbb0}.telemetry{display:flex;flex-wrap:wrap;gap:10px 22px;padding:18px 0;font-size:11px;color:#91a7bf}.telemetry strong{font-size:17px;color:#e7edf6;margin-left:6px;font-variant-numeric:tabular-nums}.architecture-help{font-size:12px;color:#91a7bf}.architecture-help>summary{cursor:pointer}.station-track{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:9px;padding:15px 0}.station{border:1px solid #3a5169;border-radius:7px;background:#21364b;min-width:0}.station summary{padding:10px 8px;font-size:12px;cursor:pointer;display:flex;align-items:center;gap:7px}.station-index{font:10px monospace;color:#d4b36e}.help-sign{margin-left:auto}.station p,.station code{display:block;padding:0 10px;font-size:11px;line-height:1.7}.board-footer{display:flex;flex-wrap:wrap;gap:12px;margin-top:20px;font-size:10px;color:#829ab1}.history{margin-top:16px;border-top:1px solid #31475f;padding-top:12px;font-size:12px}.history summary{cursor:pointer;overflow-wrap:anywhere}.history ol{max-height:320px;overflow:auto;padding-left:20px}.history pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#aec3d7;font-size:11px}@media(max-width:700px){.activity-board{padding:16px}.board-header{flex-direction:column}.controls{justify-content:flex-start}.station-track{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>

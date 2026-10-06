<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref, shallowRef } from 'vue'
import { IS_DEMO_MODE } from '../api'
import { streamActivity } from '../activity-api'
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
// 卡片当前最新事件就是那条 live 事件（origin 与 sequence 双重校验）才反馈，历史回放不点亮。
function liveFlashing(card: ActivityCard): boolean {
  return card.latest.origin === 'live' && liveFlash.value['card:' + card.key] === card.latest.sequence
}
let controller: AbortController | undefined, retry: ReturnType<typeof setTimeout> | undefined
let renderFrame: number | undefined
const expanded = ref<string | null>(null), page = ref(0)
const visibleCards = computed(() => cards.value.slice(page.value * 8, page.value * 8 + 8))
const pageCount = computed(() => Math.max(1, Math.ceil(cards.value.length / 8)))
const title = computed(() => IS_DEMO_MODE ? '历史 / 示例工作台' : connection.value === 'waiting' ? '等待连接 · 情报工作台' : connection.value === 'disconnected' ? '断线 · 情报工作台' : live.value === 0 && recorded.value > 0 ? '已连接 · 历史回放' : '已连接 · 实时情报工作台')
function publish() {
 cards.value = [...groups.values()].reverse()
 history.value = [...retained].reverse()
 page.value = Math.min(page.value, Math.max(0, Math.ceil(cards.value.length / 8) - 1))
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
  <div class="station-track" aria-label="处理工位与规则说明">
   <details v-for="(stage, index) in ACTIVITY_STAGES" :key="stage" class="station" :class="{ 'fx-beam': liveFlash['stage:' + stage] !== undefined }"><summary :aria-label="stageNames[stage] + '工位帮助'"><span class="station-index">{{ String(index + 1).padStart(2, '0') }}</span>{{ stageNames[stage] }}<span class="help-sign">?</span></summary><p>{{ rules[stage] }}</p><code>stage: {{ stage }}</code></details>
  </div>
  <div class="tray-header"><h3>情报传送托盘 <small>{{ cards.length }} 个保留聚合</small></h3><span>一次最多 8 卡 · 按 trace + intel 聚合</span></div>
  <div v-if="!cards.length" class="empty-tray" aria-label="等待真实活动"><div class="empty-symbol">▤</div><h3>等待真实活动落纸</h3><p>尚无事件。不生成模拟数据包、不推断成功。</p></div>
  <div v-else class="paper-tray">
   <article v-for="card in visibleCards" :key="card.key + ':' + card.latest.sequence" class="intel-paper" :class="card.latest.status" :aria-label="(card.latest.intel_id ?? '来源批次') + '情报卡'">
    <div class="paper-meta"><span>{{ card.latest.origin === 'live' ? '实时新增' : IS_DEMO_MODE ? '静态示例' : '历史回放' }}</span><span>#{{ card.latest.sequence }}</span></div>
    <h4>{{ card.latest.intel_id ?? '来源批次 · 未绑定情报' }}</h4><p class="paper-label">{{ card.latest.label }}</p>
    <span class="stamp" :class="{ 'fx-pulse-ring': liveFlashing(card) }">{{ card.latest.stage === 'fallback' ? '旁路 / ' : '' }}{{ statusNames[card.latest.status] }}</span>
    <div class="paper-route" :style="{ '--station': ACTIVITY_STAGES.indexOf(card.latest.stage) / (ACTIVITY_STAGES.length - 1) }" aria-hidden="true"><span class="route-slip">▤</span><span v-for="station in ACTIVITY_STAGES" :key="station" class="route-stop" :class="{ received: card.stages[station] }"></span></div>
    <div class="paper-stage">{{ stageNames[card.latest.stage] }} <span>本聚合 {{ card.count }} 次活动</span></div>
    <ul class="stage-records" :class="{ 'fx-beam': liveFlashing(card) }" aria-label="已收到的阶段状态"><li v-for="(event, stage) in card.stages" :key="stage">{{ stageNames[stage] }} · {{ event ? statusNames[event.status] : '' }}</li></ul>
    <div class="paper-bottom"><time :datetime="card.latest.at">{{ card.latest.at }}</time><div class="detail-trigger"><button type="button" :aria-expanded="expanded === card.key" :aria-controls="'activity-detail-' + card.latest.id" @click="expanded = expanded === card.key ? null : card.key" :aria-label="'展开真实字段：' + (card.latest.intel_id ?? '来源批次')">真实字段 ↗</button><pre class="field-tooltip" role="tooltip">{{ detail(card.latest) }}</pre></div></div>
    <pre v-if="expanded === card.key" :id="'activity-detail-' + card.latest.id" class="expanded-fields">{{ detail(card.latest) }}</pre>
   </article>
  </div>
  <nav v-if="pageCount > 1" class="pagination" aria-label="情报卡分页"><button type="button" :disabled="page === 0" aria-label="上一页情报卡" @click="page--">上一页</button><span>{{ page + 1 }} / {{ pageCount }}</span><button type="button" :disabled="page + 1 >= pageCount" aria-label="下一页情报卡" @click="page++">下一页</button></nav>
  <footer class="board-footer"><span>详细历史 {{ history.length }}/500 · 已压缩 {{ trimmed }} 条旧详情，累计计数保留；{{ archivedGroups }} 次旧聚合移出托盘。</span><span>心跳 {{ heartbeat || '尚未收到' }} · DB {{ dbStatus }}</span><span>装饰层：环境粒子与光束，强度可在设置页调整；不传达任何情报语义</span></footer>
  <details class="history"><summary aria-label="展开活动详细历史">活动登记簿 · 最近 {{ history.length }} 条真实记录</summary><ol><li v-for="event in history" :key="event.id + ':' + event.sequence"><details><summary>#{{ event.sequence }} · {{ event.origin === 'live' ? '实时' : '历史 / 示例' }} · {{ stageNames[event.stage] }} · {{ statusNames[event.status] }} · {{ event.label }}</summary><pre>{{ detail(event) }}</pre></details></li></ol></details>
 </section>
</template>

<style scoped>
.activity-board{--ink:#e0eaf7;--muted:#91a7bf;--line:#31475f;background:#111e30;color:var(--ink);border:1px solid #405572;border-radius:16px;padding:26px;box-shadow:0 18px 40px #09122135,inset 0 1px #7a94b333;font-family:inherit;min-width:0}.board-header{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.eyebrow{letter-spacing:.18em;font-size:10px;color:#9fb8d5;margin:0 0 8px}.board-header h2{font-size:23px;font-weight:650;letter-spacing:.04em;margin:0}.subtitle{font-size:12px;color:var(--muted);margin:9px 0 0}.controls{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;align-items:center}.activity-board button{background:#253b53;color:#e6edf7;border:1px solid #526981;border-radius:6px;padding:7px 11px;cursor:pointer;font:inherit;font-size:12px}.activity-board button:hover{background:#36516d}.activity-board button:disabled{opacity:.45;cursor:default}.activity-board :focus-visible{outline:3px solid #e2b969;outline-offset:3px}.connection{font-size:11px;color:#b2c4d9;padding:7px 0}.connection.connected{color:#8fdbbd}.connection.disconnected{color:#ffbf97}.notice{padding:11px 14px;border:1px solid #507597;background:#1e3851;border-radius:7px;font-size:12px;line-height:1.7}.notice.warning{border-color:#ac784c;background:#3a302a;color:#ffdbb0}.telemetry{display:flex;flex-wrap:wrap;gap:10px 22px;padding:18px 0;font-size:11px;color:var(--muted)}.telemetry strong{font-size:17px;color:#e7edf6;margin-left:6px;font-variant-numeric:tabular-nums}.station-track{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:9px;border-block:1px solid var(--line);padding:15px 0}.station{border:1px solid #3a5169;border-radius:7px;background:#21364b;box-shadow:inset 0 1px #6e89a544,0 3px 0 #081322;min-width:0}.station summary{padding:10px 8px;font-size:12px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:7px}.station-index{font:10px monospace;color:#d4b36e}.help-sign{margin-left:auto;border:1px solid #607992;border-radius:50%;width:15px;height:15px;text-align:center;font-size:10px;color:#adc1d8}.station p{padding:0 10px;font-size:11px;color:#bacade;line-height:1.7}.station code{display:block;padding:0 10px 10px;font-size:10px;color:#d4b36e}.tray-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:22px 0 16px}.tray-header h3{font-size:14px;margin:0}.tray-header small{font-size:11px;font-weight:400;color:var(--muted);margin-left:8px}.tray-header>span{font-size:11px;color:var(--muted)}.paper-tray{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;background:repeating-linear-gradient(90deg,#0a152366 0,#0a152366 2px,transparent 2px,transparent 28px);padding:14px;border:1px solid #263b50;border-radius:10px;align-items:start;max-height:380px;overflow-y:auto;scrollbar-width:thin}.paper-route{position:relative;display:flex;justify-content:space-between;height:22px;margin:5px 0 8px;border-bottom:2px solid #aca28a}.route-stop{width:5px;height:5px;border-radius:50%;background:#b0a995;align-self:end;margin-bottom:-3px}.route-stop.received{background:#2d705e}.route-slip{position:absolute;bottom:4px;left:calc(var(--station) * 94%);color:#2563eb;font-size:18px;animation:slip-deliver .55s ease-out}@keyframes slip-deliver{from{left:0;transform:rotate(-12deg)}to{left:calc(var(--station) * 94%);transform:none}}.intel-paper{position:relative;background:linear-gradient(100deg,#f6f0de,#e9e0c9);color:#2a3440;padding:16px 14px 13px;border-radius:3px;box-shadow:2px 5px 0 #050c1577,0 10px 15px #0003;border-top:3px solid #9b8b68;min-width:0;animation:paper-arrive .28s ease-out}.intel-paper:before{content:'';position:absolute;top:-7px;left:38%;width:42px;height:14px;background:#c5b780a6;transform:rotate(-4deg);border:1px solid #9d93694d}.paper-meta{display:flex;justify-content:space-between;font:10px monospace;color:#6e726f;border-bottom:1px dashed #acaa9b;padding-bottom:9px}.intel-paper h4{font-size:13px;margin:14px 0 7px;overflow-wrap:anywhere}.paper-label{font-size:12px;line-height:1.6;margin:0;overflow-wrap:anywhere;min-height:38px}.stamp{display:inline-block;font-size:15px;font-weight:800;color:#2d705e;border:3px double currentColor;padding:4px 7px;transform:rotate(-6deg);margin:13px 0;letter-spacing:.05em}.failed .stamp,.rejected .stamp{color:#a3483a}.review .stamp{color:#8d6528}.degraded .stamp{color:#8d603b}.running .stamp{color:#466a86}.paper-stage{font-size:11px;font-weight:700;border-top:1px dashed #a8a291;padding-top:10px}.paper-stage span{display:block;font-size:10px;font-weight:400;color:#737467;margin-top:4px}.stage-records{display:flex;flex-wrap:wrap;list-style:none;padding:0;margin:9px 0;gap:4px;font-size:9px}.stage-records li{background:#d8d1bc;border-radius:3px;padding:3px 5px}.paper-bottom{display:flex;flex-direction:column;gap:8px}.paper-bottom time{font-size:9px;color:#6d756f;overflow-wrap:anywhere}.paper-bottom button{background:#e6dfca;color:#354957;border-color:#b5b19d;width:100%}.detail-trigger{position:relative}.field-tooltip{display:none;position:absolute;bottom:100%;left:0;z-index:120;width:min(340px,70vw);background:#0e1d2e;color:#d7e5f5;padding:12px;box-shadow:0 4px 18px #0005;border:1px solid #63809c;pointer-events:none}.detail-trigger:hover .field-tooltip,.detail-trigger:focus-within .field-tooltip{display:block}.activity-board pre{font-size:10px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:340px;overflow:auto;line-height:1.6}.expanded-fields{background:#e0d7bf;padding:9px;border:1px solid #b7ad92}.empty-tray{text-align:center;padding:36px 14px;border:1px dashed #3e5670;border-radius:9px;color:#a6bbd1}.empty-symbol{font-size:35px;color:#69839e}.empty-tray h3{font-size:15px}.empty-tray p{font-size:12px}.pagination{display:flex;justify-content:center;align-items:center;gap:15px;margin-top:15px;font-size:12px}.board-footer{display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px;margin-top:19px;color:var(--muted);font-size:10px;line-height:1.7;overflow-wrap:anywhere}.history{border-top:1px solid var(--line);margin-top:15px;padding-top:12px;font-size:12px}.history summary{cursor:pointer;line-height:1.8}.history ol{max-height:320px;overflow:auto;padding-left:22px}.history li{padding:5px;border-bottom:1px solid #2b4057}.history pre{color:#b8ccdf}@keyframes paper-arrive{from{opacity:.3;transform:translateY(-5px)}to{opacity:1;transform:none}}@media(min-width:1600px){.paper-tray{gap:20px}.intel-paper{padding:19px}}@media(max-width:1050px){.paper-tray{grid-template-columns:repeat(2,minmax(0,1fr))}.station-track{grid-template-columns:repeat(3,minmax(0,1fr))}.board-header{flex-direction:column}.controls{justify-content:flex-start}}@media(max-width:580px){.activity-board{padding:16px 12px}.board-header h2{font-size:19px}.station-track{grid-template-columns:repeat(2,minmax(0,1fr))}.paper-tray{grid-template-columns:1fr;padding:10px}.tray-header{align-items:flex-start;flex-direction:column}.intel-paper{padding:18px}.paper-label{min-height:0}.field-tooltip{display:none!important}.telemetry{gap:10px 15px}.controls{gap:7px}}@media(prefers-reduced-motion:reduce){.intel-paper,.route-slip{animation:none}.activity-board *{scroll-behavior:auto!important}}
</style>

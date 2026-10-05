<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { getJson, IS_DEMO_MODE } from '../api'
import type { IngestDiagnostics, IngestSourceState } from '../types'

const report = ref<IngestDiagnostics | null>(null)
const loading = ref(false)
const error = ref('')
const refreshedAt = ref('')

async function refresh() {
  if (IS_DEMO_MODE) return
  loading.value = true
  error.value = ''
  try {
    report.value = await getJson<IngestDiagnostics>('/ingest/diagnostics')
    refreshedAt.value = new Date().toLocaleString()
  } catch (err) {
    error.value = (err as Error).message
  } finally {
    loading.value = false
  }
}

function stateLabel(state: IngestSourceState): string {
  return ({ live: '真实抓取', partial: '部分成功', fixture: 'fixture 降级', no_new_data: '无新文档', failed: '失败' })[state]
}
function stateClass(state: IngestSourceState): string { return 'state-' + state }
function modeLabel(mode?: string): string {
  return ({ live: '真实采集', mixed: '真实采集 + 降级', fixture: 'fixture 回放', no_data: '无数据' } as Record<string, string>)[mode ?? ''] ?? '未知'
}
function percent(value: number | null): string { return value === null ? '—' : Math.round(value * 100) + '%' }
function time(value?: string): string { return value ? new Date(value).toLocaleString() : '—' }

onMounted(refresh)
</script>

<template>
  <div class="diagnostics-page">
    <header class="page-head">
      <div>
        <div class="eyebrow">INGEST · EVIDENCE</div>
        <h1>采集诊断</h1>
        <p>按 SQLite lineage 和事件记录展示真实采集、无新数据、fixture 降级与富化进度。</p>
      </div>
      <button class="refresh" :disabled="loading || IS_DEMO_MODE" @click="refresh">{{ loading ? '读取中…' : '刷新' }}</button>
    </header>

    <section v-if="IS_DEMO_MODE" class="notice warning">
      <strong>当前是静态演示模式</strong>
      <span>此模式不会请求诊断 API。关闭 VITE_DEMO_MODE 后才能查看本机 SQLite 的真实采集记录。</span>
    </section>
    <section v-else-if="error" class="notice danger"><strong>诊断接口读取失败</strong><span>{{ error }}</span></section>
    <section v-else-if="report && !report.database_available" class="notice warning">
      <strong>没有可读的持久化采集库</strong><span>{{ report.note }}</span>
    </section>
    <section v-else-if="report?.note && !report.latest_run" class="notice warning">
      <strong>尚无采集运行记录</strong><span>{{ report.note }}</span>
    </section>

    <template v-if="report?.database_available && report.latest_run && !IS_DEMO_MODE">
      <section class="run-banner" :class="'mode-' + report.latest_run.mode">
        <div><span class="mode-pill">{{ modeLabel(report.latest_run.mode) }}</span><strong>本页读的是持久化采集库，不是当前 demo 的 fixture 列表</strong></div>
        <small>trace {{ report.latest_run.trace_id }} · 最近活动 {{ time(report.latest_run.last_activity_at) }}</small>
      </section>

      <section class="metrics-grid">
        <article class="metric"><span>RawDoc 原始文档</span><strong>{{ report.latest_run.counts.raw_docs }}</strong><small>本次运行</small></article>
        <article class="metric"><span>情报事件</span><strong>{{ report.latest_run.counts.intel_events }}</strong><small>去重 ID {{ report.latest_run.counts.unique_intel_ids }}</small></article>
        <article class="metric"><span>DQ1 判定</span><strong>{{ report.latest_run.counts.dq_verdicts }}</strong><small>放行 {{ report.latest_run.counts.dq_pass + report.latest_run.counts.dq_degrade }} · 隔离 {{ report.latest_run.counts.dq_quarantine }}</small></article>
        <article class="metric" :class="{ incomplete: report.latest_run.counts.enrich_coverage !== null && report.latest_run.counts.enrich_coverage < 1 }"><span>富化覆盖</span><strong>{{ report.latest_run.counts.enrich_items }} / {{ report.latest_run.counts.accepted_items }}</strong><small>{{ percent(report.latest_run.counts.enrich_coverage) }} 结果覆盖 · {{ report.latest_run.counts.enrich_degraded_items }} 条论文降级 · {{ report.latest_run.counts.fallback_events }} 次显式降级</small></article>
      </section>

      <section v-if="report.latest_run.counts.accepted_items > report.latest_run.counts.enrich_items" class="notice warning repair-note">
        <strong>富化尚未跑完</strong>
        <span>目前 {{ report.latest_run.counts.enrich_items }}/{{ report.latest_run.counts.accepted_items }} 条有结果记录，其中 fixture/降级论文 {{ report.latest_run.counts.enrich_degraded_items }} 条；结果记录不等于实时论文命中。</span>
        <code>SAFETRACE_ENRICH_OFFLINE=false npm run enrich:pending -- --limit=20</code>
        <small>分批脚本默认只读预览；按逐维状态重试未知、失败、降级或已变更输入，保留 last-good，缺失回执也会修复。执行前验证备份并显式加 --apply；联网每条至少 3 秒，源连续失败停止，不把 fixture 算成功。</small>
      </section>

      <section v-if="report.latest_run.warnings.length" class="panel warnings">
        <div class="panel-title"><h2>需要注意</h2><span class="warning-count">{{ report.latest_run.warnings.length }} 项</span></div>
        <ul><li v-for="(warning, index) in report.latest_run.warnings" :key="index">{{ warning }}</li></ul>
      </section>

      <section class="panel">
        <div class="panel-title"><h2>本轮数据源</h2><span>{{ report.latest_run.sources.length }} 个 runner</span></div>
        <p class="table-note">状态对应上方 trace 的历史记录，代码修复不会回写旧事件；需重新运行 pipeline 验证新逻辑。一个漏洞可由多个源共同支撑，来源行数会重叠，不能相加当唯一漏洞数。</p>
        <div class="table-wrap"><table>
          <thead><tr><th>来源</th><th>状态</th><th>RawDoc</th><th>归并情报</th><th>说明</th></tr></thead>
          <tbody><tr v-for="source in report.latest_run.sources" :key="source.source_id">
            <td class="mono">{{ source.source_id }}</td><td><span class="state-pill" :class="stateClass(source.state)">{{ stateLabel(source.state) }}</span></td>
            <td>{{ source.raw_docs }}</td><td>{{ source.intel_items }}</td><td class="detail">{{ source.detail }}</td>
          </tr></tbody>
        </table></div>
      </section>

      <section v-if="report.latest_run.fallbacks.length" class="panel">
        <div class="panel-title"><h2>降级记录</h2><span>逐项留痕；不是成功数据</span></div>
        <div class="fallback-list"><div v-for="item in report.latest_run.fallbacks.slice(0, 12)" :key="item.trigger" class="fallback-row">
          <span>{{ item.trigger }}</span><strong>{{ item.count }}</strong><small :class="item.user_visible ? 'visible' : 'not-visible'">{{ item.user_visible ? '用户可见' : '未标注，需排查' }}</small>
        </div></div>
      </section>

      <footer class="footnote">库 {{ report.database_name }} · 共 {{ report.total_runs }} 次采集尝试 · NVD key（当前 API 进程）{{ report.nvd_api_key_configured ? '已配置' : '未配置，限流 5 req/30s' }} · 本次开始 {{ time(report.latest_run.started_at) }} · 页面刷新 {{ refreshedAt }}</footer>
    </template>
  </div>
</template>

<style scoped>
.diagnostics-page { max-width: 1280px; margin: 0 auto; padding: 32px 24px 56px; display: grid; gap: 18px; }
.page-head { display:flex; justify-content:space-between; align-items:flex-end; gap:20px; }
.eyebrow { color:var(--accent); font:600 11px 'JetBrains Mono',monospace; letter-spacing:.14em; }
h1 { margin:7px 0 6px; color:var(--text-bright); font-size:28px; }
.page-head p { margin:0; color:var(--text-muted); font-size:13px; }
.refresh { border:1px solid var(--border); border-radius:8px; padding:9px 15px; color:var(--text-bright); background:var(--surface); cursor:pointer; }
.refresh:disabled { opacity:.45; cursor:not-allowed; }
.notice,.run-banner { border:1px solid var(--border); border-radius:10px; padding:16px 18px; display:flex; flex-direction:column; gap:6px; background:rgba(15,23,42,.7); color:var(--text-muted); }
.notice strong { color:var(--text-bright); }
.warning { border-color:rgba(234,179,8,.4); background:rgba(234,179,8,.07); }
.danger { border-color:rgba(255,45,85,.45); background:rgba(255,45,85,.08); }
.run-banner { flex-direction:row; justify-content:space-between; align-items:center; border-color:rgba(34,197,94,.35); }
.run-banner.mode-mixed,.run-banner.mode-fixture { border-color:rgba(234,179,8,.45); background:rgba(234,179,8,.06); }
.run-banner > div { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.run-banner strong { color:var(--text-bright); font-size:13px; }
.run-banner small { font-family:'JetBrains Mono',monospace; color:var(--text-muted); }
.mode-pill,.state-pill { display:inline-flex; border-radius:999px; padding:4px 9px; font-size:11px; font-weight:700; background:rgba(34,197,94,.13); color:#4ade80; }
.mode-mixed .mode-pill,.mode-fixture .mode-pill { background:rgba(234,179,8,.14); color:#facc15; }
.metrics-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }
.metric { border:1px solid var(--border); border-radius:10px; padding:16px; background:var(--surface); display:flex; flex-direction:column; gap:8px; }
.metric span,.metric small { color:var(--text-muted); font-size:12px; }
.metric strong { color:var(--text-bright); font:700 24px 'JetBrains Mono',monospace; overflow-wrap:anywhere; }
.metric.incomplete { border-color:rgba(234,179,8,.45); }
.metric.incomplete strong { color:#facc15; }
.panel { border:1px solid var(--border); border-radius:10px; padding:16px; background:rgba(15,23,42,.62); }
.panel-title { display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; color:var(--text-muted); font-size:12px; }
.panel-title h2 { margin:0; color:var(--text-bright); font-size:15px; }
.warning-count { color:#facc15; }
.warnings ul { margin:0; padding-left:20px; display:grid; gap:8px; color:#fcd34d; font-size:13px; }
.table-note { margin: -6px 0 10px; color: var(--text-muted); font-size: 11px; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; text-align:left; font-size:12px; }
th { color:var(--text-muted); font-weight:600; }
th,td { padding:10px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
td { color:var(--text); }
.mono { font-family:'JetBrains Mono',monospace; }
.detail { min-width:260px; color:var(--text-muted); }
.state-live { color:#4ade80; background:rgba(34,197,94,.12); }
.state-partial,.state-fixture,.state-no_new_data { color:#facc15; background:rgba(234,179,8,.12); }
.state-failed,.not-visible { color:#fb7185; background:rgba(244,63,94,.12); }
.fallback-list { display:grid; gap:0; }
.fallback-row { display:grid; grid-template-columns:minmax(0,1fr) auto auto; gap:16px; padding:9px 4px; border-bottom:1px solid var(--border); color:var(--text-muted); font-size:12px; }
.fallback-row strong { color:#facc15; font-family:'JetBrains Mono',monospace; }
.visible { color:#4ade80; }
.footnote { color:var(--text-muted); font-size:11px; line-height:1.7; }
@media(max-width:850px){.metrics-grid{grid-template-columns:repeat(2,minmax(0,1fr));}.run-banner{align-items:flex-start;flex-direction:column;}}
@media(max-width:520px){.diagnostics-page{padding:22px 14px 40px}.metrics-grid{grid-template-columns:1fr 1fr}.metric{padding:12px}.metric strong{font-size:18px}.page-head{align-items:flex-start}}
</style>

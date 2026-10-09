<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  getAssetsGroups,
  getAssetsOverview,
  getAssetsRepos,
  getAssetsComponents,
  getAssetsAlerts,
  postAssetsScan,
  postAssetsGroup,
  postAssetsGroupDelete,
  postAlertsRead,
  IS_DEMO_MODE,
  type AssetAlert,
  type AssetComponent,
  type AssetGroupStats,
  type AssetRepo,
  type AssetsOverview,
} from '../api'

// 本地资产扫描（A 线）· 多分组监控：
// 每组独立的扫描根目录集合；扫描、统计、提醒都按组隔离；
// 分组定义存放在 var/assets.sqlite（本页可增删改），config/assets-scan.json 只负责首次播种。

type Tab = 'alerts' | 'repos' | 'components'

const groups = ref<AssetGroupStats[]>([])
const selectedGroup = ref('') // 空 = 全部组
const overview = ref<AssetsOverview | null>(null)
const repos = ref<AssetRepo[]>([])
const components = ref<AssetComponent[]>([])
const componentTotal = ref(0)
const alerts = ref<AssetAlert[]>([])
const unread = ref(0)
const tab = ref<Tab>('alerts')
const loading = ref(false)
const scanning = ref(false)
const error = ref('')
const scanMessage = ref('')
const ecosystemFilter = ref('')
const keyword = ref('')
const refreshedAt = ref('')

// ── 分组管理 ──
const showGroupManager = ref(false)
const savingGroup = ref(false)
const formError = ref('')
const form = ref<{ group_id: string; name: string; roots: string; note: string; enabled: boolean }>({ group_id: '', name: '', roots: '', note: '', enabled: true })
const editingId = ref('') // 空 = 新建

const groupName = (id: string): string => groups.value.find((g) => g.group_id === id)?.name ?? id

const ecosystemOptions = computed(() => {
  const keys = Object.keys(overview.value?.by_ecosystem ?? {})
  return keys.sort()
})

function time(value?: string | null): string {
  return value ? new Date(value).toLocaleString() : '—'
}

async function loadAll(): Promise<void> {
  loading.value = true
  error.value = ''
  const gid = selectedGroup.value || undefined
  try {
    const [gp, ov, rp, cp, al] = await Promise.all([
      getAssetsGroups(),
      getAssetsOverview(gid),
      getAssetsRepos(gid),
      getAssetsComponents(gid, { ...(ecosystemFilter.value ? { ecosystem: ecosystemFilter.value } : {}), ...(keyword.value ? { q: keyword.value } : {}), limit: 300 }),
      getAssetsAlerts(gid),
    ])
    groups.value = gp.groups
    overview.value = ov
    repos.value = rp.repos
    components.value = cp.rows
    componentTotal.value = cp.total
    alerts.value = al.alerts
    unread.value = al.unread_count
    refreshedAt.value = new Date().toLocaleString()
  } catch (err) {
    error.value = (err as Error).message
  } finally {
    loading.value = false
  }
}

async function scan(): Promise<void> {
  scanning.value = true
  scanMessage.value = ''
  error.value = ''
  try {
    const result = await postAssetsScan(selectedGroup.value || undefined)
    const parts = result.groups.map((g) => g.group_id + '：仓库 ' + g.repo_count + ' · 组件 ' + g.component_count + ' · 命中 ' + g.affected + ' · 新增提醒 ' + g.new_alerts + (g.degraded_to ? '（降级 ' + g.degraded_to + '）' : ''))
    scanMessage.value = '扫描 ' + result.groups.length + ' 个分组完成 —— ' + parts.join('；')
    await loadAll()
  } catch (err) {
    error.value = (err as Error).message
  } finally {
    scanning.value = false
  }
}

async function markRead(ids?: string[]): Promise<void> {
  try {
    await postAlertsRead(ids ? { ids } : selectedGroup.value ? { group_id: selectedGroup.value } : undefined)
    await loadAll()
  } catch (err) {
    error.value = (err as Error).message
  }
}

// ── 分组管理动作 ──

function resetForm(): void {
  form.value = { group_id: '', name: '', roots: '', note: '', enabled: true }
  editingId.value = ''
  formError.value = ''
}

function editGroup(group: AssetGroupStats): void {
  editingId.value = group.group_id
  form.value = { group_id: group.group_id, name: group.name, roots: group.roots.join('\n'), note: group.note ?? '', enabled: group.enabled }
  formError.value = ''
}

function parseRoots(text: string): string[] {
  return text.split(/[\r\n,;]/).map((r) => r.trim()).filter((r) => r !== '')
}

async function saveGroup(): Promise<void> {
  formError.value = ''
  const id = form.value.group_id.trim()
  const name = form.value.name.trim()
  const roots = parseRoots(form.value.roots)
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$/.test(id)) {
    formError.value = '分组 id 只能包含字母数字-_（≤40 字符，字母数字开头）'
    return
  }
  if (name === '') {
    formError.value = '分组名称必填'
    return
  }
  if (roots.length === 0 || roots.length > 20) {
    formError.value = 'roots 需要 1–20 个目录（每行一个）'
    return
  }
  if (editingId.value === '' && groups.value.some((g) => g.group_id === id)) {
    formError.value = '分组 id 已存在'
    return
  }
  savingGroup.value = true
  try {
    await postAssetsGroup({ group_id: id, name, roots, enabled: form.value.enabled, note: form.value.note.trim() || undefined })
    resetForm()
    await loadAll()
  } catch (err) {
    formError.value = (err as Error).message
  } finally {
    savingGroup.value = false
  }
}

async function toggleGroup(group: AssetGroupStats): Promise<void> {
  try {
    await postAssetsGroup({ group_id: group.group_id, name: group.name, roots: group.roots, enabled: !group.enabled, note: group.note ?? undefined })
    await loadAll()
  } catch (err) {
    error.value = (err as Error).message
  }
}

async function deleteGroup(group: AssetGroupStats): Promise<void> {
  if (!window.confirm('删除分组「' + group.name + '」？历史扫描与提醒记录会保留，只是不再监控这组目录。')) return
  try {
    await postAssetsGroupDelete(group.group_id)
    if (selectedGroup.value === group.group_id) selectedGroup.value = ''
    await loadAll()
  } catch (err) {
    error.value = (err as Error).message
  }
}

function severityClass(severity: string | null): string {
  return ({ critical: 'critical', high: 'high', medium: 'medium', low: 'low' } as Record<string, string>)[severity ?? ''] ?? 'info'
}

onMounted(loadAll)
</script>

<template>
  <div class="assets-page">
    <header class="page-head">
      <div>
        <div class="eyebrow">ASSETS · LOCAL SCAN</div>
        <h1>本地资产扫描</h1>
        <p>按分组监控本机 git 仓库与项目目录：每组独立扫描根、独立技术栈快照；新情报入库后自动比对，命中受影响组件即生成提醒。</p>
      </div>
      <div class="head-actions">
        <button class="refresh" :disabled="loading" @click="loadAll">{{ loading ? '读取中…' : '刷新' }}</button>
        <button class="scan" :disabled="scanning || IS_DEMO_MODE" @click="scan">{{ scanning ? '扫描中…' : (selectedGroup ? '扫描该组' : '扫描全部组') }}</button>
      </div>
    </header>

    <section v-if="IS_DEMO_MODE" class="notice warning">
      <strong>当前是静态演示模式</strong>
      <span>此模式展示预置样本，不会真正扫描本机。关闭 VITE_DEMO_MODE 后将读写 var/assets.sqlite 真实资产库。</span>
    </section>
    <section v-else-if="error" class="notice danger"><strong>资产接口读取失败</strong><span>{{ error }}</span></section>
    <section v-else-if="scanMessage" class="notice"><strong>扫描结果</strong><span>{{ scanMessage }}</span></section>
    <section v-else-if="overview?.last_run?.degraded_to" class="notice warning">
      <strong>最近一次扫描存在显式降级：{{ overview.last_run.degraded_to }}</strong>
      <span>{{ overview.last_run.note ?? '结果不完整，但不静默——降级原因已随扫描记录落库。' }}</span>
    </section>
    <section v-else-if="overview && !overview.last_run && !IS_DEMO_MODE" class="notice warning">
      <strong>尚未扫描过</strong>
      <span>点击「扫描全部组」，或在仓库根执行 <code>npm run assets:scan</code>。分组与扫描范围可在下方「分组管理」配置。</span>
    </section>

    <section v-if="overview" class="metrics-grid">
      <article class="metric"><span>监控分组</span><strong>{{ groups.length || overview.by_group.length }}</strong><small>{{ selectedGroup ? '当前：' + groupName(selectedGroup) : '全部组' }}</small></article>
      <article class="metric"><span>已收录仓库</span><strong>{{ overview.repo_count }}</strong><small>{{ selectedGroup ? '该组最近一轮' : '各组最近一轮之和' }}</small></article>
      <article class="metric"><span>技术栈组件</span><strong>{{ overview.component_count }}</strong><small>{{ ecosystemOptions.map((k) => k + ' ' + (overview?.by_ecosystem[k] ?? 0)).join(' · ') || '按生态统计' }}</small></article>
      <article class="metric" :class="{ warn: unread > 0 }"><span>未读提醒</span><strong>{{ unread }}</strong><small>累计 {{ overview.alert_count }} 条</small></article>
    </section>

    <nav class="group-bar">
      <label class="group-select">
        <span>监控分组</span>
        <select v-model="selectedGroup" @change="loadAll">
          <option value="">全部组（{{ groups.length }}）</option>
          <option v-for="g in groups" :key="g.group_id" :value="g.group_id">{{ g.name }}{{ g.unread_count > 0 ? '（' + g.unread_count + ' 条未读）' : '' }}{{ g.enabled ? '' : '［已停用］' }}</option>
        </select>
      </label>
      <span v-if="selectedGroup" class="group-roots mono">根目录：{{ groups.find((g) => g.group_id === selectedGroup)?.roots.join(' | ') }}</span>
      <button class="link-btn" @click="showGroupManager = !showGroupManager">{{ showGroupManager ? '收起分组管理' : '分组管理' }}</button>
    </nav>

    <section v-if="showGroupManager" class="panel">
      <div class="panel-title"><h2>分组管理</h2><span>定义存于 var/assets.sqlite；config/assets-scan.json 仅在空库时播种</span></div>
      <p class="table-note">每个分组是一组要监控的根目录；同一目录可出现在多个分组（各组独立快照与提醒）。停用的分组不参与「扫描全部组」与常驻自动匹配。</p>
      <div class="table-wrap"><table>
        <thead><tr><th>分组</th><th>根目录</th><th>状态</th><th>仓库/组件</th><th>未读</th><th>最近扫描</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="g in groups" :key="g.group_id">
            <td><strong>{{ g.name }}</strong><br><span class="muted mono">{{ g.group_id }}</span><span v-if="g.note" class="muted"> · {{ g.note }}</span></td>
            <td class="mono detail">{{ g.roots.join('\n') }}</td>
            <td><span class="state-pill" :class="g.enabled ? 'on' : 'off'">{{ g.enabled ? '监控中' : '已停用' }}</span></td>
            <td>{{ g.repo_count }} / {{ g.component_count }}</td>
            <td :class="{ warn: g.unread_count > 0 }">{{ g.unread_count }}</td>
            <td class="muted">{{ time(g.last_finished_at) }}</td>
            <td class="ops">
              <button class="link-btn" @click="editGroup(g)">编辑</button>
              <button class="link-btn" @click="toggleGroup(g)">{{ g.enabled ? '停用' : '启用' }}</button>
              <button class="link-btn danger" @click="deleteGroup(g)">删除</button>
            </td>
          </tr>
        </tbody>
      </table></div>

      <form class="group-form" @submit.prevent="saveGroup">
        <h3>{{ editingId ? '编辑分组：' + editingId : '新增分组' }}</h3>
        <div class="form-row">
          <label>分组 id<input v-model="form.group_id" :disabled="editingId !== ''" placeholder="如 myproject" /></label>
          <label>名称<input v-model="form.name" placeholder="如：我的项目" /></label>
        </div>
        <label>根目录（每行一个；相对本仓库根或绝对路径）<textarea v-model="form.roots" rows="3" placeholder="D:MyProject&#10;../other"></textarea></label>
        <div class="form-row">
          <label>备注<input v-model="form.note" placeholder="可选" /></label>
          <label class="check"><input v-model="form.enabled" type="checkbox" /> 启用监控</label>
        </div>
        <p v-if="formError" class="form-error">{{ formError }}</p>
        <div class="form-actions">
          <button type="submit" :disabled="savingGroup || IS_DEMO_MODE">{{ savingGroup ? '保存中…' : '保存分组' }}</button>
          <button type="button" class="link-btn" @click="resetForm">重置</button>
        </div>
      </form>
    </section>

    <nav class="tabs">
      <button :class="{ active: tab === 'alerts' }" @click="tab = 'alerts'">漏洞提醒（{{ alerts.length }}）</button>
      <button :class="{ active: tab === 'repos' }" @click="tab = 'repos'">仓库快照（{{ repos.length }}）</button>
      <button :class="{ active: tab === 'components' }" @click="tab = 'components'">组件清单（{{ componentTotal }}）</button>
    </nav>

    <section v-if="tab === 'alerts'" class="panel">
      <div class="panel-title">
        <h2>漏洞提醒</h2>
        <button v-if="unread > 0 && !IS_DEMO_MODE" class="link-btn" @click="markRead()">{{ selectedGroup ? '该组全部已读' : '全部标记已读' }}</button>
      </div>
      <p class="table-note">提醒由确定性匹配产生：组件名归一 + 版本区间判定（复用 F2 同一套版本比较）。本地扫描不携带厂商身份，结论标注「厂商未核实」；版本取自范围约束下界时附带 semver 提示。同一组件的同一 CVE 在每个分组各提醒一次。</p>
      <div v-if="!alerts.length" class="empty">暂无提醒——扫描后若有组件命中已入库情报的受影响版本区间，会出现在这里。</div>
      <div v-else class="alert-list">
        <article v-for="alert in alerts" :key="alert.alert_id" class="alert-row" :class="{ seen: alert.status === 'seen' }">
          <div class="alert-main">
            <div class="alert-title">
              <span class="badge" :class="severityClass(alert.severity)">{{ alert.severity ?? '未分级' }}</span>
              <strong class="mono">{{ alert.name }}@{{ alert.version || '未锁定' }}</strong>
              <span class="cve mono">{{ alert.cve_id }}</span>
              <span class="group-tag">{{ groupName(alert.group_id) }}</span>
              <span v-if="alert.status === 'new'" class="new-dot">新</span>
            </div>
            <div class="alert-meta">
              <span class="mono repo">{{ alert.repo_path }}</span>
              <span class="muted">规则 {{ alert.matched_rule }}</span>
              <span class="muted">{{ time(alert.created_at) }}</span>
            </div>
            <div class="alert-reason">{{ alert.title ?? '本地情报库条目' }} — {{ alert.reason }}</div>
          </div>
          <button v-if="alert.status === 'new' && !IS_DEMO_MODE" class="link-btn" @click="markRead([alert.alert_id])">标记已读</button>
        </article>
      </div>
    </section>

    <section v-if="tab === 'repos'" class="panel">
      <div class="panel-title"><h2>仓库快照</h2><span>{{ repos.length }} 个仓库{{ selectedGroup ? ' · ' + groupName(selectedGroup) : ' · 所有分组' }}</span></div>
      <p class="table-note">git 元信息来自本地只读子命令（remote/rev-parse/log）；远程地址中的凭据已脱敏。非 git 目录按 manifest 识别为项目收录。</p>
      <div class="table-wrap"><table>
        <thead><tr><th>路径</th><th>分组</th><th>远程 / 分支</th><th>语言</th><th>框架</th><th>组件</th><th>git 备注</th></tr></thead>
        <tbody>
          <tr v-for="repo in repos" :key="repo.repo_id">
            <td class="mono detail">{{ repo.path }}</td>
            <td>{{ groupName(repo.group_id) }}</td>
            <td class="mono">{{ repo.remote_url ?? '—' }}<br><span class="muted">{{ repo.branch ?? '—' }} · {{ repo.head_commit ? repo.head_commit.slice(0, 7) : '无提交' }}</span></td>
            <td>{{ repo.languages.join('、') || '—' }}</td>
            <td>{{ repo.frameworks.join('、') || '—' }}</td>
            <td>{{ repo.component_count }}</td>
            <td class="detail">{{ repo.is_git ? (repo.git_note ?? 'git 信息完整') : '非 git 项目' }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <section v-if="tab === 'components'" class="panel">
      <div class="panel-title"><h2>组件清单</h2><span>共 {{ componentTotal }} 条</span></div>
      <div class="toolbar">
        <select v-model="ecosystemFilter" class="range-selector" @change="loadAll">
          <option value="">全部生态</option>
          <option v-for="eco in ecosystemOptions" :key="eco" :value="eco">{{ eco }}</option>
        </select>
        <input v-model="keyword" placeholder="按组件名或仓库路径过滤" @keyup.enter="loadAll" />
        <button class="refresh" :disabled="loading" @click="loadAll">应用</button>
      </div>
      <p class="table-note">版本列显示清单声明的字面量；「范围下界」表示原约束是 ^/~/&gt;= 一类，实际安装版本可能更高，匹配结论已按此保守处理。</p>
      <div class="table-wrap"><table>
        <thead><tr><th>生态</th><th>组件</th><th>版本</th><th>分组</th><th>来源清单</th><th>仓库</th></tr></thead>
        <tbody>
          <tr v-for="(c, index) in components" :key="c.ecosystem + c.name + c.repo_path + index">
            <td>{{ c.ecosystem }}</td>
            <td class="mono">{{ c.name }}</td>
            <td class="mono">{{ c.version || '未锁定' }}<span v-if="c.version_is_range_floor" class="muted">（{{ c.constraint_raw }}）</span></td>
            <td>{{ groupName(c.group_id) }}</td>
            <td class="mono">{{ c.source_file }}</td>
            <td class="mono detail">{{ c.repo_path }}</td>
          </tr>
        </tbody>
      </table></div>
    </section>

    <footer class="footnote">资产库 var/assets.sqlite（不入 git） · 分组可在本页管理 · 命令行 <code>npm run assets:scan -- --list-groups</code> · 页面刷新 {{ refreshedAt || '—' }}</footer>
  </div>
</template>

<style scoped>
.assets-page { max-width: 1280px; margin: 0 auto; padding: 32px 24px 56px; display: grid; gap: 18px; }
.page-head { display:flex; justify-content:space-between; align-items:flex-end; gap:20px; flex-wrap:wrap; }
.eyebrow { color:var(--accent); font:600 11px 'JetBrains Mono',monospace; letter-spacing:.14em; }
h1 { margin:7px 0 6px; color:var(--text-bright); font-size:28px; }
.page-head p { margin:0; color:var(--text-muted); font-size:13px; max-width:640px; }
.head-actions { display:flex; gap:10px; }
.refresh,.scan { border:1px solid var(--border); border-radius:8px; padding:9px 15px; color:var(--text-bright); background:var(--surface); cursor:pointer; }
.scan { border-color:rgba(34,197,94,.45); color:#4ade80; }
.refresh:disabled,.scan:disabled { opacity:.45; cursor:not-allowed; }
.notice { border:1px solid var(--border); border-radius:10px; padding:14px 18px; display:flex; flex-direction:column; gap:6px; background:rgba(15,23,42,.7); color:var(--text-muted); font-size:13px; }
.notice strong { color:var(--text-bright); }
.notice code,.footnote code { font-family:'JetBrains Mono',monospace; color:#4ade80; }
.warning { border-color:rgba(234,179,8,.4); background:rgba(234,179,8,.07); }
.danger { border-color:rgba(255,45,85,.45); background:rgba(255,45,85,.08); }
.metrics-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }
.metric { border:1px solid var(--border); border-radius:10px; padding:16px; background:var(--surface); display:flex; flex-direction:column; gap:8px; }
.metric span,.metric small { color:var(--text-muted); font-size:12px; }
.metric strong { color:var(--text-bright); font:700 24px 'JetBrains Mono',monospace; overflow-wrap:anywhere; }
.metric.warn { border-color:rgba(234,179,8,.45); }
.metric.warn strong { color:#facc15; }
.group-bar { display:flex; align-items:center; gap:14px; flex-wrap:wrap; border:1px solid var(--border); border-radius:10px; padding:12px 16px; background:rgba(15,23,42,.62); }
.group-select { display:flex; align-items:center; gap:10px; color:var(--text-muted); font-size:12px; }
.group-select select { border:1px solid var(--border); border-radius:8px; padding:8px 12px; background:var(--surface); color:var(--text-bright); min-width:260px; }
.group-roots { color:var(--text-muted); font-size:11px; overflow-wrap:anywhere; }
.link-btn { border:none; background:none; color:#4ade80; cursor:pointer; font-size:12px; padding:4px 6px; }
.link-btn.danger { color:#fb7185; }
.state-pill { display:inline-flex; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:700; }
.state-pill.on { background:rgba(34,197,94,.13); color:#4ade80; }
.state-pill.off { background:rgba(148,163,184,.14); color:#cbd5e1; }
.tabs { display:flex; gap:8px; flex-wrap:wrap; }
.tabs button { border:1px solid var(--border); border-radius:999px; padding:7px 16px; background:transparent; color:var(--text-muted); cursor:pointer; font-size:13px; }
.tabs button.active { border-color:rgba(34,197,94,.5); color:#4ade80; background:rgba(34,197,94,.08); }
.panel { border:1px solid var(--border); border-radius:10px; padding:16px; background:rgba(15,23,42,.62); }
.panel-title { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; color:var(--text-muted); font-size:12px; gap:10px; flex-wrap:wrap; }
.panel-title h2 { margin:0; color:var(--text-bright); font-size:15px; }
.table-note { margin:0 0 12px; color:var(--text-muted); font-size:11px; line-height:1.6; }
.empty { color:var(--text-muted); font-size:13px; padding:18px; border:1px dashed var(--border); border-radius:8px; }
.alert-list { display:grid; gap:10px; }
.alert-row { display:flex; justify-content:space-between; align-items:flex-start; gap:14px; border:1px solid var(--border); border-radius:10px; padding:13px 15px; background:rgba(15,23,42,.5); }
.alert-row.seen { opacity:.62; }
.alert-main { display:grid; gap:7px; min-width:0; }
.alert-title { display:flex; align-items:center; gap:9px; flex-wrap:wrap; }
.alert-title strong { color:var(--text-bright); font-size:14px; }
.cve { color:#facc15; font-size:12px; }
.group-tag { border:1px solid var(--border); border-radius:999px; padding:2px 9px; font-size:10px; color:var(--text-muted); }
.new-dot { border-radius:999px; background:rgba(255,45,85,.16); color:#fb7185; font-size:10px; font-weight:700; padding:2px 8px; }
.alert-meta { display:flex; gap:14px; flex-wrap:wrap; font-size:11px; }
.alert-meta .repo { color:var(--text-muted); }
.alert-reason { color:var(--text-muted); font-size:12px; line-height:1.6; }
.badge { display:inline-flex; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:700; background:rgba(148,163,184,.14); color:#cbd5e1; }
.badge.critical { background:rgba(244,63,94,.15); color:#fb7185; }
.badge.high { background:rgba(234,179,8,.15); color:#facc15; }
.badge.medium { background:rgba(56,189,248,.14); color:#7dd3fc; }
.badge.low { background:rgba(34,197,94,.13); color:#4ade80; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; text-align:left; font-size:12px; }
th { color:var(--text-muted); font-weight:600; }
th,td { padding:10px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
td { color:var(--text); }
.mono { font-family:'JetBrains Mono',monospace; }
.muted { color:var(--text-muted); }
.detail { min-width:220px; color:var(--text-muted); overflow-wrap:anywhere; white-space:pre-wrap; }
.warn { color:#facc15; font-weight:700; }
.ops { white-space:nowrap; }
.toolbar { display:flex; gap:10px; margin-bottom:12px; flex-wrap:wrap; }
.toolbar input { flex:1; min-width:220px; border:1px solid var(--border); border-radius:8px; padding:8px 12px; background:var(--surface); color:var(--text-bright); }
.group-form { margin-top:16px; border-top:1px solid var(--border); padding-top:14px; display:grid; gap:12px; }
.group-form h3 { margin:0; color:var(--text-bright); font-size:14px; }
.group-form label { display:grid; gap:6px; color:var(--text-muted); font-size:12px; }
.group-form input,.group-form textarea { border:1px solid var(--border); border-radius:8px; padding:8px 12px; background:var(--surface); color:var(--text-bright); font-size:13px; font-family:'JetBrains Mono',monospace; }
.group-form textarea { resize:vertical; }
.form-row { display:flex; gap:16px; flex-wrap:wrap; }
.form-row label { flex:1; min-width:220px; }
.form-row label.check { flex:0 0 auto; display:flex; align-items:center; gap:8px; }
.form-error { margin:0; color:#fb7185; font-size:12px; }
.form-actions { display:flex; gap:12px; align-items:center; }
.form-actions button[type="submit"] { border:1px solid rgba(34,197,94,.45); border-radius:8px; padding:8px 16px; background:rgba(34,197,94,.1); color:#4ade80; cursor:pointer; }
.form-actions button:disabled { opacity:.45; cursor:not-allowed; }
.footnote { color:var(--text-muted); font-size:11px; line-height:1.7; }
@media(max-width:850px){.metrics-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}
@media(max-width:520px){.assets-page{padding:22px 14px 40px}.metrics-grid{grid-template-columns:1fr 1fr;}.group-select select{min-width:0}}
</style>

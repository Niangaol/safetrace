<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { groupComparison, safeUiUrl } from '../qa-ui'
import type { UiDocument } from '../qa-ui'
const props = defineProps<{ document: UiDocument }>()
const sourceFilter = ref('')
const checked = ref<string[]>([])
const sources = computed(() => [...new Set(props.document.blocks.flatMap(block => block.items.map(item => item.doc_type)))])
const blocks = computed(() => props.document.blocks.map(block => {
  const items = block.items.filter(item => !sourceFilter.value || item.doc_type === sourceFilter.value)
  return { ...block, groups: block.type === 'comparison' ? groupComparison(items) : [{ cve: null, items }] }
}))
watch(() => props.document, () => { sourceFilter.value = ''; checked.value = [] })
function resetLocal() { sourceFilter.value = ''; checked.value = [] }
function setChecked(id: string, value: boolean) { checked.value = value ? [...new Set([...checked.value, id])] : checked.value.filter(item => item !== id) }
function host(url: string) { try { return new URL(url).host } catch { return '无外部链接' } }
const labels = { evidence: '来源证据', comparison: '漏洞对照', checklist: '阅读与核对清单' }
</script>

<template>
  <section class="adaptive-answer" aria-label="自适应来源证据" data-testid="adaptive-answer">
    <div class="adaptive-toolbar">
      <span>证据工作区 <small>{{ document.source === 'model' ? '模型选型 · 服务端填充' : '规则选型 · 服务端填充' }}</small></span>
      <label>来源类型 <select :value="sourceFilter" aria-label="本地来源筛选" @change="sourceFilter = ($event.target as HTMLSelectElement).value"><option value="">全部</option><option v-for="source in sources" :key="source" :value="source">{{ source }}</option></select></label>
      <button type="button" class="secondary" @click="resetLocal">重置筛选与勾选</button>
    </div>
    <p class="adaptive-note">以下为来源原文，不是新增结论。组件随完整 UI 事件一次呈现，不逐 token 更新结构。</p>
    <section v-for="block in blocks" :key="block.id" class="adaptive-block" :data-block-type="block.type">
      <h3>{{ labels[block.type] }}</h3>
      <p v-if="block.type === 'checklist'" class="local-disclaimer">勾选仅表示本地「已阅读 / 已人工核对」，不会执行修复、命令或验证，也不证明系统安全；刷新后不保存。</p>
      <p v-if="!block.groups.some(group => group.items.length)" class="adaptive-note">当前筛选没有匹配证据。</p>
      <div :class="{ 'comparison-columns': block.type === 'comparison' }">
        <section v-for="group in block.groups" :key="group.cve ?? 'unbound'" class="evidence-group">
          <h4 v-if="block.type === 'comparison'">{{ group.cve ?? '未绑定漏洞的证据' }}</h4>
          <article v-for="item in group.items" :key="item.id" class="source-card">
            <div class="source-meta"><span>{{ item.doc_type }}</span><span v-if="item.cve_id">{{ item.cve_id }}</span><code>{{ item.id }}</code></div>
            <label v-if="block.type === 'checklist'" class="read-tick"><input type="checkbox" :value="item.id" :checked="checked.includes(item.id)" @change="setChecked(item.id, ($event.target as HTMLInputElement).checked)" />已阅读 / 已人工核对（仅本地记录）</label>
            <p class="source-text">{{ item.text }}</p>
            <a v-if="safeUiUrl(item.url)" :href="safeUiUrl(item.url)!" target="_blank" rel="noreferrer noopener">{{ host(item.url) }} ↗</a>
            <span v-else class="adaptive-note">本地证据 · 无外部链接</span>
          </article>
        </section>
      </div>
    </section>
  </section>
</template>

<style scoped>
.adaptive-answer{margin:22px 0;border-top:1px solid var(--border);padding-top:18px;min-width:0}.adaptive-toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;font-size:12px}.adaptive-toolbar>span{font-weight:650;margin-right:auto}.adaptive-toolbar small{display:block;font-weight:400;color:var(--muted);margin-top:4px}.adaptive-toolbar label{display:flex;gap:6px;align-items:center}.adaptive-toolbar select{max-width:180px;font:inherit;padding:5px;border:1px solid var(--border);border-radius:8px;background:var(--panel);color:inherit}.adaptive-toolbar button{font-size:11px;padding:6px 9px}.adaptive-note{font-size:11px;color:var(--muted);line-height:1.7;margin:10px 0}.adaptive-block h3{font-size:14px;margin:20px 0 10px}.comparison-columns{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(240px,100%),1fr));gap:12px}.evidence-group{min-width:0}.evidence-group h4{font-size:12px;margin:8px 0;color:var(--muted)}.source-card{border:1px solid var(--border);border-radius:12px;padding:14px;margin:8px 0;background:color-mix(in srgb,var(--panel) 85%,transparent);overflow-wrap:anywhere}.source-meta{display:flex;gap:8px;flex-wrap:wrap;font-size:10px;color:var(--muted)}.source-meta code{margin-left:auto;font-size:10px}.source-text{font-size:12px;line-height:1.8;white-space:pre-wrap;margin:10px 0}.source-card a{font-size:11px;color:var(--accent)}.read-tick{display:flex;gap:8px;align-items:center;font-size:11px;margin:12px 0}.read-tick input{width:auto}.local-disclaimer{font-size:12px;line-height:1.7;padding:10px 12px;border-left:2px solid #b99454;background:rgba(185,148,84,.06);border-radius:4px}
</style>

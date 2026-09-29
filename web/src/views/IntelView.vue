<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import { getJson } from '../api'
import type { Paged, VulnItem } from '../types'

const rows = ref<VulnItem[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const q = ref('')
const severity = ref('')
const hasPoc = ref<'' | 'true' | 'false'>('')
const sort = ref('published_at')
const error = ref('')
const loading = ref(false)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await getJson<Paged<VulnItem>>('/vulns', {
      q: q.value, severity: severity.value, has_poc: hasPoc.value,
      sort: sort.value, page: page.value, page_size: pageSize.value,
    })
    rows.value = res.items
    total.value = res.total
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

function search() { page.value = 1; load() }
const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value))

watch([hasPoc, sort], search)
onMounted(load)
</script>

<template>
  <h1 class="page-title">情报列表</h1>
  <p class="page-subtitle">所有已采集的 AI 安全漏洞情报，支持多维度筛选与检索</p>

  <div class="toolbar">
    <input
      v-model="q"
      placeholder="搜索标题 / 描述 / CVE 编号…"
      style="min-width: 300px"
      @keyup.enter="search"
    />
    <select v-model="severity" @change="search">
      <option value="">全部等级</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <select v-model="hasPoc">
      <option value="">POC 全部</option>
      <option value="true">有 POC</option>
      <option value="false">无 POC</option>
    </select>
    <select v-model="sort">
      <option value="published_at">按发布时间</option>
      <option value="cvss_score">按 CVSS</option>
      <option value="fetched_at">按抓取时间</option>
    </select>
    <button :disabled="loading" @click="search">
      <span v-if="loading" class="spinner" style="margin-right: 6px"></span>
      查询
    </button>
  </div>

  <p v-if="error" class="muted">查询失败：{{ error }}</p>

  <div class="panel fade-in">
    <div class="panel-header">
      <h3>漏洞列表</h3>
      <span class="badge-count">共 {{ total }} 条 · 第 {{ page }} / {{ totalPages() }} 页</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>标题</th>
          <th>等级</th>
          <th>CVSS</th>
          <th>AI 风险</th>
          <th>富化</th>
          <th>发布时间</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="v in rows" :key="v.id" class="fade-in">
          <td>
            <RouterLink :to="`/intel/${v.id}`" style="font-family: 'JetBrains Mono', monospace; font-size: 12px">
              {{ v.cve_id || v.id }}
            </RouterLink>
          </td>
          <td>{{ v.title }}</td>
          <td><span class="badge" :class="v.severity">{{ v.severity }}</span></td>
          <td style="font-family: 'JetBrains Mono', monospace; font-weight: 600">{{ v.cvss_score ?? '—' }}</td>
          <td class="muted">{{ v.ai_risk_category ?? '—' }}</td>
          <td>
            <span class="badge" :class="v.enriched ? 'low' : 'medium'">
              {{ v.enriched ? '已富化' : '待富化' }}
            </span>
          </td>
          <td class="muted" style="font-family: 'JetBrains Mono', monospace; font-size: 12px">{{ v.published_at?.slice(0, 10) ?? '—' }}</td>
        </tr>
        <tr v-if="!rows.length">
          <td colspan="7" class="muted" style="text-align: center; padding: 32px">
            {{ loading ? '加载中…' : '无匹配结果' }}
          </td>
        </tr>
      </tbody>
    </table>

    <div class="toolbar" style="margin: 16px 0 0; justify-content: center">
      <button class="secondary" :disabled="page <= 1" @click="page--; load()">上一页</button>
      <span class="muted" style="font-size: 12px; padding: 0 12px">第 {{ page }} / {{ totalPages() }} 页</span>
      <button class="secondary" :disabled="page >= totalPages()" @click="page++; load()">下一页</button>
    </div>
  </div>
</template>

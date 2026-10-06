<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { BACKEND_DATA_MODE, IS_DEMO_MODE } from '../api'
import TypeLine from '../effects/TypeLine.vue'
defineProps<{ compact?: boolean }>()
const tasks = [
  { n: '01', title: '多源情报采集', to: '/ingest-diagnostics', action: '核对本轮来源与降级', text: '漏洞库、已利用目录、开源生态、厂商公告与论文分开看；登记不等于抓取成功。' },
  { n: '02', title: '情报富化与证据', to: '/intel', action: '检查逐维结论与原文', text: '论文、CVSS、修复指引先看来源和适用范围，再看 hash 与引用；未知不算成功。' },
  { n: '03', title: '证据驱动问答', to: '/qa', action: '询问影响、修复与比较', text: '追踪问题处理阶段，核对回答引用；证据不足允许拒答，模型失败明确兜底。' },
]
</script>
<template>
  <section class="focus" :class="{ compact }" aria-label="赛题九工作流">
    <div class="focus-heading"><div><span class="eyebrow">赛题 9 · AI 安全情报</span><h2 class="fx-underline"><TypeLine text="从采集到回答，每一步都能核对" :speed="34" /></h2></div><span class="mode">{{ IS_DEMO_MODE ? '静态样例 · 非实测' : BACKEND_DATA_MODE === 'live' ? '正式库 · 只读快照' : BACKEND_DATA_MODE === 'fixture' ? '本地实链 · fixture 样例' : '数据模式待核验' }}</span></div>
    <div v-if="!compact" class="task-grid"><RouterLink v-for="task in tasks" :key="task.n" :to="task.to" class="task fx-sheen fx-lift" data-sheen><span class="number">{{ task.n }}</span><h3>{{ task.title }}</h3><p>{{ task.text }}</p><strong>{{ task.action }} →</strong></RouterLink></div>
    <div class="gaps"><strong>当前可信缺口</strong><span>资产匹配 / PoC 自动复现：未实现</span><span>真实准确率与多轮语义：尚未验收</span><span>Agent 优化：观察阶段、模型层、失败兜底与引用，不用执行次数代表质量</span></div>
  </section>
</template>
<style scoped>
.focus{margin-bottom:24px;padding:24px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(120deg,rgba(34,211,238,.07),rgba(129,140,248,.05))}.focus-heading{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.eyebrow{font-size:11px;letter-spacing:1px;color:var(--accent)}h2{margin:8px 0 18px;font-size:22px;line-height:1.5}.mode{font-size:12px;border:1px solid var(--border);padding:6px 10px;border-radius:20px;white-space:nowrap}.task-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.task-grid .task:nth-child(2){--fx-delay:90ms}.task-grid .task:nth-child(3){--fx-delay:180ms}.task{display:block;padding:18px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:10px;color:var(--text);text-decoration:none}.task:hover{border-color:var(--accent)}.task-grid .task{animation:fx-rise .8s var(--fx-ease,cubic-bezier(.22,.61,.36,1)) both;animation-delay:var(--fx-delay,0ms)}@media(prefers-reduced-motion:reduce){.task-grid .task{animation:none}}.number{color:var(--accent);font-size:12px}h3{font-size:17px;margin:8px 0}.task p{color:var(--muted);font-size:13px;line-height:1.8;margin:0 0 14px}.task strong{font-size:12px;color:var(--accent)}.gaps{margin-top:18px;display:flex;flex-wrap:wrap;gap:8px 18px;font-size:12px;line-height:1.8;color:var(--muted)}.gaps strong{color:var(--text)}.compact{padding:18px}.compact h2{font-size:18px;margin-bottom:0}@media(max-width:800px){.task-grid{grid-template-columns:1fr}.focus-heading{flex-direction:column}.focus{padding:18px}h2{font-size:20px}.mode{white-space:normal}}
</style>

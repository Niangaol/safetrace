<script setup lang="ts">
/**
 * 安全 Markdown 渲染 · 组件层。
 *
 * 安全红线：
 * - 只接收 markdown.ts 产出的「节点数据」，用 Vue 渲染真实 DOM；
 *   **绝不使用 v-html / innerHTML**，行内文本一律走 {{ }} 插值自动转义；
 * - 链接只渲染 http/https（协议白名单已在解析层强制），并强制
 *   target="_blank" rel="noreferrer noopener"，域名以纯文本展示供人工核对；
 * - 代码块用 <pre><code>，标题层级来自节点 level（h1~h4）；
 * - prefers-reduced-motion: reduce 时不给任何动效，内容始终默认可见
 *   （不依赖动画揭示内容，父级可自由包裹淡入）。
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { MARKDOWN_MAX_SOURCE_LENGTH, renderMarkdown } from '../markdown'
import type { MarkdownNode } from '../markdown'

const props = withDefaults(defineProps<{ source: string; compact?: boolean }>(), {
  compact: false,
})

const source = computed(() => (typeof props.source === 'string' ? props.source : ''))
/** 空 / 纯空白输入 → []，组件退化为空容器（根元素仍在，便于测试与布局占位）。 */
const nodes = computed<MarkdownNode[]>(() => renderMarkdown(source.value))
const truncated = computed(() => source.value.length > MARKDOWN_MAX_SOURCE_LENGTH)
const sourceLength = computed(() => source.value.length)

/**
 * prefers-reduced-motion 支持：reduce → false（不加任何动效）。
 * 读取时机放在 setup（而非 onMounted），保证 SSR / 无 DOM 环境下也能得到确定值；
 * 无 matchMedia 的环境默认 true——内容始终立即可见，不依赖动画揭示内容。
 */
function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}
const motionOk = ref(!prefersReducedMotion())
let mediaQuery: MediaQueryList | null = null
function syncMotion(): void {
  motionOk.value = !(mediaQuery && mediaQuery.matches)
}
onMounted(() => {
  if (!motionOk.value) return
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
  mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  syncMotion()
  if (typeof mediaQuery.addEventListener === 'function') {
    mediaQuery.addEventListener('change', syncMotion)
  }
})
onBeforeUnmount(() => {
  if (mediaQuery && typeof mediaQuery.removeEventListener === 'function') {
    mediaQuery.removeEventListener('change', syncMotion)
  }
  mediaQuery = null
})

/** 链接域名以纯文本展示；解析失败（理论上不会发生）时退回空串。 */
function linkHost(href: string): string {
  try {
    return new URL(href).host
  } catch {
    return ''
  }
}
</script>

<template>
  <article
    class="markdown-block"
    :class="{
      'markdown-block--compact': compact,
      'markdown-block--empty': nodes.length === 0,
      'markdown-block--enter': motionOk && !compact && nodes.length > 0,
    }"
    data-testid="markdown-block"
    :data-markdown-source-length="sourceLength"
    :data-markdown-truncated="truncated ? 'true' : 'false'"
    :data-markdown-blocks="nodes.length"
    :data-motion="motionOk ? 'full' : 'reduced'"
  >
    <template v-for="(node, index) in nodes" :key="index">
      <component v-if="node.type === 'heading'" :is="'h' + node.level" class="md-heading">
        <template v-for="(inline, i) in node.text" :key="i">
          <strong v-if="inline.type === 'strong'">{{ inline.value }}</strong>
          <em v-else-if="inline.type === 'em'">{{ inline.value }}</em>
          <code v-else-if="inline.type === 'code'">{{ inline.value }}</code>
          <a v-else-if="inline.type === 'link'" class="md-link" :href="inline.href" target="_blank" rel="noreferrer noopener">{{ inline.value }}</a>
          <span v-else>{{ inline.value }}</span>
        </template>
        <template v-for="(inline, i) in node.text" :key="'host-' + i">
          <span v-if="inline.type === 'link' && !compact && linkHost(inline.href)" class="md-link-host" :title="inline.href">{{ linkHost(inline.href) }}</span>
        </template>
      </component>

      <p v-else-if="node.type === 'paragraph'" class="md-paragraph">
        <template v-for="(inline, i) in node.text" :key="i">
          <strong v-if="inline.type === 'strong'">{{ inline.value }}</strong>
          <em v-else-if="inline.type === 'em'">{{ inline.value }}</em>
          <code v-else-if="inline.type === 'code'">{{ inline.value }}</code>
          <a v-else-if="inline.type === 'link'" class="md-link" :href="inline.href" target="_blank" rel="noreferrer noopener">{{ inline.value }}</a>
          <span v-else>{{ inline.value }}</span>
        </template>
        <template v-for="(inline, i) in node.text" :key="'host-' + i">
          <span v-if="inline.type === 'link' && !compact && linkHost(inline.href)" class="md-link-host" :title="inline.href">{{ linkHost(inline.href) }}</span>
        </template>
      </p>

      <ul v-else-if="node.type === 'list' && !node.ordered" class="md-list">
        <li v-for="(item, i) in node.items" :key="i">
          <template v-for="(inline, j) in item" :key="j">
            <strong v-if="inline.type === 'strong'">{{ inline.value }}</strong>
            <em v-else-if="inline.type === 'em'">{{ inline.value }}</em>
            <code v-else-if="inline.type === 'code'">{{ inline.value }}</code>
            <a v-else-if="inline.type === 'link'" class="md-link" :href="inline.href" target="_blank" rel="noreferrer noopener">{{ inline.value }}</a>
            <span v-else>{{ inline.value }}</span>
          </template>
          <template v-for="(inline, j) in item" :key="'host-' + j">
            <span v-if="inline.type === 'link' && !compact && linkHost(inline.href)" class="md-link-host" :title="inline.href">{{ linkHost(inline.href) }}</span>
          </template>
        </li>
      </ul>

      <ol v-else-if="node.type === 'list' && node.ordered" class="md-list">
        <li v-for="(item, i) in node.items" :key="i">
          <template v-for="(inline, j) in item" :key="j">
            <strong v-if="inline.type === 'strong'">{{ inline.value }}</strong>
            <em v-else-if="inline.type === 'em'">{{ inline.value }}</em>
            <code v-else-if="inline.type === 'code'">{{ inline.value }}</code>
            <a v-else-if="inline.type === 'link'" class="md-link" :href="inline.href" target="_blank" rel="noreferrer noopener">{{ inline.value }}</a>
            <span v-else>{{ inline.value }}</span>
          </template>
          <template v-for="(inline, j) in item" :key="'host-' + j">
            <span v-if="inline.type === 'link' && !compact && linkHost(inline.href)" class="md-link-host" :title="inline.href">{{ linkHost(inline.href) }}</span>
          </template>
        </li>
      </ol>

      <blockquote v-else-if="node.type === 'quote'" class="md-quote">
        <template v-for="(inline, i) in node.text" :key="i">
          <strong v-if="inline.type === 'strong'">{{ inline.value }}</strong>
          <em v-else-if="inline.type === 'em'">{{ inline.value }}</em>
          <code v-else-if="inline.type === 'code'">{{ inline.value }}</code>
          <a v-else-if="inline.type === 'link'" class="md-link" :href="inline.href" target="_blank" rel="noreferrer noopener">{{ inline.value }}</a>
          <span v-else>{{ inline.value }}</span>
        </template>
        <template v-for="(inline, i) in node.text" :key="'host-' + i">
          <span v-if="inline.type === 'link' && !compact && linkHost(inline.href)" class="md-link-host" :title="inline.href">{{ linkHost(inline.href) }}</span>
        </template>
      </blockquote>

      <pre v-else-if="node.type === 'code'" class="md-pre" :data-lang="node.lang ?? ''"><code class="md-code">{{ node.text }}</code></pre>

      <hr v-else-if="node.type === 'divider'" class="md-divider" />
    </template>
  </article>
</template>

<style scoped>
.markdown-block {
  color: inherit;
  font-size: 14px;
  line-height: 1.75;
  overflow-wrap: anywhere;
}
.markdown-block--compact {
  font-size: 13px;
  line-height: 1.6;
}
/* 无内容时只保留空容器，不制造额外视觉噪音 */
.markdown-block--empty {
  min-height: 0;
}
.md-heading {
  margin: 14px 0 6px;
  line-height: 1.35;
  font-weight: 650;
}
.md-heading:first-child {
  margin-top: 0;
}
.md-paragraph {
  margin: 0 0 10px;
}
.md-paragraph:last-child {
  margin-bottom: 0;
}
.md-list {
  margin: 0 0 10px;
  padding-left: 22px;
}
.md-list:last-child {
  margin-bottom: 0;
}
.md-list li {
  margin: 2px 0;
}
.md-quote {
  margin: 0 0 10px;
  padding: 2px 12px;
  border-left: 3px solid var(--border, rgba(148, 163, 184, 0.35));
  color: var(--muted, inherit);
}
.md-quote:last-child {
  margin-bottom: 0;
}
.md-pre {
  margin: 0 0 10px;
  padding: 12px 14px;
  border: 1px solid var(--border, rgba(148, 163, 184, 0.35));
  border-radius: var(--radius-sm, 6px);
  background: rgba(15, 23, 42, 0.35);
  overflow-x: auto;
}
.md-pre:last-child {
  margin-bottom: 0;
}
.md-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12.5px;
  white-space: pre;
}
.md-pre .md-code {
  display: block;
}
.md-link {
  color: var(--accent, #38bdf8);
  text-decoration: underline;
  text-underline-offset: 2px;
}
.md-link-host {
  margin-left: 2px;
  font-size: 11px;
  color: var(--muted, rgba(148, 163, 184, 0.9));
  word-break: break-all;
}
.md-link-host::before {
  content: '（';
}
.md-link-host::after {
  content: '）';
}
.md-divider {
  margin: 12px 0;
  border: 0;
  border-top: 1px solid var(--border, rgba(148, 163, 184, 0.35));
}
/* 入场动效：起始不透明 0.55（内容永不隐藏），仅在允许动效时启用 */
@keyframes md-block-enter {
  from {
    opacity: 0.55;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
@media (prefers-reduced-motion: no-preference) {
  .markdown-block--enter {
    animation: md-block-enter 220ms ease-out both;
  }
}
@media (prefers-reduced-motion: reduce) {
  .markdown-block,
  .markdown-block * {
    animation: none !important;
    transition: none !important;
  }
}
</style>

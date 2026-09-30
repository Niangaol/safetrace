<script setup lang="ts">
/**
 * Linux 终端风格窗口容器：红黄绿三点标题栏 + 等宽正文区。
 * 用途：关系表、执行轨迹、编排链路等「日志/清单型」内容。
 * 特性：正文区滚轮滚动、⤢ 点大查看（整屏浮层，Esc/点遮罩还原）、放大时锁背景滚动。
 */
import { onUnmounted, ref, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    title?: string
    status?: string
    /** 最大化时正文区是否填满剩余高度 */
    fill?: boolean
  }>(),
  { title: 'terminal', status: '', fill: true },
)

const maxed = ref(false)

function close() {
  maxed.value = false
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && maxed.value) close()
}
watch(maxed, (m) => {
  document.body.style.overflow = m ? 'hidden' : ''
  if (m) window.addEventListener('keydown', onKey)
  else window.removeEventListener('keydown', onKey)
})
onUnmounted(() => {
  window.removeEventListener('keydown', onKey)
  document.body.style.overflow = ''
})
</script>

<template>
  <div class="tw" :class="{ max: maxed }" role="region" :aria-label="props.title">
    <div class="tw-bar">
      <span class="tw-dots"><i class="d-close" /><i class="d-min" /><i class="d-max" /></span>
      <span class="tw-title">{{ props.title }}<span class="tw-blink">_</span></span>
      <button
        class="tw-btn"
        :title="maxed ? '还原大小（Esc）' : '放大查看'"
        :aria-label="maxed ? '还原大小' : '放大查看'"
        @click="maxed = !maxed"
      >{{ maxed ? '⤡' : '⤢' }}</button>
    </div>
    <div class="tw-body" :class="{ max: maxed && props.fill }">
      <slot />
      <div v-if="props.status" class="tw-status">{{ props.status }}</div>
    </div>
  </div>
  <Teleport to="body">
    <div v-if="maxed" class="tw-backdrop" @click="close"></div>
  </Teleport>
</template>

<style scoped>
.tw {
  display: flex;
  flex-direction: column;
  /* 不要写 `height: 100%`：父容器（flex 行/block）高度是内容决定时，百分比高度会退化成
     auto，终端窗就塌回内容高度。改为由父级 `align-items: stretch` 拉伸；
     块级布局里则自然是内容高度。放大态由 .tw.max 的 inset 决定，不受影响。 */
  min-width: 0;
  background: #0b1020;
  border: 1px solid #2a4060;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 8px 22px rgba(0, 0, 0, 0.32);
}
.tw-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  background: linear-gradient(180deg, #1a2440, #131c30);
  border-bottom: 1px solid #2a4060;
  flex-shrink: 0;
}
.tw-dots {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
}
.tw-dots i {
  width: 11px;
  height: 11px;
  border-radius: 50%;
}
.d-close { background: #f2545b; }
.d-min { background: #f0b429; }
.d-max { background: #34d399; }
.tw-title {
  flex: 1;
  min-width: 0;
  text-align: center;
  font-family: var(--font-mono, 'JetBrains Mono', ui-monospace, monospace);
  font-size: 11.5px;
  color: #a5b7d4;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.tw-blink {
  color: #34d399;
  animation: twBlink 1.2s steps(1) infinite;
}
@keyframes twBlink {
  50% { opacity: 0; }
}
.tw-btn {
  flex-shrink: 0;
  background: transparent;
  border: 1px solid #2a4060;
  border-radius: 5px;
  color: #a5b7d4;
  font-size: 12px;
  line-height: 1;
  padding: 2px 6px;
  cursor: pointer;
}
.tw-btn:hover {
  border-color: #38bdf8;
  color: #7dd3fc;
}
.tw-body {
  background: #0a0f1e;
  /* flex:1 + min-height:0：让正文区吃掉标题栏之外的全部高度并自己滚动，
     这样终端窗高度能跟旁边的主视图严格对齐 */
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  scrollbar-width: thin;
  scrollbar-color: #2a4060 transparent;
}
.tw-body::-webkit-scrollbar { width: 8px; }
.tw-body::-webkit-scrollbar-thumb {
  background: #2a4060;
  border-radius: 4px;
}
.tw-body::-webkit-scrollbar-track { background: transparent; }
.tw-status {
  position: sticky;
  bottom: 0;
  padding: 4px 10px;
  font-family: var(--font-mono, 'JetBrains Mono', ui-monospace, monospace);
  font-size: 10px;
  color: #34d399;
  background: rgba(10, 15, 30, 0.96);
  border-top: 1px solid rgba(42, 64, 96, 0.4);
}
.tw-backdrop {
  position: fixed;
  inset: 0;
  /* 必须高于顶栏（sticky z-index:100） */
  z-index: 200;
  background: rgba(4, 8, 16, 0.55);
}
.tw.max {
  position: fixed;
  inset: 20px;
  z-index: 201;
}
</style>
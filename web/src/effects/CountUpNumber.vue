<script setup lang="ts">
/** 数字滚动到目标值；关闭动效时直接落最终值。结束时的文本就是精确目标值。 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { getMotionIntensity } from './motion-prefs'

const props = withDefaults(defineProps<{ value: number; decimals?: number; duration?: number; prefix?: string; suffix?: string }>(), { decimals: 0, duration: 900, prefix: '', suffix: '' })
const display = ref(format(props.value))
let handle = 0

function format(input: number): string {
  if (!Number.isFinite(input)) return '—'
  return props.prefix + input.toFixed(props.decimals) + props.suffix
}
function cancel() { if (handle) { cancelAnimationFrame(handle); handle = 0 } }
function run(from: number, to: number, duration: number) {
  cancel()
  if (getMotionIntensity() === 'off' || duration <= 0 || from === to) { display.value = format(to); return }
  const start = performance.now()
  const step = (now: number) => {
    const t = Math.min(1, (now - start) / duration)
    const eased = 1 - Math.pow(1 - t, 3)
    display.value = format(from + (to - from) * eased)
    if (t < 1) handle = requestAnimationFrame(step)
    else { display.value = format(to); handle = 0 }
  }
  handle = requestAnimationFrame(step)
}
const ariaLabel = computed(() => format(props.value))
watch(() => props.value, (next, previous) => { run(Number.isFinite(previous) ? previous : next, next, props.duration) })
onBeforeUnmount(cancel)
</script>

<template>
  <span class="fx-tabular" :aria-label="ariaLabel">{{ display }}</span>
</template>

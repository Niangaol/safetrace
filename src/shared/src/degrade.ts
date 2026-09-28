/**
 * 降级统一出口（FB1 / 03-roadmap 红线：兜底必须显式可见，禁止静默兜底）。
 * 所有降级路径必须经过 degrade()：产出 FallbackEvent 入总线 + 返回带 degraded_to 的标记。
 */
import { nextId } from "./time.js";
import type { FallbackEvent, FallbackLayer } from "./types.js";

export interface DegradeOptions {
  layer: FallbackLayer;
  trigger: string;
  degradedOf: string;
  traceId: string;
  /** 用户可见文案（前端渲染降级横幅） */
  label: string;
  recoveryHint?: string;
  /** FallbackEvent 落库回调（总线） */
  emit?: (event: FallbackEvent) => void | Promise<void>;
}

export interface DegradeResult {
  degraded_to: string;
  degraded_state: { label: string; since: string; detail_ref: string };
  recovery_hint?: string;
  event: FallbackEvent;
}

/**
 * 登记一次降级。返回响应侧标记对象；调用方必须把 degraded_to/degraded_state
 * 带进对外响应（HTTP/Answer/RetrievalResponse 均有此字段）。
 */
export async function degrade(opts: DegradeOptions): Promise<DegradeResult> {
  const event: FallbackEvent = {
    event_id: nextId("fb"),
    layer: opts.layer,
    trigger: opts.trigger,
    action_taken: `degrade(${opts.degradedOf})`,
    degraded_of: opts.degradedOf,
    user_visible: true,
    degraded_state: {
      label: opts.label,
      since: new Date().toISOString(),
      detail_ref: opts.traceId,
    },
    recovery_hint: opts.recoveryHint,
    trace_id: opts.traceId,
  };
  await opts.emit?.(event);
  return {
    degraded_to: opts.degradedOf,
    degraded_state: event.degraded_state,
    recovery_hint: opts.recoveryHint,
    event,
  };
}

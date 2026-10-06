/**
 * 指针光影：把指针位置以 CSS 变量写到根与被悬停卡片上（rAF 合帧，绝不每个 mousemove 改样式）。
 * 仅精确指针设备启用；触屏自动跳过。返回清理函数，供组件卸载时调用。
 */
export interface PointerLightOptions { root?: ParentNode; query?: (q: string) => boolean; requestFrame?: (cb: () => void) => number; cancelFrame?: (handle: number) => void; sheenAttribute?: string }
export function attachPointerLight(options: PointerLightOptions = {}): () => void {
 const root = options.root ?? globalThis.document;
 const attribute = options.sheenAttribute ?? "data-sheen";
 const requestFrame = options.requestFrame ?? ((cb) => requestAnimationFrame(cb));
 const cancelFrame = options.cancelFrame ?? ((handle) => cancelAnimationFrame(handle));
 const finePointer = (() => { const query = options.query ?? ((q: string) => globalThis.matchMedia?.(q).matches ?? false); try { return query("(pointer: fine)"); } catch { return false; } })();
 if (!finePointer || !root) return () => {};
 let frame: number | undefined;
 let target: HTMLElement | null = null;
 let clientX = -1; let clientY = -1;
 const flush = () => { frame = undefined;
  const doc = globalThis.document?.documentElement;
  if (doc && clientX >= 0) { doc.style.setProperty("--pointer-x", clientX + "px"); doc.style.setProperty("--pointer-y", clientY + "px"); }
  if (target) { const rect = target.getBoundingClientRect(); if (rect.width > 0 && rect.height > 0) { target.style.setProperty("--sheen-x", ((clientX - rect.left) / rect.width * 100).toFixed(2) + "%"); target.style.setProperty("--sheen-y", ((clientY - rect.top) / rect.height * 100).toFixed(2) + "%"); } }
 };
 const onMove = (event: PointerEvent) => {
  if (event.pointerType && event.pointerType !== "mouse") return;
  const element = (event.target as Element | null)?.closest?.("[" + attribute + "]") as HTMLElement | null;
  if (element !== target) { if (target) target.removeAttribute("data-sheen-hot"); target = element; if (target) target.setAttribute("data-sheen-hot", ""); }
  clientX = event.clientX; clientY = event.clientY;
  if (frame === undefined) frame = requestFrame(flush);
 };
 const onLeave = () => { if (target) { target.removeAttribute("data-sheen-hot"); target = null; } };
 root.addEventListener("pointermove", onMove as EventListener, { passive: true });
 root.addEventListener("pointerleave", onLeave as EventListener, { passive: true });
 return () => { if (frame !== undefined) cancelFrame(frame); frame = undefined; root.removeEventListener("pointermove", onMove as EventListener); root.removeEventListener("pointerleave", onLeave as EventListener); if (target) target.removeAttribute("data-sheen-hot"); target = null; };
}

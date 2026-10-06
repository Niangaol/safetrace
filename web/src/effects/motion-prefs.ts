/** 动效强度偏好：纯本地、纯装饰，不影响任何数据或证据语义。 */
export type MotionIntensity = "full" | "low" | "off";
const STORAGE_KEY = "safetrace_motion_intensity";
const VALUES: readonly MotionIntensity[] = ["full", "low", "off"];
const listeners = new Set<(value: MotionIntensity) => void>();
let current: MotionIntensity | undefined;
export function isMotionIntensity(value: unknown): value is MotionIntensity { return typeof value === "string" && (VALUES as readonly string[]).includes(value); }
function safeStorage(): Storage | undefined { try { const probe = "__safetrace_motion_probe__"; globalThis.localStorage?.setItem(probe, "1"); globalThis.localStorage?.removeItem(probe); return globalThis.localStorage; } catch { return undefined; } }
export function readStoredIntensity(): MotionIntensity | undefined { const raw = safeStorage()?.getItem(STORAGE_KEY); return isMotionIntensity(raw) ? raw : undefined; }
export function systemPrefersReducedMotion(query?: (q: string) => boolean): boolean {
 if (query) { try { return query("(prefers-reduced-motion: reduce)"); } catch { return false; } }
 try { return globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false; } catch { return false; }
}
/** 系统偏好减少动效时默认关闭；用户显式选择后始终尊重用户。 */
export function resolveMotionIntensity(stored: MotionIntensity | undefined, reduced: boolean): MotionIntensity { return stored ?? (reduced ? "off" : "full"); }
export function getMotionIntensity(query?: (q: string) => boolean): MotionIntensity { if (current === undefined) current = resolveMotionIntensity(readStoredIntensity(), systemPrefersReducedMotion(query)); return current; }
export function applyMotionIntensity(value: MotionIntensity, storage: Storage | undefined = safeStorage()): MotionIntensity {
 if (!isMotionIntensity(value)) throw new Error("动效强度必须是 full / low / off");
 current = value; storage?.setItem(STORAGE_KEY, value);
 const root = globalThis.document?.documentElement; if (root) { root.dataset.motion = value; root.style.setProperty("--motion-scale", value === "low" ? "0.45" : value === "off" ? "0" : "1"); }
 for (const listener of [...listeners]) listener(value); return value;
}
export function onMotionIntensityChange(listener: (value: MotionIntensity) => void): () => void { listeners.add(listener); return () => { listeners.delete(listener); }; }
export function motionScale(): number { const value = getMotionIntensity(); return value === "off" ? 0 : value === "low" ? 0.45 : 1; }

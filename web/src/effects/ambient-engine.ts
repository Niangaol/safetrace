/**
 * 纯装饰性环境层：缓慢漂移粒子 + 近距离连线 + 冷色斜向光束 + 间隔雷达涟漪。
 * 不承载任何信息语义；aria-hidden 由挂载组件负责。
 * 全部依赖可注入（canvas / rAF / 随机数 / 可见性 / 时钟），因此可在 node 中被确定性回归。
 */
import { getMotionIntensity, type MotionIntensity } // 显式 .ts 扩展：让特效层能在 node 里被无第三方依赖的烟测直接加载。
from "./motion-prefs.ts";
export interface Point { x: number; y: number; vx: number; vy: number; r: number; a: number; tint: number }
export interface Beam { offset: number; speed: number; width: number; alpha: number; slant: number }
export interface Ping { x: number; y: number; age: number; life: number }
export interface AmbientEngineOptions {
  canvas?: HTMLCanvasElement | null;
  createCanvas?: () => HTMLCanvasElement;
  intensity?: MotionIntensity;
  reducedMotion?: boolean;
  random?: () => number;
  requestFrame?: (callback: (time: number) => void) => number;
  cancelFrame?: (handle: number) => void;
  visible?: () => boolean;
  connectionDistance?: number;
  dprLimit?: number;
  maxConnectionsPerParticle?: number;
  maxParticles?: number;
}
export interface AmbientStats { particles: number; beams: number; pings: number; frames: number; links: number; running: boolean; intensity: MotionIntensity; dpr: number; width: number; height: number }
function clamp(value: number, min: number, max: number): number { return value < min ? min : value > max ? max : value; }
function finite(value: number, fallback: number): number { return Number.isFinite(value) ? value : fallback; }
export class AmbientEngine {
 private canvas: HTMLCanvasElement | null = null;
 private ctx: CanvasRenderingContext2D | null = null;
 private points: Point[] = [];
 private beams: Beam[] = [];
 private pings: Ping[] = [];
 private handle: number | undefined;
 private frames = 0;
 private links = 0;
 private lastTime = 0;
 private nextPing = 0;
 private width = 0;
 private height = 0;
 private dpr = 1;
 private intensity: MotionIntensity;
 private reduced: boolean;
 private running = false;
 private disposed = false;
 private readonly random: () => number;
 private readonly requestFrame: (callback: (time: number) => void) => number;
 private readonly cancelFrame: (handle: number) => void;
 private readonly visible: () => boolean;
 private readonly connectionDistance: number;
 private readonly dprLimit: number;
 private readonly maxConnectionsPerParticle: number;
 private readonly maxParticles: number;
 constructor(options: AmbientEngineOptions = {}) {
  this.intensity = options.intensity ?? getMotionIntensity();
  this.reduced = options.reducedMotion ?? false;
  this.random = options.random ?? Math.random;
  this.requestFrame = options.requestFrame ?? ((callback) => requestAnimationFrame(callback));
  this.cancelFrame = options.cancelFrame ?? ((handle) => cancelAnimationFrame(handle));
  this.visible = options.visible ?? (() => globalThis.document?.visibilityState !== "hidden");
  this.connectionDistance = clamp(finite(options.connectionDistance ?? 132, 132), 40, 260);
  this.dprLimit = clamp(finite(options.dprLimit ?? 2, 2), 1, 3);
  this.maxConnectionsPerParticle = clamp(Math.round(finite(options.maxConnectionsPerParticle ?? 3, 3)), 1, 8);
  this.maxParticles = clamp(Math.round(finite(options.maxParticles ?? 90, 90)), 8, 240);
  if (options.canvas) this.attach(options.canvas);
  else if (options.createCanvas) this.attach(options.createCanvas());
 }
 attach(canvas: HTMLCanvasElement): void {
  if (this.disposed) throw new Error("环境层已释放，不能重新挂载");
  this.canvas = canvas; this.ctx = canvas.getContext("2d");
  if (!this.ctx) throw new Error("无法获取 2D 画布上下文");
  this.resize(canvas.clientWidth || canvas.width || 0, canvas.clientHeight || canvas.height || 0);
 }
 setIntensity(intensity: MotionIntensity): void { if (this.intensity === intensity) return; this.intensity = intensity; this.reflow(); if (this.running) this.renderStatic(); }
 resize(width: number, height: number): void {
  const w = clamp(Math.round(finite(width, 0)), 0, 20000), h = clamp(Math.round(finite(height, 0)), 0, 20000);
  if (!this.canvas || !this.ctx || w <= 0 || h <= 0) return;
  const ratio = clamp(globalThis.devicePixelRatio || 1, 1, this.dprLimit);
  this.width = w; this.height = h; this.dpr = ratio;
  this.canvas.width = Math.round(w * ratio); this.canvas.height = Math.round(h * ratio);
  this.canvas.style.width = w + "px"; this.canvas.style.height = h + "px";
  this.ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  this.reflow();
 }
 private targetCount(): number {
  if (this.intensity === "off") return 0;
  const area = Math.max(this.width * this.height, 1);
  const cores = globalThis.navigator?.hardwareConcurrency ?? 8;
  let count = Math.round(area / 17000);
  if (this.width < 760) count = Math.round(count * 0.55);
  if (cores <= 4) count = Math.round(count * 0.7);
  if (this.intensity === "low") count = Math.round(count * 0.5);
  return clamp(count, 0, this.maxParticles);
 }
 private reflow(): void {
  const target = this.targetCount();
  while (this.points.length > target) this.points.pop();
  while (this.points.length < target) this.points.push(this.spawn());
  const beamTarget = this.intensity === "full" ? 3 : this.intensity === "low" ? 2 : 0;
  while (this.beams.length > beamTarget) this.beams.pop();
  while (this.beams.length < beamTarget) this.beams.push({ offset: this.random(), speed: 0.012 + this.random() * 0.02, width: 120 + this.random() * 220, alpha: 0.05 + this.random() * 0.05, slant: -0.35 + this.random() * 0.7 });
  if (this.intensity !== "full") this.pings.length = 0;
  if (!this.running) this.renderStatic();
 }
 private spawn(): Point { const r = 0.6 + this.random() * 1.9; return { x: this.random() * Math.max(this.width, 1), y: this.random() * Math.max(this.height, 1), vx: (this.random() - 0.5) * 0.16, vy: (this.random() - 0.5) * 0.16, r, a: 0.16 + this.random() * 0.34, tint: this.random() }; }
 private step(dt: number): void {
  const scale = clamp(dt / 16.667, 0.2, 3);
  for (const p of this.points) {
   p.x += p.vx * scale; p.y += p.vy * scale;
   if (p.x < -12) p.x = this.width + 12; if (p.x > this.width + 12) p.x = -12;
   if (p.y < -12) p.y = this.height + 12; if (p.y > this.height + 12) p.y = -12;
   if (!Number.isFinite(p.x) || !Number.isFinite(p.y)) { p.x = this.random() * this.width; p.y = this.random() * this.height; }
  }
  for (const beam of this.beams) { beam.offset += beam.speed * scale * 0.01; if (beam.offset > 1.4) beam.offset = -0.4; }
  for (const ping of this.pings) ping.age += scale;
  this.pings = this.pings.filter(p => p.age < p.life);
  this.nextPing -= scale;
  if (this.nextPing <= 0 && this.intensity === "full" && this.pings.length < 2) { this.pings.push({ x: this.random() * this.width, y: this.random() * this.height, age: 0, life: 150 + this.random() * 90 }); this.nextPing = 420 + this.random() * 480; }
 }
 private draw(): void {
  const ctx = this.ctx; if (!ctx || this.width <= 0 || this.height <= 0) return;
  ctx.clearRect(0, 0, this.width, this.height);
  this.links = 0;
  if (this.intensity !== "off") for (const beam of this.beams) {
   const x = beam.offset * this.width, w = beam.width;
   const gradient = ctx.createLinearGradient(x - w / 2, 0, x + w / 2, this.height);
   gradient.addColorStop(0, "rgba(56,189,248,0)"); gradient.addColorStop(0.45, "rgba(56,189,248," + beam.alpha.toFixed(3) + ")"); gradient.addColorStop(1, "rgba(129,140,248,0)");
   ctx.save(); ctx.globalCompositeOperation = "lighter"; ctx.translate(x, 0); ctx.transform(1, 0, beam.slant, 1, 0, 0); ctx.translate(-x, 0);
   ctx.fillStyle = gradient; ctx.fillRect(x - w / 2, -40, w, this.height + 80); ctx.restore();
  }
  if (this.intensity === "full") for (const ping of this.pings) {
   const t = ping.age / ping.life, radius = 24 + t * Math.min(this.width, this.height) * 0.42, alpha = (1 - t) * 0.16;
   if (!Number.isFinite(radius) || alpha <= 0) continue;
   ctx.beginPath(); ctx.arc(ping.x, ping.y, radius, 0, Math.PI * 2); ctx.lineWidth = 1; ctx.strokeStyle = "rgba(56,189,248," + alpha.toFixed(3) + ")"; ctx.stroke();
  }
  for (const p of this.points) {
   ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
   ctx.fillStyle = p.tint > 0.72 ? "rgba(129,140,248," + p.a.toFixed(3) + ")" : p.tint > 0.4 ? "rgba(56,189,248," + p.a.toFixed(3) + ")" : "rgba(148,197,255," + (p.a * 0.8).toFixed(3) + ")";
   ctx.fill();
  }
  if (this.intensity !== "low") {
   const limit = this.connectionDistance;
   for (let i = 0; i < this.points.length; i++) {
    let drawn = 0; const a = this.points[i]!;
    for (let j = i + 1; j < this.points.length && drawn < this.maxConnectionsPerParticle; j++) {
     const b = this.points[j]!, dx = a.x - b.x, dy = a.y - b.y, distance = Math.hypot(dx, dy);
     if (distance > limit) continue;
     ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
     ctx.strokeStyle = "rgba(56,189,248," + (0.11 * (1 - distance / limit)).toFixed(3) + ")"; ctx.lineWidth = 1; ctx.stroke(); this.links++; drawn++;
    }
   }
  }
 }
 private frame = (time: number): void => {
  if (!this.running || this.disposed) return;
  const previous = this.lastTime || time; this.lastTime = time;
  const dt = clamp(time - previous, 0, 64);
  if (this.intensity === "off" || this.reduced) { this.renderStatic(); this.running = false; return; }
  this.step(dt); this.draw(); this.frames++;
  this.handle = this.requestFrame(this.frame);
 };
 private renderStatic(): void {
  const ctx = this.ctx; if (!ctx || !this.canvas) return;
  ctx.clearRect(0, 0, this.width, this.height);
  if (this.intensity === "off") return;
  this.draw();
 }
 start(): void {
  if (this.disposed || this.running) return;
  if (this.intensity === "off" || this.reduced) { this.renderStatic(); return; }
  if (!this.canvas || !this.ctx) throw new Error("环境层未挂载画布");
  this.running = true; this.lastTime = 0; this.handle = this.requestFrame(this.frame);
 }
 stop(): void { this.running = false; if (this.handle !== undefined) { this.cancelFrame(this.handle); this.handle = undefined; } }
 stats(): AmbientStats { return { particles: this.points.length, beams: this.beams.length, pings: this.pings.length, frames: this.frames, links: this.links, running: this.running, intensity: this.intensity, dpr: this.dpr, width: this.width, height: this.height }; }
 /** 可见性变化时由挂载层调用；隐藏时停在最后一帧，恢复后继续，不重放时间。 */
 syncVisibility(): void { if (this.disposed) return; if (!this.visible()) { this.stop(); return; } if (this.intensity !== "off" && !this.reduced) this.start(); else this.renderStatic(); }
 dispose(): void { this.stop(); this.disposed = true; this.points = []; this.beams = []; this.pings = []; this.canvas = null; this.ctx = null; }
}

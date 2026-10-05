import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { lstat, realpath, opendir, open, stat } from "node:fs/promises";
import path from "node:path";
import { createServer } from "node:net";

export interface RuntimeStatus {
  state: "stopped" | "loading" | "ready" | "failed" | "external";
  managed: boolean;
  model_file_id: string | null;
  model_id: string | null;
  pid: number | null;
  error: string | null;
  base_url: string;
}
export interface LocalModelEntry { id: string; name: string; size_bytes: number; kind: "chat" | "embedding" | "unknown" }
export interface LocalModelRuntimeOptions {
  modelsRoots: string[];
  executableCandidates: string[];
  port?: number;
  spawnImpl?: (command: string, args: string[], options: SpawnOptions) => ChildProcess;
  fetchImpl?: typeof fetch;
  now?: () => number;
}
export interface LocalModelStart { model_file_id: string; context_size: number; gpu_layers: number }
const ALIAS = "safetrace-local-chat";
const LOAD_TIMEOUT = 120_000;
const MAX_DEPTH = 4;
const MAX_ENTRIES = 2_000;
interface Registered extends LocalModelEntry { file: string; root: string; fingerprint: string }
const within = (root: string, target: string) => {
  const rel = path.relative(root, target);
  return rel !== "" && !rel.startsWith(".." + path.sep) && rel !== ".." && !path.isAbsolute(rel);
};
const fingerprint = (s: Awaited<ReturnType<typeof stat>>) => [s.dev, s.ino, s.size, s.mtimeMs].join(":");
const kindOf = (name: string): LocalModelEntry["kind"] => /(?:embed|bge|e5[-_]|nomic|gte[-_])/i.test(name)
  ? "embedding" : /(?:instruct|chat)/i.test(name) ? "chat" : "unknown";

/** Configuration is trusted server-side only. Never accept roots/executables from HTTP input. */
export class LocalModelRuntime {
  private readonly roots: string[];
  private readonly candidates: string[];
  private readonly port: number;
  private readonly spawnImpl: NonNullable<LocalModelRuntimeOptions["spawnImpl"]>;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly salt = randomBytes(32);
  private files = new Map<string, Registered>();
  private child: ChildProcess | null = null;
  private current: RuntimeStatus;
  private disposed = false;
  private queue: Promise<unknown> = Promise.resolve();
  private poll: ReturnType<typeof setTimeout> | null = null;
  private deadline: ReturnType<typeof setTimeout> | null = null;
  private startedAt = 0;
  private controllers = new Set<AbortController>();

  constructor(options: LocalModelRuntimeOptions) {
    this.port = options.port ?? 8090;
    if (!Number.isInteger(this.port) || this.port < 1024 || this.port > 65535) throw new Error("Invalid local runtime port");
    this.roots = [...options.modelsRoots];
    this.candidates = [...options.executableCandidates];
    this.spawnImpl = options.spawnImpl ?? spawn;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
    this.current = { state: "stopped", managed: false, model_file_id: null, model_id: null, pid: null, error: null, base_url: `http://127.0.0.1:${this.port}` };
  }
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }
  private snapshot(): RuntimeStatus { return { ...this.current }; }
  private clearTimers(): void {
    if (this.poll) clearTimeout(this.poll);
    if (this.deadline) clearTimeout(this.deadline);
    this.poll = this.deadline = null;
  }
  private fail(error: string): void { this.current.state = "failed"; this.current.error = error; this.clearTimers(); }

  async catalog(): Promise<LocalModelEntry[]> {
    const found = new Map<string, Registered>();
    let remaining = MAX_ENTRIES;
    const visited = new Set<string>();
    const walk = async (root: string, dir: string, depth: number): Promise<void> => {
      if (depth > MAX_DEPTH || remaining <= 0 || visited.has(dir)) return;
      visited.add(dir);
      const entries = await opendir(dir);
      for await (const entry of entries) {
        if (--remaining < 0) break;
        const candidate = path.join(dir, entry.name);
        try {
          const s = await lstat(candidate);
          if (s.isSymbolicLink()) continue; // includes Windows junctions
          const resolved = await realpath(candidate);
          if (!within(root, resolved)) continue;
          if (s.isDirectory()) { await walk(root, resolved, depth + 1); continue; }
          if (!s.isFile() || !/\.gguf$/i.test(entry.name)) continue;
          const handle = await open(resolved, "r");
          let actual;
          try {
            actual = await handle.stat();
            const magic = Buffer.alloc(4);
            const { bytesRead } = await handle.read(magic, 0, 4, 0);
            if (!actual.isFile() || bytesRead !== 4 || magic.toString("ascii") !== "GGUF") continue;
          } finally { await handle.close(); }
          const id = createHash("sha256").update(this.salt).update(resolved).digest("hex");
          found.set(id, { id, name: entry.name, size_bytes: actual.size, kind: kindOf(entry.name), file: resolved, root, fingerprint: fingerprint(actual) });
        } catch { /* inaccessible or concurrently removed entries are not selectable */ }
      }
    };
    for (const configured of this.roots) {
      try { const root = await realpath(configured); if ((await stat(root)).isDirectory()) await walk(root, root, 0); } catch { /* missing roots */ }
    }
    this.files = found;
    return [...found.values()].map(({ id, name, size_bytes, kind }) => ({ id, name, size_bytes, kind })).sort((a, b) => a.name.localeCompare(b.name));
  }
  private async occupied(): Promise<boolean> {
    return new Promise((resolve) => {
      const server = createServer();
      const timer = setTimeout(() => { server.close(); resolve(true); }, 1_000);
      server.once("error", () => { clearTimeout(timer); resolve(true); });
      server.listen({ host: "127.0.0.1", port: this.port, exclusive: true }, () => {
        server.close(() => { clearTimeout(timer); resolve(false); });
      });
    });
  }
  private async executable(): Promise<string | null> {
    for (const candidate of this.candidates) {
      try {
        if (!path.isAbsolute(candidate) || !/^llama-server(?:\.exe)?$/i.test(path.basename(candidate))) continue;
        const s = await lstat(candidate);
        if (!s.isFile() || s.isSymbolicLink()) continue;
        const resolved = await realpath(candidate);
        if (!/^llama-server(?:\.exe)?$/i.test(path.basename(resolved))) continue;
        return resolved;
      } catch { /* no PATH search and no shell fallback */ }
    }
    return null;
  }
  async start(input: LocalModelStart): Promise<RuntimeStatus> {
    return this.serial(async () => {
      if (this.disposed) throw new Error("Local runtime disposed");
      if (!input || Object.keys(input).some(k => !["model_file_id", "context_size", "gpu_layers"].includes(k)) ||
          typeof input.model_file_id !== "string" || !/^[a-f0-9]{64}$/.test(input.model_file_id) ||
          !Number.isInteger(input.context_size) || input.context_size < 512 || input.context_size > 16384 ||
          !Number.isInteger(input.gpu_layers) || input.gpu_layers < 0 || input.gpu_layers > 99) throw new Error("Invalid local model selection or parameters");
      if (this.child) throw new Error("Local runtime already managed; stop before starting");
      const file = this.files.get(input.model_file_id);
      if (!file || file.kind === "embedding") throw new Error("Model is not a selectable chat GGUF");
      try {
        const s = await lstat(file.file);
        if (!s.isFile() || s.isSymbolicLink() || await realpath(file.file) !== file.file ||
            !within(file.root, file.file) || fingerprint(s) !== file.fingerprint) throw new Error();
        // Rewalk parents to reject a directory replaced with an escaping junction.
        let parent = path.dirname(file.file);
        while (parent !== file.root) {
          if ((await lstat(parent)).isSymbolicLink() || await realpath(parent) !== parent) throw new Error();
          parent = path.dirname(parent);
        }
        if (await realpath(file.root) !== file.root) throw new Error();
        const h = await open(file.file, "r");
        try { const b = Buffer.alloc(4); if ((await h.read(b, 0, 4, 0)).bytesRead !== 4 || b.toString("ascii") !== "GGUF") throw new Error(); } finally { await h.close(); }
      } catch { throw new Error("Model file changed or is unavailable; refresh catalog"); }
      if (await this.occupied()) {
        this.current = { ...this.current, state: "external", managed: false, model_file_id: null, model_id: null, pid: null, error: "Local runtime port is occupied by an unmanaged service" };
        return this.snapshot();
      }
      const executable = await this.executable();
      if (!executable) { this.fail("Approved llama-server executable unavailable"); return this.snapshot(); }
      this.current = { ...this.current, state: "loading", managed: true, model_file_id: file.id, model_id: ALIAS, pid: null, error: null };
      try {
        // Minimal environment: do not propagate application credentials to the model process.
        const env: NodeJS.ProcessEnv = {};
        for (const key of ["SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "HOME", "USERPROFILE", "LD_LIBRARY_PATH"]) if (process.env[key]) env[key] = process.env[key];
        const child = this.spawnImpl(executable, ["--model", file.file, "--host", "127.0.0.1", "--port", String(this.port), "--alias", ALIAS, "--ctx-size", String(input.context_size), "--n-gpu-layers", String(input.gpu_layers)], { shell: false, detached: false, stdio: "ignore", windowsHide: true, cwd: path.dirname(executable), env });
        this.child = child;
        this.current.pid = child.pid ?? null;
        child.once("error", () => {
          if (this.child !== child) return;
          if (child.pid === undefined) { this.child = null; this.current.managed = false; this.current.pid = null; }
          this.fail("Local model process failed");
        });
        child.once("exit", () => {
          if (this.child !== child) return;
          this.child = null;
          this.current.managed = false; this.current.pid = null;
          this.fail("Local model process exited");
        });
        this.startedAt = this.now();
        this.deadline = setTimeout(() => {
          if (this.current.state !== "loading") return;
          // Mark failure immediately, even if status requests are queued; never accept late ready.
          this.fail("Local model loading timed out");
          void this.serial(async () => {
            if (this.current.state === "failed" && this.current.error === "Local model loading timed out") await this.timeout();
          }).catch(() => undefined);
        }, LOAD_TIMEOUT);
        this.deadline.unref();
        this.schedule();
      } catch { this.current.managed = false; this.child = null; this.fail("Unable to start local model process"); }
      return this.snapshot();
    });
  }
  private schedule(): void {
    if (this.disposed || !this.child || this.current.state !== "loading") return;
    this.poll = setTimeout(() => { this.poll = null; void this.status().catch(() => undefined).finally(() => this.schedule()); }, 500);
    this.poll.unref();
  }
  private async json(endpoint: string): Promise<unknown> {
    const controller = new AbortController(); this.controllers.add(controller);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await this.fetchImpl(this.current.base_url + endpoint, { signal: controller.signal, redirect: "error" });
          if (!response.ok) { await response.body?.cancel(); return null; }
          const reader = response.body?.getReader(); if (!reader) return null;
          const chunks: Uint8Array[] = []; let size = 0;
          try {
            while (true) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 65536) throw new Error(); chunks.push(part.value); }
            return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
          } finally { await reader.cancel().catch(() => undefined); }
        })(),
        new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error("Probe timeout")); }, 1_000); })
      ]);
    } finally { if (timer) clearTimeout(timer); controller.abort(); this.controllers.delete(controller); }
  }
  private async timeout(): Promise<void> { await this.stopOwned(); this.fail("Local model loading timed out"); }
  async status(): Promise<RuntimeStatus> {
    return this.serial(async () => {
      if (this.disposed) return this.snapshot();
      if (!this.child) {
        if (await this.occupied()) this.current = { ...this.current, state: "external", managed: false, model_file_id: null, model_id: null, pid: null, error: "Local runtime port is occupied by an unmanaged service" };
        else if (this.current.state === "external") this.current = { ...this.current, state: "stopped", error: null };
        return this.snapshot();
      }
      if (this.current.state !== "loading" && this.current.state !== "ready") return this.snapshot();
      if (this.current.state === "loading" && this.now() - this.startedAt >= LOAD_TIMEOUT) { await this.timeout(); return this.snapshot(); }
      const child = this.child;
      try {
        const health = await this.json("/health") as { status?: unknown } | null;
        const models = await this.json("/v1/models") as { data?: Array<{ id?: unknown }> } | null;
        if (this.child === child && this.snapshot().state !== "failed") {
          if (this.current.state === "loading" && this.now() - this.startedAt >= LOAD_TIMEOUT) { await this.timeout(); return this.snapshot(); }
          if (health?.status === "ok" && Array.isArray(models?.data) && models.data.length === 1 && models.data[0]?.id === ALIAS) {
            this.current.state = "ready"; this.clearTimers();
          } else if (this.current.state === "ready") this.fail("Local model readiness or alias mismatch");
        }
      } catch { if (this.child === child && this.current.state === "ready") this.fail("Local model health check failed"); }
      return this.snapshot();
    });
  }
  private async stopOwned(): Promise<boolean> {
    this.clearTimers();
    for (const c of this.controllers) c.abort();
    const child = this.child;
    if (!child) return true;
    const wait = (signal: NodeJS.Signals) => new Promise<boolean>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) { resolve(true); return; }
      const done = () => { clearTimeout(timer); resolve(true); };
      const timer = setTimeout(() => { child.removeListener("exit", done); resolve(false); }, 1_000);
      child.once("exit", done);
      try { child.kill(signal); } catch { clearTimeout(timer); child.removeListener("exit", done); resolve(false); }
    });
    if (!await wait("SIGTERM") && !await wait("SIGKILL")) { this.fail("Owned local model process did not stop"); return false; }
    if (this.child === child) this.child = null;
    this.current.managed = false; this.current.pid = null;
    return true;
  }
  async stop(): Promise<RuntimeStatus> {
    return this.serial(async () => {
      if (!this.child && await this.occupied()) {
        this.current = { ...this.current, state: "external", managed: false, model_file_id: null, model_id: null, pid: null, error: "Cannot stop an unmanaged local service" };
        return this.snapshot();
      }
      if (await this.stopOwned()) this.current = { ...this.current, state: "stopped", managed: false, model_file_id: null, model_id: null, pid: null, error: null };
      return this.snapshot();
    });
  }
  async dispose(): Promise<void> {
    this.disposed = true;
    for (const c of this.controllers) c.abort();
    await this.serial(async () => {
      if (!await this.stopOwned()) throw new Error("Owned local model process did not stop");
      this.current = { ...this.current, state: "stopped", managed: false, model_file_id: null, model_id: null, pid: null, error: null };
    });
  }
}

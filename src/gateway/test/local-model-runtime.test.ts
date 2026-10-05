import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, symlink, rename, open } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { createServer as netServer } from "node:net";
import { createServer } from "node:http";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { LocalModelRuntime, type LocalModelRuntimeOptions } from "../src/local-model-runtime.js";

class FakeChild extends EventEmitter {
  pid = 43210;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  kills: NodeJS.Signals[] = [];
  kill(signal: NodeJS.Signals = "SIGTERM"): boolean {
    this.kills.push(signal); this.signalCode = signal;
    this.emit("exit", null, signal); return true;
  }
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const readyFetch: typeof fetch = async input => json(String(input).endsWith("/health") ? { status: "ok" } : { data: [{ id: "safetrace-local-chat" }] });
async function freePort(): Promise<number> {
  const s = netServer();
  await new Promise<void>(resolve => s.listen(0, "127.0.0.1", resolve));
  const address = s.address(); assert.ok(address && typeof address !== "string");
  await new Promise<void>((resolve, reject) => s.close(e => e ? reject(e) : resolve()));
  return address.port;
}
async function fixture(t: TestContext, overrides: Partial<LocalModelRuntimeOptions> = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-runtime-"));
  t.after(async () => { await rm(dir, { recursive: true, force: true }); });
  const root = path.join(dir, "models"); await mkdir(root);
  const exe = path.join(dir, "llama-server.exe"); await writeFile(exe, "stub, never executed");
  const model = path.join(root, "tiny-chat.gguf"); await writeFile(model, "GGUF");
  const child = new FakeChild();
  const calls: Array<{ command: string; args: string[]; options: SpawnOptions }> = [];
  const runtime = new LocalModelRuntime({ modelsRoots: [root], executableCandidates: [exe], port: await freePort(), fetchImpl: readyFetch,
    spawnImpl: (command, args, options) => { calls.push({ command, args, options }); return child as unknown as ChildProcess; }, ...overrides });
  t.after(async () => runtime.dispose());
  const select = async () => ({ model_file_id: (await runtime.catalog()).find(x => x.kind === "chat")!.id, context_size: 2048, gpu_layers: 0 });
  return { dir, root, exe, model, child, calls, runtime, select };
}

test("catalog uses opaque ids, bounded nesting, GGUF magic and filename kind hints only", async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.root, "bge-m3.gguf"), "GGUF");
  await writeFile(path.join(f.root, "plain.gguf"), "GGUF");
  await writeFile(path.join(f.root, "bad-chat.gguf"), "NOPE");
  await writeFile(path.join(f.root, "short.gguf"), "GG");
  const nested = path.join(f.root, "a", "b"); await mkdir(nested, { recursive: true });
  await writeFile(path.join(nested, "nested-instruct.GGUF"), "GGUF");
  const deep = path.join(nested, "c", "d", "e"); await mkdir(deep, { recursive: true });
  await writeFile(path.join(deep, "too-deep-chat.gguf"), "GGUF");
  // Sparse 2GB file: catalog must read only its four-byte header, not its body.
  const h = await open(path.join(f.root, "sparse-chat.gguf"), "w");
  await h.write(Buffer.from("GGUF"), 0, 4, 0); await h.truncate(2 ** 31); await h.close();
  const rows = await f.runtime.catalog();
  assert.equal(rows.length, 5);
  assert.ok(rows.every(row => /^[a-f0-9]{64}$/.test(row.id) && !JSON.stringify(row).includes(f.root)));
  assert.equal(rows.find(x => x.name === "bge-m3.gguf")?.kind, "embedding");
  assert.equal(rows.find(x => x.name === "plain.gguf")?.kind, "unknown");
  assert.equal(rows.find(x => x.name === "sparse-chat.gguf")?.size_bytes, 2 ** 31);
  assert.deepEqual(await f.runtime.catalog(), rows);
  await assert.rejects(f.runtime.start({ model_file_id: rows.find(x => x.kind === "embedding")!.id, context_size: 512, gpu_layers: 0 }), /selectable/);
});

test("junction escape and post-catalog replacement cannot select outside models", async t => {
  const f = await fixture(t);
  const outside = path.join(f.dir, "outside"); await mkdir(outside);
  await writeFile(path.join(outside, "escaped-chat.gguf"), "GGUF");
  await symlink(outside, path.join(f.root, "escape"), process.platform === "win32" ? "junction" : "dir");
  assert.equal((await f.runtime.catalog()).length, 1);
  const nested = path.join(f.root, "nested"); await mkdir(nested);
  await writeFile(path.join(nested, "nested-chat.gguf"), "GGUF");
  const id = (await f.runtime.catalog()).find(x => x.name === "nested-chat.gguf")!.id;
  await rename(nested, path.join(f.root, "old"));
  await symlink(outside, nested, process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(f.runtime.start({ model_file_id: id, context_size: 512, gpu_layers: 0 }), /changed/);
  assert.equal(f.calls.length, 0);
});

test("strict request ranges, opaque IDs, arbitrary argv/executables and changed files are rejected", async t => {
  const f = await fixture(t); const input = await f.select();
  for (const invalid of [{ ...input, model_file_id: f.model }, { ...input, context_size: 511 }, { ...input, context_size: 16385 },
    { ...input, context_size: 1024.5 }, { ...input, gpu_layers: -1 }, { ...input, gpu_layers: 100 }, { ...input, gpu_layers: NaN }, { ...input, args: ["--host", "0.0.0.0"] }]) {
    await assert.rejects(f.runtime.start(invalid), /Invalid/);
  }
  await writeFile(f.model, "GGUF changed"); await assert.rejects(f.runtime.start(input), /changed/);
  const arbitrary = await fixture(t, { executableCandidates: [process.execPath, "llama-server.exe", "cmd.exe"] });
  assert.equal((await arbitrary.runtime.start(await arbitrary.select())).state, "failed");
  assert.equal(arbitrary.calls.length, 0);
});

test("start returns loading without fetch, fixed safe argv; health and unique alias gate ready", async t => {
  let health = false; let alias = "other"; let fetchCalls = 0;
  const f = await fixture(t, { fetchImpl: async (input, init) => {
    fetchCalls++; assert.equal(init?.redirect, "error"); assert.ok(init?.signal);
    return json(String(input).endsWith("/health") ? { status: health ? "ok" : "loading" } : { data: [{ id: alias }] });
  } });
  const input = await f.select();
  const start = await f.runtime.start(input);
  assert.equal(start.state, "loading"); assert.equal(fetchCalls, 0); assert.equal(start.managed, true);
  const call = f.calls[0]!;
  assert.equal(call.command, f.exe); assert.equal(call.options.shell, false); assert.equal(call.options.detached, false); assert.equal(call.options.stdio, "ignore");
  assert.deepEqual(call.args.slice(2), ["--host", "127.0.0.1", "--port", new URL(start.base_url).port, "--alias", "safetrace-local-chat", "--ctx-size", "2048", "--n-gpu-layers", "0"]);
  assert.equal((await f.runtime.status()).state, "loading");
  health = true; assert.equal((await f.runtime.status()).state, "loading");
  alias = "safetrace-local-chat"; assert.equal((await f.runtime.status()).state, "ready");
  await assert.rejects(f.runtime.start(input), /already managed/);
  alias = "changed"; assert.equal((await f.runtime.status()).state, "failed");
  assert.equal((await f.runtime.stop()).state, "stopped"); assert.deepEqual(f.child.kills, ["SIGTERM"]);
});

test("occupied port and restarted runtime are external: never adopt or kill", async t => {
  const s = createServer((_, res) => res.end("external"));
  await new Promise<void>(resolve => s.listen(0, "127.0.0.1", resolve));
  t.after(async () => { await new Promise<void>((resolve, reject) => s.close(e => e ? reject(e) : resolve())); });
  const address = s.address(); assert.ok(address && typeof address !== "string");
  const f = await fixture(t, { port: address.port });
  assert.equal((await f.runtime.status()).state, "external");
  assert.equal((await f.runtime.start(await f.select())).state, "external");
  const stopped = await f.runtime.stop(); assert.equal(stopped.state, "external"); assert.equal(stopped.pid, null); assert.equal(stopped.managed, false);
  await f.runtime.dispose(); assert.equal(f.calls.length, 0); assert.equal(f.child.kills.length, 0);
  assert.equal((await fetch(`http://127.0.0.1:${address.port}/health`)).status, 200);
});

test("loading deadline is bounded and diagnostics do not echo transport/process secrets", async t => {
  let now = 1; const f = await fixture(t, { now: () => now, fetchImpl: async () => { throw new Error("SECRET stdout bearer token"); } });
  await f.runtime.start(await f.select()); assert.equal((await f.runtime.status()).state, "loading");
  now += 120_000; const status = await f.runtime.status();
  assert.equal(status.state, "failed"); assert.equal(status.error, "Local model loading timed out"); assert.equal(status.managed, false); assert.equal(f.child.kills.length, 1);
  const g = await fixture(t); await g.runtime.start(await g.select()); g.child.emit("error", new Error("SECRET process path"));
  assert.equal((await g.runtime.status()).error, "Local model process failed");
});

test("hung fetch ignoring AbortSignal still settles and dispose clears ownership/timers", async t => {
  const f = await fixture(t, { fetchImpl: async () => new Promise<Response>(() => {}) });
  await f.runtime.start(await f.select());
  const begin = Date.now(); assert.equal((await f.runtime.status()).state, "loading");
  assert.ok(Date.now() - begin < 3500);
  await f.runtime.dispose(); assert.equal(f.child.kills.length, 1); assert.equal((await f.runtime.status()).state, "stopped");
  await assert.rejects(f.runtime.start(await f.select()), /disposed/);
});

test("concurrent starts serialize ownership and automatic polling reaches ready", async t => {
  const f = await fixture(t); const input = await f.select();
  const outcomes = await Promise.allSettled([f.runtime.start(input), f.runtime.start(input)]);
  assert.equal(outcomes.filter(x => x.status === "fulfilled").length, 1);
  assert.equal(f.calls.length, 1);
  await delay(650);
  assert.equal((await f.runtime.status()).state, "ready");
  await f.runtime.dispose(); assert.equal(f.child.kills.length, 1);
  await delay(550); assert.equal(f.calls.length, 1);
});

test("duplicate aliases, oversized response and HTTP failure never declare ready", async t => {
  for (const body of [{ data: [{ id: "safetrace-local-chat" }, { id: "other" }] }, { data: [{ id: "safetrace-local-chat" }], padding: "x".repeat(65536) }]) {
    const f = await fixture(t, { fetchImpl: async input => json(String(input).endsWith("/health") ? { status: "ok" } : body) });
    await f.runtime.start(await f.select()); assert.equal((await f.runtime.status()).state, "loading");
    await f.runtime.dispose();
  }
  const f = await fixture(t, { fetchImpl: async () => json({ status: "ok" }, 503) });
  await f.runtime.start(await f.select()); assert.equal((await f.runtime.status()).state, "loading");
});

test("spawn exception and asynchronous spawn failure sanitize errors and release unstarted child", async t => {
  const thrown = await fixture(t, { spawnImpl: () => { throw new Error("SECRET command path"); } });
  const result = await thrown.runtime.start(await thrown.select());
  assert.equal(result.state, "failed"); assert.equal(result.managed, false); assert.equal(result.error, "Unable to start local model process");
  const child = new FakeChild(); Object.assign(child, { pid: undefined });
  const f = await fixture(t, { spawnImpl: () => child as unknown as ChildProcess });
  await f.runtime.start(await f.select()); child.emit("error", new Error("SECRET ENOENT"));
  const failed = await f.runtime.status(); assert.equal(failed.state, "failed"); assert.equal(failed.managed, false); assert.equal(failed.pid, null);
  await f.runtime.dispose(); assert.equal(child.kills.length, 0);
});

test("unexpected child exit resets ownership; status snapshots cannot mutate internal state", async t => {
  const f = await fixture(t); const loading = await f.runtime.start(await f.select());
  loading.state = "external"; assert.equal((await f.runtime.status()).state, "ready");
  f.child.exitCode = 1; f.child.emit("exit", 1, null);
  const failed = await f.runtime.status(); assert.equal(failed.state, "failed"); assert.equal(failed.managed, false); assert.equal(failed.pid, null);
  await f.runtime.dispose(); assert.equal(f.child.kills.length, 0);
});

test("local HTTP stub verifies real loopback health and model alias without loading any model", async t => {
  let server: ReturnType<typeof createServer> | undefined;
  const f = await fixture(t, { fetchImpl: fetch, spawnImpl: (_command, args) => {
    const child = new FakeChild(); const port = Number(args[args.indexOf("--port") + 1]);
    server = createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(req.url === "/health" ? { status: "ok" } : { data: [{ id: "safetrace-local-chat" }] })); });
    server.listen(port, "127.0.0.1");
    child.kill = (signal = "SIGTERM") => { server?.closeAllConnections(); server?.close(); child.signalCode = signal; child.emit("exit", null, signal); return true; };
    return child as unknown as ChildProcess;
  } });
  const started = await f.runtime.start(await f.select()); assert.equal(started.state, "loading");
  assert.equal((await f.runtime.status()).state, "ready");
  assert.equal((await f.runtime.stop()).state, "stopped");
  server?.closeAllConnections();
});

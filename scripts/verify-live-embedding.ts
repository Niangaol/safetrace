import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, SqliteEventStore, nextId, sha256Json } from "@safetrace/shared";
import { ModelGateway } from "@safetrace/gateway";

if (!process.argv.includes("--live")) {
  console.log(JSON.stringify({ status: "disabled", model_calls: 0, hint: "Pass --live to authorize one short synthetic embedding request; it may consume credits." }));
} else {
  const path = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(path), { recursive: true });
  const store = new SqliteEventStore(path);
  const trace = nextId("tr");
  try {
    const bus = new EventBus({ store });
    const gateway = new ModelGateway({ bus });
    const profile = gateway.embeddingProfile();
    if (profile.provider === "cache" || !profile.dimension) throw new Error("real profile required");
    const result = await gateway.embed("embedder", ["SafeTrace embedding connectivity check."], trace);
    if (result.degraded_to || result.provider === "cache" || result.model_id !== profile.model_id || result.vectors.length !== 1 || result.vectors[0]!.length !== profile.dimension) throw new Error("fallback or model/dimension mismatch");
    const vector = result.vectors[0]!;
    if (!vector.every(Number.isFinite) || !vector.some(v => v !== 0)) throw new Error("invalid or zero vector");
    console.log(JSON.stringify({ status: "verified", trace_id: trace, provider: result.provider, model_id: result.model_id, model_version: result.model_version, dimension: vector.length, vector_sha256: sha256Json(vector), latency_ms: result.latency_ms, degraded_to: result.degraded_to, input_count: 1, qdrant_verified: false }, null, 2));
  } catch {
    console.error("embedding verification failed; trace_id=" + trace + "; raw provider errors omitted");
    process.exitCode = 1;
  } finally { store.close(); }
}

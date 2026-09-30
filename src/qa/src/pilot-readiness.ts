export interface PilotReadinessOptions {
  qdrant_url: string;
  collection: string;
  embedding_url?: string;
  profile: { provider: string; model_id: string; model_version: string; dimension?: number };
  fetch_impl?: typeof fetch;
  timeout_ms?: number;
}
export interface ReadinessCheck { name: string; status: "ok" | "missing" | "skipped"; detail: string }

function localUrl(raw: string): URL | undefined {
  try {
    const u = new URL(raw);
    if (!["http:", "https:"].includes(u.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(u.hostname) || u.username || u.password || u.search || u.hash) return undefined;
    return u;
  } catch { return undefined; }
}

/** GET-only, loopback-only checks; does NOT prove inference capability or actual vector quality. */
export async function checkPilotReadiness(opts: PilotReadinessOptions) {
  const checks: ReadinessCheck[] = [];
  const fetcher = opts.fetch_impl ?? fetch;
  const get = async (url: string) => fetcher(url, { method: "GET", redirect: "error", signal: AbortSignal.timeout(opts.timeout_ms ?? 1200) });
  const p = opts.profile;
  const real = p.provider !== "cache" && !/cache|hash-256/i.test(p.model_id) && Boolean(p.model_id && p.model_version) && Number.isInteger(p.dimension) && (p.dimension ?? 0) > 0;
  checks.push({ name: "embedder_config", status: real ? "ok" : "missing", detail: real ? "real-provider model ID/version and dimension declared (not measured)" : "configure non-cache embedder, model ID/version and positive capability_flags.dim" });
  const q = localUrl(opts.qdrant_url);
  if (!q) checks.push({ name: "qdrant", status: "skipped", detail: "only credential-free loopback URLs may be probed" });
  else {
    try {
      const response = await get(q.toString().replace(/\/+$/, "") + "/collections");
      const data = response.ok ? await response.json() as { result?: { collections?: unknown } } : undefined;
      if (!response.ok || !Array.isArray(data?.result?.collections)) throw new Error("unavailable");
      checks.push({ name: "qdrant", status: "ok", detail: "Qdrant collection list endpoint reachable" });
      const info = await get(q.toString().replace(/\/+$/, "") + "/collections/" + encodeURIComponent(opts.collection));
      if (info.status === 404) checks.push({ name: "collection", status: "ok", detail: "collection absent; opt-in ingestion will create it" });
      else {
        const payload = info.ok ? await info.json() as { result?: { config?: { params?: { vectors?: { dense?: { size?: number; distance?: string } } } } } } : undefined;
        const dense = payload?.result?.config?.params?.vectors?.dense;
        const compatible = dense?.size === p.dimension && dense?.distance?.toLowerCase() === "cosine";
        checks.push({ name: "collection", status: compatible ? "ok" : "missing", detail: compatible ? "existing named dense vector size/distance match declared configuration" : "existing collection shape incompatible; use a fresh collection/reindex" });
      }
    } catch { checks.push({ name: "qdrant", status: "missing", detail: "loopback Qdrant unreachable, unauthorized or invalid response" }); }
  }
  const e = opts.embedding_url ? localUrl(opts.embedding_url) : undefined;
  if (!real || !e) checks.push({ name: "embedding_service", status: "skipped", detail: "real embedder and credential-free loopback base URL required; no cloud probe performed" });
  else {
    try {
      const response = await get(e.toString().replace(/\/+$/, "") + "/models");
      const payload = response.ok ? await response.json() as { data?: Array<{ id?: string }> } : undefined;
      // llama-server 的 model id 是 GGUF 文件名（如 bge-m3-Q8_0.gguf），配置里写的是短名（bge-m3），
      // 因此除精确匹配外允许「id 以配置模型名开头」的宽松匹配。
      // 只放宽命名形式，不放宽服务语义：端点仍须可达并真的列出模型。
      const listed = Array.isArray(payload?.data) && payload.data.some(model =>
        model.id === p.model_id || (typeof model.id === "string" && model.id.startsWith(p.model_id))
      );
      checks.push({ name: "embedding_service", status: listed ? "ok" : "missing", detail: listed ? "configured model advertised; embedding support and actual dimension remain unverified" : "configured model absent or model-list endpoint unavailable" });
    } catch { checks.push({ name: "embedding_service", status: "missing", detail: "loopback model endpoint unreachable or unauthorized" }); }
  }
  return { prerequisites_ready: checks.length >= 4 && checks.every(c => c.status === "ok"), embedding_inference_verified: false, vector_persistence_verified: false, checks };
}

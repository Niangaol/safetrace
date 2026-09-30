import { loadModelsConfig } from "../src/gateway/src/profiles.js";
import { checkPilotReadiness } from "../src/qa/src/pilot-readiness.js";

const cfg = loadModelsConfig();
const profile = cfg.roles.embedder;
const provider = cfg.providers[profile.provider];
const embeddingUrl = provider?.base_url_env ? process.env[provider.base_url_env] ?? provider.base_url_default : provider?.base_url_default;
const dim = profile.capability_flags.dim;
const report = await checkPilotReadiness({
  qdrant_url: process.env.QDRANT_URL ?? "http://127.0.0.1:6333",
  collection: process.env.QDRANT_COLLECTION ?? "safetrace_sources",
  embedding_url: embeddingUrl,
  profile: { provider: profile.provider, model_id: profile.model_id, model_version: profile.model_version, dimension: typeof dim === "number" ? dim : undefined },
});
console.log(JSON.stringify({ mode: "read_only_loopback_gets", paid_model_calls: 0, ...report }, null, 2));
if (process.argv.includes("--strict") && !report.prerequisites_ready) process.exitCode = 1;

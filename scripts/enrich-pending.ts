import { EventBus, nextId, SqliteEventStore } from "@safetrace/shared";
import type { EnrichmentResult, IntelItem, QualityVerdict } from "@safetrace/shared";
import { runEnrichment } from "@safetrace/enrich";
import { setTimeout as sleep } from "node:timers/promises";
import { resolve } from "node:path";

function readLimit(): number {
  const arg = process.argv.find((value) => value.startsWith("--limit="));
  const value = Number(arg?.slice("--limit=".length) ?? process.env.SAFETRACE_ENRICH_BATCH_SIZE ?? "20");
  if (!Number.isInteger(value) || value < 1 || value > 500) throw new Error("--limit 必须为 1–500 的整数");
  return value;
}

async function readAll<T>(store: SqliteEventStore, topic: "intel.items" | "dq.verdicts" | "enrich.items"): Promise<T[]> {
  const values: T[] = [];
  for (let offset = 0; ; offset += 500) {
    const page = await store.read<T>(topic, offset, 500);
    values.push(...page.map((event) => event.payload));
    if (page.length < 500) return values;
  }
}

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const offline = process.env.SAFETRACE_ENRICH_OFFLINE !== "false";
  const previousOfflineFixtures = process.env.OFFLINE_FIXTURES;
  const limit = readLimit();
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    process.env.OFFLINE_FIXTURES = offline ? "true" : "false";
    const [intelEvents, verdictEvents, enrichEvents] = await Promise.all([
      readAll<IntelItem>(store, "intel.items"),
      readAll<QualityVerdict>(store, "dq.verdicts"),
      readAll<EnrichmentResult>(store, "enrich.items"),
    ]);
    const latestIntel = new Map<string, IntelItem>();
    for (const item of intelEvents) latestIntel.set(item.intel_id, item);
    const accepted = new Set(verdictEvents.filter((item) => item.verdict === "pass" || item.verdict === "degrade").map((item) => item.item_id));
    const completed = new Set(enrichEvents.map((item) => item.intel_id));
    const pending = [...latestIntel.values()].filter((item) => accepted.has(item.intel_id) && !completed.has(item.intel_id));
    const batch = pending.slice(0, limit);
    const traceId = nextId("tr_enrich_batch");
    const delayMs = offline ? 0 : Math.max(3000, Number(process.env.SAFETRACE_ENRICH_DELAY_MS ?? "3000"));
    console.log(JSON.stringify({ mode: offline ? "fixture/offline" : "live", db_path: dbPath, unique_intel_ids: latestIntel.size, accepted_ids: accepted.size, already_enriched: completed.size, pending: pending.length, batch_size: batch.length, delay_ms_between_live_items: delayMs, trace_id: traceId }));
    for (let index = 0; index < batch.length; index++) {
      if (index > 0 && delayMs > 0) await sleep(delayMs);
      const item = batch[index]!;
      await runEnrichment([item], { offline, bus, traceId });
      if ((index + 1) % 5 === 0 || index + 1 === batch.length) console.log("enriched", index + 1, "/", batch.length, item.intel_id);
    }
    console.log(JSON.stringify({ completed_this_batch: batch.length, pending_after_batch: Math.max(0, pending.length - batch.length), mode: offline ? "fixture/offline" : "live", trace_id: traceId }));
  } finally {
    if (previousOfflineFixtures === undefined) delete process.env.OFFLINE_FIXTURES; else process.env.OFFLINE_FIXTURES = previousOfflineFixtures;
    store.close();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

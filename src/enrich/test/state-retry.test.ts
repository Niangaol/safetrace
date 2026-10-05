import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { EventBus, SqliteEventStore, SqliteEnrichmentStateStore } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { runEnrichment } from "../src/index.js";
const item: IntelItem = { intel_id: "a", title: "Log4Shell remote code execution", cve_ids: ["CVE-2021-44228"], source_ids: ["nvd"], published_at: "2021-12-10T00:00:00Z", first_seen_at: "2026-10-01T00:00:00Z", raw_refs: [], source_reliability: 0.9, schema_version: "1.0", entities: { product: "log4j", vendor: "apache", version_range: [], cwe: [], cpes: [] } };
export const scoreSources = [{ source_of_score: "nvd" as const, cvss_v3_base: 10, cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }];
test("fixture paper degraded, independent EPSS fallback, selective retry preserves CVSS", async () => {
 const dir = mkdtempSync(join(tmpdir(), "enrich-retry-")); const path = join(dir, "state.sqlite");
 const events = new SqliteEventStore(path); const stateStore = new SqliteEnrichmentStateStore(path); const bus = new EventBus({ store: events });
 try {
  const now = new Date("2026-10-04T00:00:00Z");
  await runEnrichment([item], { offline: true, now, bus, stateStore, scoreSources });
  assert.equal(stateStore.get("a", "paper")!.status, "degraded");
  assert.equal(stateStore.get("a", "cvss")!.status, "live"); assert.equal(stateStore.get("a", "epss")!.status, "degraded");
  const cvssAttempts = stateStore.get("a", "cvss")!.attempts;
  const latest = (await events.read("enrich.items"))[0]!;
  assert.equal(stateStore.get("a", "paper")!.enrich_event_id, latest.event_id);
  let calls = 0;
  await runEnrichment([{ ...item, first_seen_at: "2026-10-03T00:00:00Z" }], { now, bus, stateStore, scoreSources, fetchImpl: async () => { calls++; throw new Error("should not run"); } });
  assert.equal(calls, 0); assert.equal((await events.read("enrich.items")).length, 1);
  const epss = stateStore.get("a", "epss")!; stateStore.put({ ...epss, retry_after: "2026-10-08T00:00:00Z" });
  await runEnrichment([item], { now: new Date("2026-10-04T00:06:00Z"), bus, stateStore, scoreSources, fetchImpl: async url => { calls++; assert.match(url, /arxiv/); return { ok: true, status: 200, text: async () => '<feed><entry><id>http://arxiv.org/abs/1</id><title>Unrelated astronomy</title><summary>Stars and planets</summary></entry></feed>', json: async () => ({}) }; } });
  assert.equal(calls, 1); assert.equal(stateStore.get("a", "paper")!.status, "empty");
  assert.equal(stateStore.get("a", "cvss")!.attempts, cvssAttempts);
  assert.equal(stateStore.get("a", "cvss")!.status, "live");
  assert.equal(stateStore.get("a", "cvss")!.enrich_event_id, (await events.read("enrich.items")).at(-1)!.event_id);
 } finally { stateStore.close(); events.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("CLI defaults to read-only dry-run and refuses quarantined recheck", async () => {
 const dir = mkdtempSync(join(tmpdir(), "enrich-cli-")); const path = join(dir, "events.sqlite");
 const events = new SqliteEventStore(path); const bus = new EventBus({ store: events });
 try {
  const cliItem = { ...item, intel_id: "intel_cli", source_ids: ["nvd_cve"] };
  const intelEnv = await bus.publish("intel.items", cliItem, { trace_id: "tr_cli" });
  await bus.publish("dq.verdicts", { item_id: "intel_cli", item_kind: "intel", quality_score: 1, dimension_scores: { structure: 1, completeness: 1, consistency: 1, timeliness: 1, sourcing: 1 }, flags: [], verdict: "pass", gate_version: "test" }, { trace_id: "tr_cli", causation_id: intelEnv.event_id });
  const args = ["--import", pathToFileURL(resolve("scripts/test-network-guard.mjs")).href, "--import", "tsx", "scripts/enrich-pending.ts"];
  const env = { ...process.env, SQLITE_PATH: path, SAFETRACE_ENRICH_OFFLINE: "true", SAFETRACE_ENRICH_LLM_ENABLED: "false" };
  const dry = spawnSync(process.execPath, args, { env, encoding: "utf8" });
  assert.equal(dry.status, 0, dry.stderr); assert.equal(JSON.parse(dry.stdout).dry_run, true);
  const db = new DatabaseSync(path, { readOnly: true });
  assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='enrichment_dimension_state'").get(), undefined); db.close();
  assert.equal((await events.read("enrich.items")).length, 0);
  await bus.publish("dq.verdicts", { item_id: "intel_cli", item_kind: "intel", quality_score: 0, dimension_scores: { structure: 0, completeness: 0, consistency: 0, timeliness: 0, sourcing: 0 }, flags: [], verdict: "quarantine", gate_version: "test" });
  const reject = spawnSync(process.execPath, [...args, "--recheck-ids=intel_cli"], { env, encoding: "utf8" });
  assert.equal(reject.status, 1); assert.match(reject.stderr, /DQ/);
 } finally { events.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("EPSS-only retry keeps CVSS, while failed CVSS retry does not fetch live EPSS", async () => {
 const stateStore = new SqliteEnrichmentStateStore(":memory:");
 try {
  const now = new Date("2026-10-04T00:00:00Z");
  await runEnrichment([item], { offline: true, now, stateStore, scoreSources });
  const paper = stateStore.get("a", "paper")!; stateStore.put({ ...paper, retry_after: "2026-10-10T00:00:00Z" });
  let calls = 0;
  await runEnrichment([item], { now: new Date("2026-10-04T00:06:00Z"), stateStore, scoreSources, fetchImpl: async url => { calls++; assert.match(url, /epss/); return { ok: true, status: 200, text: async () => "", json: async () => ({ data: [{ cve: item.cve_ids[0], epss: "0.42", percentile: "0.85", date: "2026-10-04" }] }) }; } });
  assert.equal(calls, 1); assert.equal(stateStore.get("a", "epss")!.status, "live");
  assert.equal(stateStore.get("a", "cvss")!.attempts, 1);
  const cvss = stateStore.get("a", "cvss")!; stateStore.put({ ...cvss, status: "failed", retry_after: null });
  await runEnrichment([item], { now: new Date("2026-10-04T00:07:00Z"), stateStore, scoreSources, fetchImpl: async () => { throw new Error("live EPSS must not be fetched"); } });
  assert.equal(stateStore.get("a", "cvss")!.status, "live");
  assert.equal(stateStore.get("a", "epss")!.attempts, 2);
  assert.equal((stateStore.get("a", "cvss")!.artifact as { epss_score: number }).epss_score, 0.42);
 } finally { stateStore.close(); }
});

import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, nextId, sha256, SqliteEventStore } from "@safetrace/shared";
import { runControlledPage } from "../src/ingest/src/controlled-page.js";

async function main(): Promise<void> {
  const url = process.argv[2];
  if (!url) {
    console.error("用法：FIRECRAWL_ENABLED=true FIRECRAWL_ALLOWED_HOSTS=vendor.example npm run crawl:page -- https://vendor.example/advisory");
    process.exitCode = 2;
    return;
  }
  const traceId = nextId("tr");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    const enabled = process.env.FIRECRAWL_ENABLED === "true";
    const allowedHosts = (process.env.FIRECRAWL_ALLOWED_HOSTS ?? "").split(",").map((host) => host.trim()).filter(Boolean);
    if (!enabled) {
      await bus.recordLineage({
        trace_id: traceId,
        stage: "crawler.cli_gate",
        operation_version: "crawl-page-cli.v1",
        status: "rejected",
        input_refs: [{ kind: "RequestedUrl", id: "url:" + sha256(url), sha256: sha256(url) }],
        decision: { reason: "FIRECRAWL_ENABLED is not true; no network request made" },
      });
      console.error("采集默认关闭；显式设置 FIRECRAWL_ENABLED=true 后再运行。未发起请求。trace_id=" + traceId);
      process.exitCode = 2;
      return;
    }
    if (allowedHosts.length === 0) {
      await bus.recordLineage({
        trace_id: traceId,
        stage: "crawler.cli_gate",
        operation_version: "crawl-page-cli.v1",
        status: "rejected",
        input_refs: [{ kind: "RequestedUrl", id: "url:" + sha256(url), sha256: sha256(url) }],
        decision: { reason: "exact FIRECRAWL_ALLOWED_HOSTS missing; no network request made" },
      });
      console.error("必须设置精确的 FIRECRAWL_ALLOWED_HOSTS；未发起请求。trace_id=" + traceId);
      process.exitCode = 2;
      return;
    }
    const ingestEnabled = process.env.PAGE_INGEST_ENABLED === "true";
    let metadata: unknown;
    let metadataParents: string[] = [];
    if (ingestEnabled) {
      try {
        const metadataPath = process.env.PAGE_INGEST_METADATA;
        if (!metadataPath) throw new Error("metadata file required");
        const text = await readFile(resolve(metadataPath), "utf8");
        metadata = JSON.parse(text) as unknown;
        const loaded = await bus.recordLineage({ trace_id: traceId, stage: "crawler.metadata_load", operation_version: "crawl-page-cli.v1", status: "success",
          input_refs: [{ kind: "MetadataFile", id: "metadata-file", sha256: sha256(text) }], output_refs: [{ kind: "Metadata", id: "metadata-file", sha256: sha256(text) }] });
        metadataParents = [loaded.lineage_id];
      } catch {
        await bus.recordLineage({ trace_id: traceId, stage: "crawler.metadata_load", operation_version: "crawl-page-cli.v1", status: "failed", error: "metadata file missing, unreadable or invalid JSON; no network request made" });
        throw new Error("PAGE_INGEST_METADATA missing/unreadable/invalid; no network request made");
      }
    }
    const run = await runControlledPage(url, {
      enabled: true,
      respect_robots: true,
      allowed_hosts: allowedHosts,
      firecrawl_api_key: process.env.FIRECRAWL_API_KEY,
      firecrawl_base_url: process.env.FIRECRAWL_BASE_URL,
      firecrawl_api_hosts: (process.env.FIRECRAWL_API_HOSTS ?? "api.firecrawl.dev").split(",").map((host) => host.trim()).filter(Boolean),
      bus,
      trace_id: traceId,
      ingest_enabled: ingestEnabled,
      metadata,
      parent_lineage_ids: metadataParents,
    });
    const { page: result, extraction, admission, evidence } = run;
    console.log(JSON.stringify({
      status: admission?.status ?? "untrusted_page_fetched_not_ingested",
      admission_reason: admission?.status === "rejected" ? admission.reason : undefined,
      dq_verdict: admission && admission.status !== "rejected" ? admission.verdict.verdict : undefined,
      source_chunks: evidence?.chunks.length ?? 0,
      index_status: "not_indexed",
      trace_id: result.trace_id,
      lineage_ids: (await bus.readLineage(traceId)).map(record => record.lineage_id),
      extraction_status: extraction.status,
      ...(extraction.status === "candidate" ? { extracted_by: extraction.extracted_by, candidate_cve_ids: extraction.candidate.cve_ids, next_step: extraction.next_step } : { review_id: extraction.review_id, review_reason: extraction.reason }),
      source_url: result.source_url,
      final_url: result.final_url,
      title: result.title,
      fetched_via: result.fetched_via,
      stale: result.stale,
      degraded_to: result.degraded_to,
      content_sha256: result.content_sha256,
      fallback_reasons: result.fallback_reasons,
      text_preview: result.text.slice(0, 500),
    }, null, 2));
  } catch (error) {
    console.error("trace_id=" + traceId + " " + (error instanceof Error ? error.message : String(error)));
    process.exitCode = 1;
  } finally {
    store.close();
  }
}

void main().catch((error: unknown) => {
  console.error("crawler CLI failed: " + (error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});

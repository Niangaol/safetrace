/**
 * Y 线采集流水线（runIngestOnce）：
 * fetch → adapter → dedupe（内存 Map 按 intel）→ dq1 → publish 到总线
 * （raw.docs / intel.items / dq.verdicts，trace_id 贯穿，causation_id 串联）。
 * 闸门口径：只放行 pass/degrade 进 intel.items；review/quarantine 的判定仍入 dq.verdicts（A1/S1 可见）。
 * 所有降级（fixture 回放）都以 FallbackEvent 形式发往 fallback.events，并在返回结果上标记
 * degraded_to（禁止静默兜底）。
 */
import { EventBus, nextId, nowIso, sha256Json } from "@safetrace/shared";
import type { EventStore, FallbackEvent, IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import { parseKev } from "./adapters/kev.js";
import { parseNvd } from "./adapters/nvd.js";
import { parseOsv } from "./adapters/osv.js";
import { parseCveOrg } from "./adapters/cveorg.js";
import { fetchKev } from "./sources/kev.js";
import { fetchNvd } from "./sources/nvd.js";
import { fetchOsv } from "./sources/osv.js";
import { fetchCveOrg } from "./sources/cveorg.js";
import { fetchUsn } from "./sources/usn.js";
import { parseUsn } from "./adapters/usn.js";
import { dedupeAll } from "./dedupe.js";
import { releasedIntelPayload } from "./intel-payload.js";
import { assessQualityVerdict } from "./dq1.js";
import { sha256PayloadRef } from "./common.js";
import type { FetchOpts, ParseResult } from "./common.js";

export interface RunIngestOnceOpts {
  /** 事件存储（S2）：pipeline 内部按 store 构造 EventBus 发事件。 */
  store: EventStore;
  /** 强制离线：所有源直接回放 fixtures 预置样本（冒烟/测试用）。 */
  offline?: boolean;
  /** 只跑指定源（source_id 列表）；缺省为全部已就绪源。 */
  sourceIds?: string[];
  /** 调用方可指定 trace_id 以关联 ingest/enrich/index 全链路。 */
  trace_id?: string;
  /** 单轮抓取条目上限，透传给各源采集器（未实现的源忽略）。 */
  limit?: number;
  /** 调度器单源运行时可传入已持久化的 CVE IDs，作为 OSV/cve.org 查询种子。 */
  cve_ids?: string[];
  /**
   * 源特有入参（按 source_id 透传给对应采集器）。
   * 目前仅 `nvd_cve` 支持：历史回补时传 `{ skipLastModWindow: true, pubWindow }`。
   */
  sourceOptions?: Record<string, Record<string, unknown>>;
}

export interface IngestRunResult {
  trace_id: string;
  /** DQ1 lineage parent for each IntelItem; downstream stages use it to continue the DAG. */
  lineage_parent_by_intel_id: Record<string, string>;
  causation_by_intel_id: Record<string, string>;
  /** 实际抓取到的 RawDoc（离线时为回放样本）。 */
  fetched: RawDoc[];
  /** 适配器解析出的全部 IntelItem（归并前）。 */
  parsed: IntelItem[];
  /** 归并后的全部 IntelItem（含被闸门拦下的）。 */
  merged: IntelItem[];
  /** 每条归并产物的 DQ1 判定。 */
  verdicts: QualityVerdict[];
  /** 本轮登记的全部降级事件（同步发往 fallback.events）。 */
  fallbackEvents: FallbackEvent[];
  /**
   * 降级标记（红线：禁止静默兜底，响应对象必须携带）。
   * 本轮发生过 fixture 回放降级时为 "fixture"；未发生任何降级则不设置。
   */
  degraded_to?: string;
}

interface SourceRunner {
  id: string;
  run: (opts: FetchOpts) => Promise<RawDoc | null>;
  parse: (raw: RawDoc) => Promise<ParseResult>;
}

/** 已就绪源（planned 的 ghsa/arxiv 没有采集器，不参与）。 */
const SOURCE_RUNNERS: SourceRunner[] = [
  { id: "cisa_kev", run: (o) => fetchKev(o), parse: parseKev },
  { id: "nvd_cve", run: (o) => fetchNvd(o), parse: parseNvd },
  { id: "osv", run: (o) => fetchOsv(o), parse: parseOsv },
  { id: "cve_org", run: (o) => fetchCveOrg(o), parse: parseCveOrg },
  { id: "ubuntu_usn", run: (o) => fetchUsn(o), parse: parseUsn },
];

export async function runIngestOnce(opts: RunIngestOnceOpts): Promise<IngestRunResult> {
  const bus = new EventBus({ store: opts.store });
  const traceId = opts.trace_id ?? nextId("tr");
  const wanted = opts.sourceIds;
  const runners = wanted === undefined ? SOURCE_RUNNERS : SOURCE_RUNNERS.filter((r) => wanted.includes(r.id));
  // KEV/NVD 先跑，随后把近期 CVE ID 有界传给 OSV/cve.org；冷启动不再把这两家当成“成功但无数据”。
  const discoveredCves = new Map<string, string>((opts.cve_ids ?? []).map((id) => [id, ""]));
  const candidateCveIds = (): string[] => [...discoveredCves.entries()]
    .sort((a, b) => b[1].localeCompare(a[1]))
    .slice(0, 10)
    .map(([id]) => id);

  const fetched: RawDoc[] = [];
  const parsed: IntelItem[] = [];
  const fallbackEvents: FallbackEvent[] = [];
  /** intel_id → 首次产出它的 raw.docs 事件 id（Envelope 因果锚点）。 */
  const rawEventById = new Map<string, string>();
  /** source_id → 产生该源解析结果的 lineage records，归并时保留多父关系。 */
  const parseLineageBySourceId = new Map<string, Set<string>>();
  const lineageParentByIntelId: Record<string, string> = {};
  const causationByIntelId: Record<string, string> = {};

  for (const runner of runners) {
    const sourceEvents: FallbackEvent[] = [];
    const fetchStarted = nowIso();
    let raw: RawDoc | null;
    let noDataReason: string | undefined;
    try {
      raw = await runner.run({
        offline: opts.offline,
        traceId,
        ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
        ...(opts.sourceOptions?.[runner.id] ?? {}),
        ...(discoveredCves.size > 0 ? { cveIds: candidateCveIds() } : {}),
        onNoData: (reason) => { noDataReason = reason; },
        emit: (event) => { sourceEvents.push(event); },
      });
    } catch {
      await bus.recordLineage({
        trace_id: traceId,
        stage: "ingest.fetch",
        operation_version: runner.id + ".fetch.v1",
        status: "failed",
        started_at: fetchStarted,
        input_refs: [{ kind: "Source", id: runner.id }],
        error: "source fetch failed; see source adapter logs",
      });
      throw new Error("采集失败；lineage 已记录 trace_id=" + traceId + " source_id=" + runner.id);
    }
    if (raw === null) {
      await bus.recordLineage({
        trace_id: traceId,
        stage: "ingest.fetch",
        operation_version: runner.id + ".fetch.v1",
        status: "success",
        started_at: fetchStarted,
        input_refs: [{ kind: "Source", id: runner.id }],
        decision: { reason: noDataReason ?? "source returned no new document" },
      });
      continue;
    }
    fetched.push(raw);
    const rawId = "raw:" + raw.source_id + ":" + raw.external_id;
    const rawMetadataHash = sha256Json(raw);
    let payloadHash: string;
    try {
      payloadHash = await sha256PayloadRef(raw.payload_ref);
    } catch {
      await bus.recordLineage({
        trace_id: traceId,
        stage: "ingest.fetch",
        operation_version: runner.id + ".fetch.v1",
        status: "failed",
        started_at: fetchStarted,
        source: { source_id: raw.source_id, source_type: raw.source_type, url: raw.url, fetched_at: raw.fetched_at, ...(raw.http_etag ? { etag: raw.http_etag } : {}) },
        output_refs: [{ kind: "RawDoc", id: rawId, sha256: rawMetadataHash, url: raw.url }],
        error: "RawDoc payload_ref could not be read and hashed; refusing untraceable ingestion",
      });
      throw new Error("原始 payload 无法读取或计算 SHA-256；拒绝无溯源入库：" + raw.source_id);
    }
    const fetchCompleted = nowIso();
    const fetchLineage = await bus.recordLineage({
      trace_id: traceId,
      stage: "ingest.fetch",
      operation_version: runner.id + ".fetch.v1",
      status: sourceEvents.length > 0 ? "degraded" : "success",
      started_at: fetchStarted,
      completed_at: fetchCompleted,
      input_refs: [{ kind: "Source", id: runner.id, sha256: sha256Json({ source_id: raw.source_id, source_type: raw.source_type, url: raw.url }) }],
      output_refs: [
        { kind: "RawDoc", id: rawId, sha256: rawMetadataHash, url: raw.url },
        { kind: "RawPayload", id: "payload:" + rawId, sha256: payloadHash, url: raw.url },
      ],
      source: { source_id: raw.source_id, source_type: raw.source_type, url: raw.url, fetched_at: raw.fetched_at, ...(raw.http_etag ? { etag: raw.http_etag } : {}) },
      ...(sourceEvents.length > 0 ? { decision: { fallback_to: sourceEvents[0]!.degraded_of, reason: "source emitted " + sourceEvents.length + " fallback event(s)" } } : {}),
    });

    const parseStarted = nowIso();
    let parsedResult: ParseResult;
    try {
      parsedResult = await runner.parse(raw);
    } catch {
      await bus.recordLineage({
        trace_id: traceId,
        parent_lineage_ids: [fetchLineage.lineage_id],
        stage: "ingest.parse",
        operation_version: runner.id + ".parser.v1",
        status: "failed",
        started_at: parseStarted,
        input_refs: [{ kind: "RawDoc", id: rawId, sha256: rawMetadataHash }, { kind: "RawPayload", id: "payload:" + rawId, sha256: payloadHash }],
        error: "source parser failed; no output artifacts published",
      });
      throw new Error("解析失败；lineage 已记录 trace_id=" + traceId + " source_id=" + runner.id);
    }
    raw.parse_warnings = parsedResult.warnings;
    for (const item of parsedResult.items) {
      for (const cveId of item.cve_ids) {
        const publishedAt = item.published_at ?? "";
        const previous = discoveredCves.get(cveId);
        if (previous === undefined || publishedAt > previous) discoveredCves.set(cveId, publishedAt);
      }
    }
    const rawEnv = await bus.publish("raw.docs", raw, { trace_id: traceId, causation_id: null });
    const rawPublish = await bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: [fetchLineage.lineage_id],
      causation_id: rawEnv.event_id,
      stage: "ingest.publish_raw_doc",
      operation_version: "event-bus.publish.v1",
      status: "success",
      input_refs: [{ kind: "RawDoc", id: rawId, sha256: rawMetadataHash }],
      output_refs: [{ kind: "EventEnvelope", id: rawEnv.event_id, sha256: sha256Json(rawEnv) }],
    });
    const fallbackEventRefs = [];
    for (const event of sourceEvents) {
      fallbackEvents.push(event);
      const fallbackEnv = await bus.publish("fallback.events", event, { trace_id: traceId, causation_id: rawEnv.event_id });
      fallbackEventRefs.push({ kind: "FallbackEvent", id: fallbackEnv.event_id, sha256: sha256Json(event) });
      await bus.recordLineage({
        trace_id: traceId,
        parent_lineage_ids: [fetchLineage.lineage_id, rawPublish.lineage_id],
        causation_id: fallbackEnv.event_id,
        stage: "ingest.fallback",
        operation_version: "fallback.events.v1",
        status: "degraded",
        input_refs: [{ kind: "RawDoc", id: rawId, sha256: rawMetadataHash }],
        output_refs: [fallbackEventRefs[fallbackEventRefs.length - 1]!],
        decision: { fallback_to: event.degraded_of, reason: event.action_taken },
      });
    }
    const parseLineage = await bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: [fetchLineage.lineage_id, rawPublish.lineage_id],
      causation_id: rawEnv.event_id,
      stage: "ingest.parse",
      operation_version: runner.id + ".parser.v1",
      status: parsedResult.warnings.length > 0 ? "degraded" : "success",
      started_at: parseStarted,
      input_refs: [{ kind: "RawDoc", id: rawId, sha256: rawMetadataHash }, { kind: "RawPayload", id: "payload:" + rawId, sha256: payloadHash }],
      output_refs: parsedResult.items.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
      source: { source_id: raw.source_id, source_type: raw.source_type, url: raw.url, fetched_at: raw.fetched_at, ...(raw.http_etag ? { etag: raw.http_etag } : {}) },
      ...(parsedResult.warnings.length > 0 ? { decision: { reason: "parser emitted " + parsedResult.warnings.length + " warning(s)" } } : {}),
    });
    for (const item of parsedResult.items) {
      parsed.push(item);
      if (!rawEventById.has(item.intel_id)) rawEventById.set(item.intel_id, rawEnv.event_id);
      for (const sourceId of item.source_ids) {
        const parents = parseLineageBySourceId.get(sourceId) ?? new Set<string>();
        parents.add(parseLineage.lineage_id);
        parseLineageBySourceId.set(sourceId, parents);
      }
    }
  }

  const dedupeStarted = nowIso();
  let dedupeResult: ReturnType<typeof dedupeAll>;
  try {
    dedupeResult = dedupeAll(parsed);
  } catch {
    await bus.recordLineage({
      trace_id: traceId,
      stage: "ingest.dedupe",
      operation_version: "dedupeAll.v1",
      status: "failed",
      started_at: dedupeStarted,
      input_refs: parsed.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
      error: "dedupe failed; no merged output produced",
    });
    throw new Error("去重失败；lineage 已记录 trace_id=" + traceId);
  }
  const mergedItems = dedupeResult.items;
  const parseLineageParents = [...new Set([...parseLineageBySourceId.values()].flatMap((set) => [...set]))];
  const dedupeLineage = await bus.recordLineage({
    trace_id: traceId,
    parent_lineage_ids: parseLineageParents,
    stage: "ingest.dedupe",
    operation_version: "dedupeAll.v1",
    status: "success",
    started_at: dedupeStarted,
    input_refs: parsed.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
    output_refs: mergedItems.map((item) => ({ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) })),
    ...(dedupeResult.links.length > 0 ? { decision: { reason: "merged " + dedupeResult.links.length + " duplicate relation(s)" } } : {}),
  });
  const verdicts: QualityVerdict[] = [];
  for (const item of mergedItems) {
    const dqStarted = nowIso();
    let verdict: QualityVerdict;
    try {
      verdict = assessQualityVerdict(item);
    } catch {
      await bus.recordLineage({
        trace_id: traceId,
        parent_lineage_ids: [dedupeLineage.lineage_id],
        stage: "ingest.dq1",
        operation_version: "dq1.quality-gate.v1",
        status: "failed",
        started_at: dqStarted,
        input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }],
        error: "DQ1 assessment failed",
      });
      throw new Error("DQ1 评估失败；lineage 已记录 trace_id=" + traceId + " intel_id=" + item.intel_id);
    }
    verdicts.push(verdict);
    const rawEventId = rawEventById.get(item.intel_id) ?? null;
    const sourceParents = item.source_ids.flatMap((sourceId) => [...(parseLineageBySourceId.get(sourceId) ?? [])]);
    let intelEventId: string | undefined;
    let dqEnv;
    if (verdict.verdict === "pass" || verdict.verdict === "degrade") {
      // DQ-only metadata stays in parsed/merged audit inputs, not the frozen IntelItem payload.
      const intelEnv = await bus.publish("intel.items", releasedIntelPayload(item), { trace_id: traceId, causation_id: rawEventId });
      intelEventId = intelEnv.event_id;
      causationByIntelId[item.intel_id] = intelEnv.event_id;
      dqEnv = await bus.publish("dq.verdicts", verdict, { trace_id: traceId, causation_id: intelEnv.event_id });
    } else {
      dqEnv = await bus.publish("dq.verdicts", verdict, { trace_id: traceId, causation_id: rawEventId });
      causationByIntelId[item.intel_id] = dqEnv.event_id;
    }
    const dqStatus = verdict.verdict === "pass" ? "success" : verdict.verdict === "degrade" ? "degraded" : verdict.verdict === "review" ? "review" : "rejected";
    const dqLineage = await bus.recordLineage({
      trace_id: traceId,
      parent_lineage_ids: [...new Set([dedupeLineage.lineage_id, ...sourceParents])],
      causation_id: dqEnv.event_id,
      stage: "ingest.dq1",
      operation_version: verdict.gate_version,
      status: dqStatus,
      started_at: dqStarted,
      input_refs: [{ kind: "IntelItem", id: item.intel_id, sha256: sha256Json(item) }],
      output_refs: [
        { kind: "QualityVerdict", id: "dq:" + item.intel_id, sha256: sha256Json(verdict) },
        ...(intelEventId ? [{ kind: "EventEnvelope", id: intelEventId, sha256: sha256Json(releasedIntelPayload(item)) },
          { kind: "ReleasedIntelItem", id: item.intel_id, sha256: sha256Json(releasedIntelPayload(item)) }] : []),
        { kind: "EventEnvelope", id: dqEnv.event_id },
      ],
      decision: { reason: verdict.verdict, quality_score: verdict.quality_score, review_required: verdict.verdict === "review" },
    });
    lineageParentByIntelId[item.intel_id] = dqLineage.lineage_id;
    if (intelEventId) causationByIntelId[item.intel_id] = intelEventId;
  }

  // 红线：fixture 回放是真实发生的降级，必须在响应对象上标记 degraded_to
  const degradedToFixture = fallbackEvents.some((e) => e.degraded_of === "fixture");
  return {
    trace_id: traceId,
    lineage_parent_by_intel_id: lineageParentByIntelId,
    causation_by_intel_id: causationByIntelId,
    fetched,
    parsed,
    merged: mergedItems,
    verdicts,
    fallbackEvents,
    ...(degradedToFixture ? { degraded_to: "fixture" } : {}),
  };
}

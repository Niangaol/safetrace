/**
 * Y 线采集流水线（runIngestOnce）：
 * fetch → adapter → dedupe（内存 Map 按 intel）→ dq1 → publish 到总线
 * （raw.docs / intel.items / dq.verdicts，trace_id 贯穿，causation_id 串联）。
 * 闸门口径：只放行 pass/degrade 进 intel.items；review/quarantine 的判定仍入 dq.verdicts（A1/S1 可见）。
 * 所有降级（fixture 回放）都以 FallbackEvent 形式发往 fallback.events（禁止静默兜底）。
 */
import { EventBus, nextId } from "@safetrace/shared";
import type { EventStore, FallbackEvent, IntelItem, QualityVerdict, RawDoc } from "@safetrace/shared";
import { parseKev } from "./adapters/kev.js";
import { parseNvd } from "./adapters/nvd.js";
import { parseOsv } from "./adapters/osv.js";
import { parseCveOrg } from "./adapters/cveorg.js";
import { fetchKev } from "./sources/kev.js";
import { fetchNvd } from "./sources/nvd.js";
import { fetchOsv } from "./sources/osv.js";
import { fetchCveOrg } from "./sources/cveorg.js";
import { dedupeAll } from "./dedupe.js";
import { assessQualityVerdict } from "./dq1.js";
import type { FetchOpts, ParseResult } from "./common.js";

export interface RunIngestOnceOpts {
  /** 事件存储（S2）：pipeline 内部按 store 构造 EventBus 发事件。 */
  store: EventStore;
  /** 强制离线：所有源直接回放 fixtures 预置样本（冒烟/测试用）。 */
  offline?: boolean;
  /** 只跑指定源（source_id 列表）；缺省为全部已就绪源。 */
  sourceIds?: string[];
}

export interface IngestRunResult {
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
];

export async function runIngestOnce(opts: RunIngestOnceOpts): Promise<IngestRunResult> {
  const bus = new EventBus({ store: opts.store });
  const traceId = nextId("tr");
  const wanted = opts.sourceIds;
  const runners = wanted === undefined ? SOURCE_RUNNERS : SOURCE_RUNNERS.filter((r) => wanted.includes(r.id));

  const fetched: RawDoc[] = [];
  const parsed: IntelItem[] = [];
  const fallbackEvents: FallbackEvent[] = [];
  /** intel_id → 首次产出它的 raw.docs 事件 id（因果链锚点）。 */
  const rawEventById = new Map<string, string>();

  for (const runner of runners) {
    const sourceEvents: FallbackEvent[] = [];
    const raw = await runner.run({
      offline: opts.offline,
      traceId,
      emit: (event) => {
        sourceEvents.push(event);
      },
    });
    if (raw === null) continue;
    fetched.push(raw);
    const parsedResult = await runner.parse(raw);
    raw.parse_warnings = parsedResult.warnings; // Y2 告警落到 RawDoc 契约字段
    const rawEnv = await bus.publish("raw.docs", raw, { trace_id: traceId, causation_id: null });
    for (const event of sourceEvents) {
      fallbackEvents.push(event);
      await bus.publish("fallback.events", event, { trace_id: traceId, causation_id: rawEnv.event_id });
    }
    for (const item of parsedResult.items) {
      parsed.push(item);
      if (!rawEventById.has(item.intel_id)) rawEventById.set(item.intel_id, rawEnv.event_id);
    }
  }

  const { items: mergedItems } = dedupeAll(parsed);
  const verdicts: QualityVerdict[] = [];
  for (const item of mergedItems) {
    const verdict = assessQualityVerdict(item);
    verdicts.push(verdict);
    const rawEventId = rawEventById.get(item.intel_id) ?? null;
    if (verdict.verdict === "pass" || verdict.verdict === "degrade") {
      const intelEnv = await bus.publish("intel.items", item, { trace_id: traceId, causation_id: rawEventId });
      await bus.publish("dq.verdicts", verdict, { trace_id: traceId, causation_id: intelEnv.event_id });
    } else {
      // 闸门拦下：不发 intel.items，但判定必须留痕
      await bus.publish("dq.verdicts", verdict, { trace_id: traceId, causation_id: rawEventId });
    }
  }

  return { fetched, parsed, merged: mergedItems, verdicts, fallbackEvents };
}

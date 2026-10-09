/**
 * 自动匹配编排：情报事件库（intel.items）× 资产快照组件 → 新告警。
 *
 * 三种调用方：
 * - CLI（scripts/assets-scan.ts）：扫描后立刻匹配一轮（组件直接来自本轮 ScanRun）；
 * - 采集守护（src/ingest/src/cli/watch.ts）：每轮采集有新增后匹配一轮，
 *   失败只记日志不打断采集（显式失败，不静默吞掉）；
 * - API（POST /api/v1/assets/scan）：与 CLI 同路径。
 *
 * 幂等：告警按 (component_key, cve_id) 去重，重复匹配不会产生重复提醒。
 */
import type { EventStore, IntelItem } from "@safetrace/shared";
import type { AssetsStore } from "./store.js";
import { matchComponents, type MatchedComponent } from "./matcher.js";
import type { NewAssetAlert } from "./types.js";

export interface AutoMatchReport {
  items_read: number;
  components: number;
  affected: number;
  new_alerts: number;
  skipped_reason: string | null;
}

export interface AutoMatchOptions {
  /** 读取情报事件的分页大小，默认 500。 */
  itemPageSize?: number;
  /** 测试注入的"现在"。 */
  now?: () => Date;
}

/** 把匹配结果展开成告警草稿（一条情报的每个 CVE 各一条）。 */
export function alertsFromMatches(matches: ReturnType<typeof matchComponents>, firstRunId: string): NewAssetAlert[] {
  const out: NewAssetAlert[] = [];
  for (const match of matches) {
    for (const cveId of match.cve_ids) {
      if (!cveId) continue;
      out.push({
        component_key: match.component_key,
        ecosystem: match.ecosystem,
        name: match.name,
        version: match.version,
        repo_path: match.repo_path,
        cve_id: cveId,
        intel_id: match.intel_id,
        matched_rule: match.rule,
        matched_ranges: match.matched_ranges,
        reason: match.reason,
        vendor_unverified: match.vendor_unverified,
        first_run_id: firstRunId,
      });
    }
  }
  return out;
}

/** 分页读取情报事件库里的全部 IntelItem。 */
export async function readAllIntelItems(eventStore: EventStore, pageSize = 500): Promise<IntelItem[]> {
  const size = Math.min(Math.max(pageSize, 1), 5000);
  const items: IntelItem[] = [];
  for (let offset = 0; ; offset += size) {
    const page = await eventStore.read<IntelItem>("intel.items", offset, size);
    for (const event of page) items.push(event.payload);
    if (page.length < size) break;
  }
  return items;
}

/** 纯函数路径：给定组件集合与事件库，产出匹配与告警草稿（不落库）。 */
export async function matchIntelAgainstComponents(
  eventStore: EventStore,
  components: readonly MatchedComponent[],
  firstRunId: string,
  options: AutoMatchOptions = {},
): Promise<{ items_read: number; affected: number; alerts: NewAssetAlert[] }> {
  const items = await readAllIntelItems(eventStore, options.itemPageSize);
  const matches = matchComponents(items, components);
  return { items_read: items.length, affected: matches.length, alerts: alertsFromMatches(matches, firstRunId) };
}

/** 存储驱动路径：对最新一轮快照自动匹配并落库（watch 常驻模式用）。 */
export async function autoMatchIntel(eventStore: EventStore, assets: AssetsStore, options: AutoMatchOptions = {}): Promise<AutoMatchReport> {
  const run = assets.latestRun();
  if (!run) {
    return { items_read: 0, components: 0, affected: 0, new_alerts: 0, skipped_reason: "无本地资产快照，先执行一次扫描（npm run assets:scan）" };
  }
  const components: MatchedComponent[] = assets.latestComponents();
  if (components.length === 0) {
    return { items_read: 0, components: 0, affected: 0, new_alerts: 0, skipped_reason: "最新快照没有解析出任何组件" };
  }
  const matched = await matchIntelAgainstComponents(eventStore, components, run.run_id, options);
  const newAlerts = assets.insertAlerts(matched.alerts, options.now);
  return {
    items_read: matched.items_read,
    components: components.length,
    affected: matched.affected,
    new_alerts: newAlerts,
    skipped_reason: null,
  };
}

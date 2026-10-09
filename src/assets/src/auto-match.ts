/**
 * 自动匹配编排：情报事件库（intel.items）× 各分组最新资产快照 → 新告警。
 *
 * 三种调用方：
 * - CLI（scripts/assets-scan.ts）：扫描某组后立刻匹配该组；
 * - 采集守护（src/ingest/src/cli/watch.ts）：每轮采集有新增后匹配所有启用组，
 *   失败只记日志不打断采集（显式失败，不静默吞掉）；
 * - API（POST /api/v1/assets/scan）：与 CLI 同路径。
 *
 * 幂等：告警按 (group_id, component_key, cve_id) 去重，重复匹配不会产生重复提醒。
 * 同一组件被多个分组监控时，每个分组各自提醒（分组即监控边界）。
 */
import type { EventStore, IntelItem } from "@safetrace/shared";
import type { AssetsStore } from "./store.js";
import { matchComponents, type MatchedComponent } from "./matcher.js";
import type { AssetGroup, NewAssetAlert } from "./types.js";
import { releasedIntel, withReleasedIntel } from "./intel-admission.js";

export interface AutoMatchOptions {
  /** 兼容旧调用选项；准入现用全局一致快照，不再按各 topic 独立分页。 */
  itemPageSize?: number;
  /** 测试注入的"现在"。 */
  now?: () => Date;
}

export interface GroupAutoMatchReport {
  group_id: string;
  group_name: string;
  items_read: number;
  components: number;
  affected: number;
  new_alerts: number;
  skipped_reason: string | null;
}

export interface AllGroupsAutoMatchReport {
  groups: GroupAutoMatchReport[];
  /** 情报只读一批，多组复用；items_read 记这一批的条数。 */
  items_read: number;
  total_affected: number;
  total_new_alerts: number;
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
        group_id: match.group_id,
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

/** Historical export name retained; now returns only latest-version, latest-DQ released Intel. */
export async function readAllIntelItems(eventStore: EventStore, _pageSize = 500): Promise<IntelItem[]> {
  if(!eventStore.readIntelAdmissionEvents)throw new Error("Asset matching refuses independently paginated historical Intel without a coherent DQ snapshot");
  return releasedIntel(eventStore.readIntelAdmissionEvents());
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

/** 单组自动匹配：对该组最新一轮快照的组件做匹配并落库。 */
export async function autoMatchGroup(
  eventStore: EventStore,
  assets: AssetsStore,
  group: AssetGroup,
  options: AutoMatchOptions = {},
): Promise<GroupAutoMatchReport> {
  const base = { group_id: group.group_id, group_name: group.name, items_read: 0, components: 0, affected: 0, new_alerts: 0, skipped_reason: null as string | null };
  const run = assets.latestRun(group.group_id);
  if (!run) {
    return { ...base, skipped_reason: "该组还没有快照，先执行一次扫描" };
  }
  const components: MatchedComponent[] = assets.latestComponents(group.group_id);
  if (components.length === 0) {
    return { ...base, skipped_reason: "该组最新快照没有解析出任何组件" };
  }
  const {matched,newAlerts} = withReleasedIntel(eventStore,items=>{
    const matches=matchComponents(items,components);
    const matched={items_read:items.length,affected:matches.length,alerts:alertsFromMatches(matches,run.run_id)};
    return {matched,newAlerts:assets.insertAlerts(matched.alerts,options.now)};
  });
  return {
    group_id: group.group_id,
    group_name: group.name,
    items_read: matched.items_read,
    components: components.length,
    affected: matched.affected,
    new_alerts: newAlerts,
    skipped_reason: null,
  };
}

/** 所有启用组依次匹配；情报只读一批（多组复用），任一组失败不中断其他组。 */
export async function autoMatchAllGroups(
  eventStore: EventStore,
  assets: AssetsStore,
  options: AutoMatchOptions & { groups?: readonly AssetGroup[] } = {},
): Promise<AllGroupsAutoMatchReport> {
  const groups = options.groups ?? assets.listGroups().filter((g) => g.enabled);
  const items = await readAllIntelItems(eventStore, options.itemPageSize);
  const reports: GroupAutoMatchReport[] = [];
  for (const group of groups) {
    const base = { group_id: group.group_id, group_name: group.name, items_read: items.length, components: 0, affected: 0, new_alerts: 0, skipped_reason: null as string | null };
    try {
      const run = assets.latestRun(group.group_id);
      if (!run) {
        reports.push({ ...base, skipped_reason: "该组还没有快照，先执行一次扫描" });
        continue;
      }
      const components: MatchedComponent[] = assets.latestComponents(group.group_id);
      if (components.length === 0) {
        reports.push({ ...base, skipped_reason: "该组最新快照没有解析出任何组件" });
        continue;
      }
      const {matches,newAlerts}=withReleasedIntel(eventStore,current=>{
        const matches=matchComponents(current,components);
        return {matches,newAlerts:assets.insertAlerts(alertsFromMatches(matches,run.run_id),options.now)};
      });
      reports.push({ ...base, components: components.length, affected: matches.length, new_alerts: newAlerts, skipped_reason: null });
    } catch (error) {
      reports.push({ ...base, skipped_reason: "匹配失败：" + (error instanceof Error ? error.message : String(error)) });
    }
  }
  return {
    groups: reports,
    items_read: items.length,
    total_affected: reports.reduce((sum, r) => sum + r.affected, 0),
    total_new_alerts: reports.reduce((sum, r) => sum + r.new_alerts, 0),
  };
}

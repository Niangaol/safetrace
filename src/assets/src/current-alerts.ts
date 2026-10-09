import type { IntelItem } from "@safetrace/shared";
import { matchComponent, type MatchedComponent } from "./matcher.js";
import type { AlertRow, AssetsStore } from "./store.js";

/** Revalidate historical alerts, never infer safety from absent/unknown matches. */
export function revalidateAssetAlerts(rows:readonly AlertRow[],items:readonly IntelItem[],components:readonly MatchedComponent[]) {
  const byId=new Map(items.map(i=>[i.intel_id,i]));
  return rows.flatMap(row=>{
    const item=byId.get(row.intel_id);
    if(!item || !item.cve_ids.includes(row.cve_id))return [];
    const candidates=components.filter(c=>c.group_id===row.group_id&&c.repo_path===row.repo_path&&c.ecosystem===row.ecosystem&&c.name===row.name);
    const matched=candidates.map(c=>matchComponent(item,c)).find(m=>m.status==='affected');
    if(!matched)return [];
    return [{...row,historical_version:row.version,version:matched.version,matched_rule:matched.rule,matched_ranges:matched.matched_ranges,reason:matched.reason,
      vendor_unverified:true,version_is_range_floor:matched.version_is_range_floor,validation:'latest_dq_and_scan_revalidated',assessment:'potentially_affected'}];
  });
}
export function currentAssetAlertView(store:AssetsStore,items:readonly IntelItem[],groupId?:string) {
  const groups=new Set(store.listGroups().filter(g=>g.enabled).map(g=>g.group_id));
  const components=store.latestComponents(groupId).filter(c=>c.group_id==='adhoc'||groups.has(c.group_id));
  const rows=store.listAlerts({...(groupId?{groupId}:{}),limit:1000});
  const alerts=revalidateAssetAlerts(rows,items,components);
  return {alerts,unread_count:alerts.filter(a=>a.status==='new').length,assessment:'potential_matches_only; absent_alerts_are_not_safety',
    alerts_truncated:store.overview(groupId).alert_count>rows.length};
}

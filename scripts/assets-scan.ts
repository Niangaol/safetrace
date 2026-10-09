/**
 * 本地资产扫描 CLI（A 线入口）· 多分组版。
 *
 * 用法：
 *   npm run assets:scan                                  # 扫描所有启用分组 + 情报匹配
 *   npm run assets:scan -- --group safetrace             # 只扫指定分组
 *   npm run assets:scan -- --group all                   # 显式扫全部启用分组
 *   npm run assets:scan -- --json                        # 机器可读输出
 *   npm run assets:scan -- --no-match                    # 只扫描不匹配
 *   npm run assets:scan -- --db path                     # 覆盖资产库路径
 *   npm run assets:scan -- --list-groups                 # 只列分组（含统计）不扫描
 *
 * 合规：只读本地 manifest 与 git 本地元信息；情报匹配只读本地事件库；零网络请求。
 * 分组定义运行时真相源是 var/assets.sqlite 的 groups 表（Web 可管理）；
 * config/assets-scan.json 仅在 groups 表为空时播种。
 */
import path from "node:path";
import { scanLocalProjects } from "../src/assets/src/scanner.js";
import { AssetsStore } from "../src/assets/src/store.js";
import { defaultAssetsDbPath, groupsFromConfig, scanOptionsForGroup } from "../src/assets/src/config.js";
import { alertsFromMatches } from "../src/assets/src/auto-match.js";
import { withReleasedIntel, withReleasedIntelDb } from "../src/assets/src/intel-admission.js";
import { currentAssetAlertView } from "../src/assets/src/current-alerts.js";
import { matchComponents, type MatchedComponent } from "../src/assets/src/matcher.js";
import { SqliteEventStore } from "@safetrace/shared";
import { defaultDbPath } from "../src/ingest/src/scheduler.js";

const args = process.argv.slice(2);
const has = (flag: string): boolean => args.includes(flag);
const valueOf = (flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

interface GroupReport {
  group_id: string;
  group_name: string;
  run_id: string;
  status: string;
  degraded_to: string | null;
  note: string | null;
  roots: string[];
  repo_count: number;
  component_count: number;
  skipped: number;
  affected: number;
  new_alerts: number;
  alerts: Array<{ name: string; version: string; repo_path: string; cve_id: string; reason: string }>;
}

async function main(): Promise<number> {
  const cwd = process.cwd();
  const dbPath = valueOf("--db") ?? defaultAssetsDbPath(cwd);
  const store = new AssetsStore(dbPath);
  const seeded = store.seedGroups(groupsFromConfig(cwd));
  if (seeded > 0) console.log("[assets] 已从 config/assets-scan.json 播种 " + seeded + " 个分组");

  const groups = store.listGroups();
  if (groups.length === 0) {
    console.error("[assets] 没有任何分组：请在 config/assets-scan.json 配置 groups，或在 Web 资产页添加");
    store.close();
    return 1;
  }

  if (has("--list-groups")) {
    let current:ReturnType<typeof currentAssetAlertView>|undefined;
    try {current=withReleasedIntelDb(defaultDbPath(),items=>currentAssetAlertView(store,items));}
    catch {console.warn("[assets] 最新 DQ 视图不可用，当前风险计数未核验，不回放历史计数为当前风险");}
    for (const row of store.listGroupsWithStats()) {
      const unread=current?current.alerts.filter(a=>a.group_id===row.group_id&&a.status==="new").length:"未核验";
      console.log(
        "[assets][组] " + row.group_id + " | " + row.name + (row.enabled ? "" : "（已停用") +
          " | 根=" + row.roots.join(" | ") + " | 仓库=" + row.repo_count + " 组件=" + row.component_count +
          " 当前未读提醒=" + unread + " | 最近扫描 " + (row.last_finished_at ?? "从未"),
      );
    }
    store.close();
    return 0;
  }

  const groupArg = valueOf("--group");
  const targets = groupArg === undefined || groupArg === "" || groupArg === "all"
    ? groups.filter((g) => g.enabled)
    : groups.filter((g) => g.group_id === groupArg);
  if (targets.length === 0) {
    console.error("[assets] 没有匹配的分组：" + (groupArg ?? "(无启用分组)") + "；现有分组：" + groups.map((g) => g.group_id).join(", "));
    store.close();
    return 1;
  }

  console.log("[assets] 资产库=" + dbPath);
  console.log("[assets] 本轮分组=" + targets.map((g) => g.group_id + "(" + g.name + ")").join(" | "));

  const useMatch = !has("--no-match");
  const eventStore = useMatch ? new SqliteEventStore(defaultDbPath()) : null;
  // Admission is captured after scanning, under the Intel writer reservation before alert commit.

  let admittedItemsCount=0;
  const reports: GroupReport[] = [];
  for (const group of targets) {
    const run = await scanLocalProjects(scanOptionsForGroup(cwd, group));
    const components: MatchedComponent[] = run.repos.flatMap((repo) => repo.components.map((c) => ({ ...c, repo_path: repo.path, group_id: group.group_id })));
    let affected = 0;
    let newAlerts = 0;
    if (eventStore && components.length > 0) {
      withReleasedIntel(eventStore,intelItems=>{
        admittedItemsCount=intelItems.length;
        const matches = matchComponents(intelItems, components);
        affected = matches.length;
        store.saveScanRun(run, matches.length);
        newAlerts = store.insertAlerts(alertsFromMatches(matches, run.run_id));
      });
    } else {
      store.saveScanRun(run, 0);
    }
    const alerts = eventStore?withReleasedIntel(eventStore,items=>currentAssetAlertView(store,items,group.group_id).alerts.filter(a=>a.status==="new").slice(0,50)):[];
    reports.push({
      group_id: group.group_id,
      group_name: group.name,
      run_id: run.run_id,
      status: run.status,
      degraded_to: run.degraded_to,
      note: run.note,
      roots: run.roots,
      repo_count: run.repo_count,
      component_count: run.component_count,
      skipped: run.skipped.length,
      affected,
      new_alerts: newAlerts,
      alerts: alerts.map((a) => ({ name: a.name, version: a.version, repo_path: a.repo_path, cve_id: a.cve_id, reason: a.reason })),
    });
  }
  if (eventStore) eventStore.close();
  store.close();

  if (has("--json")) {
    console.log(JSON.stringify({ db: dbPath, groups: reports }, null, 2));
    return 0;
  }

  for (const report of reports) {
    console.log(
      "[assets][" + report.group_id + "] 仓库=" + report.repo_count + " 组件=" + report.component_count +
        " 跳过=" + report.skipped + (report.degraded_to !== null ? " 显式降级=" + report.degraded_to + (report.note ? "（" + report.note + "）" : "") : ""),
    );
    if (useMatch) {
      console.log("[assets][" + report.group_id + "] 情报=" + admittedItemsCount + " 命中=" + report.affected + " 新增提醒=" + report.new_alerts);
    }
    for (const alert of report.alerts) {
      console.log("[assets][" + report.group_id + "][提醒] " + alert.name + "@" + (alert.version || "未锁定") + " ← " + alert.repo_path + " :: " + alert.cve_id + "（" + alert.reason + "）");
    }
  }
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((err: unknown) => {
    console.error("[assets] 异常：" + (err instanceof Error ? err.stack ?? err.message : String(err)));
    process.exitCode = 1;
  });

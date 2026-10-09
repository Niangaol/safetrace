/**
 * 本地资产扫描 CLI（A 线入口）。
 *
 * 用法：
 *   npm run assets:scan                                  # 按 config/assets-scan.json 扫描 + 情报匹配
 *   node --import tsx scripts/assets-scan.ts --roots A;B # 覆盖扫描根（PATH 分隔符分隔）
 *   node --import tsx scripts/assets-scan.ts --no-match  # 只扫描不匹配
 *   node --import tsx scripts/assets-scan.ts --json      # 机器可读输出
 *   node --import tsx scripts/assets-scan.ts --db path   # 覆盖资产库路径
 *
 * 合规：只读本地 manifest 与 git 本地元信息；情报匹配只读本地事件库；零网络请求。
 */
import path from "node:path";
import { scanLocalProjects } from "../src/assets/src/scanner.js";
import { AssetsStore } from "../src/assets/src/store.js";
import { resolveScanConfig, defaultAssetsDbPath } from "../src/assets/src/config.js";
import { matchIntelAgainstComponents } from "../src/assets/src/auto-match.js";
import type { MatchedComponent } from "../src/assets/src/matcher.js";
import { SqliteEventStore } from "@safetrace/shared";
import { defaultDbPath } from "../src/ingest/src/scheduler.js";

const args = process.argv.slice(2);
const has = (flag: string): boolean => args.includes(flag);
const valueOf = (flag: string): string | undefined => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main(): Promise<number> {
  const cwd = process.cwd();
  const config = resolveScanConfig(cwd);
  const rootsArg = valueOf("--roots");
  const roots = rootsArg !== undefined && rootsArg !== ""
    ? rootsArg.split(path.delimiter).map((r) => r.trim()).filter(Boolean).map((r) => path.resolve(r))
    : config.roots;
  const dbPath = valueOf("--db") ?? defaultAssetsDbPath(cwd);

  console.log("[assets] 扫描根=" + roots.join(" | "));
  console.log("[assets] 资产库=" + dbPath);

  const run = await scanLocalProjects({ roots, ...config.limits, ...(config.skipDirNames.length > 0 ? { skipDirNames: config.skipDirNames } : {}) });
  const components: MatchedComponent[] = run.repos.flatMap((repo) =>
    repo.components.map((c) => ({ ...c, repo_path: repo.path })),
  );

  const store = new AssetsStore(dbPath);
  let matchSummary: string;
  let alertRows: Array<{ name: string; version: string; repo_path: string; cve_id: string; reason: string }> = [];

  if (has("--no-match") || components.length === 0) {
    store.saveScanRun(run, 0);
    matchSummary = components.length === 0 ? "无组件可匹配（快照已保存）" : "--no-match：跳过情报匹配";
  } else {
    const eventStore = new SqliteEventStore(defaultDbPath());
    try {
      const matched = await matchIntelAgainstComponents(eventStore, components, run.run_id);
      store.saveScanRun(run, matched.alerts.length);
      const inserted = store.insertAlerts(matched.alerts);
      matchSummary = "情报=" + matched.items_read + " 命中=" + matched.affected + " 新增提醒=" + inserted + "（去重吞掉 " + (matched.alerts.length - inserted) + "）";
      const alerts = store.listAlerts({ status: "new", limit: 50 });
      alertRows = alerts.map((a) => ({ name: a.name, version: a.version, repo_path: a.repo_path, cve_id: a.cve_id, reason: a.reason }));
    } finally {
      eventStore.close();
    }
  }
  store.close();

  const gitRepos = run.repos.filter((r) => r.is_git).length;
  const summary = {
    run_id: run.run_id,
    status: run.status,
    degraded_to: run.degraded_to,
    note: run.note,
    roots: run.roots,
    repo_count: run.repo_count,
    git_repo_count: gitRepos,
    component_count: run.component_count,
    skipped: run.skipped,
    match: matchSummary,
  };

  if (has("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return 0;
  }

  console.log("[assets] 仓库=" + run.repo_count + "（git " + gitRepos + "） 组件=" + run.component_count + " 跳过=" + run.skipped.length);
  if (run.degraded_to !== null) console.log("[assets] 显式降级 degraded_to=" + run.degraded_to + (run.note ? "（" + run.note + "）" : ""));
  console.log("[assets] " + matchSummary);
  for (const alert of alertRows) {
    console.log("[assets][提醒] " + alert.name + "@" + (alert.version || "未锁定") + " ← " + alert.repo_path + " :: " + alert.cve_id + "（" + alert.reason + "）");
  }
  if (alertRows.length === 0 && matchSummary.includes("新增提醒=0") === false && !has("--no-match")) {
    console.log("[assets] 暂无新提醒");
  }
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((err: unknown) => {
    console.error("[assets] 异常：" + (err instanceof Error ? err.stack ?? err.message : String(err)));
    process.exitCode = 1;
  });

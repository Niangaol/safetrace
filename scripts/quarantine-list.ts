/**
 * E-04：DQ1 隔离区查询/导出（quarantine 表；verdict=quarantine 的审计留存，可查可导出）。
 * 用法：npm run quarantine:list            # 人类可读列表
 *       npm run quarantine:list -- --json  # JSON 导出（含完整 verdict，可复算）
 */
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { SqliteEventStore } from "@safetrace/shared";

async function main(): Promise<void> {
  const asJson = process.argv.includes("--json");
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  try {
    const entries = await store.quarantineEntries();
    if (asJson) {
      console.log(JSON.stringify({ quarantined: entries.length, entries }, null, 2));
      return;
    }
    if (entries.length === 0) {
      console.log("隔离区为空（0 条）。DQ1 verdict=quarantine 的条目落在此表；--json 可导出完整判定。");
      return;
    }
    console.log("隔离区共 " + entries.length + " 条（DQ1 quarantine，硬红线与分数无关）：");
    for (const entry of entries) {
      console.log("- " + entry.quarantine_ref + "｜" + entry.reason + "｜质量分 " + entry.verdict.quality_score.toFixed(2) + "｜" + entry.quarantined_at);
    }
    console.log("");
    console.log("完整判定（dimension_scores/flags/gate_version）用 --json 导出，可复算。");
  } finally {
    store.close();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
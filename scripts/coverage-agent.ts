/**
 * 覆盖率检查 Agent：先审计（只读），再按结论决定是否继续跑批次。
 *
 * 设计原则（与项目红线一致）：
 * - 覆盖率只按 sidecar 真实 live 状态计算；pending 计数、空结果、降级结果都不算覆盖；
 * - 默认只读审计；--apply 才写库，且沿用既有门禁（已验证备份 + 单写 lease + 联网显式开启）；
 * - 达到目标或判定为结构性天花板就停，不空转、不虚报。
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { SqliteEnrichmentStateStore } from "@safetrace/shared";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { auditCoverage } from "../src/qa/src/coverage-audit.js";

function num(name: string, fallback: number, min: number, max: number): number {
  const raw = process.argv.find(v => v.startsWith("--" + name + "="))?.slice(name.length + 3);
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isFinite(value) || value < min || value > max) throw new Error("--" + name + " 必须为 " + min + "–" + max + " 的数字");
  return value;
}
function pct(value: number): string { return (value * 100).toFixed(1) + "%" }

function readAudit(sqlitePath: string, target: number) {
  const snapshot = readIntelIndexSnapshot(sqlitePath);
  const store = new SqliteEnrichmentStateStore(sqlitePath, { readOnly: true });
  try {
    const audit = auditCoverage({ items: [...snapshot.accepted.values()].map(e => e.item), states: store.list(), target });
    return {
      mode: "coverage-agent", db_path: sqlitePath,
      accepted: audit.accepted, covered: audit.covered, uncovered: audit.uncovered,
      coverage: pct(audit.coverage), target: pct(audit.target), target_met: audit.targetMet,
      progress_possible: audit.progressPossible, dimension_live_items: audit.dimensionLiveItems,
      by_dimension: audit.byDimension, uncovered_by_reason: audit.uncoveredByReason,
      next_actions: audit.nextActions, writes: 0,
    };
  } finally { store.close() }
}

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const target = num("target", 0.9, 0, 1);
  const apply = process.argv.includes("--apply");
  const maxBatches = num("batches", 1, 0, 50);
  const offline = process.env.SAFETRACE_ENRICH_OFFLINE !== "false";
  const first = readAudit(dbPath, target);

  if (!apply || maxBatches === 0) { console.log(JSON.stringify(first, null, 2)); return }

  await requireVerifiedBackup(dbPath, process.env.SAFETRACE_VERIFIED_BACKUP_DIR ?? resolve("./.tmp/verified-backups"));
  const release = acquireIntelIndexLease("http://127.0.0.1", "coverage-agent:" + dbPath, fileURLToPath(new URL("../.tmp/data-maintenance-locks/", import.meta.url)));
  const report: Record<string, unknown>[] = [first];
  try {
    for (let batch = 1; batch <= maxBatches; batch++) {
      const before = readAudit(dbPath, target);
      if (before.target_met) { report.push({ batch, skipped: "target already met", coverage: before.coverage }); break }
      if (!before.progress_possible) { report.push({ batch, skipped: "structural ceiling; further runs cannot raise coverage", coverage: before.coverage, uncovered_by_reason: before.uncovered_by_reason }); break }
      await new Promise<void>((done, fail) => {
        const child = spawn(process.execPath, ["--import", "tsx", "scripts/enrich-pending.ts", "--apply", "--dimensions=cvss,epss", "--limit=500"], { stdio: "ignore", env: { ...process.env, SAFETRACE_ENRICH_OFFLINE: offline ? "true" : "false" } });
        child.on("error", fail);
        child.on("exit", code => (code === 0 ? done() : fail(new Error("enrich batch exited " + code))));
      });
      const after = readAudit(dbPath, target);
      report.push({ batch, coverage_before: before.coverage, coverage_after: after.coverage, gained: after.covered - before.covered, target_met: after.target_met, progress_possible: after.progress_possible });
      if (after.target_met) break
    }
    const final = readAudit(dbPath, target);
    report.push({ final: true, accepted: final.accepted, covered: final.covered, coverage: final.coverage, target_met: final.target_met, progress_possible: final.progress_possible, next_actions: final.next_actions });
  } finally { release() }
  console.log(JSON.stringify(report, null, 2));
}

void main().catch(error => { console.error(error); process.exitCode = 1 });

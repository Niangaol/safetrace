/**
 * 覆盖率检查 Agent：先审计（只读），再按结论决定是否继续跑批次。
 *
 * 设计原则（与项目红线一致）：
 * - 覆盖率只按 sidecar 真实 live 状态计算；pending 计数、空结果、降级结果都不算覆盖；
 * - 默认只读审计；--apply 才写库，且沿用既有门禁（已验证备份 + 单写 lease + 联网显式开启）；
 * - 达到目标或判定为结构性天花板就停，不空转、不虚报；
 * - 覆盖数字必须多口径并列输出（A 任一维度 / B 必备维度 cvss / 可选维度 paper /
 *   C 逐维度 / D 投影验证，见 calibers 字段）：单报口径 A 会把"EPSS 一枝独秀"报成
 *   "覆盖 94.9%"，与仪表盘数字对不上时无法归因（2026-10-09 实测踩过，已用文档+字段固化）。
 *   target 达标线按口径 B 判定（2026-10-09 用户决策：paper 作为可选项，不进达标线）。
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { SqliteEnrichmentStateStore } from "@safetrace/shared";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { auditCoverage, DIMENSIONS, REQUIRED_LIVE_DIMENSIONS, OPTIONAL_LIVE_DIMENSIONS } from "../src/qa/src/coverage-audit.js";

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
      // 保留的历史扁平字段等于口径 A；多口径并列见 calibers，禁止只引用 headline
      coverage: pct(audit.coverage), target: pct(audit.target), target_met: audit.targetMet,
      calibers: {
        A_any_dimension_live: { covered: audit.covered, ratio: pct(audit.coverage), definition: "sidecar 任一维度 live 即算覆盖（历史 headline，最宽松）" },
        B_required_dimensions_live: { dimensions: [...REQUIRED_LIVE_DIMENSIONS], covered: audit.coveredRequired, ratio: pct(audit.coverageRequired), definition: "覆盖必备维度 live（target 达标线按此判定；2026-10-09 用户决策 paper 降为可选）" },
        optional_dimensions_live: { dimensions: [...OPTIONAL_LIVE_DIMENSIONS], live: Object.fromEntries(OPTIONAL_LIVE_DIMENSIONS.map(d => [d, audit.dimensionLiveItems[d]])), ratio: Object.fromEntries(OPTIONAL_LIVE_DIMENSIONS.map(d => [d, pct(audit.dimensionLiveRatio[d])])), definition: "可选增强维度：命中算赚到，缺失不影响达标判定" },
        C_per_dimension_live: Object.fromEntries(DIMENSIONS.map(d => [d, { live: audit.dimensionLiveItems[d], ratio: pct(audit.dimensionLiveRatio[d]) }])),
        D_qa_projection_verified: { computed_here: false, definition: "paper/cvss artifact 与原始 NVD/CNA 报文逐字匹配且血缘完整（仪表盘/QA 引用口径，readLiveKnowledgeView 投影验证）；需读取原始 payload，本纯函数审计不计算", see: "docs/TUTORIAL.md §7 富化覆盖率口径" },
      },
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

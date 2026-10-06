import { test } from "node:test";
import assert from "node:assert/strict";
import { auditCoverage } from "../src/coverage-audit.js";
import type { EnrichmentDimensionState, IntelItem } from "@safetrace/shared";

const now = new Date("2026-10-06T12:00:00.000Z");
const item = (id: string): IntelItem => ({ intel_id: id, cve_ids: [], ghsa_ids: [], osv_ids: [], aliases: [], title: "t", summary: "s", entities: [], source_ids: ["s"], published_at: "2026-10-06T00:00:00.000Z", raw_refs: [], schema_version: "1.0" } as unknown as IntelItem);
const state = (intel_id: string, dimension: EnrichmentDimensionState["dimension"], status: EnrichmentDimensionState["status"]): EnrichmentDimensionState => ({ intel_id, dimension, status, input_hash: "h", result_hash: "r", enrich_event_id: "e", retry_after: null, reason: "r", attempts: 1, updated_at: now.toISOString(), artifact: null });

test("覆盖率按真实 live 状态计算，pending/空/降级都不算覆盖", () => {
  const audit = auditCoverage({
    items: [item("a"), item("b"), item("c"), item("d")], now, target: 0.5,
    states: [state("a", "epss", "live"), state("b", "cvss", "live"), state("c", "epss", "empty"), state("d", "cvss", "degraded")],
  });
  assert.equal(audit.accepted, 4);
  assert.equal(audit.covered, 2, "只有 live 才算覆盖");
  assert.equal(audit.coverage, 0.5);
  assert.equal(audit.targetMet, true, "0.5 >= 目标 0.5");
  assert.equal(audit.dimensionLiveItems.epss, 1);
  assert.equal(audit.dimensionLiveItems.cvss, 1);
});

test("未覆盖按原因归类：从未跑过 vs 结构性天花板", () => {
  const audit = auditCoverage({
    items: [item("never"), item("only-epss-empty"), item("cvss-empty")], now,
    states: [state("only-epss-empty", "epss", "empty"), state("cvss-empty", "cvss", "empty")],
  });
  assert.equal(audit.uncoveredByReason["no-state"], 1, "三维度都没状态 → 从未跑过");
  assert.equal(audit.uncoveredByReason["epss-empty-backoff"], 1);
  assert.equal(audit.uncoveredByReason["cvss-no-local-source"], 1);
  assert.equal(audit.progressPossible, true, "还有一条从未跑过，应继续");
  assert.ok(audit.nextActions.some(a => a.includes("从未跑过")));
});

test("结构性天花板：剩余条目全部无可推进原因时判定不再继续", () => {
  const audit = auditCoverage({
    items: [item("a"), item("b")], now,
    states: [state("a", "epss", "empty"), state("b", "cvss", "empty")],
  });
  assert.equal(audit.progressPossible, false, "只剩空结果退避，不该靠空转凑数");
  assert.equal(audit.targetMet, false);
  assert.ok(audit.nextActions.some(a => a.includes("结构性缺口")));
});

test("传输失败算可推进，目标未达时应继续跑", () => {
  const audit = auditCoverage({ items: [item("a")], now, target: 0.9, states: [state("a", "epss", "failed")] });
  assert.equal(audit.uncoveredByReason["epss-failed"], 1);
  assert.equal(audit.progressPossible, true);
  assert.ok(audit.nextActions.some(a => a.includes("传输失败")));
});

test("空输入不造假进度", () => {
  const audit = auditCoverage({ items: [], states: [], now });
  assert.equal(audit.accepted, 0);
  assert.equal(audit.coverage, 0, "空集合不能算 100% 覆盖");
  assert.equal(audit.targetMet, false);
});

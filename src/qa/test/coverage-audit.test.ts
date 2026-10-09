import { test } from "node:test";
import assert from "node:assert/strict";
import { auditCoverage, REQUIRED_LIVE_DIMENSIONS, OPTIONAL_LIVE_DIMENSIONS } from "../src/coverage-audit.js";
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
  assert.equal(audit.dimensionLiveItems.epss, 1);
  assert.equal(audit.dimensionLiveItems.cvss, 1);
  assert.equal(audit.coverageRequired, 0.25, "口径 B 只认 cvss live（b）");
  assert.equal(audit.targetMet, false, "target 按口径 B 判定：0.25 < 0.5，口径 A 的 0.5 不构成达标");
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
  assert.equal(audit.coverageRequired, 0);
  assert.equal(audit.dimensionLiveRatio.paper, 0);
});

test("口径 B：必备维度只有 cvss，paper 可选不计入（2026-10-09 用户决策）", () => {
  const audit = auditCoverage({
    items: [item("cvss-only"), item("paper-only"), item("epss-only"), item("all-three")], now,
    states: [
      state("cvss-only", "cvss", "live"),
      state("paper-only", "paper", "live"),
      state("epss-only", "epss", "live"),
      state("all-three", "paper", "live"), state("all-three", "cvss", "live"), state("all-three", "epss", "live"),
    ],
  });
  assert.equal(audit.covered, 4, "口径 A：任一维度 live 即覆盖，四条都算");
  assert.equal(audit.coverage, 1);
  assert.equal(audit.coveredRequired, 2, "口径 B：只有 cvss live 的 cvss-only/all-three 算；paper-only 不算");
  assert.equal(audit.coverageRequired, 0.5);
  assert.deepEqual([...REQUIRED_LIVE_DIMENSIONS], ["cvss"], "必备维度 = cvss");
  assert.deepEqual([...OPTIONAL_LIVE_DIMENSIONS], ["paper"], "paper 是可选增强");
});

test("口径 C：逐维度 live 比率分开算，可选维度为零不预警、必备维度为零才预警", () => {
  const audit = auditCoverage({
    items: [item("a"), item("b"), item("c"), item("d")], now,
    states: [state("a", "epss", "live"), state("b", "epss", "live"), state("c", "cvss", "live"), state("d", "cvss", "empty")],
  });
  assert.equal(audit.coverage, 0.75, "口径 A 被 EPSS 抬高");
  assert.equal(audit.dimensionLiveRatio.epss, 0.5);
  assert.equal(audit.dimensionLiveRatio.cvss, 0.25);
  assert.equal(audit.dimensionLiveRatio.paper, 0);
  assert.ok(!audit.nextActions.some(a => a.includes("live 为 0")), "可选维度 paper 为 0 不触发预警");
  const noCvss = auditCoverage({ items: [item("a"), item("b")], now, states: [state("a", "epss", "live"), state("b", "paper", "live")] });
  assert.ok(noCvss.nextActions.some(a => a.includes("cvss") && a.includes("live 为 0")), "必备维度 cvss 零 live 必须显式预警");
});

test("target 达标线按口径 B 判定：口径 A 达标但必备维度未达标不算真实达标", () => {
  const epssOnly = auditCoverage({ items: [item("a"), item("b")], now, target: 0.9, states: [state("a", "epss", "live"), state("b", "epss", "live")] });
  assert.equal(epssOnly.coverage, 1, "口径 A 满分");
  assert.equal(epssOnly.coverageRequired, 0);
  assert.equal(epssOnly.targetMet, false, "必备维度 0 覆盖，不得判定达标");
  const withCvss = auditCoverage({ items: [item("a"), item("b")], now, target: 0.5, states: [state("a", "cvss", "live"), state("b", "cvss", "live")] });
  assert.equal(withCvss.coverageRequired, 1);
  assert.equal(withCvss.targetMet, true, "必备维度全覆盖即达标，不要求 paper");
});

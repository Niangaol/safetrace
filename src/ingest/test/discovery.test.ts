/**
 * E-08（本 PR 收缩后的范围）· 持久化交叉验证清单与覆盖视图。
 * 队长的 a46c9f0 已把 CVE 清单接进 pipeline/scheduler（进程内 seen 集合推进）；
 * 本 PR 只补他没覆盖的部分：① 持久视角（重启不丢、能回答"还差多少"）② 时效样本按漏洞去重 ③ 看板取数健壮性。
 * 全部离线：网络用 globalThis.fetch 打桩，不依赖真实外网。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryEventStore, EventBus } from "@safetrace/shared";
import type { FallbackEvent, IntelItem, RawDoc } from "@safetrace/shared";
import { needsBackfillList, planBackfill, coverageGaps, CVE_ORG_CAP } from "../src/discovery.js";
import { fetchCveOrg } from "../src/sources/cveorg.js";

function item(over: Partial<IntelItem> & { intel_id: string; cve_ids: string[]; source_ids: string[] }): IntelItem {
  return {
    title: "t",
    published_at: "2026-10-01T00:00:00.000Z",
    first_seen_at: "2026-10-01T00:00:00.000Z",
    entities: { product: null, vendor: null, version_range: [], cwe: [], cpes: [] },
    raw_refs: ["tmp/ingest-cache/live.json"],
    source_reliability: 0.9,
    schema_version: "1.0",
    ...over,
  };
}

function rawDoc(sourceId: string, externalId: string): RawDoc {
  return {
    source_id: sourceId,
    source_type: sourceId === "osv" ? "osv" : "cve_org",
    external_id: externalId,
    url: "https://example.invalid",
    fetched_at: "2026-10-01T00:00:00.000Z",
    content_type: "json",
    payload_ref: "tmp/ingest-cache/x.json",
  };
}

async function seeded(items: IntelItem[], docs: RawDoc[] = []): Promise<MemoryEventStore> {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  for (const it of items) await bus.publish("intel.items", it, { trace_id: "tr" });
  for (const d of docs) await bus.publish("raw.docs", d, { trace_id: "tr" });
  return store;
}

test("discovery：覆盖判定只认该源自己的 raw.doc external_id（不用归并后的 source_ids）", async () => {
  const store = await seeded(
    [
      item({ intel_id: "intel_a", cve_ids: ["CVE-2026-0001"], source_ids: ["nvd_cve", "cve_org"] }),
      item({ intel_id: "intel_b", cve_ids: ["CVE-2026-0002"], source_ids: ["nvd_cve"] }),
      // 归并把姊妹号 0003 带进同一条 intel：source_ids 含 cve_org 并不代表它验证过 0003
      item({ intel_id: "intel_c", cve_ids: ["CVE-2026-0001", "CVE-2026-0003"], source_ids: ["cisa_kev", "cve_org"] }),
    ],
    [rawDoc("cve_org", "CVE-2026-0001")], // 它真正查过的只有 0001
  );

  const plan = await planBackfill(store, "cve_org");
  assert.deepEqual(plan.cve_ids, ["CVE-2026-0002", "CVE-2026-0003"]);
  assert.equal(plan.known_cves, 3);
  assert.equal(plan.covered_cves, 1);
  assert.equal(plan.deferred, 0);

  // OSV 一条都没查过 ⇒ 三个号都在它的清单里（覆盖判定按源分开）
  const osvPlan = await planBackfill(store, "osv");
  assert.equal(osvPlan.cve_ids.length, 3);
  assert.equal(osvPlan.covered_cves, 0);
});

test("discovery：fixture 回放的 raw.doc 不算「已验证」——离线顶替不等于交叉验证", async () => {
  const store = await seeded(
    [item({ intel_id: "intel_a", cve_ids: ["CVE-2021-44228"], source_ids: ["cve_org"] })],
    [rawDoc("cve_org", "cve_org_fixture")],
  );
  const plan = await planBackfill(store, "cve_org");
  assert.deepEqual(plan.cve_ids, ["CVE-2021-44228"]);
  assert.equal(plan.covered_cves, 0);
});

test("discovery：空库=空清单（首轮无已知 CVE 是正常态，不是故障）", async () => {
  const plan = await planBackfill(new MemoryEventStore(), "cve_org");
  assert.deepEqual(plan.cve_ids, []);
  assert.equal(plan.known_cves, 0);
  assert.equal(plan.deferred, 0);
});

test("discovery：同库同轮同清单、最近入库优先、上限截断记 deferred", async () => {
  const items: IntelItem[] = [];
  for (let i = 0; i < CVE_ORG_CAP + 5; i += 1) {
    items.push(item({
      intel_id: "intel_" + i,
      cve_ids: ["CVE-2026-" + String(1000 + i).padStart(4, "0")],
      source_ids: ["ubuntu_usn"],
      first_seen_at: new Date(Date.UTC(2026, 9, 1, 0, i)).toISOString(),
    }));
  }
  const store = await seeded(items);
  const a = await planBackfill(store, "cve_org");
  const b = await planBackfill(store, "cve_org");
  assert.deepEqual(a.cve_ids, b.cve_ids, "可复算");
  assert.equal(a.cve_ids.length, CVE_ORG_CAP);
  assert.equal(a.deferred, 5);
  assert.equal(a.cve_ids[0], "CVE-2026-1012", "最近入库的那条排第一");

  assert.ok(needsBackfillList("cve_org") && needsBackfillList("osv"));
  assert.equal(needsBackfillList("ubuntu_usn"), false, "主动发现型源不需要清单");
  assert.equal(needsBackfillList("nvd_cve"), false);
});

test("coverageGaps：把「还差多少、要跑多少轮」算给看板看（进程重启也不丢）", async () => {
  const items: IntelItem[] = [];
  for (let i = 0; i < 30; i += 1) {
    items.push(item({
      intel_id: "intel_g" + i,
      cve_ids: ["CVE-2026-" + String(3000 + i).padStart(4, "0")],
      source_ids: ["nvd_cve"],
    }));
  }
  const store = await seeded(items, [rawDoc("cve_org", "CVE-2026-3000"), rawDoc("cve_org", "CVE-2026-3001")]);
  const gaps = await coverageGaps(store);
  assert.equal(gaps.length, 2);
  const cveOrg = gaps.find((g) => g.source_id === "cve_org")!;
  assert.equal(cveOrg.known_cves, 30);
  assert.equal(cveOrg.verified_cves, 2);
  assert.equal(cveOrg.pending_cves, 28);
  assert.match(cveOrg.note, /nextCveSeeds/, "上限口径只指一处，不在这里复制常量");
  const osv = gaps.find((g) => g.source_id === "osv")!;
  assert.equal(osv.verified_cves, 0);
  assert.equal(osv.pending_cves, 30);
});

test("回归钉桩：按号补抓遇到 404 时不回放 fixture（不用别的 CVE 内容冒充本次结果）", async () => {
  const original = globalThis.fetch;
  const events: FallbackEvent[] = [];
  globalThis.fetch = (async () => new Response('{"message":"Not Found"}', { status: 404 })) as typeof globalThis.fetch;
  try {
    const raw = await fetchCveOrg({ cveId: "CVE-2099-000001", traceId: "tr_t", emit: (e) => { events.push(e); } });
    assert.equal(raw, null, "查不到就不产出");
    assert.equal(events.length, 0, "404 属于「查无记录」，不该记成降级");
  } finally {
    globalThis.fetch = original;
  }
});

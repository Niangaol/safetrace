import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { SqliteEventStore, type Envelope, type IntelItem } from "@safetrace/shared";
import { AssetsStore } from "../src/store.js";
import { autoMatchGroup, autoMatchAllGroups, alertsFromMatches, readAllIntelItems } from "../src/auto-match.js";
import type { AssetGroup, ScanRun } from "../src/types.js";

const FIXED_NOW = new Date("2026-10-09T08:00:00.000Z");

function intelItem(id: string, product: string, range: string[], cve: string): IntelItem {
  return {
    intel_id: id,
    cve_ids: [cve],
    source_ids: ["nvd_cve"],
    title: "demo " + product,
    published_at: "2026-10-01T00:00:00.000Z",
    first_seen_at: "2026-10-01T00:00:00.000Z",
    entities: { product, vendor: null, version_range: range, cwe: [], cpes: [] },
    raw_refs: [],
    source_reliability: 0.95,
    schema_version: "1.0",
  };
}

function event(item: IntelItem, eventId: string): Envelope<IntelItem> {
  return { event_id: eventId, topic: "intel.items", occurred_at: "2026-10-01T00:00:00.000Z", trace_id: "tr_x", causation_id: null, payload: item, schema_version: "1.0" };
}

function group(id: string, name: string): AssetGroup {
  return { group_id: id, name, roots: ["D:/demo"], enabled: true, note: null, created_at: "2026-10-09T07:00:00.000Z" };
}

function runFor(groupId: string, groupName: string, componentName: string, version: string): ScanRun {
  return {
    run_id: "run-" + groupId,
    started_at: "2026-10-09T07:59:50.000Z",
    finished_at: "2026-10-09T08:00:00.000Z",
    group_id: groupId,
    group_name: groupName,
    roots: ["D:/demo"],
    status: "ok",
    degraded_to: null,
    note: null,
    repo_count: 1,
    component_count: 1,
    repos: [
      {
        repo_id: "repo-" + groupId,
        path: "D:/demo/" + groupId,
        remote_url: null,
        branch: null,
        head_commit: null,
        head_commit_at: null,
        is_git: false,
        git_note: null,
        languages: [],
        frameworks: [],
        manifests: ["package.json"],
        components: [{ ecosystem: "npm", name: componentName, version, constraint_raw: version, version_is_range_floor: false, source_file: "package.json" }],
      },
    ],
    skipped: [],
  };
}

async function admit(events:SqliteEventStore,item:IntelItem,id:string,verdict:'pass'|'quarantine'='pass') {
  await events.append(event(item,id));
  await events.append({event_id:'dq_'+id,topic:'dq.verdicts',occurred_at:FIXED_NOW.toISOString(),trace_id:'tr_x',causation_id:id,schema_version:'1.0',payload:{item_id:item.intel_id,item_kind:'intel',quality_score:0.9,dimension_scores:{structure:1,completeness:1,consistency:1,timeliness:1,sourcing:1},flags:[],verdict,gate_version:'dq1.v1'}});
}
async function setup(): Promise<{ events: SqliteEventStore; dir: string }> {
  const events = new SqliteEventStore(":memory:");
  await admit(events,intelItem("intel_vue", "vue", ["<3.5.0"], "CVE-2026-1001"),"ev_1");
  await admit(events,intelItem("intel_react", "react", ["<18.0.0"], "CVE-2026-1002"),"ev_2");
  return { events, dir: "" };
}

test("按组匹配：各组独立快照独立告警，无快照显式跳过", async () => {
  const { events } = await setup();
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-automatch-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    store.saveScanRun(runFor("g1", "组一", "vue", "3.4.21"), 0);
    store.saveScanRun(runFor("g2", "组二", "react", "18.3.1"), 0);

    const r1 = await autoMatchGroup(events, store, group("g1", "组一"), { now: () => FIXED_NOW });
    assert.equal(r1.affected, 1, "vue 3.4.21 命中 <3.5.0");
    assert.equal(r1.new_alerts, 1);
    assert.equal(r1.skipped_reason, null);

    const r2 = await autoMatchGroup(events, store, group("g2", "组二"), { now: () => FIXED_NOW });
    assert.equal(r2.affected, 0, "react 18.3.1 不在 <18.0.0");
    assert.equal(r2.new_alerts, 0);

    const r3 = await autoMatchGroup(events, store, group("g3", "组三"), { now: () => FIXED_NOW });
    assert.equal(r3.skipped_reason, "该组还没有快照，先执行一次扫描");

    const alerts = store.listAlerts({ groupId: "g1" });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]!.group_id, "g1");
    assert.equal(alerts[0]!.name, "vue");
    assert.equal(alerts[0]!.cve_id, "CVE-2026-1001");
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    events.close();
  }
});

test("autoMatchAllGroups：情报只读一批，多组复用，幂等", async () => {
  const { events } = await setup();
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-assets-automatch-"));
  try {
    const store = new AssetsStore(path.join(dir, "assets.sqlite"));
    store.seedGroups([group("g1", "组一"), group("g2", "组二"), group("g3", "组三")]);
    store.saveScanRun(runFor("g1", "组一", "vue", "3.4.21"), 0);
    store.saveScanRun(runFor("g2", "组二", "vue", "3.0.0"), 0);

    const first = await autoMatchAllGroups(events, store, { now: () => FIXED_NOW });
    assert.equal(first.items_read, 2, "情报只读一批");
    assert.equal(first.groups.length, 3);
    assert.equal(first.total_new_alerts, 2, "两组各自命中一次");
    assert.equal(first.groups.find((g) => g.group_id === "g3")!.skipped_reason, "该组还没有快照，先执行一次扫描");

    const second = await autoMatchAllGroups(events, store, { now: () => FIXED_NOW });
    assert.equal(second.total_new_alerts, 0, "重复匹配幂等");

    // 停用组不参与全量匹配
    const g3 = store.getGroup("g3")!;
    store.upsertGroup({ ...g3, enabled: false });
    const third = await autoMatchAllGroups(events, store, { now: () => FIXED_NOW });
    assert.equal(third.groups.length, 2, "停用组被跳过");
    store.close();
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    events.close();
  }
});

test("CLI/watch 不借历史准入：缺 DQ、隔离、未复核新版本均拒绝",async()=>{
  const {events}=await setup();
  try {
    await events.append(event(intelItem('intel_missing','vue',['<9'],'CVE-2026-1011'),'missing'));
    await admit(events,intelItem('intel_quarantined','vue',['<9'],'CVE-2026-1012'),'quarantined','quarantine');
    const original=(await readAllIntelItems(events)).find(i=>i.intel_id==='intel_vue')!;
    await events.append(event({...original,title:'new unreviewed version'},'ev_new'));
    assert.deepEqual((await readAllIntelItems(events)).map(i=>i.intel_id),['intel_react']);
    await admit(events,{...original,title:'current released version'},'ev_fresh');
    assert.equal((await readAllIntelItems(events)).find(i=>i.intel_id==='intel_vue')!.title,'current released version');
    const entry=events.readIntelAdmissionEvents().find(e=>e.event_id==='dq_ev_fresh')!;
    await events.append({event_id:'dq_revoke',topic:'dq.verdicts',occurred_at:FIXED_NOW.toISOString(),trace_id:'tr_x',causation_id:'ev_fresh',schema_version:'1.0',payload:{...(entry.payload as object),verdict:'quarantine'}});
    assert.ok(!(await readAllIntelItems(events)).some(i=>i.intel_id==='intel_vue'));
  } finally {events.close();}
});

test("alertsFromMatches：一条情报多个 CVE 各生成一条，group_id 透传", () => {
  const matches = [{
    component_key: "npm:vue",
    ecosystem: "npm" as const,
    name: "vue",
    version: "3.4.21",
    repo_path: "D:/demo/g1",
    source_file: "package.json",
    constraint_raw: "3.4.21",
    version_is_range_floor: false,
    group_id: "g1",
    intel_id: "intel-1",
    cve_ids: ["CVE-2026-1001", "CVE-2026-1003"],
    status: "affected" as const,
    vendor_unverified: true,
    rule: "<3.5.0",
    tested_version: "3.4.21",
    matched_ranges: ["<3.5.0"],
    reason: "命中",
  }];
  const alerts = alertsFromMatches(matches, "run-1");
  assert.equal(alerts.length, 2);
  assert.deepEqual(alerts.map((a) => a.cve_id), ["CVE-2026-1001", "CVE-2026-1003"]);
  assert.ok(alerts.every((a) => a.group_id === "g1" && a.first_run_id === "run-1"));
});

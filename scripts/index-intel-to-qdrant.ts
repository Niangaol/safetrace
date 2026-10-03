#!/usr/bin/env node
/**
 * 把 SQLite 里已采集的真实情报灌进 Qdrant，让 Q2 演示/服务能查真实库而不是 fixture。
 *
 * 为什么单独一个脚本（而不是改 ingest:once 硬开 SAFETRACE_INDEX_QDRANT）：
 *   E-02 那次实跑没开向量入库，raw.docs 只有 6 条（按次追加、不跨次保留），
 *   所以 buildSourceEvidenceChunks 那套（吃内存里的 parsed/fetched）用不上。
 *   这里改为**直接从 events 表重建证据块**，provenance 用情报自带来源 URL（不用 raw.docs）。
 *
 * 红线保持：
 *   - 只灌 DQ1 放行的（pass/degrade）；review/quarantine 不入库（脏数据不进底座）
 *   - 全部走真实本地 embedder（bge-m3），不允许 hash 占位向量
 *   - provenance.url + sha256 必填（source-index 闸门要求）
 *   - 写独立集合（默认 safetrace_intel_demo），不污染 safetrace_sources 那个验收集合
 *
 * 用法：node --env-file=.env.local --import tsx scripts/index-intel-to-qdrant.ts
 *   可选：QDRANT_INTEL_COLLECTION 换集合名、INTEL_LIMIT 限条数（默认全量）
 */
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { EventBus, MemoryEventStore, nextId, sha256Json } from "@safetrace/shared";
import { ModelGateway, createCliCloudConfirm } from "@safetrace/gateway";
import { indexSourceChunks } from "../src/qa/src/source-index.js";

const DB = process.env.SQLITE_PATH ?? "./var/safetrace.sqlite";
const URL_BASE = process.env.QDRANT_URL ?? "http://127.0.0.1:6333";
const COLLECTION = process.env.QDRANT_INTEL_COLLECTION ?? "safetrace_intel_demo";
const LIMIT = Number(process.env.INTEL_LIMIT ?? 0);
// 小批灌库：大 batch 会被 MG1 熔断放大成整批降级（见下方 writeWithRetry 注释）

/** 情报自带的来源 URL 映射（源 id → 可引用的公开页面）。 */
const SOURCE_URL = {
  cisa_kev: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  nvd_cve: "https://nvd.nist.gov/vuln/search",
  ubuntu_usn: "https://ubuntu.com/security/notices",
  osv: "https://osv.dev/vulnerability/",
  cve_org: "https://www.cve.org/",
};
const FALLBACK_URL = "https://nvd.nist.gov/vuln/search";

function sourceUrlFor(item: any): string {
  const sid = Array.isArray(item.source_ids) ? item.source_ids[0] : undefined;
  const base = (sid && (SOURCE_URL as Record<string, string>)[sid]) || FALLBACK_URL;
  // 有 CVE 就拼到具体条目，便于人点开核对
  const cve = Array.isArray(item.cve_ids) && item.cve_ids.length > 0 ? item.cve_ids[0] : undefined;
  if (sid === "ubuntu_usn" && Array.isArray(item.aliases) && item.aliases.length > 0) {
    return base + "/" + item.aliases[0];
  }
  if (sid === "osv" && Array.isArray(item.ghsa_ids) && item.ghsa_ids.length > 0) {
    return base + item.ghsa_ids[0];
  }
  if (cve) return base + "?cve=" + encodeURIComponent(cve);
  return base;
}

/**
 * 证据块文本：标题 + 摘要（Q2 检索的最小可用正文）。
 *
 * 为什么要截断：本地 llama-server 的 embedding 实例按 -c 2048 起上下文，
 * 实测 2357 字符（NVD 的长摘要）会让它对该请求失败 → MG1 降级 → 被闸门拒绝写入。
 * 这不是数据脏，是本地推理服务的上下文上限，所以在此显式截断并把"已截断"
 * 透传到 chunk 文本里（不静默改内容）。截断阈值按 n_ctx 留足余量。
 */
const MAX_CHUNK_CHARS = Number(process.env.INTEL_MAX_CHARS ?? 1200);

function textOf(item: any): string {
  const title = String(item.title ?? "").trim();
  const summary = String(item.summary ?? "").trim();
  const cves = Array.isArray(item.cve_ids) ? item.cve_ids.join(" ") : "";
  const parts = [cves, title, summary].filter(Boolean);
  let text = parts.join("\n");
  if (text.length > MAX_CHUNK_CHARS) {
    text = text.slice(0, MAX_CHUNK_CHARS) + "\n[内容过长已按本地 embedder 上下文上限截断]";
  }
  return text;
}

function shaOf(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** 查集合里已有的 chunk_id 集合，实现断点续跑（中断后重跑不重复写入）。 */
async function existingChunkIds(collection: string): Promise<Set<string>> {
  const ids = new Set<string>();
  let offset = undefined;
  for (let guard = 0; guard < 200; guard += 1) {
    const body: Record<string, unknown> = { limit: 1000, with_vector: false, with_payload: true };
    if (offset !== undefined) body.offset = offset;
    const res = await fetch(URL_BASE + "/collections/" + encodeURIComponent(collection) + "/points/scroll", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    });
    if (!res.ok) break;
    const data = await res.json() as { result?: { points?: any[]; next_page_offset?: unknown } };
    const points = data.result?.points ?? [];
    for (const p of points) {
      const cid = p?.payload?.chunk_id;
      if (cid !== undefined && cid !== null) ids.add(String(cid));
    }
    offset = data.result?.next_page_offset;
    if (offset === null || offset === undefined) break;
  }
  return ids;
}

/** 把 sqlite 行里的 payload 字符串安全解析为 JSON（坏行返回 null，不猜）。 */
function parseRows(rows: Array<{ payload?: unknown }>): any[] {
  return rows
    .map((r) => {
      const raw = r.payload;
      if (typeof raw !== "string") return null;
      try { return JSON.parse(raw); } catch { return null; }
    })
    .filter((v): v is Record<string, any> => v !== null && typeof v === "object");
}

async function main() {
  const db = new DatabaseSync(DB, { readOnly: true });
  // --retry <chunk_id...>：只重写指定条目（收尾补救用：独立进程 + 干净 MG1 实例）
  // 主循环末尾偶发孤立失败（同文本在长跑实例里反复失败、在独立进程一次就过），
  // 所以把补救路径固化成交互参数，而不是在主进程里和实例状态死磕。
  const retryArgIndex = process.argv.indexOf("--retry");
  if (retryArgIndex >= 0) {
    const wantIds = new Set(process.argv.slice(retryArgIndex + 1).filter(Boolean));
    const bus = new EventBus({ store: new MemoryEventStore() });
    const gw = new ModelGateway({ bus, configPath: process.env.MODELS_CONFIG_PATH ?? "config/models.tokendance.yml", confirmCloudFallback: createCliCloudConfirm() });
    const profile = gw.embeddingProfile();
    const all = parseRows(db.prepare("SELECT payload FROM events WHERE topic='intel.items'").all() as any);
    let okCount = 0;
    for (const it of all) {
      // intel_id 本身已是 intel_xxx 形态，直接当 chunk_id，别再拼前缀
      const cid = String(it.intel_id);
      if (!wantIds.has(cid)) continue;
      const text = textOf(it);
      const chunks = [{
        chunk_id: cid, doc_type: "vuln_advisory" as const, text,
        provenance: { url: sourceUrlFor(it), section: "", sha256: shaOf(text) },
      }];
      const parent = await bus.recordLineage({
        trace_id: nextId("tr"), parent_lineage_ids: [], causation_id: null,
        stage: "runner.retry", operation_version: "intel-index.retry.v1", status: "success",
        started_at: new Date().toISOString(),
        input_refs: chunks.map((c) => ({ kind: "EvidenceChunk", id: c.chunk_id, sha256: c.provenance.sha256, url: c.provenance.url })),
        output_refs: [],
      });
      try {
        const r = await indexSourceChunks(chunks, {
          enabled: true, offline: false, url: URL_BASE, collection: COLLECTION, profile, bus,
          trace_id: "tr_retry_" + cid, parent_lineage_ids: [parent.lineage_id],
          embedder: (t, tid) => gw.embed("embedder", t, tid),
        });
        okCount += r.chunks;
        console.log("[retry] OK " + cid);
      } catch (err) {
        const m = err instanceof Error ? err.message : String(err);
        console.log("[retry] FAIL " + cid + " : " + m.slice(0, 100));
      }
    }
    console.log("[retry] 完成 " + okCount + "/" + wantIds.size);
    return;
  }
  // DQ1 放行的 intel_id（pass/degrade）；取不到判定的按未放行处理，宁缺勿滥
  const allowed = new Set<string>(
    parseRows(db.prepare("SELECT payload FROM events WHERE topic='dq.verdicts'").all() as any)
      .filter((v) => v.verdict === "pass" || v.verdict === "degrade")
      .map((v) => String(v.item_id)),
  );
  const verdictRow = db.prepare("SELECT COUNT(*) n FROM events WHERE topic='dq.verdicts'").get() as { n?: unknown };
  const verdictCount = Number(verdictRow?.n ?? 0);
  console.log("[index] DQ1 判定 " + verdictCount + " 条，放行 " + allowed.size + " 条");

  let items = parseRows(db.prepare("SELECT payload FROM events WHERE topic='intel.items'").all() as any)
    .filter((x) => x.intel_id && allowed.has(String(x.intel_id)));
  console.log("[index] intel.items " + items.length + " 条通过 DQ1 放行");
  if (LIMIT > 0) items = items.slice(0, LIMIT);

  // 去重（同一 intel_id 多次运行会重复入 events）
  const seen = new Set();
  const unique = [];
  for (const it of items) {
    if (seen.has(it.intel_id)) continue;
    seen.add(it.intel_id);
    unique.push(it);
  }
  console.log("[index] 去重后 " + unique.length + " 条");

  console.log("[index] 步骤1/4 读 DQ1 放行集合完成");
  // 断点续跑：跳过已在集合里的 chunk_id
  const already = await existingChunkIds(COLLECTION);
  console.log("[index] 步骤2/4 已查集合现存 " + already.size + " 条");
  const pending = unique.filter((it) => !already.has(String(it.intel_id)));
  console.log("[index] 集合已有 " + already.size + " 条，待写入 " + pending.length + " 条");
  if (pending.length === 0) {
    console.log("[index] 无需写入，全部已就绪");
    return;
  }
  const queue = pending;

  const bus = new EventBus({ store: new MemoryEventStore() });
  const traceId = nextId("tr");
  const cfgPath = process.env.MODELS_CONFIG_PATH ?? "config/models.tokendance.yml";
  // 必须显式指向本机真实 embedder 配置：不传 configPath 会用默认 models.yml 的 cache 占位
  //
  // 为什么允许重建 gateway：MG1 的熔断器状态活在实例里（连续 5 次失败 → 打开 60s，
  // 窗口内所有请求直接 fallback 到 cache）。灌库是长跑任务，一旦某几分钟服务抖动
  // 就会持续吃降级；此时重试无用（每次失败还重置 60s 窗口），正确做法是丢掉旧实例、
  // 新建一个干净熔断状态的 gateway 继续。服务本身没问题（已用 curl 直连验证 200）。
  let gateway = new ModelGateway({ bus, configPath: cfgPath, confirmCloudFallback: createCliCloudConfirm() });
  let rebuilds = 0;
  const rebuildGateway = (why: string): void => {
    rebuilds += 1;
    console.log("[index] 重建 MG1 实例（第 " + rebuilds + " 次，原因：" + why.slice(0, 60) + "）");
    gateway = new ModelGateway({ bus, configPath: cfgPath, confirmCloudFallback: createCliCloudConfirm() });
  };
  // profile 是静态配置，取一次即可；但重建后 model_id/version 不变，可继续复用
  const profile = gateway.embeddingProfile();
  console.log("[index] embedder=" + profile.provider + "/" + profile.model_id + " dim=" + profile.dimension);

  // 父 lineage：本次灌库动作本身（source-index 闸门要求非空父链）
  const parent = await bus.recordLineage({
    trace_id: traceId,
    parent_lineage_ids: [],
    causation_id: null,
    stage: "runner.intel_index",
    operation_version: "intel-index.v1",
    status: "success",
    started_at: new Date().toISOString(),
    input_refs: [{ kind: "IntelItemSet", id: "intel_dq1_pass", sha256: sha256Json({ count: unique.length }) }],
    output_refs: [],
  });

  // ---- 灌库主循环：小批 + 失败细分重试 + 如实统计 ----
  // 为什么不用大 batch：实测本地 llama-server 在连续大批请求下会有零星失败，
  // 而 MG1 的熔断器（连续 5 次失败 → 打开 60s）会把零星失败放大成整批降级到 cache，
  // source-index 闸门随即拒绝写入（这是对的：不许把降级向量当真向量）。
  // 所以这里用 40 条小批 + 批间停顿；失败的批自动二分重试，重试仍失败的条目如实记入
  // skipped 并继续，绝不静默丢弃、也不用 fixture 顶替。
  const SMALL = Number(process.env.INTEL_BATCH ?? 40);
  const PAUSE_MS = Number(process.env.INTEL_PAUSE_MS ?? 300);
  const skipped: string[] = [];
  let done = 0;

  type IntelRow = { intel_id: string; title?: string; summary?: string; cve_ids?: string[]; aliases?: string[]; ghsa_ids?: string[]; source_ids?: string[] };
  const toChunks = (items: IntelRow[]) => items.map((item: IntelRow) => {
    const text = textOf(item);
    return {
      // intel_id 已是 intel_xxx，直接作 chunk_id（曾误拼成 intel_intel_xxx 导致续跑失效）
      chunk_id: String(item.intel_id),
      doc_type: "vuln_advisory" as const,
      text,
      provenance: { url: sourceUrlFor(item), section: "", sha256: shaOf(text) },
    };
  });

  const writeOne = async (item: any): Promise<void> => {
    const chunks = toChunks([item]);
    await indexSourceChunks(chunks, {
      enabled: true,
      offline: false,
      url: URL_BASE,
      collection: COLLECTION,
      profile,
      bus,
      trace_id: traceId,
      parent_lineage_ids: [parent.lineage_id],
      embedder: (texts, tid) => gateway.embed("embedder", texts, tid),
    });
  };

  const writeWithRetry = async (items: IntelRow[], depth = 0): Promise<void> => {
    if (items.length === 0) return;
    try {
      await writeOne(items[0]); // 先探一条，确认 embedding 通（不通会抛，避免整批白跑）
      if (items.length > 1) {
        const chunks = toChunks(items);
        await indexSourceChunks(chunks, {
          enabled: true, offline: false, url: URL_BASE, collection: COLLECTION, profile, bus,
          trace_id: traceId, parent_lineage_ids: [parent.lineage_id],
          embedder: (texts, tid) => gateway.embed("embedder", texts, tid),
        });
        done += chunks.length;
      } else {
        done += 1;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // 降级/熔断导致的失败（不是数据问题）：丢掉旧 gateway 重建一个干净熔断状态的，
      // 比重试有效——熔断窗口内每次失败还会把 60s 窗口重新计时，硬试只会一直吃降级。
      if (msg.includes("已降级") && rebuilds < 20) {
        rebuildGateway("MG1 降级");
        await new Promise((r) => setTimeout(r, 800));
        await writeWithRetry(items, depth);
        return;
      }
      const only = items[0];
      if (items.length === 1 && only) {
        // 单条也失败：如实记录并跳过，不静默丢弃、不用假数据顶替
        skipped.push(only.intel_id + " (" + msg.slice(0, 60) + ")");
        console.log("[index] 跳过 " + only.intel_id + "：" + msg.slice(0, 90));
        return;
      }
      // 二分重试：把失败批拆成两半各自处理（可能是批里某几条触发服务端问题）
      const mid = Math.ceil(items.length / 2);
      console.log("[index] 批失败（" + msg.slice(0, 70) + "），拆分 " + items.length + " → " + mid + " + " + (items.length - mid));
      await writeWithRetry(items.slice(0, mid), depth + 1);
      await writeWithRetry(items.slice(mid), depth + 1);
    }
  };

  console.log("[index] 步骤3/4 开始灌库，队列 " + queue.length + " 条，小批 " + SMALL + "，批间停 " + PAUSE_MS + "ms");
  for (let i = 0; i < queue.length; i += SMALL) {
    const slice = queue.slice(i, i + SMALL);
    await writeWithRetry(slice);
    if ((i / SMALL) % 10 === 9) {
      console.log("[index] 进度 " + Math.min(i + SMALL, queue.length) + "/" + queue.length + "（已写 " + done + "，跳过 " + skipped.length + "）");
    }
    if (PAUSE_MS > 0) await new Promise((r) => setTimeout(r, PAUSE_MS));
  }

  // ---- 收尾：剩余条目移交独立进程重试 ----
  // 实测（2026-10-03）：主循环末尾有孤立失败——同一条文本在独立进程里一次就过，
  // 但在长跑实例里反复失败（与该实例的 MG1 状态 / bus 上累积的大量 lineage 相关，未最终定位）。
  // 与其在主进程死磕，不如打印重跑命令：独立进程 = 干净 MG1 实例 + 空 bus。
  if (skipped.length > 0) {
    const retryIds = skipped.map((s) => s.split(" ")[0]);
    console.log("[index] 有 " + retryIds.length + " 条未写入，请用独立进程重试（干净实例，实测有效）：");
    console.log("        node --env-file=.env.local --import tsx scripts/index-intel-to-qdrant.ts --retry " + retryIds.join(" "));
  }

  const info = await (await fetch(URL_BASE + "/collections/" + encodeURIComponent(COLLECTION))).json() as { result?: { points_count?: number } };
  const pts = info.result?.points_count;
  console.log("[index] 集合 " + COLLECTION + " 现有点数 " + pts + "（本次写入 " + done + "，跳过 " + skipped.length + "）");
  if (skipped.length > 0) {
    console.log("[index] 被跳过的条目（未写入，未用假数据顶替）：");
    for (const s of skipped.slice(0, 20)) console.log("   - " + s);
    if (skipped.length > 20) console.log("   … 共 " + skipped.length + " 条");
  }
  console.log("[index] 完成。Q2 指向该集合：QDRANT_URL=" + URL_BASE + " QDRANT_COLLECTION=" + COLLECTION);
}

main().catch((err) => {
  console.error("[index] 失败：" + (err instanceof Error ? err.message : String(err)));
  process.exitCode = 1;
});

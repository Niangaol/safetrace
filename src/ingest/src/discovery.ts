/**
 * E-08 · 漏报补偿的发现清单（Y4）。
 *
 * 问题：`fetchOsv` 无 `queries/cveIds` 直接 `return null`、`fetchCveOrg` 无 `cveId` 直接 `return null`
 * （`sources/osv.ts:64`、`sources/cveorg.ts:50`）⇒ 调度器无人值守轮询时，5 个 active 源里只有 3 个真产出数据，
 * "72h 可用率"其实只覆盖那 3 个。台账把这两个源定位成"按需查询"，但没人给它按需的那个"需"。
 *
 * 本模块就是那个"需"：从事件库里已有的 `intel.items` 取出「我们见过的全部 CVE 号」，
 * 减去「该源自己的 `raw.docs` 已经查过的 CVE 号」，得到本轮该补的清单。三条口径写死在这里：
 *
 *  1. **覆盖判定只认该源自己的 raw.doc `external_id`**，不认归并后的 `intel.source_ids`——
 *     一条 intel 的 `source_ids` 含 `cve_org` 只能证明 cve_org 报道了**触发归并的那个号**，
 *     同一条目里被别的源带进来的姊妹号并没有被它验证过（早期版本在这里 over-exclude，已修）。
 *     同理，fixture 回放的 `external_id`（`cve_org_fixture` 之类）不含 CVE 号 ⇒ 不算覆盖：
 *     离线顶替不等于真验证过。
 *  2. 候选按「最近入库优先」（`first_seen_at` 倒序，同分按 CVE 号升序），保证新漏洞先被交叉验证，
 *     且同库同轮必得同一清单（可复算，不依赖 Map 遍历顺序之外的任何偶然因素）。
 *  3. 每源每轮有硬上限（`CVE_ORG_CAP`=8、`OSV_CAP_PER_RUN`=20），都低于各自 registry `rate_per_min`；
 *     请求间隔由 `scheduler.ts` 控制（默认 1200ms），绝不因补清单变成扫库。
 *
 * 已知保守之处：OSV 走包查询批次时 `external_id` 是 `osv_query_<包名>`，不含 CVE 号 ⇒ 这些号下一轮
 * 仍会被列入清单再查一次（代价受上限约束）。宁可重复查，不可漏查——写在这里而不是藏在代码里。
 *
 * 红线：本模块只读库、不发请求。"查不到就跳过"在采集器侧（`FetchOpts.noFixtureFallback`），
 * 因为**用另一条 CVE 的 fixture 冒充这一条的抓取结果，是错映射而不是降级**。
 */
import type { EventStore, IntelItem, RawDoc } from "@safetrace/shared";

/** 需要发现清单才肯干活的源（与 `SOURCE_RUNNERS` 里的 id 对齐）。 */
export const BACKFILL_SOURCES = ["cve_org", "osv"] as const;
export type BackfillSource = (typeof BACKFILL_SOURCES)[number];

/** 单轮补抓上限：cve.org 每条一个 GET；OSV 按 CVE 别名逐条 GET 后合并，故同样受上限约束。 */
export const CVE_ORG_CAP = 8;
export const OSV_CAP_PER_RUN = 20;

const DEFAULT_CAPS: Record<BackfillSource, number> = { cve_org: CVE_ORG_CAP, osv: OSV_CAP_PER_RUN };

const CVE_IN_TEXT = /CVE-\d{4}-\d{4,}/g;

/** 该源是否需要发现清单。 */
export function needsBackfillList(sourceId: string): sourceId is BackfillSource {
  return (BACKFILL_SOURCES as readonly string[]).includes(sourceId);
}

export interface BackfillPlan {
  source_id: BackfillSource;
  /** 本轮该源要去查的 CVE 号（按第 2 条排序、第 3 条截断）。 */
  cve_ids: string[];
  /** 库里去重后的已知 CVE 总数（分母，用来说明"为什么这轮只补 8 条"）。 */
  known_cves: number;
  /** 该源已通过自己的 raw.doc 查过的 CVE 数。 */
  covered_cves: number;
  /** 尚未覆盖、但本轮没排上队的条数（>0 表示清单被上限截断，下一轮继续）。 */
  deferred: number;
}

/** 读全库事件用的一页上限；72h 量级远小于此，超出部分下一轮自然轮到。 */
const READ_PAGE = 50_000;

/**
 * 算出某个补抓源本轮该查哪些 CVE。
 * 库为空（首轮）时返回空清单——此时没有任何已知 CVE，属于正常状态，不是故障。
 */
export async function planBackfill(
  store: EventStore,
  sourceId: BackfillSource,
  opts: { cap?: number } = {},
): Promise<BackfillPlan> {
  const cap = opts.cap ?? DEFAULT_CAPS[sourceId];

  /** CVE → 我们最早见到它的时间（毫秒），用于"最近优先"排序。 */
  const seenAt = new Map<string, number>();
  for (const env of await store.read<IntelItem>("intel.items", 0, READ_PAGE)) {
    const cveIds = Array.isArray(env.payload.cve_ids) ? env.payload.cve_ids : [];
    const parsed = Date.parse(env.payload.first_seen_at ?? "");
    const at = Number.isNaN(parsed) ? 0 : parsed;
    for (const cve of cveIds) {
      if (typeof cve !== "string" || cve === "") continue;
      const prev = seenAt.get(cve);
      if (prev === undefined || at < prev) seenAt.set(cve, at);
    }
  }

  /** 该源自己查过的号：只看它的 raw.doc external_id（见文件头第 1 条）。 */
  const covered = new Set<string>();
  for (const env of await store.read<RawDoc>("raw.docs", 0, READ_PAGE)) {
    if (env.payload.source_id !== sourceId) continue;
    for (const m of String(env.payload.external_id).matchAll(CVE_IN_TEXT)) covered.add(m[0]);
  }

  const candidates: string[] = [];
  for (const [cve, at] of seenAt) {
    if (covered.has(cve)) continue;
    candidates.push(cve);
  }
  candidates.sort((a, b) => {
    const ta = seenAt.get(a) ?? 0;
    const tb = seenAt.get(b) ?? 0;
    return tb - ta || a.localeCompare(b);
  });

  const picked = candidates.slice(0, cap);
  return {
    source_id: sourceId,
    cve_ids: picked,
    known_cves: seenAt.size,
    covered_cves: covered.size,
    deferred: Math.max(0, candidates.length - picked.length),
  };
}

/** 一次排全部补抓源的清单（调度器每轮调用一次，避免每个源各扫一遍库）。 */
export async function planBackfillAll(
  store: EventStore,
  opts: { caps?: Partial<Record<BackfillSource, number>> } = {},
): Promise<BackfillPlan[]> {
  const out: BackfillPlan[] = [];
  for (const sourceId of BACKFILL_SOURCES) {
    const cap = opts.caps?.[sourceId];
    out.push(await planBackfill(store, sourceId, cap === undefined ? {} : { cap }));
  }
  return out;
}

/** 一个源的交叉验证进度（持久视角：从该源自己的 raw.doc 反推，进程重启不丢）。 */
export interface CoverageGap {
  source_id: BackfillSource;
  known_cves: number;
  verified_cves: number;
  pending_cves: number;
  /** 每轮实际上限由 scheduler 的 nextCveSeeds 决定；本模块不复制该常量，避免两处口径漂移。 */
  note: string;
}

/**
 * 给看板/报告用的覆盖视图：不改动任何抓取节奏，只把"还差多少"算清楚并说明排队口径。
 * 队长 a46c9f0 的推进状态在进程内存里（重启即归零），这里给的是**持久化**的对账口径。
 */
export async function coverageGaps(store: EventStore): Promise<CoverageGap[]> {
  const out: CoverageGap[] = [];
  for (const sourceId of BACKFILL_SOURCES) {
    const plan = await planBackfill(store, sourceId);
    out.push({
      source_id: sourceId,
      known_cves: plan.known_cves,
      verified_cves: plan.covered_cves,
      pending_cves: Math.max(0, plan.known_cves - plan.covered_cves),
      note: "每轮上限见 scheduler.nextCveSeeds；此处不复制常量",
    });
  }
  return out;
}

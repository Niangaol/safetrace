# SafeTrace · 监测时效与可用率口径（v1.1.0）

> 负责人：XueXuhang ｜ 台账：`E-01`（第 7 源）、`E-02`（真实抓取留痕）、`E-07`（连续运行）
> 实现：`src/ingest/src/freshness.ts`、`src/ingest/src/uptime.ts`、`src/ingest/src/scheduler.ts`
> 取数：`node --import tsx src/ingest/src/cli/report.ts`（写 `tmp/freshness.json` + 终端打表）
> **本文与代码不一致时以代码为准，并请回头改本文**（口径漂移比数字难看更致命，见 `TEAM-PLAN.md` 红线 5）。

## 0. 为什么要写这份文档

`TASKS.md` 的 `P-08` 要求：任何指标必须先定义**样本规模、时间窗、统计方法**；
`ROADMAP.md` §三 定义 A 级证据 = "现场可跑 + 数字可复现"。
本文件就是那份定义，答辩时"这个 P95 怎么测的"的直接答案。

## 1. 监测延迟 lag

```
lag = first_seen_at − published_at        （单位：秒，取整）
```

- `published_at`：上游首次公开发布时间（由各 Y2 适配器归一化成 ISO-8601 带 Z）；
- `first_seen_at`：**本系统**首次入库时间（`IntelItem` 契约字段，两者分离正是为了不让上游延迟污染自证）；
- 同一 `intel_id` 被多轮重复上报时只算**最早**那次 `first_seen_at`，其余计入 `excluded.duplicate_intel_rows`。

## 2. 双口径（关键，别只截图一个）

| 口径 | 字段 | 样本定义 | 能说明什么 | 不能说明什么 |
|---|---|---|---|---|
| **严格** | `overall` / `by_source` | `published_at ≥ 监控起点` 的真实条目 | **我们开始监测之后新发布的漏洞，多久被抓到**（对应决赛「≤6h 优秀档」） | 上线第一天窗口内几乎没有"上线后发布"的新漏洞，`n` 会是 0——**这不是故障，是样本还没长出来** |
| **参考** | `reference.overall` | 统计窗口内全部真实条目（含上线前发布、本次才首次见到的历史 CVE） | 知识库整体新鲜度分布 | **不能写成"监测延迟"**：里面混着上游自身的发布/更新延迟 |

> 为什么必须分两个口径（实测踩到的坑）：NVD 2.0 增量按 `lastModStartDate` 拉，返回的条目里
> `published` 可能是两天前——若不分口径，首轮统计会得到 P50≈38.9h、P95≈119.8h 这种"看着像我们很慢"的数字，
> 而它实际度量的是 NVD 的更新滞后。监控起点由调度器运行日志的第一条源抓取记录确定。

**上线早期截图请两个都拍**：严格口径证明"方法对了"，参考口径证明"确实在抓"。

## 3. 时间窗与统计方法

- 窗口：`--days N`，缺省 **最近 7 天**，按 `published_at` 落窗（不是按抓取时间）；
- 分位数：**最近秩法**（nearest-rank，`rank = ceil(q × n)`），`n=0` 时返回 `null`——**空集绝不返回 0**；
- 精度：秒保留 1 位小数，比例保留 4 位（上游时间戳只到秒，再细的精度是假的）；
- `sla_6h_ratio` = `lag ≤ 21600s` 的样本占比（阈值常量 `SLA_6H_SECONDS`）；
- 分源统计：一条多源归并后的情报**同时计入它每个来源**的样本，所以各源 `n` 之和可能大于 `overall.n`
  （这是归并口径，不是重复计数；报告里 `by_source_note` 已写明）。

## 4. 排除规则（红线：宁可少一条，不可错一条）

| 排除项 | 判据 | 计数字段 |
|---|---|---|
| 离线回放样本 | `raw_refs` 全部指向 `fixtures/` | `excluded.fixture_rows` |
| 窗口外 | `published_at` 不在窗口内 | `excluded.out_of_window` |
| 上线前发布 | `published_at < 监控起点`（仍进参考口径） | `excluded.published_before_monitor_start` |
| 时间戳不可解析 | 解析失败 | `excluded.unparseable` |
| 负 lag | `first_seen < published`（上游补录/时钟偏差） | `excluded.negative_lag` |
| 跨轮重复 | 同 `intel_id` 已计 | `excluded.duplicate_intel_rows` |

`data_basis` 三态：`live`（严格口径有样本）/ `backfill_only`（只有上线前条目）/ `fixture_only`（一条真实样本都没有）。
**`fixture_only` 时任何数字都不得写进报告或 PPT**（终端会额外打一行提示）。

## 5. 连续运行与可用率（E-07）

- 载体：`src/ingest/src/scheduler.ts`，按 `registry.poll_interval_s` 分源到点调度；
- 日志：`tmp/ingest-runs.jsonl`（每行一条；`kind:"tick"` = 进程存活心跳，其余 = 单源抓取结果）；
  **不新增总线主题**——`contracts/events.md` 的主题清单是契约件，D6 后只能追加字段不能加主题，故心跳走本地日志；
- 心跳节拍：取窗口内相邻心跳的最小正间隔（当前 300s，可用 `--cycle-ms` 覆盖），下限 60s；
- 覆盖率：`观测到的不同 run_at 数 / 期望心跳数`，期望数 = `floor(窗口/节拍)+1`；窗口**从监控起点算**，
  否则刚上线就会显示"覆盖率 0.3%"这种误导性数字；
- 连续段：相邻间隔 ≤ 1.5×节拍 视为同一段，段时长补一个节拍；
- **节拍不许从稀疏日志里"推断"**：期望节拍取 active 源里最小的 `poll_interval_s`（当前 1800s）。
  日志最小间隔大于 4× 该节拍时判 `heartbeat_source="insufficient"`，并置 `coverage_reliable=false`——
  否则"手动跑两轮、间隔 9 小时"会算出**覆盖率 100%** 的假信号（实测踩过，已用单测固化）；
- 两种"没拿到数据"分开计：`failed_runs`（抓取异常）≠ `degraded_runs`（网络不可达时按红线显式回放 fixtures）；
- **分段挂机用 `--since`**：`node --import tsx src/ingest/src/cli/report.ts -- --since 2026-10-01T00:00:00Z --days 3`
  会把监控起点、严格口径样本与覆盖率窗口一起锁定在该时刻之后，避免把上一段停机时间算进本轮证据。
  非法时间会显式报错退出（不静默当"无起点"）。

## 6. 第 7 源 `ubuntu_usn`（E-01）的选型依据

| 候选 | 本机实测 | 契约改动 | 结论 |
|---|---|---|---|
| **Ubuntu Security Notices** `https://ubuntu.com/security/notices.json` | **200**（0.6–2.7s，3 次全过） | 无（`source_type=vendor_advisory` 已在 `SourceType` 枚举；USN 编号进 `aliases`） | **采用** |
| GitHub Advisory `api.github.com/advisories` | **403**（线路 2 共享出口 IP 配额打满） | 无 | 需 GitHub PAT 才能作为 `ghsa` 激活 |
| CISA KEV / vulnrichment | **DNS 不可解析 / 域名不存在** | — | 本机不可用，见 §7 |
| cvelistV5 git 差分 | `raw.githubusercontent.com` 可达 | **要改 Y3 归并主键**（`external_id` 与 `nvd_cve` 同 `CVE-*` 命名空间） | 不做：契约语义变更 + 撞 D6 冻结 |
| OpenAI/Anthropic 公告 RSS | openai 200 / anthropic 404 | 需 XML 通道（`fetchJsonWithRetry` 只解析 JSON） | 留作第 8 源候选 |

归并效果（离线 fixture 可复现）：USN 的 Log4Shell 公告与 KEV/NVD/OSV/cve.org 报道**归并成同一条 `intel_id`**，
`source_ids` 5 个、`aliases` 带出 `USN-5192-1/5192-2/5197-1`、`cve_ids` 多出姊妹编号 `CVE-2021-45046`，
DQ1 判定 `pass`（见 `src/ingest/test/pipeline.test.ts`）。

## 7. 线路可达性实测矩阵（影响所有"真跑"类验收）

2026-09-29 由本机（线路 2，出口 IP 103.223.120.130）实测，每目标 3 次：

| 域名 | 结果 | 对验收的影响 |
|---|---|---|
| `services.nvd.nist.gov` | 200（0.4–5.0s） | NVD 真跑可用 |
| `cveawg.mitre.org` | 200（1.4–4.8s，**首次超时**） | 可用但需容忍抖动 |
| `api.osv.dev` | 405/400（GET/错误 body） | 服务可达，需 POST（现有连接器已实现） |
| `ubuntu.com` | 200（0.6–2.7s） | 第 7 源可用；`robots.txt`：`Allow: /security`、`Crawl-delay: 1` |
| `export.arxiv.org`、`www.first.org` | 200 | F1/F4 可用 |
| `api.github.com` | **403 配额超限** | `ghsa` 激活需 PAT |
| `www.cisa.gov` / `cisa.gov` | **DNS 不可解析** | **`cisa_kev` 在本机必然走 fixture 降级** |
| `vulnrichment.org`、`epss.first.org`、`github.blog`、`reddit.com` | 不通 / 超时 / 连接重置 | `TEAM-PLAN §3.3` 建议的 vulnrichment 方案在本线路下不成立 |

**待拍板**：72h 挂机与 E-02 真跑留痕最好放在**能同时访问 CISA 的机器**上跑（队长本机 9/29 已实测
`cveawg.mitre.org`/arXiv/NVD 返 200，但未验证 CISA）。否则 KEV 那一栏永远是"回放中"，
监测 15 分里"≥7 类源实时登记"的 KEV 证据只能靠队长机器或备用云主机。

## 8. 前端交接（给 KKK9747human）

`node --import tsx src/ingest/src/cli/report.ts -- --out docs/evidence/freshness.json` 产出的对象，
字段名与 `web/src/types.ts` 的 `MetricsOverview` / `CollectStatus` **已对齐**：

```
latency.p50_seconds / latency.p95_seconds / latency.sla_6h_ratio   ← 取 report.overall.*
collect.raw_items / intel_items / merge_ratio / sources / sources_active
watermarks[]  { source, last_sync_at, last_published_at, items_last_run, success, error,
                replaying_fixture, skipped_this_run }              ← 新增两个布尔位，见下
queue_depth                                                        ← 恒 0（同步投递）
reference / excluded / monitor_start / metric_version / data_basis  ← 新增，建议在诊断页露出
```

三条渲染要求（对应你们的"诚实降级"设计）：
1. **`data_basis != "live"` 时不许展示严格口径数字**，改显式标注"样本尚未长出（backfill_only）"或"离线回放（fixture_only）"；
2. `watermarks[].success === false` 分两种：`replaying_fixture`（回放中，黄）与 `skipped_this_run`（本轮未抓取，灰），
   **不要都渲染成红色"故障"**——OSV/cve.org 需要查询目标才发起请求，是设计而非事故；
3. P50/P95 旁边必须带 `n` 和窗口（`report.window` + `report.monitor_start`），否则评委问"多少样本测的"会卡住。

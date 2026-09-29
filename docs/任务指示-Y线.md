# 任务指示：Y 线 + 框架层 + 富化线

> 面向下一个接手的 AI。**先读完第 0、1 节再动手**，第 1 节里有一条是本轮新发现的问题，
> 它比原计划的 S4 更靠前。
>
> 版本：v1.1　编写日期：2026-09-29　**v1.1 更新：§1/§2/§3/§4-1/§4-2 已全部完成，见 §8 接力结果**
> 上游文档：`docs/交接说明.md`（项目全貌）、`docs/契约对齐-SafeTrace.md`（契约设计）
> 融合前备份：`E:\code\_backups\ai-threat-intel-20260929-114540`（本仓**不是 git 仓库**）

---

## 8. 接力结果（2026-09-29 夜，v1.1）

按 §7 的建议顺序全部执行完毕，门禁从 `346 passed` 涨到 **`401 passed`**，五条全绿：

```
pytest                        401 passed
ruff check                    All checks passed
ruff format --check           93 files already formatted
mypy src                      Success, 63 files
python -m scripts.validate_contracts   11 schema（权威 8 + 本仓 3）, 12 fixture, 冻结指纹 8/8
```

| 原任务 | 状态 | 交付物 | 验收命令 |
| --- | --- | --- | --- |
| §3 契约校验路径硬编码 | ✅ | `contracts/schemas/FROZEN_MANIFEST.json` + `check_authoritative_frozen()` 改走仓内指纹；`--regen-manifest` | `python -m scripts.validate_contracts` |
| §1 事件载荷不合契约 | ✅ | `nodes.py` 三处改用投影函数；`LocalPayloads.json` 固化内联载荷；`check_payload_coverage()` | `pytest -k payload`（17 条） |
| §2 DQ1 质量闸门 | ✅ | `services/dq1.py` + `node_dq1` + `dq.verdicts` + `quality_score` 落库 | `pytest -k "dq1 or quality or verdict"`（31 条） |
| §4-1 降级统一出口 | ✅ | `build_result`/`to_dimension_evidence` 均经 `degrade()`，重复映射已删 | `pytest -k degrade` |
| §4-2 空插座接线 | ✅ | `enrich.papers` + `enrich.evidence` 生产者；`ALLOWED_TOPICS` 扩到 5 | `pytest -k papers` |
| §4-3 从 `raw_refs` 回读 | ⬜ 未做 | 入向适配仍只在测试中验证 | — |
| §4-4 `accept.py` 重跑 | ⬜ 待做 | 需在有 PostgreSQL 的机器上把 `[SKIP]` 变 `[OK]` | `python -m scripts.accept` |
| §4-5 重启 Demo 进程 | ✅ | 旧实例（PID 16416/31576）已停；API 以 demo SQLite DSN 重启并验证 `/health` 200、`enrich.dimensions=7` | `Invoke-WebRequest http://127.0.0.1:8000/health` |
| S6 QA 拒答 / S7 检索投影 | ⬜ 不做 | 明确划给 Q 线（见 §0.2） | — |

**顺带修掉 4 个此前被漏掉的真 bug**（都有回归测试）：

1. `to_intel_item` 的 `source_ids` 被引用字典列表污染（权威要求字符串数组）；
2. 一轮多条情报时，`intel.items` / `dq.verdicts` 的 `causation_id` 全部塌到同一个 parent；
3. `enrich.items` 按维度各发一条短字典，而权威 `EnrichmentResult` 是"一次富化一条"；
4. SQLite 的 `DateTime(timezone=True)` 丢 tzinfo → `load_intel_item` 产出无时区字符串
   → DQ1 把 demo 库 12/12 全隔离。修法：`_iso_utc()` 把 naive 按 UTC 补全。

**真库验证**（`data/check_real_data.py`，demo.db 12 条真实记录）：DQ1 判定 12 条全部 `pass`、
命中 flag 0 条，发布的 12 条 `dq.verdicts` 信封与载荷全部过契约。

**新增契约件**：`contracts/schemas/LocalPayloads.json`（本仓第 3 个扩展件，把 7 个内联载荷
`EnrichRequest`/`AlertRaised`/`DailyReport`/`BudgetExceeded`/`SelfHealAction`/`TriageOrder`/`QualityVerdict`
以及 `QueryTurn`/`Answer`/`FallbackEvent` 固化成可校验定义）。

---

## 9. 接力结果（第二轮：动态优先级，2026-09-29 夜）

按 `docs/路线评估-优先级与RAG.md` §4 的"立刻可做"项实施**提案①改写版**
（该文档已评估并否决提案②，理由是桩底座 + 无 embedding + 无 Key + 无真库）。

| 任务 | 状态 | 交付物 |
| --- | --- | --- |
| `node_triage` 改用 EPSS/KEV/CVSS 排序 | ✅ | `services/triage.py`（策略 `1.0.0`，权重 `cvss .4 / epss .45 / kev .15`，版本化可分档） |
| 顺带修"一次只处理一条" | ✅ | `state["triage_queue"]` Top-N（`TRIAGE_DETAIL_TOP_N`，默认 10）+ `route` 字段 |
| 权重版本化 + 可复算 | ✅ | 同 `policy_version` + 同输入 ⇒ 同分数同排名（全序：同分按 vuln_id） |
| `enrich.triage` 载荷补齐 | ✅ | `TriageOrder` 契约加 `cvss/epss/kev/score/rank/route/reasons/policy_version` |
| **未在评估文档中发现的阻塞项** | ✅ | EPSS/KEV 原本**根本没有写入方**：归一阶段没抽、dedup 合并会丢 → 一并修掉 |
| **顺带修的 CVSS 真 bug** | ✅ | NVD 分数藏在 `raw["cve"]["metrics"]`，归一阶段只读顶层 `cvss_vector` → NVD 条目 CVSS 一直是空的 |

  门禁：**466 passed**，ruff / format / mypy / validate_contracts 全绿
（95 → 96 files formatted、63 → 64 mypy files）。

**实测效果**（demo.db 12 条真实记录）：**5/12 条排名变化**，
`CVE-2026-28114` 从"CVSS 单因子第 4 名"升到"动态策略第 2 名"（EPSS 0.71 + KEV）。
复现命令：`python -m data.check_real_data`（`POSTGRES_DSN` 指向 `data/demo.db`）。

**新增测试**：`tests/test_triage_policy.py`（15）、`tests/test_triage_wiring.py`（8）。

> ⚠️ 诚实边界（必须写进报告）：`asset_scan_enabled=False` 时没有"业务暴露面"维度，
> 策略只能做到"**被利用概率优先**"，做不到"**对我们最危险**"。

**仍然待做**（与第一轮一致）：§4-3 从 `raw_refs` 回读、§4-4 在有 PG 的机器上跑 `accept.py`。

---

## 10. 接力结果（第三轮：真库 E2E 暴露的 persist 崩溃，2026-09-29 夜）

### 10.1 做了什么

按 §7 顺序完成两项前置（§3.5 `accept.py` 传 `--db`、§4-6 脚本移出 `data/`），
并新增 **`scripts/check_e2e_cycle.py`** —— 跑一次完整 MonitorGraph cycle，
逐条校验事件信封/载荷契约与因果链。它把 §6.1 的"只有单测证据"推进了一步。

### 10.2 它一次就抓出了 3 个真问题（前两项是代码缺陷）

第一次跑（`--sources nvd`，网络不可达→用 demo.db 已落库的 22 条 raw_item 驱动）：

| # | 问题 | 根因 | 修法 |
| --- | --- | --- | --- |
| 1 | **`persist` 节点直接崩**：`table chunk has no column named embedding` | `index_owner` 让 SQLAlchemy 按 ORM 映射写**所有**列（含 pgvector 的 `embedding`），老库/非 PG 库没这列就炸 | `chunk_columns()` 能力探测：缺必需列就**体面跳过、不发 SQL** |
| 2 | **`persist` 把已提交的数据弄丢**（本轮最严重） | `chunk_columns` 用 `inspect(engine)` 反射表结构，会**另开一条连接**；`StaticPool`（测试/演示全池一条连接）下这条连接抢占并归还 session 正在用的那条，触发隐式回滚 —— 表现为"commit 之后行数变 0" | 改用 `session.connection()` 在同一连接内反射 |
| 3 | 我自己的校验脚本把因果链方向写反了 | `zip(chain, chain[1:])` 当成了"子→父" | 修正为父→子；并承认 `enrich.items` 的父是 `intel.items`（权威钉死），`dq.verdicts` 是**同上游的分支** |

> 第 2 条尤其值得记：症状是"commit 成功但数据没了"，
> **426 个单测全绿**也发现不了 —— 因为 `conftest` 的 `chunk` 表是手工补的空表，
> 而真实库/演示库的表结构不同。这就是 §6.1 强调"绿灯≠线上验过"的实例。

### 10.3 现在的 E2E 证据（可复跑）

```powershell
$env:POSTGRES_DSN="sqlite:///E:/code/ai-threat-intel/data/demo.db"
$env:REDIS_URL=""; $env:DEMO_MODE="true"; $env:LLM_LOCAL_ENABLED="false"
python -m scripts.check_e2e_cycle --sources nvd
```

输出（2026-09-29 夜实测）：

```
阶段 2/3：归一 → 去重 → DQ1 → 排序 → 富化 → 落库 → 告警 → 日报
  [ ok ] normalize merged=22   [ ok ] dedup merged=12   [ ok ] dq1 merged=12
  [ ok ] triage   merged=12    [ ok ] enrich enriched=7  [ ok ] verify ...
  [ ok ] persist  merged=12    [ ok ] alert             [ ok ] report
阶段 3/3：事件载荷与因果链校验
  发布事件 33 条，主题 ['dq.verdicts','enrich.evidence','enrich.items','intel.items','intel.report.daily']
  因果链 intel.items → enrich.items: 1/1    因果链 intel.items → dq.verdicts: 12/12
OK：整条链在真实配置下跑通，全部事件载荷过契约，因果链完整
```

**这条证据的边界（不要说过头）**：
- ✅ 证明了**出版侧**：谁发、发什么、载荷过不过契约、因果链对不对、9 个节点在真实服务层能跑通。
- ❌ **仍未证明 Redis 传输**：本机没有 redis-server / Docker / fakeredis，
  脚本默认写内存总线。要验传输需起 Redis 后加 `--redis`。
- ❌ 采集仍是"兜底用已落库条目"（NVD 网络不可达）。**真实采集联调仍未做过。**

### 10.4 两个新脚本

| 脚本 | 用途 |
| --- | --- |
| `scripts/check_real_data.py` | 真库接线检查：EPSS/KEV 抽取、跨源合并不丢信号、triage 排名与载荷契约 |
| `scripts/check_e2e_cycle.py` | 跑一次完整 cycle + 事件载荷/因果链校验（§6.1 的落地工具） |

**新增测试**：`tests/test_indexer_degradation.py`（8 条，锁住"分块失败不拖垮 persist"与 chunk 能力探测）。

---

## 0. 范围与红线

### 0.1 我们负责什么

| 线 | 目录 | 状态 |
| --- | --- | --- |
| 框架层 | `core/`（8 文件 1390 行）、`db/`、`agents/`、`api/` | 约 90% |
| 富化线 F | `services/enrich/`（15 文件 2598 行） | 约 85% |
| **监测线 Y** | `services/collectors/`、`services/ingest/`、`services/dq1.py`（待建） | 见 §2 |

### 0.2 明确不做的

- **Q 线（问答）**：`services/qa/` 的 S6 拒答机制、§S7 检索投影 —— 划给别人。
  副作用：`Answer.abstained` 字段已在事件信封里就位，且**第 1 条拒答条件（证据为空）已实现**
  （`services/qa/agent.py:224` `"abstained": not evidence`，随 `qa.answers` 事件发出）。
  剩余 3 条（重排分<0.3 / `needs_clarify` / 证据未覆盖指定 CVE）由 Q 线补，本线不要动。
- **不做 Python→TypeScript 重写**。SafeTrace 的 TS 实现只作契约参照。

### 0.3 四条红线（违反即回退）

1. **可溯源性优先于准确率** —— 富化/判定结论没有证据 URL 就是 bug。
   `confirmed` 类结论必须有可打开的来源链接，否则置信度不得高于 0.5。
2. **降级必须显式** —— 所有兜底都要带 `degraded_to` + 原因，禁止静默。
3. **契约优先** —— 字段形状以 `contracts/schemas/` 的权威 Schema 为准，内部字段名不算数。
4. **8 个权威 Schema 是冻结件** —— 逐字节校验，本仓无权改。
   要加字段就加本仓扩展 Schema（照 `DimensionEvidence.json` 的先例），
   并登记进 `scripts/validate_contracts.py::LOCAL_SCHEMAS`。

---

## 1. ✅ 已完成：主链路事件载荷不合契约（已修，含门禁测试）

> **状态：已完成**（见 §8 接力结果）。本节保留作为背景 —— **这个坑值得记住**：
> 绿色的门禁曾对一个坏掉的实现持续报「通过」。

S3 改造当时把事件**信封**和**主题名**换成了权威版，但**载荷体仍是内部随手写的短字典**。
`contracts/events.md` 声明 `intel.items` 的 payload 必须是 `IntelItem.json`，
`validate_contracts` 当时却只校验 fixtures、不校验真实发布的载荷 —— 所以 346 个测试全绿也照样错。

当时的实测（均已修）：

| 主题 | 当时的实际载荷 | 权威 required | 匹配 |
| --- | --- | --- | --- |
| `raw.docs` | `{raw_item_id, source, vuln_id}` | `RawDoc` 7 字段 | **0/7** |
| `intel.items` | `{vuln_id, merged_raw_ids, merge_type}` | `IntelItem` 10 字段 | **0/10** |
| `enrich.items` | `{vuln_id, dimension, confidence}` | `EnrichmentResult` 7 字段 | **0/7** |

**为什么没被发现**：`validate_contracts.py::check_fixtures` 只拿 `fixtures/*.json` 去过 Schema，
真实发布路径的载荷**一次都没校验过**。这不是"测试没跟上"，是测试根本不存在。

### 1.1 现在的修法

- `nodes.py` 三处改用投影函数：`to_raw_doc()`（L112）、`to_intel_item()`（L155）、
  `to_enrichment_result()`（L324、L363）
- 新增 `contracts/schemas/LocalPayloads.json`（189 行）承载内联载荷的假内联定义，
  `check_payload_coverage()` 强制每个已发布事件都有对应契约
- 新增 `tests/test_event_payloads.py`：`recorder` fixture 抓**真实发布**的载荷
  （不是 fixture 冒充），21 个测试，`pytest -k payload` 全绿

### 1.2 验收（已通过，可复跑）

```
python -m pytest -p no:cacheprovider --no-cov -k "payload"   # 21 passed
```

**教训留在这里**：加门禁时务必让测试从**真实发布路径**取载荷。
只校验 fixture 的门禁，会对坏掉的实现持续报「通过」。

---

## 2. Y 线现状

### 2.1 已完成（不用重做）

| 项 | 位置 | 说明 |
| --- | --- | --- |
| 5 个采集器 | `services/collectors/` | `kev` 119（CISA KEV 官方目录，priority=5）/ `nvd` 152 / `ghsa` 151 / `arxiv` 107 / `community_rss` 115，基类 `base.py` 176 |
| 采集器注册表 | `collectors/registry.py` | `CollectorRegistry` 单例，`_COLLECTOR_CLASSES` 元组注册 |
| 去重 | `ingest/dedup.py` 101 行 | 精确 hash + SimHash 近似 |
| 归一化 | `ingest/pipeline.py` 251 行 | LLM 字段抽取 + CVE Schema 归一 |
| 19 张表 | `db/models.py` | 含 `raw_item` / `sync_watermark` / `source_config` / `vuln` |
| 水位线 | `sync_watermark` | 单源隔离，有测试（`test_watermark.py`） |
| `Vuln` 关键列 | `db/models.py` L128-131 | `affected_products` / `references` / `version_ranges` / `quality_score` |
| 状态机 | `agents/graph.py` + `nodes.py` L250 | 11 节点：`collect→normalize→dedup→**dq1**→triage→enrich→verify→persist→alert→report`（+`repair` 条件回环） |
| 因果链 | `agents/state.py` + `nodes.py` | S3 新增，`test_event_causality.py` 覆盖 |
| **DQ1 质量闸门** | `services/dq1.py` 325 行 | ✅ 已完成，见 §2.2 |

### 2.2 ✅ DQ1 数据质量闸门（已完成，325 行）

挂在 `dedup` 与 `triage` 之间（`nodes.py::node_dq1` L177），发 `dq.verdicts` 主题（L221）。
载荷形状（内联 `QualityVerdict`）：

```json
{
  "item_id": "...", "item_kind": "intel | enriched",
  "quality_score": 0.0,
  "dimension_scores": {"structure":0,"completeness":0,"consistency":0,"timeliness":0,"sourcing":0},
  "flags": ["ts_no_tz","reject_status","poc_dead_link","key5_missing","boilerplate","multi_id_mismatch"],
  "verdict": "pass | degrade | review | quarantine",
  "quarantine_ref": null, "reviewer": null, "reviewed_at": null,
  "gate_version": "1.0.0"
}
```

落地要点：

- **6 类 flag 与分数解耦** —— 命中即置位，`quarantine` 判定不受分数影响
- **阈值口径只有一处**：`services/dq1.py::thresholds_for()`。
  `dimensions.py::dimensions_for_quality()`（L189）已改为调它，
  旧阈值 `enrich_min_quality_partial=0.4` / `full=0.7`（`config.py` L78-79）映射为
  `review=0.5` / `degrade=0.7`，**保留配置项名**（否则现有测试会红）
- **`Vuln.quality_score` 有了运行时写入方**（此前只有 `demo_seed.py` 硬编码 `0.78`）
- 验收：`pytest -k "dq1 or quality or verdict"`；`test_dq1.py:244` 断言载荷过契约

### 2.3 验收

```
python -m pytest -p no:cacheprovider --no-cov -k "dq1 or quality or verdict"
python -m scripts.validate_contracts
```
- 6 类 flag 每个至少一个命中用例 + 一个不命中用例
- 同输入跑两次断言 `quality_score` 与 `flags` 完全相同
- 断言 `dq.verdicts` 的载荷能过内联 `QualityVerdict` 校验

---

## 3. ✅ 已完成：契约校验脚本路径硬编码

**当时的写法**（已改）：

```python
upstream = Path(r"D:\TrueDownload\safetrace-main\safetrace-main\contracts\schemas")
if not upstream.is_dir():
    return []  # 上游不可达时静默跳过
```

**问题**：换机器后冻结校验**静默失效**（返回 `[]` 看起来像通过）；
路径写死成某人的下载目录，不可移植。

**现在的解法（比"读环境变量"更彻底）**：8 个权威 Schema 的 sha256 指纹**随仓入库** ——
`contracts/schemas/FROZEN_MANIFEST.json`，`check_authoritative_frozen()` 改比仓内指纹。
**校验不再依赖任何外部路径**。上游路径降级为可选交叉核对（`SAFETRACE_CONTRACTS_DIR`，
L105/L219），配了才比对 SafeTrace 原件。

当前输出：`冻结指纹 8/8`。

---

## 3.5 ✅ 已完成：`accept.py` 默认覆写正在被服务使用的库（会毁数据）

```python
scripts/accept.py    L148: run("演示数据", [sys.executable, "-m", "scripts.demo_seed"])
scripts/demo_seed.py L970: parser.add_argument("--db", default="data/demo.db", ...)
```

`accept.py` 调 `demo_seed` **没传 `--db`**，落到默认值 `data/demo.db` —— 而那正是运行中的
API 服务握着的文件。已实测：服务在跑时 `accept.py` 的「演示数据」一步会因文件锁失败。

**这不是「服务开着导致的临时问题」，是代码缺陷。** 验收脚本不该假设「没人开着服务」。
不修的代价：

- 任何人开着服务跑 `accept.py` 都会失败，报错信息还指向错误方向（看起来像环境问题）
- 新克隆仓库的人跑 `accept.py`，会**静默毁掉自己的演示库**

**改法**（`demo_seed.py` 早已支持 `--db`，只是没人传）：

```python
suite.add(
    "演示数据",
    *run(
        "演示数据",
        [
            sys.executable,
            "-m",
            "scripts.demo_seed",
            "--db",
            "data/accept_check.db",
        ],
    ),
)
# 跑完清理临时库
```

这样 `accept.py` 就能在服务运行时独立执行，不需要停任何东西。

### 3.5.1 修复与实测（2026-09-29 夜）

已按上面改法修好（含跑完清理 `-wal`/`-shm` 残留）。**实测证据**：

```
API 正握着 data/demo.db（/health 200）时：
  demo_seed --db data/accept_probe.db   → exit 0，生成 495616 字节临时库
  demo_seed（不传 --db，旧写法）         → PermissionError WinError 32: 'data\demo.db'
  python -m scripts.accept 的「演示数据」→ [ OK ]
```

**残留说明**：`data/demo.db` 本身是**旧 schema**（`chunk` 表缺 `embedding` 列），
因为它在服务运行期间无法被重建。`demo_seed` 现在建全列（`embedding` 为占位列），
新生成的库不会再触发该问题；线上库重建一次即可。

---

## 4. P1 清单

**状态栏含义**：`待做` = 真缺口；`确认不做` = 有意划出范围或有客观阻塞，不必再尝试；
`已完成` = 见 §8/§9 接力结果。**区分这三者很重要 —— 「确认不做」不用重新评估。**

| # | 任务 | 线 | 状态 | 说明 / 位置 |
| --- | --- | --- | --- | --- |
| 1 | 降级统一出口接线：富化链路改调 `degrade()` | 框架 | ✅ **已完成** | `evidence.py:162` / `contracts.py:423,500-507` 均已走 `degrade()`，重复映射已删 |
| 2 | `enrich.papers` / `enrich.evidence` 接生产者 | F | ✅ **已完成** | `nodes.py:306,336` + `s2_events.py:35,36` |
| 3 | 生产代码真正从 `raw_refs` 回读原始 payload | Y/F | **确认不做** | 入向适配仅在 `tests/conftest.py` 验证过，本轮未动。后续接 F 线入向契约时再做 |
| 4 | 在真实 PostgreSQL 上重跑 `accept.py`，`[SKIP]` → `[OK]` | 全局 | **待做** | 本机无 PG。前置 §3.5 **已修**，现在开着服务也能跑 |
| 5 | S6 QA 拒答 / S7 检索投影 | Q | **确认不做** | 按 §0.2 划给 Q 线。副作用：`Answer.abstained` 第 1 条（证据为空）已实现，剩 3 条，**不要动** |
| 6 | 把 `data/check_real_data.py` 移入 `scripts/` | 全局 | ✅ **已完成** | 已移到 `scripts/check_real_data.py`（`python -m scripts.check_real_data`） |
| 7 | 收尾：停掉遗留 Demo 进程 | 全局 | **确认不做** | 服务当前在用，交接完成后自行停即可 |
| 8 | 分块写入会拖垮整条 persist | F/底座 | ✅ **已完成** | 见 §10（真库 E2E 才暴露，两个独立缺陷） |

### 4.1 ✅ 已完成：`check_real_data.py` 已移出 `data/`

它曾是手写的真库验证脚本，放在 `.gitignore` 覆盖的 `data/` 目录下 ——
既不在版本控制里，也不在融合前备份里：**这份验证资产当时只存在于一台机器上**。

现已移到 `scripts/check_real_data.py`：

```powershell
$env:POSTGRES_DSN="sqlite:///E:/code/ai-threat-intel/data/demo.db"
python -m scripts.check_real_data
```

同目录还新增了 `scripts/check_e2e_cycle.py`（跑一次完整 cycle 并逐条校验事件载荷与因果链，
见 §6.1 与 §10）。

---

## 5. 硬约束（踩过的坑，别再踩）

1. **不要用 PowerShell 5.1 的 `Set-Content -Encoding UTF8` 写文件** —— 会加 BOM，
   而 `ruff 0.16.9` 的 `format --check` 在 BOM 文件上直接 panic。仓库约定**全部无 BOM**。
2. **静态检查用 `python -m` 调用**：`python -m ruff check src tests scripts`、
   `python -m mypy src`。裸 `ruff` / `mypy` 命令在本机不可用。
3. **`POSTGRES_DSN` 指向 sqlite 时 PG 专有语法会炸**：`DISTINCT ON`、`pgvector` 运算符、
   `ON CONFLICT` 的 PG 变体。`core/metrics.py` 已踩过一次。
4. **新增 DB 逻辑先写测试**，复用 `tests/conftest.py` 的 SQLite + StaticPool + fake embedding fixture。
5. **`parse_nvd` 只从 `raw` / `raw_json` 键取原始 CVE JSON** —— 直接传裸 payload 会**静默返回空**
   （不报错，最难查的一类 bug）。共享 fixture 用 `parse_nvd({"cve_id":..., "raw": cve_json})`。
6. **`source_ids` 是字符串列表，`sources`/`references` 是字典列表** —— 两者语义不同，
   互填会 `AttributeError: 'str' object has no attribute 'get'`。
7. **新增事件主题要改两处**：`contracts/events.md` §3 登记 + `EventEnvelope.json` 的 `topic` 枚举。
   有测试 `test_every_topic_is_declared_in_the_envelope_schema` 强制一致，漏一处就红。
8. **改富化维度列表要同步 7 处**（§0.3 红线 4 同源），最易漏的是 `tests/test_imports.py` 的维度断言
   和 `core/contracts.py::DIMENSION_TO_CONTRACT`。
9. **本机无 Docker / 无 PostgreSQL 服务 / 无 LLM API Key / 无 redis-server** ——
   数据库迁移脚本在真实 PG 上没跑过、真实 LLM 路径没验证过、Redis 传输没验证过。
   **别在"本机能不能起 PG"上浪费时间**（笔记本免提权安装试过，backend 一连就崩：DLL 初始化失败）。
10. **不要在持有 session 时用 `inspect(engine)` 反射表结构** —— 它会另开一条连接；
    `StaticPool`（测试/演示全池一条连接）下这条连接会抢占并归还 session 正在用的那条，
    **触发隐式回滚**。症状极隐蔽：`commit()` 成功但数据没了（见 §10.2 第 2 条）。
   要反射就用 `session.connection()`。
11. **语句级 DB 错误会打脏 session** —— SQLite 上一条 `OperationalError` 之后，
    外层事务在退出时会整体回滚，连带丢掉已 flush 的结构化数据。
    所以"缺列/缺能力"要**先探测、体面跳过**，而不是"试一下、失败再回滚"。

---

## 6. 提交前必过的门禁

```powershell
python -m pytest -p no:cacheprovider --no-cov    # 当前基线 346 passed
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts  # 当前 89 files
python -m mypy src                              # 当前 62 files
python -m scripts.validate_contracts            # 当前 10 schema / 12 fixture
```

**基线：接手时先跑一遍确认是绿的，再动手。** 改完再跑一遍，全绿才算完成。
非阻塞警告：`StarletteDeprecationWarning: using httpx with starlette.testclient`（1 个）。

### 6.1 🔴 绿灯不等于线上验证过 —— 已验证 / 未验证的边界

**这一节专门防止「全绿所以线上是对的」这个误判。**

> 📌 2026-09-29 第三轮更新：新增 `scripts/check_e2e_cycle.py` 后，
> **「采集→富化端到端」从"从未跑过"升级为"用真实库跑通过（但采集是兜底数据）"**，
> 并且它第一次运行就抓出了两个会让线上静默丢数据的缺陷（见 §10）。
> 但**「事件总线在活进程里跑通」仍是未验证** —— 本机没有 redis-server / Docker / fakeredis。

| 项目 | 证据强度 | 说明 |
| --- | --- | --- |
| 构建、导入、静态类型 | ✅ 已验证 | ruff / mypy |
| 单元逻辑（契约映射、载荷投影、去重、DQ1 评分、事件信封、因果链） | ✅ 已验证 | 434 个测试，含 21 个载荷门禁 |
| **服务能启动、能出页面** | ✅ 已验证 | 见下方活进程实测 |
| **采集→富化→落库→告警→日报 全链跑通（真实库）** | ✅ **已验证（第三轮）** | `scripts/check_e2e_cycle.py`：9 个节点全 `[ ok ]`，33 条事件载荷过契约，因果链 12/12 挂上 |
| **事件总线在真 Redis 上跑通** | ❌ **未验证** | **无 redis-server / Docker / fakeredis**（复核于 2026-09-29 第三轮） |
| **真实采集源联调** | ❌ **未验证** | E2E 里 NVD 网络不可达，用 demo.db 已落库条目兜底 |
| 真实 PostgreSQL 上的迁移 | ❌ 未验证 | 本机无 PG |
| 真实 LLM 路径 | ❌ 未验证 | 无 API Key |

**活进程实测（2026-09-29 复核）**：

```
PID 14484  python -m uvicorn aiintel.api.main:app --host 0.0.0.0 --port 8000
端口 8000 /health                     → 200
端口 8000 /api/v1/metrics/overview   → 200, enrich.dimensions = 7
端口 5173 (前端)                      → 200
```

看着像"验证过了"，但**实际证明的只有「新代码能启动并正常服务」**。反证：

1. **6379 端口无监听** → 没有 Redis → `EventBus` 必然走降级分支
   → S3 的信封 / 因果链 / 主题 / 载荷在**活进程里**一次都没真正执行过
   （第三轮的 E2E 用的是内存总线，验的是出版侧，不是 Redis 传输）。
2. **Prometheus 计数器全空**（复核仍为空）：`intel_enrich_success_total`、
   `intel_collect_items_total`、`intel_llm_tokens_total` 一个都没有，
   `intel_enrich_coverage_ratio 0.0` → 采集、富化、LLM **执行次数为零**。
3. **`/api/v1/metrics/overview` 里的 69 条记录是 `demo_seed` 预置数据，不是管线产出**。
   判据：逐维度数据里 `asset.mock_ratio=1.0`、`fix.mock_ratio=1.0`
   —— 正是 `demo_seed` 灌的 Mock 声明值。

**所以：事件链路目前只有单测证据，没有任何活进程证据。**
这不否定单测的价值（单测是充分的），但**别在汇报或交接时说成「已经在线上验过」**。

**要真正验证事件链路，需要先起 Redis**，然后跑一次带采集的完整 cycle，
检查 `raw.docs → intel.items → dq.verdicts → enrich.items` 的因果链与载荷形状。

### 6.2 端点容易搞混

| 端点 | 返回格式 | 用途 |
| --- | --- | --- |
| `GET /api/v1/metrics/overview` | **JSON** | 业务指标（`dimensions`、`records`、逐维度统计）。前端用的就是这个 |
| `GET /metrics/overview` | Prometheus 文本 | 指标导出，**没有** `enrich.dimensions` 字段 |
| `GET /metrics` | Prometheus 文本 | 原始计数器（判断「到底跑过没有」看这里） |

`/metrics/overview` 和 `/api/v1/metrics/overview` 路径只差一个前缀，返回格式完全不同。
要确认「跑过多少次」，看 `/metrics` 的计数器，不要看 JSON 端点里的静态统计。

---

## 7. 建议执行顺序

**§1 / §2 / §3 / §4-1 / §4-2 / §3.5 / §4-6 已完成**（见 §8–§10）。剩下的按此顺序：

```
1. §6.1  起 Redis + 跑一次完整 cycle     ← 唯一还缺的「活进程链路」证据
   （前半已用内存总线验过：9 节点跑通 + 33 条载荷过契约 + 因果链完整；
     缺的是「真 Redis 传输」+「真实采集源联调」两件事）
2. §4-4  有 PG 的机器上重跑 accept.py     ← 前置 §3.5 已修，现在开着服务也能跑
3. 核对提案①的权重是否需要按真实数据分布微调  ← 见 docs/路线评估-优先级与RAG.md §2
   （权重已按该方法论的公式实现并版本化；但原计划要求"基于真实数据分布调权重"，
     而真实采集尚未跑过，当前权重来自文档里的设计值）
```

**为什么排到 §6.1 才有真实分布**：动态优先级要基于真实数据分布调权重，
而现在活进程从未跑过一次**真实采集**（E2E 用的是 demo.db 已落库条目兜底）。
权重已经版本化（`POLICY_WEIGHTS["1.0.0"]`），换权重只需加一个版本号，不必改代码。

> 📌 **上一轮执行顺序的变化（诚实记录）**：第二轮先做了提案①，
> 而本文原定的顺序是「§3.5 → §4-6 → §6.1 → §4-4 → 提案①」。
> 即提案①**跳过了 §6.1 的前置**。影响有限（权重来自
> `docs/路线评估-优先级与RAG.md` 的设计值，且已用 12 条真实库记录验证排序变化），
> 但"基于真实数据分布调权重"这一条实质上**尚未做到**，第 3 步就是补它。


> 📌 **另有两条被提为「P0 立即」的提案（动态优先级 / 深化 RAG）已完成可行性评估**，
> 结论与改写方案见 **`docs/路线评估-优先级与RAG.md`**。**不要重新评估一遍** ——
> 其中「深化 RAG」被判定为**不建议按原描述做**（与 F5 版本号红线、F6 确定性设计冲突，
> 且知识底座目前是桩模式、无库可检索）。

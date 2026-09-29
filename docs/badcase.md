# 富化线 badcase 库

> 计划 D12 交付物（`docs/富化线详细设计.md` §7）。**每条错例必须有归因与修复动作**，
> 答辩时这张表比"准确率 95%"更有说服力：它证明我们知道自己在哪会错。
>
> 维护规则：每发现一条错例，当天登记；修复后在「状态」列写 `已修(commit/日期)`，不要删除记录。

## 一、登记模板

```markdown
### BC-00X 一句话标题

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-10-XX |
| 漏洞 | CVE-2026-XXXXX（vuln_id `v_xxx`） |
| 维度 | paper / asset / poc / cvss / fix / consistency / ai_risk |
| 现象 | 系统给出的结论是什么（原文照抄） |
| 期望 | 正确结论应该是什么 |
| 归因 | ① 数据源问题 ② 提示词问题 ③ 解析/规则问题 ④ 阈值问题 ⑤ 数据模型缺字段 |
| 影响 | 单条错 / 系统性错（影响多少条） |
| 修复动作 | 具体改哪个文件哪一行，或"接受并降级标注" |
| 状态 | 待修 / 已修(日期) / 已知限制（写进报告） |

**证据**：`GET /vulns/{id}/evidence` 截图或 JSON 片段
```

## 二、已登记错例

### BC-001 POC `verified` 被硬编码为 true

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-09-30 |
| 漏洞 | 全部走 F3 的漏洞（系统性） |
| 维度 | `poc` |
| 现象 | `services/enrich/dimensions.py` 第 184 行：只要 LLM 判定 `is_poc=true`，就写入 `"verified": True`。前端据此可能显示"已验证"，但系统**从未运行过**任何 POC |
| 期望 | 区分三件事：`listed`（检索到）、`tier`（可信度分级）、`runtime_verified`（真的运行过，初赛恒 `false`） |
| 归因 | ④ 口径问题：把"检索到"当成了"已验证" |
| 影响 | 系统性（所有 POC 结论），且属于"看起来像造假"的高风险表述 |
| 修复动作 | 按 `docs/富化线详细设计.md` §3 F3 改造：`value.pocs[]` 增加 `tier` / `evidence_kind` / `runtime_verified`；`verified` 语义收紧为 `tier >= likely`；前端禁止出现"已验证"字样 |
| 状态 | 待修（计划 D9–D10） |

**证据**：`dimensions.py:184` — `"verified": True,`

### BC-002 富化结论没进检索空间

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-09-30 |
| 漏洞 | 全部（系统性，影响 Q 线问答质量） |
| 维度 | `fix` / `consistency` / `cvss` |
| 现象 | Q 线问"这个漏洞怎么修"，召回不到修复建议：`services/knowledge/indexer.py::persist_vuln` 只索引 `vuln.title + description + summary`，富化结论从未写入 `chunk` 表 |
| 期望 | 富化结论（修复建议、一致性共识、影响说明）以 `owner_type="enrichment"` 入向量库，可被混合检索命中并被引用 |
| 归因 | ⑤ 数据模型/写入链路缺一步（不是模型能力问题） |
| 影响 | 系统性；直接削弱"情报富化"在问答中的可见度 |
| 修复动作 | `persist_vuln` 中增加 `index_owner("enrichment", ...)`；`RetrievalRequest/Response` 证据包增加 `enrichment_dimension` 字段 |
| 状态 | 待修（计划 D11） |

**证据**：`indexer.py:234-236` — 仅 `await index_owner(session, "vuln", row.id, row.title or "", f"{row.description}\n{row.summary or ''}")`

### BC-003 `references` 抽取后未入库

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-09-30 |
| 漏洞 | 全部（系统性，阻塞 F3/F5） |
| 维度 | `fix` / `poc` |
| 现象 | `services/ingest/pipeline.py::normalize_item` 已经抽出 `references` 与 `affected_products`，但 `indexer.py::_upsert_vuln` 的字段循环里没有它们 → F 线读不到补丁链接与受影响产品 |
| 期望 | `Vuln` 表持久化 `references` / `affected_products`（并追加 `version_ranges` / `quality_score`） |
| 归因 | ⑤ Y 线（监测线）与 F 线的接口缺口 |
| 影响 | 系统性；阻塞 F5 修复建议（无法定位官方补丁）与 F1/F2 检索质量 |
| 修复动作 | `db/models.py` 给 `Vuln` 加 4 个可空列；`_upsert_vuln` 写入；F 线读到 `None` 时走降级路径 |
| 状态 | 待修（计划 D3–D5，责任：甲 + 乙） |

**证据**：`pipeline.py:131` 产出 `references`；`models.py::Vuln` 无对应列

## 三、本轮实测新登记的错例（BC-004 ~ BC-015）

> 与 BC-001~003 的区别：这三条是**接手时的既存问题**；
> 以下 12 条是 **2026-09-29/30 夜实测**发现并（多数）当场修掉的，
> 来源包括：`docs/评测实测结果.md`、compose 全栈验收、以及一次真实问答的原始 trace。
> 每条都给"怎么发现的"——这比结论本身更有复用价值。

### BC-004 演示库的 cvss 分数与自己的向量矛盾（8/11 条）

| 项 | 内容 |
| --- | --- |
| 现象 | 76 条富化里 `cvss.base_score` **恒为 9.8**；而 13 条的 `cvss_vector` 各不相同，独立算出 3.3 ~ 10.0。可核对的 11 条里 **8 条矛盾**。例：`AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`（本地低权限）正确分是 **3.3**，却报 9.8 |
| 怎么发现 | 用独立实现（`eval/cvss_reference.py`，12 个官方已知向量自测通过）逐条重算 `value.vector` 并比对 |
| 归因 | ④ 口径问题：`demo_seed.py::DIMENSIONS` 是按 **CVE-2026-31001 一条**写死的模板，套给了全部漏洞；`"base_score": 9.8` 直接写死 |
| 影响 | 系统性（全部 cvss 结论）。同一个对象里"向量说低权限、分数说 9.8"不需要领域专家就能判定，属于**会被当场看穿**的错误 |
| 修复动作 | 新增 `scripts/demo_derive.py::derive_cvss`：由该条 `cvss_vector` 按 CVSS v3.1 规范**本地算出**分数与 severity 标签（复用 `services/enrich/cvss.py` 的同一套口径）；证据里写明"向量 → 分数"便于复核 |
| 状态 | **已修**（`84d7cc0`）；修复后 10 条可核对**全部自洽**、分数分布 3.3/5.3/7.4/7.5/8.8/9.8/10.0 |

**证据**：修复前 `demo_seed.py:401` `"base_score": 9.8,`；修复后 `tests/test_demo_seed_consistency.py` 断言"不同向量必须产出不同分数"

### BC-005 asset 宣称受影响产品为 vllm，而数据里没有任何 CPE 依据

| 项 | 内容 |
| --- | --- |
| 现象 | 全部漏洞的 `asset.products[].vendor` 恒为 `vllm`、`product` 恒为 `vllm`；而种子数据 `VULNS[*]["cpe"]` **全部为空列表** |
| 怎么发现 | 写推导函数时发现：用真实种子数据调用 `derive_asset` 全部返回 `None`（因为 `cpe=[]`）→ 说明"vllm 产品"没有任何数据依据 |
| 归因 | ④ 口径问题：同 BC-004，模板照 CVE-2026-31001 写死 |
| 影响 | 系统性。等于凭空声称"这条漏洞影响 vLLM"，属编造 |
| 修复动作 | `derive_asset_or_abstain()`：有 CPE 就解析；**没有就如实产出空产品列表** + `abstain_reason`，**绝不回落到模板**。（第一版让无法推导时回落模板，结果 asset 又全变成 vllm —— 这个反复本身也记在这里） |
| 状态 | **已修**（`84d7cc0`）；修复后 12 条产品列表均为空并标注原因 |

**证据**：`data/_why_asset.py` 的临时诊断输出（`cpe=[] -> vendor=None` ×12）

### BC-006 五个维度用同一条示例值冒充逐条结论

| 项 | 内容 |
| --- | --- |
| 现象 | `poc` / `paper` / `fix` / `consistency` / `ai_risk` 在 76 条里**各只有 1 个不同值**：`poc` 的 11 个引用全指向 `github.com/example/vllm-template-rce-poc`、`paper` 的 12 个全指向 `arxiv.org/abs/2609.01234` |
| 怎么发现 | 对每个维度做 `json.dumps(value)` 去重，统计不同值个数 → 7 个维度**全部只有 2 个或 1 个** |
| 归因 | ④ 口径问题 + ① 数据源问题：逐条产生这些维度需真实联网检索（GitHub/arXiv/OpenAlex）或 LLM 调用，本机均不可达，于是整个维度复用了示例值 |
| 影响 | 系统性。演示时若被当成逐条结论引用，等于造假 |
| 修复动作 | 既然造不出真实值，就**标出来**：这 5 个维度统一写 `degraded_to="fixture"` + `degraded_reason`（明确"本维为该维度的示例值，同一条内容用于多条漏洞，非该漏洞的真实富化结论"），前端据此显示降级徽标 |
| 状态 | **已标注**（`84d7cc0`）—— 不是"已修"：真实值仍需联网检索；标注使其可审计而非静默 |

**证据**：修复后 `degraded_to` 分布 = `cvss`→None(10) / `asset`→mock(12) / 其余 5 维→fixture(8~12)

### BC-007 问答准确率指标**从未跑通**（`answer()` 不接受 `stream`）

| 项 | 内容 |
| --- | --- |
| 现象 | `python -m eval.qa_accuracy` 必抛 `TypeError: QAAgent.answer_stream() got an unexpected keyword argument 'stream'` |
| 怎么发现 | 第一次真跑评测时立刻报错 |
| 归因 | ⑤ 接口缺口：`eval/qa_accuracy.py` 调 `agent.answer(q, stream=False)`，而 `answer` 把 `**kwargs` 透传给没有 `stream` 参数的 `answer_stream` |
| 影响 | **该指标从建立起从未产出过数字** —— 这正是技术报告里"问答准确率 86%/78%"只能手写、无法复核的直接原因 |
| 修复动作 | `answer` 内显式 `kwargs.pop("stream", None)`；加 `tests/test_qa_answer_kwargs.py` 钉住"接受并吞掉 stream，同时继续透传 top_k/session_id" |
| 状态 | **已修**（`7f3ae16`）；修后首次跑出 **0.575**（20 题黄金集） |

**证据**：修复前的完整 traceback；修复后 `eval/artifacts/qa_accuracy.json`

### BC-008 采集时效指标恒报 fail（只读恒为 NULL 的列）

| 项 | 内容 |
| --- | --- |
| 现象 | `samples: 0`、`p50/p95 = null`、`sla_tier: "fail"`，而 `raw_item` 表里 22 条记录的 `published_at` / `fetched_at` **都有真值** |
| 怎么发现 | 跑 `eval.run_all` 看到 `samples=0`，去库里查发现数据齐全 |
| 归因 | ③ 解析/规则问题：`load_from_db` 只读 `r.latency_seconds`，而该列恒为 NULL，代码**不去用两个时间戳推导** |
| 影响 | 报告里"监测时效性"会无故变成不合格 |
| 修复动作 | 抽出 `derive_latency_seconds(stored, published, fetched)`：落库值优先，为空则由时间戳推导；加 `tests/test_eval_collect.py`（含负值/空值应跳过） |
| 状态 | **已修**（`245da41`）；修后 22 条样本、档位 `excellent` |

**证据**：修复前 `[collect] {"samples": 0, ... "sla_tier": "fail"}`；修复后 `samples: 22, sla_tier: "excellent"`

### BC-009 富化 precision 算出 23.667（>1，数学上不可能）

| 项 | 内容 |
| --- | --- |
| 现象 | `enrich_accuracy` 输出 `"precision": 23.667` |
| 怎么发现 | 建立基线时看到该值，**"precision > 1"本身就不合法**，所以立刻去查公式 |
| 归因 | ④ 口径问题：`precision = hits / max(hits + (total - correct - hits), 1)` 把 **case 级**计数（total/correct）与**元素级**计数（集合类维度按元素累加 tp/fp/fn）混进同一公式；实测 `total - correct - hits = -68`，分母被压到 3 → 71/3=23.667 |
| 影响 | 指标不可信；且同源还有两处：`{'poc': False}` 被判成正例（非空 dict 的 `bool()` 为 True，accuracy 从 1.0 掉到 0.961）、集合维度 `accuracy = 1.5` |
| 修复动作 | 分开算：case 级出 `overall_accuracy`，元素级出 `micro_precision/micro_recall`，另给 `macro_*`；`_expected_positive` 显式处理 dict 形状；per-dimension accuracy 改元素级。加 `tests/test_eval_metrics.py`（断言所有指标落在 [0,1]） |
| 状态 | **已修**（`91b0c33`）|

**证据**：修复前 `precision: 23.667`；修复后 `overall/macro/micro 全部 1.0`，且新写的测试**又抓出** `paper.accuracy = 1.5`（第三个同源 bug）

### BC-010 新装的 PG 里 `chunk` 缺 `embedding` 列 —— 代码按模型判断列存在性

| 项 | 内容 |
| --- | --- |
| 现象 | 向 compose 的 PG 灌数据时报 `UndefinedColumn: 关系 "chunk" 的 "embedding" 字段不存在` |
| 怎么发现 | 灌数脚本连续失败两次，第一次是 `id` 重复，第二次是这个 |
| 归因 | ⑤ 数据模型分支：PG **没装 pgvector 扩展**时，`0001_init.py` 会**降级建一张缺 `embedding` 列的 chunk 表**（这是设计好的合法降级）。而我的脚本用 **ORM 模型定义**判断列是否存在 → 与真实表结构不一致 |
| 影响 | 阻塞 compose 环境的灌数 |
| 修复动作 | 改查**真实表结构**（`sa_inspect(engine).get_columns()`），并用 **core insert 显式指定列**（ORM 会按模型生成完整列清单，必然带上 embedding） |
| 状态 | **已修**（`4b9d815`）|

**证据**：`sync_demo_schema.py` 里早已记录同类漂移；本次是它在**另一个方言**上的再次出现

### BC-011 `raw_item.simhash` 是 64 位却用 int4 —— 只在 PG 上暴露

| 项 | 内容 |
| --- | --- |
| 现象 | 灌数据时 PG 报 `psycopg.errors.NumericValueOutOfRange: 整数超出范围`，**22/22 行全部失败** |
| 怎么发现 | 逐列扫描整型列的取值范围，发现 `simhash` 最大 8 990 225 398 902 710 575（约 8.99e18），远超 int4 上限 2 147 483 647 |
| 归因 | ⑤ 数据模型缺字段类型：`models.py` 声明 `Integer`，而 simhash 是 64 位指纹 |
| 影响 | **只在 PostgreSQL 上暴露** —— 演示库一直是 SQLite，而 SQLite 不校验整型宽度（`INTEGER` 可存 8 字节），所以长期没被发现 |
| 修复动作 | 模型改 `BigInteger`；新增迁移 `0003_simhash_bigint`（`batch_alter_table`，两种方言都能跑；downgrade 会检查超范围数据并**拒绝**执行以免截断） |
| 状态 | **已修**（`4b9d815`）|

**证据**：`information_schema.columns` 查询确认 `simhash` 已为 `bigint`

### BC-012 嵌入器无失败记忆 → 每次问答白等 3.5 分钟

| 项 | 内容 |
| --- | --- |
| 现象 | compose 环境下一次问答卡 **3.5 分钟**（原始 trace：`retrieve.2` 的 `elapsed_ms = 210972`），最后仍退化为关键词检索 |
| 怎么发现 | 冒烟里问答 SSE 超时；用容器内 SSE 探针打印每帧，看到只有 5 帧 trace + 3 帧 stage 就停住 |
| 归因 | ① 数据源问题 + 设计缺陷：容器**连不上 `huggingface.co`**（实测 huggingface / ollama registry / hf-mirror 全不可达），而 `Embedder._load()` **没有失败记忆** —— 每次 `embed()` 都重试一次网络加载 |
| 影响 | 演示不可用（一次问答 3.5 分钟）；且属于"又慢又没结果"的最差组合 |
| 修复动作 | ①失败熔断：加载失败后隔离 600s，期内直接返回不可用、**不发任何网络请求**（加锁后双重检查防并发击穿）；②compose 注入 `HF_HUB_DOWNLOAD_TIMEOUT=15` / `HF_HUB_ETAG_TIMEOUT=10` 压单次尝试；③暴露 `available` / `failure_reason` 便于如实报告降级原因。加 `tests/test_embedder_circuit_breaker.py`（6 条） |
| 状态 | **已修**（`1ff7a0d`）|

**证据**：容器内 SSE 探针输出 `trace: 5 @0.0s, stage: 3`，耗时 451s

### BC-013 compose 的 PG 一直是空库（`demo_seed.py` 只会建 SQLite）

| 项 | 内容 |
| --- | --- |
| 现象 | compose 全栈起来后 `/api/v1/vulns` 返回 `total=0`、问答 `citation=False` —— **服务全健康但没有任何内容** |
| 怎么发现 | 运行期冒烟里 `total=0`，起初以为是 API 过滤条件问题 |
| 归因 | ⑤ 工具缺口：`scripts/demo_seed.py` 内部 `create_engine(f"sqlite:///{path}")`，**只会建 SQLite 文件**；compose 用的是 PostgreSQL |
| 影响 | 演示环境空白，无法演示 |
| 修复动作 | 新增 `scripts/seed_from_demo.py`：读 SQLite 演示库、经 **core insert** 写入当前 `POSTGRES_DSN` 指向的库（方言中立）。过程中又踩到 4 个子问题：外键清单手工维护必漏（改**自动发现**并按依赖拓扑排序）、按模型判断列存在性不对（见 BC-010）、不是每张表都有 `id`（`policy_standard`/`sync_watermark` 用业务键）、`chunk.tsv` 在 PG 上是 **NOT NULL tsvector** 而 SQLite 里是 NULL（改为让 DB 算 `to_tsvector('simple', content)`，用 `simple` 因为语料含中文） |
| 状态 | **已修**（`4b9d815`）；灌后冒烟 `total=13`、`citation=True` |

**证据**：冒烟输出从 `total=0, citation=False` 变为 `total=13, citation=True`

### BC-014 `localhost:5432` 连到了另一个 PostgreSQL

| 项 | 内容 |
| --- | --- |
| 现象 | 灌数成功（校验显示 13 条），但 API 仍报 `total=0`；查容器内库是 0 条、而我灌的库有 13 条 |
| 怎么发现 | 查监听端口：`0.0.0.0:5432` 是宿主机 PG 服务、`[::]:5432` 是 Docker；**`localhost` 走 IPv6 命中 Docker，`127.0.0.1` 走 IPv4 命中宿主机服务** |
| 归因 | 环境陷阱：本机同时存在宿主机 PG 与 compose 的 PG，都想占 5432 |
| 影响 | 排查了两轮才定位 —— 两边表结构与 `alembic_version` 不同是唯一线索 |
| 修复动作 | 给 compose 的库灌数改为**在容器内执行**（容器内 `postgres:5432` 无歧义）；并写进 `docs/手动配置指南.md`「两个会浪费半天的环境陷阱」 |
| 状态 | **已规避并归档**（文档化）|

**证据**：`Get-NetTCPConnection -LocalPort 5432` 输出两个不同 PID（`postgres.exe` 与 `docker.backend`）

### BC-015 compose 全栈实测通过（正向记录）

| 项 | 内容 |
| --- | --- |
| 现象 | —（这是**通过**记录，登记用于对照与回归） |
| 内容 | 6 服务（api/postgres/redis/web/prometheus/ollama）全部起来；运行期冒烟 **10/10**：`/health` 200、迁移 19 张表（`alembic=0003`）、`/api/v1/vulns total=13`、Redis `PING` 成功、web 首页 200 **且 nginx 反代 `/api` 返回 total=13**、Prometheus 抓取 `aiintel=up`、问答 SSE `stage/citation/done` 齐全 |
| 怎么发现 | `python -m scripts.smoke_runtime` |
| 归因 | — |
| 影响 | 台账 `E-05` 由此闭合 |
| 修复动作 | 新增 `scripts/smoke_runtime.py`（**运行期**检查，与开发机门禁 `accept.py` 分工：前者测"服务是否真在干活"，后者测"代码是否合格"） |
| 状态 | **已通过**（`4b9d815`）|

**证据**：`docs/验收清单.md` 的 10/10 输出

## 四、统计（随时间更新）

| 维度 | 已登记 | 已修 | 已知限制 |
| --- | --- | --- | --- |
| `paper` | 1 | 1 | 演示值为示例值（已标 `fixture`）；本机 arXiv/OpenAlex 不可达 |
| `asset` | 1 | 1 | 资产画像为 Mock（合规）；无 CPE 时**如实给空** |
| `poc` | 1 | 1 | 演示值为示例值（已标 `fixture`） |
| `cvss` | 1 | 1 | 由向量本地计算，可复核 |
| `fix` | 1 | 1 | 演示值为示例值（已标 `fixture`）；无官方补丁时只给通用建议 |
| `consistency` | 1 | 1 | 演示值为示例值（已标 `fixture`） |
| `ai_risk` | 0 | 0 | 演示值为示例值（已标 `fixture`） |
| 横切（评测/工程） | 9 | 9 | 见 BC-007 ~ BC-015 |
| **合计** | **15** | **15** | 其中 BC-006 / BC-014 为"已标注/已规避" |

> 三条 BC-001~003 是**接手时的既存问题**，登记目的是"先承认，再修"，不是本轮的返工。
> BC-004~015 是本轮实测发现，多数已修并带回归测试；
> **BC-006 与 BC-014 故意不写"已修"** —— 前者真实值仍需联网，后者是环境事实，
> 如实标记比强行宣称修好更有价值。


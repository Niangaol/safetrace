# SafeTrace · 任务台账（D2 → D22）

> **建立于 D2 = 2026-09-29**。本文件是唯一可执行任务清单，替代原先只存在于 `README.md` 一句话里的「D2 起任务单」。
> 出处：`plan-bubbly-karp.md`（本目录 `docs/` 无该文件，plan 存放在队长本地计划目录）。
> **纪律**：任务只在这里增删改；每次 PR 必须同步更新对应行状态；周五对齐会直接照本文件过，不靠口述。

## 0. 怎么用这份台账

| 字段 | 取值 |
|---|---|
| `状态` | `待办` / `进行中` / `已完成` / `阻塞` / `已砍` |
| `线` | `甲` 监测线+运维 ｜ `乙` 富化线 ｜ `丙` 问答线+编排 ｜ `丙(H)` 底座（队长兼） ｜ `全` 全员 |
| `砍单层级` | `禁砍`（一票否决）｜ `保`（必须保住）｜ `基础`（不做则证据不可信）｜ `砍①`~`砍⑤`（落后时从上往下砍）｜ `—` 常规 |

**流程约束**（`docs/GITHUB-FLOW.md`）：

1. 一个分支只干一件事，合入后即删；`contract/` 前缀的 PR 必须三线 sign-off。
2. **D6 = 10/3 契约冻结后，只允许新字段追加 + 旧字段标 deprecated，禁止改语义、改枚举、删字段。**
3. 交件前 checklist 的第一条是门禁全绿——当前它不可信，见 `基础` 级任务。

## 1. 硬节点

```
D2(9/29)    D6★(10/3)   D9(10/6)   D11(10/8)  D13(10/10)  D16★(10/13)  D18★(10/15)  D20★(10/17)  D22★(10/19)
台账建立    契约冻结     中期冲刺   首源贯通    7源/Trace   完整彩排      报名截止      功能冻结      交件 24:00
```

| 节点 | 日期 | 准入条件（照本台账核对） |
|---|---|---|
| **D6** | 10/3 | `C-01`~`C-06` 全部 `已完成`；`R-01`~`R-06` 全部 `已完成` |
| D9 | 10/6 | `E-01` 第 7 源 `已完成`；`A-01` 接口层 `已完成` |
| D11 | 10/8 | `E-02` 真跑留痕 `已完成`；冒烟第 5 段黄金问答 20 条 `已完成` |
| D13 | 10/10 | `A-01`~`A-06` 全部 `已完成` 或按砍单顺序转入 `已砍` |
| **D16** | 10/13 | 20 问全过 + 7 源登记 + 时效看板有真实数字；完整彩排 |
| **D20** | 10/17 | `D-01`~`D-13` 文档口径 `已完成`；`S-01`~`S-04` 就绪；tag `submission-v1` |

## 2. 状态总览

| 阶段 | 任务数 | 待办 | 进行中 | 已完成 | 阻塞 |
|---|---|---|---|---|---|
| 第 0 阶段 根因修复（D2–D5） | 6 | 3 | 0 | 3 | 0 |
| 第 1 阶段 契约扩展（**必须 D6 前**） | 6 | 6 | 0 | 0 | 0 |
| 第 2 阶段 架构改造（D13–D18） | 6 | 6 | 0 | 0 | 0 |
| 第 3 阶段 证据链（D7–D18） | 7 | 5 | 0 | 0 | 2 |
| 第 4 阶段 文档口径同步 | 13 | 13 | 0 | 0 | 0 |
| 第 5 阶段 冻结与交件（D19–D22） | 4 | 4 | 0 | 0 | 0 |
| **合计** | **42** | **37** | **0** | **3** | **2** |

> 本表随 PR 更新。任何一项转 `已砍` 必须在 PR 描述里写清「保留下什么证据」。

## 3. 第 0 阶段：根因修复（D2–D5，最高优先）

> 原则：这些不改，后面所有"证据"都不可信。README 第 7 节宣称的「门禁全绿 / 132 单测 / 契约校验全绿」目前有四处不成立。

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| R-01 | 丙 | `package.json` 的 `validate:contracts` 调 `python`，本机只有 `python3` → `npm run check` 必失败 exit 127。改为 `PY=$(command -v python3 \|\| command -v python) && "$PY" scripts/validate_contracts.py` | — | 已完成 | 基础 | `npm run check; echo $?` → 0  ✅ 本 PR 已修：改为 `python3`/`python` 双探，`npm run check` 本机首次 exit 0|
| R-02 | 丙 | `.githooks` 接线：`git config core.hooksPath .githooks` + `chmod +x .githooks/*`（**已做**，待随本 PR 提交模式变更）+ 修 `docs/GITHUB-FLOW.md:91` 的假陈述「本仓库已配置」（已随本 PR 修正，并补 `chmod +x` 要求） | — | 已完成 | 基础 | 试提交 `bad message` 被拒；`npm run hooks:install` 可复现  ✅ 本 PR 已完成：`core.hooksPath` 已配置 + 补 `chmod +x` + GITHUB-FLOW:91 假陈述已改 + 新增 `npm run hooks:install`|
| R-03 | 丙 | MG1 usage 表丢两字段：`src/gateway/src/index.ts:246-247` 把 `latency_ms:0`/`cached:false` 写死，丢了 reply 里正确的值（`record()` 入参只收 `{usage, degraded_to}`） | — | 待办 | 基础 | 新增断言：同 prompt 二次调用 → usage 新增一行且 `cached=true`、`latency_ms>0` |
| R-04 | 丙 | 黄金问答口径做实 + 契约校验覆盖：仅 10 条（目标 20）；无期望答案文本；`scripts/smoke.ts:121-127` 不传 `cve_ids`；`:139` 只断言「带引用或拒答」且**不用 `expected_intent`**；`scripts/validate_contracts.py:34-46` 的 `FIXTURE_SCHEMA_MAP` 不含 golden-qa | R-01 | 待办 | 基础 | 扩到 20 条（覆盖 8 类意图，≥3 条 `expect_abstain`）；smoke 改硬断言 `expected_intent` + `expected_cve_ids` + `expected_answer_must_include`；校验器加 golden-qa 条目 |
| R-05 | 丙 | `.gitignore:32` 是 ` recordings/`（**行首有空格**），对 `recordings/` 目录无效 | — | 待办 | 基础 | `git check-ignore -v recordings/x.mp4` 命中 |
| R-06 | 丙 | 建本台账（原先 `find -iname "*todo*"` 仓库内零命中；Taskwarrior 已装但 `project:safetrace` 零任务） | — | 已完成 | 基础 | 本文件存在且随 PR 更新  ✅ 本 PR 已建：本文件|

## 4. 第 1 阶段：契约扩展（**必须赶在 D6 = 10/3 前**）

> D6 后禁止改枚举。**C-01 是唯一过期就违约的一项。**

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| C-01 | 丙 | `contracts/schemas/DecisionReply.json` 的 `decided_by` 枚举追加 `human`（四层兜底阶梯的"人工"层契约位）。已核实该枚举在代码里唯一出现是 `src/shared/src/types.ts:116` 类型声明、零运行消费方，加值不破坏实现 | — | 待办 | 禁砍 | `contract/` PR 三线 sign-off；`python3 scripts/validate_contracts.py` 绿；CHANGELOG v1.1.0 |
| C-02 | 丙 | `RetrievalResponse.json` 的 chunk 增 `published_at` + `trust`(trusted/untrusted)。已知限制⑤的地基 + 注入防护"证据信封"的载体（`EvidenceChunk` 现无时间字段、无信任标记） | — | 待办 | 基础 | 校验器绿；`shared/types.ts` 同步；fixture 样本更新 |
| C-03 | 丙 | `QualityVerdict` 内联契约增 `injection_score` + `injection_flags`（内联契约，追加式） | C-02 | 待办 | 砍② | 校验器 green；`fixtures/qualityverdict.sample.json` 补样本 |
| C-04 | 丙 | `Answer` 接口增 `stale_warning?` + `injection_guard?`（时效提示与注入筛查计数要显式出现在响应对象上，符合"兜底必须显式可见"） | C-02 | 待办 | 砍⑤ | 运行时校验测试；冒烟断言非拒答条可带 `stale_warning` |
| C-05 | 丙(H) | `config/models.yml` 增 provider `trust_boundary`(cloud/local/cache) + role `data_domain`(public/private)；`openapi.yaml` 请求体增 `data_domain` | — | 待办 | 禁砍 | 隔离闸门测试：private 数据 + cloud provider → 硬拒 + FallbackEvent |
| C-06 | 丙 | `contracts/schemas/CHANGELOG.md` 升 v1.1.0，逐条登记影响面与破坏性评估；同步 `scripts/validate_contracts.py:271-280` 硬编码的 expected 集合 | C-01~C-05 | 待办 | 禁砍 | 校验器输出的 schema 数与 CHANGELOG 一致 |

## 5. 第 2 阶段：架构改造（D13–D18）

> 队长已定：**适配层 + 双实现**；**暂不接云端**，先做实隔离与链路；**链路真跑、模型用 cache provider 占位**。

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| A-01 | 丙 | **StateMachine 适配层 + 双实现**。新增 `src/qa/src/orchestrator/statemachine.ts`（接口：`MachineState`+reducers / `MachineNode` / `compile` / `invoke(state,{threadId})` / `resume(threadId,value)` / `MachineResult` 含 `interrupted`）；后端 A `backends/langgraph.ts`、后端 B `backends/native.ts`（迁移现有 `taskgraph.ts` 105 行的 topoOrder+状态合并+interrupt 挂起）；`config/orchestration.yml` 切 `backend: native\|langgraph`，默认 `native` 保 main 可演示。**同一套测试跑两个后端** | C-01 | 待办 | 砍① | `test/statemachine.test.ts` 用 `for (backend of ["native","langgraph"])` 环跑相同断言；原 5 条 taskgraph 测试语义保留 |
| A-02 | 丙 | **四层兜底阶梯 工具→规则→LLM→人工**。新 `src/qa/src/ladder/`；契约位已现成（`decided_by` 四通道 + `models.yml:78` 的 `decision` role `rule-fallback-v0` 无调用方 + `openapi.yaml:135` 的 `/v1/decide` 未挂路由）。**LLM 层必须允许返回空（低置信度弃权）才能下坠到人工层** | A-01, C-01 | 待办 | 禁砍 | `decision.replies` 全量入总线可 `bus.replay()`；`/v1/decide` 挂路由并有测试；冒烟断言阶梯留痕 `escalation_trace` |
| A-03 | 丙(H) | **数据隔离闸门**。MG1 增 `data_domain × trust_boundary` 两维；`private` + `cloud` → **硬拒**（非 warning）并 `degrade()` 登记（`degraded_of:"isolation:private->cloud"`）；`openai-compat.ts` 的 `postJson` 前加 `assertPublicScope()` 扫描 `asset_id`/`internal_host`/`tenant` 等 private 标记。**注意 `profiles.ts` 是手写 YAML 子集解析器，新字段必须是同形态标量** | C-05 | 待办 | 禁砍 | `src/gateway/test/isolation.test.ts`：private+cloud 必拒且落 FallbackEvent；全链无 local provider 时显式失败不静默改投云端；`profiles.ts` 解析结果断言 |
| A-04 | 乙+丙 | **注入防护（新模块，最要紧）**。实测确认全链路零防御：`adapters/nvd.ts:89` 读外部描述 → DQ1 无注入检查 → `q4-answer.ts:150`/`:142` 把原始不可信文本直接拼进 prompt，无分隔符无数据角色标记。四层：①入库期 DQ1 扩注入维度（`src/shared/src/injection.ts` 纯函数检测器）②检索期证据信封（`trust:untrusted` + `<<<UNTRUSTED_EVIDENCE id=.. provenance=..>>>`）③合成期 `assertNoInjectionLeak()` ④工具权限边界（`ToolRegistration.permissions` + `roles.ts` 白名单）。**同时必须处理 `f1-papers.ts:165-176` `cleanText()` 的实体解码放大**（会把 `&#73;gnore...` 解码成真指令） | C-02, C-03 | 待办 | 禁砍 | `fixtures/injection/` ≥10 条攻击样本（instruction-override / role-confusion / zero-width / base64-hidden / html-entity-encoded / comment-embedded / exfil-instruction / fake-system-prompt / citation-spoof / multi-stage）；`src/ingest/test/injection.test.ts` + `src/qa/test/injection.test.ts` 逐条断言 |
| A-05 | 丙 | **时效性**。`q2-retrieval.ts:181-192` 的 `passesFilter()` 真正实现 `published_after`（现在直接 `return true`）；按意图定时效阈值（KEV/trend ≤7d、impact_range ≤90d），超龄在答案尾部显式提示并进 `reasoning_chain`；`EvidenceChunk.score_sparse` 开始填充 BM25 原始分 | C-02, C-04 | 待办 | 砍⑤ | 冒烟断言 `published_after` 真生效；过龄证据答案带 `stale_warning` |
| A-06 | 丙(H) | **A1 自愈 + Langfuse**。现状 `roles.ts:42-48` selfheal 的三个 tool（`replay`/`dead_letter_drain`/`healthcheck`）零实现，L2/L4 无任何实现。实现 `src/qa/src/orchestrator/selfheal.ts`（订阅 `fallback.events`、死信指数退避重投、聚合 `/healthz`+熔断状态）；`ops/scripts/drill.sh` 自愈演练；`src/shared/src/trace.ts` 把 FallbackEvent 与 Envelope 转发 Langfuse（HTTP 无 SDK）。**注意 compose 里 Langfuse 的 `NEXTAUTH_SECRET`/`SALT` 硬编码 `dev-only-change-me`，需改 env** | A-01, R-03 | 待办 | 砍③ | `ops/scripts/drill.sh` 跑通 检测→降级→恢复→重放→验证 全链路并入 Trace；Langfuse 上可见 FallbackEvent |

## 6. 第 3 阶段：证据链补齐（D7–D18，与架构改造并行）

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| E-01 | 甲 | **第 7 源**。现 6 源（4 active + ghsa/arxiv 两个 planned），目标 ≥7。选 cvelistV5 git 差分（需新增 git 能力，`common.ts:53` 只有 HTTP JSON）或先落地 ghsa。要动 7 处：`registry.ts` / 新 `sources/<id>.ts` / 新 `adapters/<id>.ts` / `index.ts` export / `pipeline.ts:57-62` SOURCE_RUNNERS / `fixtures/sources/<id>.sample.json` / `registry.test.ts:7` 的 6→7。**连累三处计数断言**：`pipeline.test.ts:13-14` 的 `fetched/parsed.length===4`、`pipeline.test.ts:27` 的 `merged.raw_refs.length===4`（容易漏）。`smoke.ts:63` 是 `>=4` 前向兼容不用改 | — | 待办 | 保 | `registry.test.ts` 断言 7 源；`npm run smoke` 仍全绿 |
| E-02 | 甲 | **真实联网抓取留痕**。`common.ts:53-85` 已有 fetch + 3 次指数退避 + 落盘 `tmp/ingest-cache/`，NVD 有真实令牌桶。已实测 cveawg.mitre.org / arXiv / NVD API 2.0 均返 200。跑一次 `runIngestOnce({offline:false})` 并与 fixture 回放结果对比 | E-01 | 待办 | 保 | 留采集日志 + 对比表；失败/离线仍走 `degrade()` 显式登记 |
| E-03 | 乙 | **F1 recall@5 基线**。现状零基线（`f1-papers.ts:122-128` 只有词级重合启发式）。建 20 条标注集，报 recall@5 | — | 待办 | 砍② | 输出 recall@5 数字并纳入冒烟聚合门槛 |
| E-04 | 乙 | **DQ1 隔离区落库**。`quarantine_ref` 只是字符串（`dq1.ts:238`），无表无目录，隔离形态仅是 `dq.verdicts` 里 verdict=quarantine 的事件。`store.ts` 增 quarantine 表（照抄 `dead_letters` 模式） | — | 待办 | 保 | 隔离区可查可导出；10 条 `fixtures/dirty/` 全捕获回归仍绿 |
| E-05 | 甲 | **compose 验证**。Docker 未装，7 服务（qdrant/postgres/langfuse×2/clickhouse/redis/minio）从未拉起，README:82 明示交件前必须验一遍 | — | **阻塞** | 禁砍 | `cd ops && docker compose up -d qdrant postgres && bash scripts/wait-healthy.sh` 全 PASS；QdrantEngine 走真检索 |
| E-06 | 全 | **NVD API key**。`.env` 不存在，`NVD_API_KEY=` 空；无 key 限流 5 req/30s，有 key 50 req/30s。申请入口 README:65-66 | — | **阻塞** | 基础 | `.env` 填好；`runIngestOnce({offline:false})` 走 50 req/30s 档 |
| E-07 | 甲 | **72h 挂机证据**。零脚本零调度（`registry.ts` 的 `poll_interval_s` 只是字段声明，`runIngestOnce()` 是单次函数）。实现 `src/ingest/src/scheduler.ts` 按 `poll_interval_s` 周期调度 + `ops/scripts/uptime.sh` 记可用率 | E-01 | 待办 | 禁砍 | 可用率截图 ≥72h；降级次数与 FallbackEvent 对齐 |

## 7. 第 4 阶段：文档口径同步（D13–D18，与架构改造同批 PR）

> 逐条改，不留矛盾。每条都要在 PR 里贴出改动前后的行号。

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 |
|---|---|---|---|---|---|
| D-01 | 丙 | `README.md:21/34`、`ROADMAP.md:19` 写「7 个 JSON Schema」，实际 8 个，而 `README.md:128` 又写「8 schema」——统一为实际数 | C-06 | 待办 | 基础 |
| D-02 | 丙 | 契约冻结日三个口径并存：README:128「D1 冻结 v1」/ ROADMAP:19「D6」/ README:10 与 GITHUB-FLOW:101「D8」→ 统一为「v1 内容 D1 落库，D6=10/3 形式化冻结」 | C-06 | 待办 | 基础 |
| D-03 | 丙 | `PROJECT-INTRO.md:15/75`、`README.md:29` 说编排框架是 **pi-agent-core——从未安装、零代码、零 spike**，实际是自研 TaskGraph → 改为适配层 + LangGraph 后端 + 原生后备；pi-agent-core 移入「已评估未采用」并写明理由 | A-01 | 待办 | 基础 |
| D-04 | 丙 | 黄金问答「20 条」vs 实际 10 条（README:48/97/133/160、ROADMAP:22/86、PROJECT-INTRO:41/95）→ 扩到 20 后统一；未扩前如实写 10/20 | R-04 | 待办 | 基础 |
| D-05 | 丙 | `README.md:49`「Trace 全落 Langfuse」vs 代码零 Langfuse → 改为「S2 总线 trace_id 已贯穿；Langfuse 外发在 D13-D18 落地」 | A-06 | 待办 | 砍③ |
| D-06 | 丙 | `PROJECT-INTRO.md` 与 README 多用 `C:\Users\niangao\safetrace\`、`C:\Users\niangao\asktrace9\` → 改成本仓库实际路径与远端 | — | 待办 | 基础 |
| D-07 | 丙 | `PROJECT-INTRO.md:136` 指向 `asktrace9/docs/` 四篇报告 + 三张图，**仓库内完全缺失**（`docs/` 只有 GITHUB-FLOW.md）；交叉引用（GITHUB-FLOW:4 引 03-roadmap、README:54、GITHUB-FLOW:86 引 02-report）全部不可解析 → 迁入 `docs/` 或改写索引 | — | 待办 | 基础 |
| D-08 | 丙 | `PROJECT-INTRO.md:138` 称合订本 68 页，仓库内 PDF 实为 **15 页**，且是 README/ROADMAP/PROJECT-INTRO 的合订、早于 D1 交付 → 改页数、说明性质 | — | 待办 | 基础 |
| D-09 | 丙 | `README.md:51`「A1 自愈 L1/L2」vs 只有角色声明 → 按 A-06 实施后改写；未完成前如实标注 | A-06 | 待办 | 基础 |
| D-10 | 丙(H) | `config/models.yml:4` 说 openai_compat 对四家「通用」→ 补注「chat/embed 通用；rerank 无标准端点，会显式报错（`openai-compat.ts:107-111`）」 | — | 待办 | 基础 |
| D-11 | 丙 | `src/qa/package.json` 声明依赖 `@safetrace/gateway`，但 Q 线零 import → 删空声明或注明「经 AnswerSynthesizer 注入、不直接依赖」 | — | 待办 | 基础 |
| D-12 | 丙 | `src/qa/server.ts:127` 只绑 `127.0.0.1`，README 未提 → 补注（这其实是合规优点，写明「默认仅本机」） | — | 待办 | 基础 |
| D-13 | 丙 | README:123「零外部依赖即可演示」在接入 LangGraph 后不成立 → 改写为「零 provider SDK、无 API key 亦可离线跑通；编排层可选接 LangGraph」，并按新三条红线措辞 + CI grep 断言重述 | A-01 | 待办 | 基础 |

## 8. 第 5 阶段：冻结与交件（D19–D22）

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| S-01 | 丙 | 本台账全表清零或转「已知限制」；最后一轮 `npm run check` + `npm run smoke` + compose 验证 | 全部 | 待办 | 禁砍 | 三道命令全绿并留记录 |
| S-02 | 全 | D20（10/17）打 tag `submission-v1`，功能冻结，只修 S1 级缺陷 | S-01 | 待办 | 禁砍 | tag 存在；冻结后提交仅 fix |
| S-03 | 丙 | 技术报告 Word+PDF（封面后第 1–2 页核心亮点预览页）+ 演示视频 + 讲解 PPT；「已知限制」写清全部 Mock 清单（cache provider 占位、hash-256 占位向量、资产清单 Mock、F2/F3/F5 契约位、无独立 rerank、pi-agent-core 未采用） | S-02 | 待办 | 禁砍 | 三件齐；Mock 清单与代码现状逐条对得上 |
| S-04 | 丙 | D22（10/19 24:00）交件，回执双人复核；**脱敏检查：PPT/视频/公开仓库无真实单位名、人名、内网地址、密钥** | S-03 | 待办 | 禁砍 | 全仓 PII 扫描记录；回执双签 |

## 9. 阻塞项（需要人做，代码侧无法推进）

| 阻塞 | 影响任务 | 谁来做 | 备注 |
|---|---|---|---|
| Docker 未安装 | E-05（compose 验证，交件 checklist 显式项） | 甲 | 不装则 P0「一键起 compose」与 Qdrant 真检索始终未验证 |
| NVD API key 未申请 | E-02、E-06 | 全 | 免费，邮箱激活链接 7 天有效；无 key 限流 5 req/30s |
| 云端模型 API key 未提供 | A-02 的 LLM 层、A-03 的 cloud provider | 丙 | 当前 `.env` 全空。**已定：暂不接云端，模型出口留 MG1 接线位，等 key 只改 `config/models.yml` + `.env`** |
| Ollama / vLLM 未安装（无模型文件、11434/8000 未监听） | A-02 的本地层、A-03 的 local provider | 丙 | **已定：链路真跑、模型用 cache provider 占位**，隔离闸门不依赖真实本地模型 |

## 10. 砍单顺序（落后时从上往下砍）

| 序 | 动作 | 保留下什么证据 |
|---|---|---|
| 保 | 报名与交件流程（D18/D22） | 回执归档 |
| 保 | 单源贯通 + 带引用问答闭环 | 演示视频骨架 |
| 保 | ≥7 类源登记表 + 时效看板数字 | 监测 15 分主要证据 |
| 砍① | LangGraph 后端 → 只留原生后端 | `statemachine` 接口层保留，报告写「适配层已验证 LG 可用」 |
| 砍② | F2 资产真链路 → Mock 清单 + 合规说明；F1 recall@5 暂停 | 隔离闸门实现与测试仍在（闸门不依赖真实资产） |
| 砍③ | Langfuse 外发 → 原生 trace + 截图 | `bus`/`store` 的 trace_id 全链路已在 |
| 砍④ | compose 全 7 服务 → 只起 qdrant + postgres | 最小 infra 冒烟通过 |
| 砍⑤ | 时效看板美化 → 三口径数字打表；答案层过期提示简化 | `freshness.ts` 的实时数 |
| **禁砍** | 模块缺席 / 脱敏合规 / 稳定运行时长证据 | 一票否决 |

## 11. 三条工程红线（每项设计前自查）

1. **模型接入标准化解耦**：任何模型调用必须经 `src/gateway`（MG1）。接入 LangGraph 后红线措辞改为：
   ① 业务代码禁止 import 任何 provider SDK；② 业务代码禁止 import `@langchain/core` 的 `chat_models`/`language_models`/`tools`/`prompts`（仅允许作为传递依赖存在）；③ 所有模型请求经 MG1。CI 加 grep 机械断言。
2. **脏数据不进知识底座**：进 Qdrant 前必过 DQ1 质量闸门。宁可少一条，不可错一条。
3. **兜底必须显式可见，禁止静默兜底**：任何降级必须经 `shared/src/degrade.ts` 的 `degrade()` 登记 FallbackEvent，响应带 `degraded_to`，`user_visible` 必须为 true。冒烟第 7 项断言零静默兜底。

## 12. 验收命令（阶段准入准出）

```bash
# 第 0 阶段准出（R-01 修完这里才真的会绿）
npm run check                 # typecheck + 单测 + 契约校验
npm run smoke                 # 端到端 7 段断言，含零静默兜底
npm run cli:ask -- "Log4Shell 影响哪些版本？怎么修复？"

# 第 1 阶段准出
python3 scripts/validate_contracts.py

# 第 2 阶段准出（双后端同测 + 注入 + 隔离 + 红线断言）
node --import tsx --test "src/qa/test/statemachine.test.ts"
node --import tsx --test src/ingest/test/injection.test.ts src/qa/test/injection.test.ts
node --import tsx --test src/gateway/test/isolation.test.ts
! grep -rE '@langchain/(openai|anthropic|community)|@langchain/core/(chat_models|language_models|tools|prompts)' src/ scripts/ \
  && echo "红线一通过" || { echo "红线一违规"; exit 1; }

# 第 3 阶段准出
NVD_API_KEY=... node --import tsx -e "import {runIngestOnce} from './src/ingest/src/pipeline.js'; console.log(await runIngestOnce({offline:false}))"
cd ops && docker compose up -d qdrant postgres && bash scripts/wait-healthy.sh && cd .. && npm run smoke
```

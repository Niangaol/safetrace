# SafeTrace · 任务台账（D2 → D22）

> **建立于 D2 = 2026-09-29**。本文件是唯一可执行任务清单，替代原先只存在于 `README.md` 一句话里的「D2 起任务单」。
> 出处：`plan-bubbly-karp.md`（本目录 `docs/` 无该文件，plan 存放在队长本地计划目录）。
> **职责**：`TEAM-PLAN.md` 是 D3 起的唯一分工/优先级/协作口径；本文件维护细化任务、依赖、状态和验收证据。每次代码提交同步更新对应行；周五对齐会照本文件过。
> 每行标注的「PR #N」可在 GitHub 上回溯到实际改动；无标注的表示尚未动手。

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
| 第 0 阶段 根因修复（D2–D5） | 6 | 0 | 0 | 6 | 0 |
| 第 1 阶段 契约扩展（**必须 D6 前**） | 6 | 5 | 1 | 0 | 0 |
| 第 2 阶段 架构改造（D13–D18） | 6 | 6 | 0 | 0 | 0 |
| 第 3 阶段 证据链（D7–D18） | 7 | 5 | 0 | 0 | 2 |
| 第 4 阶段 文档口径同步 | 13 | 12 | 0 | 1 | 0 |
| 第 5 阶段 冻结与交件（D19–D22） | 4 | 4 | 0 | 0 | 0 |
| 第 6 阶段 PRD v1.0 需求补齐 | 10 | 7 | 3 | 0 | 0 |
| **合计** | **52** | **39** | **4** | **7** | **2** |

> 本表随 PR 更新。任何一项转 `已砍` 必须在 PR 描述里写清「保留下什么证据」。

## 3. 第 0 阶段：根因修复（D2–D5，最高优先）

> 原则：这些不改，后面所有"证据"都不可信。README 第 7 节宣称的「门禁全绿 / 132 单测 / 契约校验全绿」目前有四处不成立。

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| R-01 | 丙 | `package.json` 的 `validate:contracts` 解释器探测。PR #1 改为 bash 双探 `PY=$(command -v python3 \|\| command -v python) && "$PY" ...`，但 Windows 上 npm 走 `cmd.exe`、`command -v` 不存在 → `npm run check` 实际 exit 1（「本机首次 exit 0」是假绿，正是本节要消灭的那类宣称）。已本地重建为 Node 跨平台入口 `scripts/validate-contracts.mjs`：SAFETRACE_PYTHON→python3→python→py 按序探测、每个候选真跑 `--version` 验证（防 Microsoft Store 占位别名）、无解释器显式 exit 1；`pre-push` 钩子第三步同步改走同一入口 | — | 已完成 | 基础 | `npm run check; echo $?` → 0（Windows 实测通过；已合入 main，commit 8d72d9d，队长批准直推免 PR，CI 与 pre-push 门禁双绿） |
| R-02 | 丙 | `.githooks` 接线：`git config core.hooksPath .githooks` + `chmod +x .githooks/*`（**已做**，待随本 PR 提交模式变更）+ 修 `docs/GITHUB-FLOW.md:91` 的假陈述「本仓库已配置」（已随本 PR 修正，并补 `chmod +x` 要求） | — | 已完成 | 基础 | 试提交 `bad message` 被拒；`npm run hooks:install` 可复现  ✅ 本 PR #1 已完成：`core.hooksPath` 已配置 + 补 `chmod +x` + GITHUB-FLOW:91 假陈述已改 + 新增 `npm run hooks:install`|
| R-03 | 丙 | MG1 usage 表丢两字段：`src/gateway/src/index.ts` 的 `record()` 把 `latency_ms:0`/`cached:false` 写死（入参只收 `{usage, degraded_to}`），chat 的缓存命中与真实延迟全部丢失，延迟/降级统计失真；embed/rerank 两条路径此前也完全不测延迟 | — | 已完成 | 基础 | 新增断言 ✅：①同 prompt 二次调用 → 第二行 `cached=true`（修复前恒 false）；②注入约 20ms 延迟的 fetch → `latency_ms>=15`（修复前恒 0）。实现：`MeteredResult` 约束 + `record()` 改从结果取真值 + embed/rerank 补 `t0` 计时 + `Embedding`/`RankedDocs` 类型补两字段；已合入 main（commit 14538ff，直推免 PR），两条断言在 133 单测内 |
| R-04 | 丙 | 黄金问答口径做实 + 契约校验覆盖：仅 10 条（目标 20）；无期望答案文本；`scripts/smoke.ts` 第 5 段不传 `cve_ids`、只断言「带引用或拒答」且**不用 `expected_intent`**；`scripts/validate_contracts.py` 的 `FIXTURE_SCHEMA_MAP` 不含 golden-qa | R-01 | 已完成 | 基础 | ✅ 本地已完成并实测：fixture 扩到 20 条（6 类意图 + 拒答×5 + 澄清×1 = 8 类）；smoke 逐条硬断言 `expected_intent`/`expected_cve_ids`/`expected_answer_must_include`，请求透传 `cve_ids`，「15 条非拒答全部带引用」精确断言（原来 >=5 和稀泥）；校验器加 golden-qa 条目（None=JSON 合法性，覆盖面 9→10）；`npm run check` 与 `npm run smoke` 全绿，已合入 main（commit d631231，直推免 PR）。D-04 的「20 条」口径自此与实际一致 |
| R-05 | 丙 | `.gitignore:32` 是 ` recordings/`（**行首有空格**），对 `recordings/` 目录无效 | — | 已完成 | 基础 | `git check-ignore -v recordings/x.mp4` 命中 ✅ 本地已删行首空格并验证 rc=0（普通路径不受影响）；已合入 main（commit 0d0e92f，直推免 PR） |
| R-06 | 丙 | 建本台账（原先 `find -iname "*todo*"` 仓库内零命中；Taskwarrior 已装但 `project:safetrace` 零任务） | — | 已完成 | 基础 | 本文件存在且随 PR 更新  ✅ 本 PR #1 已建：本文件|

## 4. 第 1 阶段：契约扩展（**必须赶在 D6 = 10/3 前**）

> D6 后禁止改枚举。**C-01 是唯一过期就违约的一项。**

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| C-01 | 丙 | `contracts/schemas/DecisionReply.json` 的 `decided_by` 枚举追加 `human`（四层兜底阶梯的"人工"层契约位）。同步 OpenAPI、类型、样例及 CHANGELOG v1.1.0；仅扩契约，不代表 A-02 人工兜底已实现 | — | 进行中 | 禁砍 | `contract/` PR 待三线 sign-off；`python3 scripts/validate_contracts.py` 验证人工作为有效值；待合并后转已完成 |
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
| D-04 | 丙 | 黄金问答「20 条」vs 实际 10 条（README:48/97/133/160、ROADMAP:22/86、PROJECT-INTRO:41/95）→ 扩到 20 后统一；未扩前如实写 10/20 | R-04 | 已完成 | 基础 | ✅ R-04（commit d631231）已把 fixture 扩到 20 条，README:48/97 与 ROADMAP:22 的「20 条」口径自此与 fixtures/golden-qa.v0.json 实际一致；README:133 的 `src/qa` 测试数与 README:160 的黄金问答数字随 C-06/D-01 一并核准 |
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

## 13. PRD v1.0 需求映射与新增待办

> 需求来源：用户提供的 `SafeTrace-产品需求文档-PRD-v1.0.docx`（本地文件，未复制入仓库；内部讨论稿）。该文档说明“建议调整/建议新增”须团队确认后才成为正式基线；特别是 FR-F05 的 P0 标注带“待确认”，本台账只先做本地合成演示原型，不视为批准真实资产接入或冻结契约。

### 13.1 本轮已做的一部分：F2 本地演示原型

`src/enrich/src/f2-assets.ts` 对输入的 `IntelItem` 和明确传入的资产清单执行确定性版本比较；样例 `fixtures/assets/demo-assets.v0.json` 含 20 条合成演示资产，`npm run assets:demo` 输出受影响 / 不受影响 / 待核实状态与规则依据。当前只支持数字点分版本和常见比较符；无法解析的版本、厂商不一致或不完整规则会返回 `unknown`。数据不出本机，不扫描、不探测、不读取真实企业资产，也未改 `EnrichmentResult` 冻结契约。

这只是 FR-F05 / AT-09 的可复现演示切片；产品别名映射、真实资产导入、结构化持久化、API/界面、完整生态版本语义、冲突处置、自动化验收及问答链路接入仍未完成。由于需求本身待确认，状态保持“进行中”。

远端主线合入的 PR #3 已提供 Vue 态势大屏、情报列表/详情和问答页面，但 `web/src/api.ts` 当前固定使用预置样例。页面级演示提示与数据模式共用一个开关，逐条富化样例也带 `mock` 标记；前端构建纳入本地/CI 门禁。真实接口、Trace/诊断、资产页及真实性验收仍归 P-07，样例统计不得当作运行证据。

### 13.2 PRD 后续工作项

| id | 线 | PRD 条款 | 工作项 / 验收重点 | 依赖 | 状态 | 砍单层级 |
|---|---|---|---|---|---|---|
| P-01 | 乙+丙 | FR-F04/F05、AT-09 | F2 演示版闭环：在团队确认后补产品别名/版本语义边界、资产清单导入、查询或界面接线；20 条匹配/不匹配/未知均带可核验规则证据，且持续明确标记为演示数据 | 本地原型已实现；R1 决策 | 进行中 | 砍② |
| P-02 | 甲+乙 | FR-DQ02 | 制定带版本的 AI 安全相关性分类规则、产品/组件标签、来源证据及人工复核状态；抽样可解释纳入/排除/待审核原因 | 规则负责人确认 | 待办 | 砍② |
| P-03 | 丙 | FR-S02 | 将 CVE 状态、受影响版本和资产关系接入结构化查询；“版本是否受影响”走确定性规则并返回依据，不由相似度或模型自由生成 | P-01、持久化选择 | 待办 | 保 |
| P-04 | 丙 | FR-S03 | 证据增加 document_id、source_url、fetched_at、content_hash、chunk_id、索引版本；更新/撤销可定位并使旧索引失效，历史可审计 | C-02、存储方案 | 待办 | 基础 |
| P-05 | 丙 | FR-Q02/Q03、AT-04/05 | 混合查询结构化事实与多份独立来源；答案保留来源冲突、证据不足状态和原文页/段定位，不能把冲突压成单一结论 | P-03、P-04、A-05 | 待办 | 保 |
| P-06 | 乙+丙 | FR-F06、FR-Q04、FR-S401 | POC 仅展示引用/元数据且不执行；修复建议无可靠来源时标“待核实”；攻击链和工具注册若展示须标为静态演示，不宣称自动推理/热注册 | 报告披露口径 | 待办 | 砍⑤ |
| P-07 | KKK9747human | PRD 7.3 界面清单 | 接 Q 线 HTTP 真数据；实现一屏完整问答与可展开推理链；展示降级；对接 compose 演示环境。当前 main 页面仍是预置样例，真实 API 接线与验收未完成；F2 资产页待 R1 确认 | P-03、P-05、A-06；R1 | 进行中 | 砍④ |
| P-08 | 全 | NFR-03/08、AT-07、DoD | 定义每个指标的样本规模、时间窗和统计方法；补 provider 配置切换可复现记录及边界样本结果。≤60 秒只是 PRD 建议目标；前端预置看板值不能充当实测，任何准确率/完成度不得在无实测时写成已达成 | A-03、R-04、E-07 | 待办 | 基础 |
| P-09 | 全 | PRD 第 11 节 R1–R8 | 形成负责人决策记录：F2 是否提 P0、7 类源及完成判定、24h/72h、D6/D8、Jev 定位、“推理链”口径、矛盾统计来源、完成度仅作内部估算 | 负责人确认；分别关联 E-01/E-07/D-02/A-02 | 待办 | 禁砍 |
| P-10 | 李念（MG1/Q2）；与 Xue 对齐来源，KKK 接前端 | FR-Y01/S02/S03/Q02/Q04 | 受控单页 Firecrawl + 规则→受控 LLM→人工复核 + Qdrant 真实 embedding/BM25 混合检索。当前本地小切片已实现 allowlist/robots、direct→Firecrawl→last-good、证据校验、MG1→Qdrant RRF；新增 SQLite append-only lineage_records 覆盖 ingest fetch/parse/dedupe/DQ1、enrich F1/F4/F6、Q2 index/search/fusion、crawler/extractor、MG1 provider attempts 与 CLI/HTTP Q&A。已有默认离线的 ingest:once SQLite runner，网页→DQ1 显式来源 API 与 crawl:page 独立入库开关已实现（元数据文件联网前校验，默认预览；见 [本地指南](P10-LOCAL-VERIFY.md)），并有零网络 page:demo，stale/待复核/证据不符不自动放行；sqlite-page→来源证据块→BM25 适配已验证（缺快照/URL不符拒绝）；正式 SourceRegistry 调度及网页原文富化适配仍待办；SQLite last-good、按 SHA 保留的历史快照与 review queue 已持久化（跨 URL 更新/数据库重启保留审核证据），但人工决定不自动写入 DQ1；来源 EvidenceChunk 构建与临时 BM25 预览已接入 ingest:once（DQ1 放行、单来源 URL/hash、全步骤 lineage）；来源 Qdrant 持久入库 opt-in 入口已实现，拒绝离线/fixture/cache/hash，写失败不报告成功；pilot:doctor 可 GET-only 检查本地前置条件（不生成 embedding）；默认仍 cache；独立 Tokendance qwen3.7-text-embedding profile 已经 API/MG1 单文本实测为1024维且无降级，密钥仅本地；Qdrant 不可达，持久索引/召回和语义质量仍待验收；MemoryEventStore 仅用于测试/smoke。A-03/A-04 前不将不可信网页送云 LLM，外部 API 默认关闭 | C-02/C-04、A-03/A-04；来源白名单确认；不得挤占 R-04/R-05/A-02 | 进行中（lineage + 小切片） | 砍④ |

### 13.3 需求覆盖索引

PRD 条款按当前台账唯一归属，避免重复开任务；“待办/阻塞”以对应任务状态为准。

| PRD 条款 | 当前代码/台账映射 | 当前口径 |
|---|---|---|
| FR-Y01–Y05 | E-01、E-02、E-07 | 第 7 源、真实运行留痕、补偿及看板仍待办；E-05/E-06 有外部条件阻塞 |
| FR-DQ01 / DQ02 | 已有 DQ1、E-04 / P-02 | 质量闸门已实现；独立隔离存储待办；AI 安全相关性标签未实现 |
| FR-F01/F02/F03 | `src/enrich` F1/F4/F6 | 基础模块已实现；真实运行与特定冲突验收样本仍按 E-02/P-05 跟踪 |
| FR-F04/F05 | P-01 | 本次改动仅新增静态合成数据匹配原型；团队未确认范围，不接真实资产 |
| FR-F06 | P-06、S-03 | 只保留 Mock/披露要求，尚无 POC 执行或修复建议生产链路 |
| FR-S01 | P-10/E-05 | Qdrant 查询/写入已拒绝 hash/cache embedding，Q2 通过 MG1 真实 provider 并支持 BM25-lite RRF；索引、查询和融合写 append-only lineage。默认仍是 BM25，正式来源索引和 Qdrant/模型实测待办 |
| FR-S02/S03 | P-03/P-04 | 结构化事实检索、证据版本与失效处理待办 |
| FR-Q01 | R-04 | 20 条黄金问答已接入回归；未知/攻击/冲突样本继续由 A-04、P-05、P-08 补齐 |
| FR-Q02/Q03 | P-05/P-10 | 多来源检索、原文定位和显式冲突/不足仍待办；P-10 先做单源受控抓取及 hybrid retrieval 小切片 |
| FR-Q04/Q05 | P-06、A-04 | Q3 仅后续演示；外部内容注入防护仍为禁砍待办 |
| FR-MG01/AG01/D401/A101 | A-03/A-01/A-02/A-06，R-03，P-10 | 网关基础与 MG1 provider attempt lineage 已实现；数据隔离、编排替换、决策旁路、自愈及 Langfuse 完整 Trace 未完成 |
| FR-S401 | P-06 | 静态工具注册与可见披露；不把热注册作为本轮闭环前提 |
| NFR-01/02/04/05/06/07 | E-05/E-07/A-06/A-03/A-04/S-04 | Compose、运行时长、Trace、安全和脱敏按既有行验收；不可用文档声明替代实测 |
| NFR-03/08 | P-08、R-04、A-04 | 建立指标统计口径；黄金集以外的未见/恶意样本结果尚待实测 |
| AT-01/02/03 | E-01/E-04/E-07 | 来源归并、隔离、失败恢复分别按这些行验收 |
| AT-04/05 | P-05 | 多来源原文引用与冲突样本验收待办 |
| AT-06/07/08/10 | R-04/P-08/A-03/A-06/A-04 | 黄金问答拒答已覆盖；Provider 切换、降级 Trace、攻击 fixture 仍需完成相应任务 |
| PRD 7.3 页面清单 | P-07 | 大屏、列表、详情、问答页面已合入，但全为预置样例；真实接口接线与 Trace/诊断页仍待办 |
| PRD 第 11 节 R1–R8 | P-09 | 未把讨论稿建议误记为团队决策；需负责人逐项定案 |
| FR-Y/Q 受控采集与语义检索 | P-10 | 计划按单域名 Firecrawl + 规则/MG1/人工兜底 + Qdrant hybrid 小步验收；不得把占位 hash 向量写成真实语义能力 |

**新增任务计数**：本节 10 项，P-01、P-07、P-10 进行中，其余 7 项待办。纳入第 2 节总览后，全台账 52 项：39 待办、4 进行中、7 已完成、2 阻塞（已完成 7 项含 PR #2 转入的 D-04）。

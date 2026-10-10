# SafeTrace · 任务台账（D2 → D22）

> **建立于 D2 = 2026-09-29**。本文件是唯一可执行任务清单，替代原先只存在于 `README.md` 一句话里的「D2 起任务单」。
> 出处：`plan-bubbly-karp.md`（本目录 `docs/` 无该文件，plan 存放在队长本地计划目录）。
> **职责**：`TEAM-PLAN.md` 是 D3 起的唯一分工/优先级/协作口径；本文件维护细化任务、依赖、状态和验收证据。每次代码提交同步更新对应行；周五对齐会照本文件过。
> 每行标注的「PR #N」可在 GitHub 上回溯到实际改动；无标注的表示尚未动手。

## 2026-10-04 首批审查整改增量

本节记录当前执行状态；下方旧阶段总览/历史任务状态尚未全面重算，不能继续当实时统计。详细证据见[首批整改记录](<D:/AgentPrograms/safetrace/docs/REMEDIATION-2026-10-04.md>)与[富化重点整改](<D:/AgentPrograms/safetrace/docs/ENRICHMENT-REMEDIATION-2026-10-04.md>)。

| 新计划编号 | 状态 | 结果与剩余 |
|---|---|---|
| N01 索引/DQ准入、更新撤销 | 已实现，回归通过；正式迁移待验 | 两路径统一latest gate，单写lease、条件清理、completed校验；只读dry-run 5237待更新/0预计撤销，正式库0写入 |
| N02 归并红线 | 已实现，回归通过 | 逐源metadata、源顺序不洗白、正常workflow不误伤；gate_version=1.0.1；历史重新判定仍待办 |
| N03 熔断恢复 | 已完成代码验收 | 半开失败→新OPEN冷却→新探针→成功关熔断；纯内存回归 |
| N04 单测出网 | 已完成默认测试验收 | npm test/smoke guard+mock；live另命令，本轮未执行 |
| N05 工程基线 | 部分完成 | 前端私有Temp修复，当前四门禁543/543与smoke通过，前端SSE/来源8项；入口统一配置仍待办 |
| N06 备份恢复 | 已完成本机恢复验收 | 7表一致性SQLite副本 + 5237完整向量 + 6原始payload；单独临时集合真实恢复比对后删除，正式库不覆盖 |
| N07 来源/富化投影 | 已实现，临时库整链与正式库只读验收通过；正式工件复核待办 | 原文/论文/CVSS有hash、causation及lineage；真实只读API已兼容前端、无长期服务切换；旧1123记录无sidecar，不能自动变已验证 |
| N08 逐维状态/续跑 | 已实现，回归与保存原文10条小批通过 | source bytes/评分依赖/TTL失效，last-good、原子状态提交、回执repair进入默认pending；CVSS/EPSS主CVE不串分 |
| C01 赛题重点前端与模型设置 / 实时工作台 | 已实现，真实浏览器与四门禁验收 | 三主线与可信缺口置顶；data_mode/qa_mode如实而非写死；新增/设置页（私密加密草稿、显式测试与启用、CSRF/Origin/Host/启用确认门、GGUF受控runtime）；SSE真实事件拟物工作台、hover/键盘字段、历史与重连明确标记；562/562与前端两项smoke通过 |
| N20 评测骨架 | 已实现，人工标注/隐藏集/真实检索待办 | 3篇官方metadata，4个agent提议参考case；排序与发布策略分开，不冒充盲测或真实准确率 |
| N09 保存原文评分复核 | 小批已验收，扩大范围仍待办 | 当前10条NIST主CVE评分正式发布并可引用；备份前后验证，未验证原文不能借proof；未调用网络/模型/向量 |
| N10 修复建议维度 | 确定性模块与只读派生接口/问答已验收；统一队列/公用契约待确认 | USN同公告CVE+固定包版本；KEV通用指引，来源声明非验证修复；51边界测试，正式保存源只读预览 |
| N11–N19、N21–N24 | 后续独立验收 | 本轮重点富化质量；新增有效维度、真实小批复核与语义/多轮等不能按本轮完成报告 |
| C01 赛题重点前端、模型设置与实时工作台 | 已实现，真实浏览器与全门禁验收 | 三主线/可信缺口置顶；data_mode 与 qa_mode 如实显示；新增设置页（私密加密草稿、CSRF/Origin/Host、显式测试与启用、GGUF 受控 runtime）；SSE 真实事件拟物工作台与 hover/键盘细节；562/562 与前端两项 smoke 通过；云真实生成、第二份托管加载、盲测待办 |
| A01 本地资产扫描线（扫描→快照→匹配→提醒，含多文件夹分组监控） | 已实现，四门禁通过；存量情报区间刷新待办 | src/assets 新包：manifest 解析 9 生态、git 仓库发现、var/assets.sqlite 快照库、复用 F2 版本比较的确定性匹配；多分组监控：groups 表（config 播种一次后 UI/API 可管理）、run/repo/component/alert 全带 group_id 按组隔离、告警去重键 (group_id,component_key,cve_id)、停用组不参与全量扫描与常驻匹配；出口：Web 铃铛+/assets 页（分组下拉+分组管理面板）、CLI assets:scan（--group/--list-groups）、watch 每轮自动匹配（遍历启用组）；契约 v1.2.0/v1.2.1 纯追加；NVD 适配器补 version_range 提取（存量 9280 条需重跑 NVD 源才生效，见 docs/ASSET-SCAN.md §4）；54 条新单测 |

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
| 第 0 阶段 根因修复（D2–D5） | 7 | 0 | 1 | 6 | 0 |
| 第 1 阶段 契约扩展（**必须 D6 前**） | 6 | 5 | 1 | 0 | 0 |
| 第 2 阶段 架构改造（D13–D18） | 6 | 3 | 3 | 0 | 0 |
| 第 3 阶段 证据链（D7–D18） | 7 | 4 | 1 | 0 | 2 |
| 第 4 阶段 文档口径同步 | 13 | 5 | 1 | 7 | 0 |
| 第 5 阶段 冻结与交件（D19–D22） | 4 | 4 | 0 | 0 | 0 |
| 第 6 阶段 PRD v1.0 需求补齐 | 10 | 7 | 3 | 0 | 0 |
| **合计** | **53** | **28** | **10** | **14** | **2** |

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
| R-07 | 丙(H) | **前端「假数据」可信度缺陷**（`web/`；条目与验收要求摘自 KKK9747human 的 `aab1488` 与其 fork 台账草案）。原三处：① `web/src/api.ts` 硬编码 mock → 界面从不请求后端；② 大屏「采集趋势」由 `Math.random()` + 写死日期伪造却按真实指标口径展示；③ `TopNav.vue` 恒显绿色「系统运行中」、无任何「预置数据」标识 | — | 进行中 | 基础 | 三处缺陷在 main 均已消（`2aeec7c` 合入的 b30c9a5 一系，与 KKK 的 `aab1488` 目标等价、路径不同）：① api.ts 改 `VITE_DEMO_MODE` 环境开关、**默认真实后端、不可达即报错、不静默回退**；② `genTrendData` 改按情报真实 `published_at` 聚合（无随机数、无写死日期）；③ TopNav 显示真实模式 + `App.vue` 全站横幅（「本地实链模式（fixture）」/「静态演示模式」）。API 层验收通过：三场景 SSE 实测（Log4Shell 带 5 条真实引用 / CVE-2099-4321 显式拒答 / 「嗯」澄清引导；done 事件全带 `data_mode=fixture`、`cost_cny=null`），证据留痕于 `D:/AgentPrograms/safetrace-evidence/`（sse-log4shell.txt / sse-unknown-cve.txt / sse-clarify.txt）。**未完成**：浏览器页面级验收（横幅、大屏数字、问答页目视+录屏）尚未做。KKK `aab1488` 的三态开关在 main 已有等价二值实现，故不整支合并；但其两项 main 缺失的修复已摘入（2026-10-01）：① `api.ts` SSE 改为逐行取 `data:`，多行帧不再静默丢事件；② `DashboardView.vue` echarts 按需引入（原整库入包）。数据来源烟测已按 main 二值口径移植（`npm run smoke:data-source`，5 条含 SSE 多行帧用例） |

## 4. 第 1 阶段：契约扩展（**必须赶在 D6 = 10/3 前**）

> D6 后禁止改枚举。**C-01 是唯一过期就违约的一项。**

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| C-01 | 丙 | `contracts/schemas/DecisionReply.json` 的 `decided_by` 枚举追加 `human`（四层兜底阶梯的"人工"层契约位）。同步 OpenAPI、类型、样例及 CHANGELOG v1.1.0；仅扩契约，不代表 A-02 人工兜底已实现 | — | **代码侧已完成，待三线 sign-off 后转已完成** | 禁砍 | 已合入 main（commit 2455623）：schema/OpenAPI/TS 镜像/`fixtures/decisionreply.human.sample.json` 齐备，`npm run validate:contracts` 校验 human 为有效值；新增 `src/shared/test/contracts-c01.test.ts` 3 条断言（枚举未回退、样例通过且未知通道被拒、CHANGELOG 影响面已登记），全量 204 项测试与 typecheck 通过。已用反向验证确认测试非空转（把 `human` 改为他值 → 2 条断言失败）。**剩余：三线 sign-off**，队长/甲/乙各确认一次后把状态改为已完成 |
| C-02 | 丙 | `RetrievalResponse.json` 的 chunk 增 `published_at` + `trust`(trusted/untrusted)。已知限制⑤的地基 + 注入防护"证据信封"的载体（`EvidenceChunk` 现无时间字段、无信任标记） | — | **代码侧已完成，待三线 sign-off 后转已完成** | 基础 | 已落地：schema/OpenAPI 注释/`shared/types.ts`（含 `TrustLevel`）/`fixtures/retrievalresponse.sample.json` 同步；CHANGELOG 记 v1.1.1（纯追加、旧生产者兼容）。生产者：ingest 证据块 `published_at` 只取已归一化的 `IntelItem.published_at`（缺失留空不猜），`trust` 按来源类型判定；Q2 在 Qdrant 载荷双向携带并回填。测试：`contracts-c02.test.ts`（2 条，含"旧形状仍合法/未知 trust 被拒"）+ `evidence-metadata.test.ts`（4 条，含 6 个种子块日期来自 fixture）。**附带修复**：运行时校验器 `validateInstance` 此前不遍历 `items`，数组内对象（如 chunks）字段约束实际未被校验；已与 `validate_contracts.py` 对齐。全量测试与 typecheck 通过。**剩余：三线 sign-off** |
| C-03 | 丙 | `QualityVerdict` 内联契约增 `injection_score` + `injection_flags`（内联契约，追加式） | C-02 | **代码侧已完成，待三线 sign-off 后转已完成** | 砍② | 已落地：`contracts/events.md` 内联契约追加两个可选字段（十类注入迹象枚举）并同步 `flags` 里既有的 `unknown_version`；`shared/types.ts` 同步 `InjectionFlag`；新增 `fixtures/qualityverdict.injection.sample.json`（校验器计入，现 12 个样例）；CHANGELOG 记 v1.1.2。测试 `contracts-c03.test.ts` 3 条：旧形状仍合法、越界评分/未知标签被拒、契约与镜像已登记。**本条只落契约位**：注入检测实现归 A-04，DQ1 当前不填该字段，缺省语义为“未筛查”。全量 213 项测试与 typecheck 通过。**剩余：三线 sign-off** |
| C-04 | 丙 | `Answer` 接口增 `stale_warning?` + `injection_guard?`（时效提示与注入筛查计数要显式出现在响应对象上，符合"兜底必须显式可见"） | C-02 | **代码侧已完成，待三线 sign-off 后转已完成** | 砍⑤ | 已落地：`contracts/events.md` 内联 Answer 追加两个可选对象字段；`shared/types.ts` 同步 `StaleWarning`/`InjectionGuard`；Q4 真实填充——`stale_warning` 依据 C-02 的 `published_at` 判定过龄/未知并在正文输出用户可见提示（缺来源时间不编造），`injection_guard` 现在会对问题与 Q2 证据运行共享本地启发式并合并上游结果，`screened=true` 只表示扫描运行过、不保证检出所有攻击，且如实统计 untrusted 证据条数；CHANGELOG 记 v1.1.3。测试 `answer-c04.test.ts` 6 条（旧形状合法、过龄提示、缺时间不编造、新鲜不误报、未筛查如实、lineage 不复制正文）；冒烟新增 2 条断言（20/20 带 guard、15 条非拒答全部带 stale_warning）。全量 222 项测试、typecheck、validate:contracts、smoke 通过。A-05 将按意图细化时效阈值。**剩余：三线 sign-off** |
| C-05 | 丙(H) | `config/models.yml` 增 provider `trust_boundary`(cloud/local/cache) + role `data_domain`(public/private)；`openapi.yaml` 请求体增 `data_domain` | — | **代码侧已完成，待三线 sign-off 后转已完成** | 禁砍 | 已落地：`profiles.ts` 解析两个新标量字段（未声明时 trust_boundary 按 provider type 推断、data_domain 缺省 public，向后兼容）；`ModelGateway.chat/embed` 增 dataDomain 入参并贯通 HTTP 层；`config/models.yml` 显式声明（deepseek/glm=cloud、vllm/ollama=local、cache=cache；decision 角色 data_domain=private，其余 public）；openapi 两个请求体加可选 `data_domain`。**隔离闸门已实现**：private + cloud → 硬拒并登记 FallbackEvent（degraded_of=`isolation:private->cloud`）+ lineage，不降级改投云端。测试 `isolation.test.ts` 4 条：解析推断、硬拒零网络请求/事件落账、local 通道不误伤、显式 private 覆盖角色默认。全量 226 项测试与 typecheck 通过。**剩余**：private 内容标记扫描与"全链无 local 时显式失败"的完整路径归 A-03。|
| C-06 | 丙 | `contracts/schemas/CHANGELOG.md` 升 v1.1.0，逐条登记影响面与破坏性评估；同步 `scripts/validate_contracts.py:271-280` 硬编码的 expected 集合 | C-01~C-05 | **代码侧已完成，待三线 sign-off 后转已完成** | 禁砍 | 已落地：CHANGELOG 逐条登记 v1.1.0(C-01)～v1.1.4(C-05) 并新增 **v1.1 汇总段**（台账编号→契约→追加内容→状态对照表，注明全部为纯追加、schema 文件数仍为 8）；`validate_contracts.py` 的 expected 集合与实际一致，并**新增两项交叉校验**：① schema 目录出现未登记文件 → 失败；② expected 中的契约未在 CHANGELOG 登记、或缺少 v1.1.x 增量段 → 失败。校验器输出的 schema 数（8）与 CHANGELOG 汇总段声明一致。测试 `contracts-c06.test.ts` 4 条：现状通过、漏登记/未登记文件/缺增量段三种破坏均被检出（已用真实改文件方式反向验证，非空转）。全量 230 项测试与 typecheck 通过。**剩余：三线 sign-off** |

## 5. 第 2 阶段：架构改造（D13–D18）

> 队长已定：**适配层 + 双实现**；**暂不接云端**，先做实隔离与链路；**链路真跑、模型用 cache provider 占位**。

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| A-01 | 丙 | **StateMachine 适配层 + 双实现**。新增 `src/qa/src/orchestrator/statemachine.ts`（接口：`MachineState`+reducers / `MachineNode` / `compile` / `invoke(state,{threadId})` / `resume(threadId,value)` / `MachineResult` 含 `interrupted`）；后端 A `backends/langgraph.ts`、后端 B `backends/native.ts`（迁移现有 `taskgraph.ts` 105 行的 topoOrder+状态合并+interrupt 挂起）；`config/orchestration.yml` 切 `backend: native\|langgraph`，默认 `native` 保 main 可演示。**同一套测试跑两个后端**。**2026-10-10 收口剩余项①（threadId 持久化 + invoke/resume 接通）**：新增 `orchestrator/runtime.ts`（`runMachine`/`resumeMachine`）——`newThreadId()` 开始被调用（线程身份始终存在，缺省自动生成）；native 后端补齐状态流（节点间共享 state、`writes` 字段重复写入按 `spec.reducers` 合并、恢复值注入保留键 `RESUME_VALUE_KEY`）；shared store 新增 `machine_threads` 检查点表（thread_id 主键 + executed 前缀 + interrupt_node_id + 状态快照 + suspended/completed，SQLite/内存双实现，跨重启可恢复）；`taskgraph-machine.ts` 接线 threadStore/threadId/resumeValue，`TaskGraphMachineResult` 带 thread_id/interrupted/interrupted_at；`MachineState` 索引签名改为可变（节点写状态是既定用法）；fail-closed：completed 线程禁重复 invoke、未挂起禁 resume、已挂起禁静默重跑。`config/orchestration.yml` 默认仍 `interrupts.enabled:false`（演示路径不挂起、行为不变），挂起/恢复能力经单测与冒烟 [13] 段实证可用，yml 注释写明启用方式 | C-01 | **代码侧已完成，待三线 sign-off 后转已完成** | 砍① | `src/qa/test/machine-runtime.test.ts` 7 条（reducers 合并、挂起快照+检查点 suspended、resume 跳过已执行+恢复值注入+completed、fail-closed 四路径、无 store 内存语义、SQLite 跨重启恢复、TaskGraph 适配层 thread_id 贯穿）；`statemachine.test.ts` 6 条 + `taskgraph.test.ts` 6 条回归全绿；冒烟第 [13] 段 7 断言全 PASS（invoke 挂起→检查点→resume 不重跑→completed→重复调用抛错）；全量 747 项测试 0 失败、typecheck 0 错误。**已核销**：原「装 langgraph 后补跑双后端环跑」作废——2026-09-30 判定该后端作用为零（依赖从未安装、4 用例永久 SKIP），改为删除 langgraph 分支只留 native，4 条核心断言一条未少；同期发现并修掉 `compile()` 对注入 config 不校验导致非法 backend 静默放过的问题。原验收：`test/statemachine.test.ts` 用 `for (backend of ["native","langgraph"])` 环跑相同断言；原 5 条 taskgraph 测试语义保留 |
| A-02 | 丙 | **四层兜底阶梯 工具→规则→LLM→人工**。新 `src/qa/src/ladder/`；契约位已现成（`decided_by` 四通道 + `models.yml:78` 的 `decision` role `rule-fallback-v0` 无调用方 + `openapi.yaml:135` 的 `/v1/decide` 未挂路由）。**LLM 层必须允许返回空（低置信度弃权）才能下坠到人工层** | A-01, C-01 | **代码侧已完成，待三线 sign-off 后转已完成（2026-10-10 人工工单队列尾项已落地）** | 禁砍 | 已落地：`src/qa/src/ladder/decision-ladder.ts` 的 `runDecisionLadder`——层序 tool→rule→llm→human，每层产 `LadderAttempt{layer,status:success/abstained/unavailable/failed,reason,latency_ms}`；任一层缺失/弃权/异常都**显式下坠**，经 `degrade()` 登记 FallbackEvent（`degraded_of=ladder:<层>`）并写 `decide.ladder` lineage（含输入输出 SHA-256 与 status=degraded/success/review，不复制正文）。`decided_by` 如实映射：tool/rule→`rule_fallback`（契约无 tool 通道）、llm→`llm_fallback`、human→`human`（C-01 新增通道）；全链未决 → `decision.abstain=true` + `decided_by=human` + lineage `status=review`，不伪造 choice。`/v1/decide` 已挂路由：`createGatewayServer({decideHandler})` 由编排层注入，未注入时显式 501 `not_implemented`；`@safetrace/qa`、`@safetrace/gateway` 出口各补一条追加式导出。验收：`src/qa/test/ladder.test.ts` 9 条（原兜底路径 + 上游校准概率隔离）；`src/qa/test/stepfun-decision.test.ts` 6 条（public projection、screen、类型/校准限制、默认 rule-first、人工下坠）；`src/qa/test/decide-http.test.ts` 5 条（冻结回复 schema、StepPlan mock 组合、错误请求 400、未注入 501）。冒烟新增第 [6] 段 7 条断言（工具层显式 unavailable、路径 tool>rule>llm>human、未决 abstain+human、replies 2 条、lineage review、不复制正文）。反向验证确认非空转：human 映射改回 `rule_fallback` → 1 条红；501 改成 200 → 1 条红。**最新能力边界（2026-10-01）**：新增 StepPlan resolver 与 `npm run qa:decision:serve`；handler 默认先跑确定性规则候选（`public_facts.rule_candidate` 与 rule calibration map 精确匹配且概率≥0.65），通过则不调模型。原始 `DecisionRequest.state` 默认 private；仅规则弃权后，显式 public opt-in、已筛查的 allowlist 公共事实、单个 choice 问题和由 rule/tool/policy 提供的完整 `calibrated_option_probabilities` 才可能调用 public planner。模型自评不冒充校准概率；响应概率来自上游分布，缺条件/低置信则显式转人工/挂起。新增路径只有 mock 测试，未做真实云端验收，且目前没有业务生产者提供校准分布/人工队列。新增数据库 ctx 管理（2026-10-01）：`src/shared/src/llm-context.ts` 提供 `llm_context_sets`/`llm_context_blocks` 两表与 `MemoryLlmContextStore`/`SqliteLlmContextStore`；MG1 `chat()` 发请求前按 `task_key`+`role`+`data_domain` 解析 ctx，稳定块（通用规则→任务规则）拼成 system 前缀放最前、易变块其次、真实请求最后，保证稳定前缀逐字节一致以命中 prompt-prefix 缓存；ctx 版本不可变，`mg1.chat` lineage 记 `LlmContextSet`/`LlmPromptStablePrefix`/`LlmContextSnapshot` 且只存 hash；显式 task 缺 active ctx 时 fail-closed（记 `llm-context:unavailable` 降级事件、不发 provider）；public 调用过滤 private ctx。运维命令 `npm run llm:context`（list/show/put/activate/deactivate），演示/受控采集/A-02 三个入口都已接同一个 SQLite ctx 库。验收：`src/shared/test/llm-context.test.ts` 4 条 + `src/gateway/test/llm-context.test.ts` 4 条。**2026-10-10 尾项落地（人工工单队列）**：shared store 新增 `human_tickets` 表（ticket_id 主键 + decision_id/trace_id/kind + typed questions + pending/claimed/resolved 状态机 + 接单/决单人与时间 + reply_event_id；SQLite/内存双实现、跨重启保留；**私有 state 一律不落库**，只存结构信息）；`decision-ladder.ts` 全链未决时入队（幂等按 ticket_id，`LadderResult.ticket_id` 回带，未接 ticketStore 时 lineage 显式记录无队列）；新增 `src/qa/src/ladder/human-queue.ts`（`claimHumanTicket`/`resolveHumanTicket`：人工决策过与阶梯同一套 `validateDecision` 契约校验 → 发布 `decision.replies`（`decided_by=human`，choice 记 1/abstain 记 0/score 取原值，与阶梯人工层同口径）→ 销单关联 reply_event_id → 落 `human.ticket_resolve` lineage）；CLI `npm run human:queue`（list/claim/decide，choice/score/abstain + reason）。验收：`src/qa/test/human-queue.test.ts` 7 条（幂等入队不落私有 state、人工层已决不入队、无队列显式挂起、决单全链路含总线回放、fail-closed 四路径、score/noul 口径、SQLite 跨重启）；冒烟第 [14] 段 10 断言全 PASS；全量 754 项测试 0 失败、typecheck 0 错误。**剩余：三线 sign-off**；业务生产者接入工单队列（QA/决策入口注入 ticketStore）待排期 |
| A-03 | 丙(H) | **数据隔离闸门**。MG1 增 `data_domain × trust_boundary` 两维；`private` + `cloud` → **硬拒**（非 warning）并 `degrade()` 登记（`degraded_of:"isolation:private->cloud"`）；`openai-compat.ts` 的 `postJson` 前加 `assertPublicScope()` 扫描 `asset_id`/`internal_host`/`tenant` 等 private 标记。**注意 `profiles.ts` 是手写 YAML 子集解析器，新字段必须是同形态标量** | C-05 | **代码侧已完成，待三线 sign-off 后转已完成** | 禁砍 | 已落地（在 C-05 第一道闸门之上补齐第二道与本机通道预检）：① 新增 `src/gateway/src/isolation.ts`——`PRIVATE_MARKERS`（asset_id / internal_host / tenant_id / tenant: / employee_id / -----begin / corp.internal / intranet）、`scanPrivateMarkers()`（递归扫字符串与键名，只返回「标记 + 路径」）、`assertPublicScope()`、`IsolationError` / `ScopeViolationError`；错误信息与 lineage **不回显命中内容**。② `providers/openai-compat.ts` 的唯一出网点 `postJson()` 前置扫描，且按信任边界区分：`trustBoundary` 非 local（缺省按 cloud，fail-closed）才扫描，`local` 是私有数据合法目的地不扫描；`resolveConfig` 透传 `trust_boundary`。③ `ModelGateway.withFallback` 两处收紧：**(a)** `data_domain=private` 且降级链无本机通道（trust_boundary=local/cache）→ 在**任何 provider 尝试之前**显式抛 `IsolationError` + `degrade(degraded_of=isolation:no-local-provider)` + `mg1.isolation_gate` rejected lineage，不再静默落到确定性 cache 模板冒充模型回答；**(b)** 出网载荷命中私域标记属**策略拒绝而非 provider 故障**——登记 `isolation:private-marker` 后立即终止整条降级链（不改投下一家），circuit breaker 不计故障。④ private 数据最终落到本机 cache 时，degrade 文案与 lineage 明示「未出网、内容为确定性模板，非真实模型产出」。验收：`src/gateway/test/isolation.test.ts` 扩到 8 条（原 4 条全部保留通过 + 新增 4 条：私域标记硬拒且零网络请求、错误不回显内容；全链无本机通道显式失败且无 cache 假成功；private+local 含私域标记仍放行；默认 `config/models.yml` 的 `decision` 角色 private+cache 不被误伤）。反向验证三条均转红：去掉 `postJson` 扫描 → 1 条红；扫描不区分边界 → local 放行条红；去掉无本机通道预检 → 显式失败条红。冒烟第 [6] 段新增 3 条断言（默认配置 private 角色走本机通道、不触发隔离拒绝、隔离 lineage 不复制请求内容）；全量 255 项测试（251 通过 + 4 SKIP）、typecheck、validate:contracts、check:web 四道门禁全绿。**剩余：三线 sign-off**；A-04 复用同一份标记口径做入库期/合成期检测 |
| A-04 | 乙+丙 | **注入防护：启发式已全链路落地（仍有界，非防护保证）**。共享 `src/shared/src/injection-screen.ts` 在 Q1/Q2/Q4、A-02 public projection、受控网页解析和 F1 advice 上筛查已知信号；网页模型调用额外要求显式 opt-in、精确 HTTPS host、24,000 字符上限、hash-bound attestation，过期快照拒绝。F1 只发公开标题/规则词项，输出仅为不改变论文顺序/评分的 review sidecar。**2026-10-09 增量（本条主体落地）**：DQ1 gate 1.1.0 对 title+summary 跑共享筛查器并填 `QualityVerdict.injection_score/injection_flags`（命中 → verdict 至少 review 路由人工复核、pipeline 不放行；无法筛查 → fail-closed 至少 review 且不填字段保持“未筛查”缺省语义；quarantine 仍只由硬红线决定，启发式误判不杀数据）；`fixtures/injection/` 12 个样本（十类对抗 + 2 良性对照）；新增 `src/ingest/test/injection.test.ts` 15 条 + `src/qa/test/injection.test.ts` 6 条反向验收（云合成器零调用、FallbackEvent 用户可见、lineage 不复制载荷、untrusted/未知 trust 不出云、未筛查不当已筛查）。**这是本地有界 heuristic，不是 prompt-injection 防护保证**。仍未闭环：更强证据 envelope/出处界线核查、完整 tool 权限边界审计（S4 热注册前）、元内容误判的人工复核队列接线。 | C-02, C-03 | **代码侧已完成，待三线 sign-off 后转已完成** | 禁砍 | 验收命令（台账 §12）两文件均存在且通过：`node --import tsx --test src/ingest/test/injection.test.ts src/qa/test/injection.test.ts` → 21/21 PASS（2026-10-09 实测；本机 DSH 沙禁子进程 spawn，以 transform-types + 逐文件隔离方式运行，结论等价）；`npm run smoke` 全段 PASS。反向验证：注掉 DQ1 注入分支 → ingest 用例红；去掉 Q4 screenPassed 的 trustConfirmed → qa 用例红。 |
| A-05 | 丙 | **时效性（2026-10-10 落地主体）**。`q2-retrieval.ts` 的 `passesFilter()` 真正实现 `published_after`（旧实现直接 `return true`，检索时效过滤是假的）；Q1 已抽到的 `time_range` 槽位经 `publishedAfterFor()` 转成 `published_after` 硬检索条件（7d/30d/90d/1y/ytd，ISO-8601 UTC）；按意图定时效阈值（trend ≤7d、impact_range ≤90d、其余 365d，`staleThresholdDays()`），过龄在答案尾部显式提示并进 `reasoning_chain`；双引擎同口径——MemoryIndex 内存过滤 + Qdrant 服务端 `published_at` range 下推，载荷缺 `published_at` 的点不匹配（未知时效按最不新鲜处理，fail-closed）。`EvidenceChunk.published_at` 三类 chunk（source/paper/cvss） projection 均已填充，契约字段早已存在（C-02），本次无契约变更 | C-02, C-04 | **代码侧已完成，待三线 sign-off 后转已完成** | 砍⑤ | 冒烟第 [10] 段 6 断言全 PASS（未来窗口空结果/宽窗口不误伤/不可解析抛错/time_range 转 published_after/trend 阈值 7 天过龄提示且作答/正文可见）；`src/qa/test/q2.test.ts` 新增 3 条（MemoryIndex 时效过滤含未知滤除、fail-closed 抛错、Qdrant range 下推与归一化）；`src/qa/test/q1.test.ts` 新增 2 条（publishedAfterFor 全码值、意图阈值映射）；`src/qa/test/cli-lineage.test.ts` 新增 1 条（buildRetrievalRequest 槽位转换）；`src/qa/test/answer-c04.test.ts` 新增 1 条（trend 阈值 7 天过龄）；全量 716 项测试 0 失败、typecheck 0 错误。**剩余**：`EvidenceChunk.score_sparse` 填充 BM25 原始分（现为归一化分，涉及 0.3 拒答阈值口径，单独评估）；真实语料（Qdrant + 2026 情报）下时间窗演示待本地栈就绪 |
| A-06 | 丙(H) | **A1 自愈 + Langfuse：已落地（2026-10-09）**。`src/qa/src/orchestrator/selfheal.ts` 实现 roles.ts selfheal 三工具：`replay`（按主题重读重投 + lineage）、`dead_letter_drain`（死信指数退避重投，base 1s→上限 5min→最多 8 次，成功即销档、超限显式 still_failed 转人工）、`healthcheck`（聚合死信/退避队列/fallback 统计/MG1 熔断状态/Trace 外发，缺探针显式注明不冒充健康）；订阅 `fallback.events` 全量登记（兜底透明率 100%）并落 lineage。`src/shared/src/trace.ts` Langfuse v3 ingestion HTTP 外发（零 SDK）：默认关闭（未配 host/keys 零网络零副作用）、只发元数据不外发 trigger/正文、失败只计数不外溢。总线新增 `redeliver`（单条重投不重复 append）与 store `clearDeadLetter`（SQLite+内存双实现）。验收：`ops/scripts/drill.sh`（`npm run selfheal:drill`）跑通 检测→降级→故障注入→重投失败→指数退避→恢复→重放销档→验证 全链路；冒烟第 [9] 段接入同链路断言。**仍未完成**：compose 内 Langfuse 的 `NEXTAUTH_SECRET`/`SALT` 仍硬编码 `dev-only-change-me`（E-05 顺延）；真实 Langfuse 面板验收待 Docker/本地栈就绪；72h 常驻自愈证据（E-07）待补跑。 | A-01, R-03 | **代码侧已完成，待三线 sign-off 后转已完成** | 砍③ | `npm run selfheal:drill` → 11 项断言全 PASS（2026-10-09 实测，零真实网络：MemoryEventStore + Trace 外发桩）；`src/qa/test/selfheal.test.ts` 8 条（工具白名单与角色声明一致、fallback 登记、退避窗口/到拍恢复/超限转人工、replay、healthcheck 聚合、drill 全链路、Trace 禁用态与失败计数）；`npm run smoke` 第 [9] 段 PASS；typecheck 0 错误。反向验证：maxAttempts 调大 → still_failed 用例红；去掉 backoff 窗口判断 → 退避用例红。**2026-10-10 尾项落地（常驻自愈）**：新增 `src/qa/src/orchestrator/selfheal-daemon.ts` `SelfHealDaemon`——与演练/冒烟共用同一 `SelfHealAgent`（同一工具白名单与退避参数，不造第二套自愈逻辑）；`start()` 订阅 fallback.events + 周期拍（默认 60s，`intervalMs` 可配），每拍 `dead_letter_drain`（指数退避重投、成功销档）+ `healthcheck` 聚合，报告经 `onTick` 显式交出（禁静默自愈），`stop()` 退净订阅与定时器，拍串行禁并发 drain；新增 `npm run selfheal:daemon` 常驻进程（SQLITE_PATH/SELFHEAL_INTERVAL_MS 可配，每拍一行 JSON 摘要到 stdout 并追加 `var/selfheal-daemon.log`，SIGINT/SIGTERM 优雅停止——停止路径 healthcheck 失败也关库退出；Windows 下 git-bash `kill -TERM` 走 TerminateProcess，Node 拦不住，属平台限制，停止逻辑由单测覆盖）。验收：`src/qa/test/selfheal-daemon.test.ts` 5 条（单拍报告交出+退避窗口、修复后恢复归零、start 订阅+stop 退净+幂等、并发拍串行、周期拍触发与停止）；冒烟第 [15] 段 8 断言全 PASS（订阅登记→死信首拍→修复恢复→stop 退净）；`src/qa/test/selfheal.test.ts` 回归全绿；全量 759 项测试 0 失败、typecheck 0 错误、validate:contracts 通过。**剩余**：72h 常驻自愈证据（E-07）待真实挂机跑满；compose 内 Langfuse 密钥与真实面板验收仍待 Docker/本地栈 |

## 6. 第 3 阶段：证据链补齐（D7–D18，与架构改造并行）

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 | 验收命令 / 证据 |
|---|---|---|---|---|---|---|
| E-01 | 甲 | **第 7 源**。现 6 源（4 active + ghsa/arxiv 两个 planned），目标 ≥7。选 cvelistV5 git 差分（需新增 git 能力，`common.ts:53` 只有 HTTP JSON）或先落地 ghsa。要动 7 处：`registry.ts` / 新 `sources/<id>.ts` / 新 `adapters/<id>.ts` / `index.ts` export / `pipeline.ts:57-62` SOURCE_RUNNERS / `fixtures/sources/<id>.sample.json` / `registry.test.ts:7` 的 6→7。**连累三处计数断言**：`pipeline.test.ts:13-14` 的 `fetched/parsed.length===4`、`pipeline.test.ts:27` 的 `merged.raw_refs.length===4`（容易漏）。`smoke.ts:63` 是 `>=4` 前向兼容不用改 | — | 待办 | 保 | `registry.test.ts` 断言 7 源；`npm run smoke` 仍全绿 |
| E-02 | 甲 | **真实联网抓取留痕**。fetch + 指数退避 + NVD 令牌桶已实现；首次真实采集实跑后持续补齐证据，不把 HTTP 200 单点探测当端到端验收 | E-01 | 进行中 | 保 | 2026-10-01 实跑证据见 [E-02 真实采集记录](E-02-REAL-RUN-2026-10-01.md)：2 轮共 6970 条 intel.items 事件、6976 DQ verdict、6 raw.docs；最新 trace 3727 intel events / 3727 unique IDs，真实源 KEV/NVD/USN，OSV/cve.org 当时因 pipeline 未传 CVE IDs 返回 no-data；USN 曾显式 fixture 降级；富化只覆盖 1139/放行项，arXiv 429 降级已留事件。**修复已落代码**：pipeline 把上游 CVE IDs 有界传给 OSV（最多 10）与 cve.org（1）；404 不重试，429 尊重 Retry-After；OSV/cve.org 的未请求、零匹配、部分失败分开记 lineage/fallback；scheduler 从 SQLite 种子传 CVE 且单进程避免每轮重复查询。真实单源 probe 与 MemoryEventStore 端到端联网 pipeline probe 均通过（OSV/cve.org 非 fixture，分别归并回 KEV；未写正式 SQLite）；正式 E-02 fixture 比较表和持久化 trace 验收仍待补。富化现在在线默认最多 50 条，剩余可用 `npm run enrich:pending -- --limit=20` 分批续跑（每条至少间隔 3 秒）；页面 `/ingest-diagnostics` 展示来源/富化/降级，跨源计数会重叠、跨轮 event 为 append-only，不应直接求和当唯一 CVE。SQLite seq 并发分配已原子化并加唯一索引。**尚待**：对比 fixture 的正式 E-02 验收、完整富化收尾、NVD key、72h E-07 |
| E-03 | 乙 | **F1 recall@5 基线**。现状零基线（`f1-papers.ts:122-128` 只有词级重合启发式）。建 20 条标注集，报 recall@5 | — | 待办 | 砍② | 输出 recall@5 数字并纳入冒烟聚合门槛 |
| E-04 | 乙 | **DQ1 隔离区落库（2026-10-10 落地）**。`quarantine_ref` 此前只是字符串（`dq1.ts`），无表无目录，隔离形态仅是 `dq.verdicts` 里 verdict=quarantine 的事件。`store.ts` 增 quarantine 表（照抄 `dead_letters` 模式：quarantine_ref 主键幂等 + verdict 原样 JSON 留存可复算 + SQLite/内存双实现）；`dq1.ts` 新增 `recordQuarantine()`（只落 quarantine 判定，review 不走隔离区）与 `quarantineReason()`（红线标记优先、否则质量分不足）；`pipeline.ts` DQ1 分支接线；新增 `npm run quarantine:list`（人类可读列表 / `--json` 完整导出，含 dimension_scores/flags/gate_version） | — | **代码侧已完成，待三线 sign-off 后转已完成** | 保 | `src/ingest/test/quarantine.test.ts` 4 条（reason 红线优先/只落 quarantine 且幂等/review 不混入；fixtures/dirty 六条 quarantine 全落表；SQLite 跨重启保留）；`src/ingest/test/dq1.test.ts` 14 条回归全绿（10 条 dirty 判定口径不变）；`npm run quarantine:list` 双模式实测（临时库 1 条列出+JSON 导出、真实库空态如实报告）；全量 727 项测试 0 失败、typecheck 0 错误 |
| E-05 | 甲 | **compose 验证**。Docker 未装，7 服务（qdrant/postgres/langfuse×2/clickhouse/redis/minio）从未拉起，README:82 明示交件前必须验一遍 | — | **阻塞** | 禁砍 | `cd ops && docker compose up -d qdrant postgres && bash scripts/wait-healthy.sh` 全 PASS；QdrantEngine 走真检索 **〔2026-09-30 D4 更新〕** 本仓已拍板弃用 Docker/compose、改全本地直起（TEAM-PLAN §1.2/§六）；compose 验证按砍单④降级为后续补验项，本机无 Docker 不再阻塞 demo 主线 |
| E-06 | 全 | **NVD API key**。`.env` 不存在，`NVD_API_KEY=` 空；无 key 限流 5 req/30s，有 key 50 req/30s。申请入口 README:65-66 | — | **阻塞** | 基础 | `.env` 填好；`runIngestOnce({offline:false})` 走 50 req/30s 档 |
| E-07 | 甲 | **72h 挂机证据**。零脚本零调度（`registry.ts` 的 `poll_interval_s` 只是字段声明，`runIngestOnce()` 是单次函数）。实现 `src/ingest/src/scheduler.ts` 按 `poll_interval_s` 周期调度 + `ops/scripts/uptime.sh` 记可用率 | E-01 | 待办 | 禁砍 | 可用率截图 ≥72h；降级次数与 FallbackEvent 对齐 |

## 7. 第 4 阶段：文档口径同步（D13–D18，与架构改造同批 PR）

> 逐条改，不留矛盾。每条都要在 PR 里贴出改动前后的行号。

| id | 线 | 标题 | 依赖 | 状态 | 砍单层级 |
|---|---|---|---|---|---|
| D-01 | 丙 | `README.md:21/34`、`ROADMAP.md:19` 写「7 个 JSON Schema」，实际 8 个，而 `README.md:128` 又写「8 schema」——统一为实际数 | C-06 | **已完成（2026-10-05）** | 基础 | README §1 目录树与 §7 状态表均按实测 8 schema 编写；ROADMAP D6 行 7→8 并补 v1.1 冻结状态；`npm run validate:contracts` 实测输出「8 个 schema 契约文件 / fixtures 12」 |
| D-02 | 丙 | 契约冻结日三个口径并存：README:128「D1 冻结 v1」/ ROADMAP:19「D6」/ README:10 与 GITHUB-FLOW:101「D8」→ 统一为「v1 内容 D1 落库，D6=10/3 形式化冻结」 | C-06 | **已完成（2026-10-05）** | 基础 | README §1 红线第 1 条、§7 状态表与 ROADMAP D6 行统一为「v1 内容 D1 落库，D6=10/3 形式化冻结，三线 sign-off 收尾中」；旧 README:128 段落已随状态表重写一并替换 |
| D-03 | 丙 | `PROJECT-INTRO.md:15/75`、`README.md:29` 说编排框架是 **pi-agent-core——从未安装、零代码、零 spike**，实际是自研 TaskGraph → 改为适配层 + 原生后端；pi-agent-core 移入「已评估未采用」并写明理由 | A-01 | **已完成（2026-10-05）** | 基础 | README 目录树、PROJECT-INTRO §一头表与架构图均已改为自研 TaskGraph（statemachine 适配层 + native 后端）；**并以实测修正台账原文目标**：LangGraph 后端并非"后备"，2026-09-30 已判定死代码（依赖从未进 package.json、4 用例永久 SKIP）并删除，现为 native 单后端；pi-agent-core 标注「已评估未采用（从未安装、零代码、零 spike）」 |
| D-04 | 丙 | 黄金问答「20 条」vs 实际 10 条（README:48/97/133/160、ROADMAP:22/86、PROJECT-INTRO:41/95）→ 扩到 20 后统一；未扩前如实写 10/20 | R-04 | 已完成 | 基础 | ✅ R-04（commit d631231）已把 fixture 扩到 20 条，README:48/97 与 ROADMAP:22 的「20 条」口径自此与 fixtures/golden-qa.v0.json 实际一致；README:133 的 `src/qa` 测试数与 README:160 的黄金问答数字随 C-06/D-01 一并核准 |
| D-05 | 丙 | `README.md:49`「Trace 全落 Langfuse」vs 代码零 Langfuse → 改为「S2 总线 trace_id 已贯穿；Langfuse 外发在 D13-D18 落地」 | A-06 | 待办 | 砍③ |
| D-06 | 丙 | `PROJECT-INTRO.md` 与 README 多用 `C:\Users\niangao\safetrace\`、`C:\Users\niangao\asktrace9\` → 改成本仓库实际路径与远端 | — | **已完成（2026-10-05）** | 基础 | PROJECT-INTRO §一「工程目录」行已改为仓库实际路径（`D:/AgentPrograms/safetrace` 本仓库 + `safetrace-models` 5.0G + `qdrant` Qdrant 二进制实测运行中）；README 目录树同步核实无残留旧用户目录引用（grep 零命中） |
| D-07 | 丙 | `PROJECT-INTRO.md` 曾指向 `asktrace9/docs/` 四篇报告 + 三张图，**仓库内完全缺失**；交叉引用全部不可解析 → 迁入 `docs/` 或改写索引 | — | **进行中（2026-10-05 阻塞升级）** | 基础 | 本轮核实发现事态比原登记严重：`C:/Users/niangao/asktrace9/` **整个目录已不存在**（全盘 find 无副本，四篇 md + 三张 SVG/JPG 去向不明，回收站未见）。PROJECT-INTRO §四表格已改为如实标注「源目录已不存在，需重建或从合订本导出」。**交件前 S-03 依赖这四篇，需队长确认重建口径** |
| D-08 | 丙 | `PROJECT-INTRO.md:138` 称合订本 68 页，仓库内 PDF 实为 **15 页**，且是 README/ROADMAP/PROJECT-INTRO 的合订、早于 D1 交付 → 改页数、说明性质 | — | **已完成（2026-10-05）** | 基础 | PDF 页数已用 `/Count` 解析实测复核 = **15 页**；PROJECT-INTRO §四表格改为「实为 15 页，README/ROADMAP/PROJECT-INTRO 合订、早于 D1 交付」，指向本仓库根 `SafeTrace-三件套-内部版.docx/.pdf`（实测在位） |
| D-09 | 丙 | `README.md:51`「A1 自愈 L1/L2」vs 只有角色声明 → 按 A-06 实施后改写；未完成前如实标注 | A-06 | 待办 | 基础 |
| D-10 | 丙(H) | `config/models.yml:4` 说 openai_compat 对四家「通用」→ 补注「chat/embed 通用；rerank 无标准端点，会显式报错（`openai-compat.ts:107-111`）」 | — | 待办 | 基础 |
| D-11 | 丙 | `src/qa/package.json` 声明依赖 `@safetrace/gateway`，但 Q 线零 import → 删空声明或注明「经 AnswerSynthesizer 注入、不直接依赖」 | — | **已完成（2026-10-05 核实后注销）** | 基础 | 实测推翻原登记前提：`src/qa/src/index.ts` 的约定注释（「本包不 import @safetrace/gateway」）已过时——`server.ts:10` 确有 `import { ModelGateway } from "@safetrace/gateway"`（用于 /v1/retrieve 服务注入）。依赖声明与实际相符，本项作为「登记失实」注销，无需改动 |
| D-12 | 丙 | `src/qa/server.ts` 只绑 `127.0.0.1`，README 未提 → 补注（这其实是合规优点，写明「默认仅本机」） | — | **已完成（2026-10-05）** | 基础 | README §7 状态表已在 `src/qa` 行与已知限制⑦如实标注；`server.ts:225` 实测 `listen(port, "127.0.0.1")`，只回环不对外，作为合规优点写入 |
| D-13 | 丙 | README:123「零外部依赖即可演示」在接入 LangGraph 后不成立 → 改写为「零 provider SDK、无 API key 亦可离线跑通；编排层可选接 LangGraph」，并按新三条红线措辞 + CI grep 断言重述 | A-01 | **已完成（2026-10-05）** | 基础 | README §7 已改为「零 provider SDK 即可演示」并补「2026-10-05 实测门禁：543/543、冒烟全段 PASS」；**台账原文需按实测修正**：LangGraph 已删、并非"可选接"，编排为 native 单后端；「零外部依赖」的准确口径是「零 provider SDK + 零 API key + 离线 fixture 可复现」 |

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
| P-03 | 丙 | FR-S02 | 将 CVE 状态、受影响版本和资产关系接入结构化查询；"版本是否受影响"走确定性规则并返回依据，不由相似度或模型自由生成。**2026-10-10 落地问答侧入口**：`assets/matcher.ts` 抽出 `assessVersionImpact()`（版本影响判定核心规则，组件扫描与问答共用同一实现，不引入第二套逻辑；产品标识归一化后精确匹配，禁模糊匹配；存在无法解析的版本规则时不过度结论——不能排除即 unknown）；新增 `src/qa/src/version-impact.ts` `answerVersionImpact()`（多源聚合：affected 优先 → unknown → not_affected；无产品命中显式 unknown 并说明"无法判定不等于安全"）；Q4 新增 `version_impact` 选项，正文输出「## 版本影响判定（确定性规则）」段（结论+规则+命中区间+依据）并进 reasoning_chain，拒答路径同样展示；本地演示服务新增 `POST /api/v1/qa/version-impact` 结构化查询端点，问答链路按 Q1 产品/版本槽位自动判定并随答案展示 | P-01、持久化选择 | **代码侧已完成，待三线 sign-off 后转已完成** | 保 | `src/qa/test/version-impact.test.ts` 11 条（affected/not_affected/unknown 三态、大小写归一、禁模糊匹配、cve_id 限定、多源聚合、不可解析规则不过度结论、判定进正文与推理链、拒答路径保留、缺省不渲染）；`src/qa/test/local-demo-server.test.ts` 新增 2 条（结构化查询端点三态+400 校验、问答链路答案含判定段）；`src/assets/test/matcher.test.ts` 重构回归全绿（matchComponent 行为不变，仅措辞中立化）；冒烟第 [12] 段 6 断言全 PASS；全量 740 项测试 0 失败、typecheck 0 错误、validate:contracts 通过。**剩余**：资产关系（本地扫描组件 × 情报）进结构化查询归 A 线既有 auto-match 链路，问答侧只做「产品 × 版本 × CVE」判定；fixture 单源不产多版本规则分歧的演示样本 |
| P-04 | 丙 | FR-S03 | 证据增加 document_id、source_url、fetched_at、content_hash、chunk_id、索引版本；更新/撤销可定位并使旧索引失效，历史可审计 | C-02、存储方案 | 待办 | 基础 |
| P-05 | 丙 | FR-Q02/Q03、AT-04/05 | 混合查询结构化事实与多份独立来源；答案保留来源冲突、证据不足状态和原文页/段定位，不能把冲突压成单一结论。**2026-10-10 落地主体**：富化 F6 的 conflicts 审计字段不再被静默剥离丢弃——`runEnrichment` 返回类型 widen 为 EnrichmentOutcome（内存侧带 conflicts，总线发布的 EnrichmentResult 契约不变）；`normalizeSourceConflicts()` fail-closed 归一化（同值无分歧/来源越界/分值越 0-10/已仲裁缺 rationale/字段越界 → 抛错，重复条目按内容哈希去重）；Q4 `synthesizeAnswer` 新增 `source_conflicts` 选项，正文输出「## 来源冲突」段落（逐条列出来源分值与仲裁状态/理由）并进 reasoning_chain，**拒答路径同样保留冲突**；Answer 契约追加可选 `source_conflicts`（v1.2.2，纯追加，缺省=未提供、禁当无冲突）；本地演示服务按证据 CVE 归并冲突注入问答链路 | P-03、P-04、A-05 | **代码侧已完成，待三线 sign-off 后转已完成** | 保 | 冒烟第 [11] 段 5 断言全 PASS（outcome 带 conflicts/冲突段落与分歧数值进正文/Answer 字段与推理链齐备/未提供不渲染/同值 fail-closed）；`src/qa/test/answer-p05.test.ts` 5 条（进答案三处可见、拒答路径保留、缺省语义、归一化 fail-closed 五类、契约镜像旧形状合法）；`src/qa/test/local-demo-server.test.ts` 新增端到端 1 条（注入冲突 → 问答 SSE 答案含冲突段落）；`src/qa/test/stepfun-answerer.test.ts` 新增 1 条（模型结论不覆盖冲突段）；全量测试 0 失败、typecheck 0 错误、validate:contracts 通过。**剩余**：真实多源语料（E-02 实采库）才产出冲突，fixture 单源不产，演示需注入样本；live-intel-server 只读路径的冲突需 SQLite 持久化（照 E-04 模式）后才能回放；多份独立来源的混合查询（结构化事实+多源）整体归 P-03/P-04 |
| P-06 | 乙+丙 | FR-F06、FR-Q04、FR-S401 | POC 仅展示引用/元数据且不执行；修复建议无可靠来源时标“待核实”；攻击链和工具注册若展示须标为静态演示，不宣称自动推理/热注册 | 报告披露口径 | 待办 | 砍⑤ |
| P-07 | KKK9747human | PRD 7.3 界面清单 | 接 Q 线 HTTP 真数据；实现一屏完整问答与可展开推理链；展示降级；对接 compose 演示环境。当前 main 页面仍是预置样例，真实 API 接线与验收未完成；F2 资产页待 R1 确认。**〔2026-09-30 D4 更新〕** 队长拍板 P-07 提前为主任务：KKK9747human 先交付完整基础 demo（全栈含本机 API 路由；本机直起、不依赖 compose），起点分支 `feat/qa-local-live-demo`（b30c9a5，已含 Q1→Q2→Q4 真链路、SSE 问答、前端接线与 82 行测试），施工指南与验收见 `docs/P07-DEMO-PLAN.md`；“对接 compose 演示环境”按 D4 口径改为本机直起。**〔2026-10-01 合入更新〕** 该起点分支已 rebase 合入 main（本提交）：新增 `npm run demo:serve`（启动实跑离线采集→DQ1→富化；问答实跑 Q1→Q2→Q4，SSE 事件 stage/citation/token/done）与 `docs/LOCAL-DEMO.md` 手册；前端默认真实后端，仅 `VITE_DEMO_MODE=true` 用静态 mock。本行前述“当前 main 页面仍是预置样例”自本次合入起失效。仍待办：Q2 只查独立 evidence fixture 索引、未接本次采集结果；真实联网源/云模型/Trace 诊断页未做；**浏览器手动验收（录屏/截图）未完成，不得表述为生产实时系统** | P-03、P-05、A-06；R1 | 进行中 | 砍④ |
| P-08 | 全 | NFR-03/08、AT-07、DoD | 定义每个指标的样本规模、时间窗和统计方法；补 provider 配置切换可复现记录及边界样本结果。≤60 秒只是 PRD 建议目标；前端预置看板值不能充当实测，任何准确率/完成度不得在无实测时写成已达成 | A-03、R-04、E-07 | 待办 | 基础 |
| P-09 | 全 | PRD 第 11 节 R1–R8 | 形成负责人决策记录：F2 是否提 P0、7 类源及完成判定、24h/72h、D6/D8、Jev 定位、“推理链”口径、矛盾统计来源、完成度仅作内部估算 | 负责人确认；分别关联 E-01/E-07/D-02/A-02 | 待办 | 禁砍 |
| P-10 | 李念（MG1/Q2）；与 Xue 对齐来源，KKK 接前端 | FR-Y01/S02/S03/Q02/Q04 | 受控单页 Firecrawl + 规则→受控 LLM→人工复核 + Qdrant 真实 embedding/BM25 混合检索。当前本地小切片已实现 allowlist/robots、direct→Firecrawl→last-good、证据校验、MG1→Qdrant RRF；新增 SQLite append-only lineage_records 覆盖 ingest fetch/parse/dedupe/DQ1、enrich F1/F4/F6、Q2 index/search/fusion、crawler/extractor、MG1 provider attempts 与 CLI/HTTP Q&A。已有默认离线的 ingest:once SQLite runner，网页→DQ1 显式来源 API 与 crawl:page 独立入库开关已实现（元数据文件联网前校验，默认预览；见 [本地指南](P10-LOCAL-VERIFY.md)），并有零网络 page:demo，stale/待复核/证据不符不自动放行；sqlite-page→来源证据块→BM25 适配已验证（缺快照/URL不符拒绝）；正式 SourceRegistry 调度及网页原文富化适配仍待办；SQLite last-good、按 SHA 保留的历史快照与 review queue 已持久化（跨 URL 更新/数据库重启保留审核证据），但人工决定不自动写入 DQ1；来源 EvidenceChunk 构建与临时 BM25 预览已接入 ingest:once（DQ1 放行、单来源 URL/hash、全步骤 lineage）；来源 Qdrant 持久入库 opt-in 入口已实现，拒绝离线/fixture/cache/hash，写失败不报告成功；pilot:doctor 可 GET-only 检查本地前置条件（不生成 embedding）；默认仍 cache；独立 Tokendance qwen3.7-text-embedding profile 已经 API/MG1 单文本实测为1024维且无降级，密钥仅本地；Qdrant 不可达，持久索引/召回和语义质量仍待验收；MemoryEventStore 仅用于测试/smoke。A-03/A-04 前不将不可信网页送云 LLM，外部 API 默认关闭。**2026-10-10 向量链复验（开箱可用）**：本地栈实测跑通——Qdrant :6333（third_party/qdrant/qdrant.exe，集合 safetrace_intel_demo 5237 点）+ bge-m3 :8081（llama-server，实测 1024 维）；`npm run pilot:doctor` 四项全绿（embedder_config/qdrant/collection/embedding_service，`prerequisites_ready: true`；该 script 已改为默认读 `.env.local`，不再需要手跑 `--env-file`；默认占位 cache 配置下诚实报 `embedder_config: missing`，不假装可用）；`npm run vector:verify` 验收通过（真实推理 1024 维 + Qdrant 写入 + 语义召回排序正确：0.81 > 0.66 > 0.61，清理验证点后剩 5237 点）。起服务口径：`npm run local:up`（pwsh；幂等，已在跑就跳过）。**仍待办**：72h 常驻索引保鲜、真实语义质量的人工标注评估（E-03 口径）、受控网页→DQ1 的 SourceRegistry 正式调度 | C-02/C-04、A-03/A-04；来源白名单确认；不得挤占 R-04/R-05/A-02 | 进行中（lineage + 小切片 + 向量链复验通过） | 砍④ |

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

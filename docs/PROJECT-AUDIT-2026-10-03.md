# SafeTrace 项目总览与赛题对照审查（2026-10-03）

> 审查基线：本地 main，提交 b860edd。以当前源码、原题四页和本轮只读实测为准，不把历史台账或记忆当成当前事实。
> 本轮只新增审查文档与忽略目录内的诊断材料；未改业务代码，未执行采集、补富化或向量写入。未读取或输出本地密钥。未进行浏览器页面验收、真实问答质量评测、企业资产或 PoC 验证。

> **历史基线说明**：本报告保存10/3发现，不代表10/4之后代码仍原样；首批安全修复及当前验证结果见[整改记录](<D:/AgentPrograms/safetrace/docs/REMEDIATION-2026-10-04.md>)。

## 1. 总结：不是空壳，但还不是完整交付态

现有项目已经有可复现的基础链路：多源采集适配、质量判定、论文和评分富化、SQLite 事件与 lineage、本地真实 embedding、Qdrant、问答模板/模型入口、Vue 页面和测试门禁。显式降级、私域数据出云限制、来源与模型版本留痕，是值得保留的工程优点。

**主要问题不在“目录不够多”，而在三件事：**
1. **赛题主题与能力覆盖不足**：大量通用 CVE 不等于 AI 安全知识；论文、标准、法规尚未形成独立采集底座；主链只有两种富化维度。
2. **多个模块有实现但没接成一条生产链**：真实情报向量库、fixture 网页演示、富化事件库是不同数据面；富化结果没有进入当前真实情报索引，网页问答也仍走 fixture。
3. **工程红线存在可复现缺口**：索引重试绕过 DQ、历史放行覆盖最新隔离、归并丢红线状态、熔断恢复锁死、测试没有保证离线。

**建议：先补安全门禁与数据链，再补第三种富化和 AI 专题，最后做真实评测与交付。不要先盲目补跑几千条富化。** 本报告不预测比赛分数：没有真实标注和现场验收，给精确分数会误导。

## 2. 原题要求：哪些是硬交付，哪些是评分档位

原始依据：[赛题九 PDF](<C:/Users/niangao/Downloads/5c1833f3-1bfb-4b5a-8fbf-63d00ea2bb1c/9 赛题九：网信产业应用赛道-智能体驱动的AI安全知识情报系统设计与实现（奇安信科技集团股份有限公司）.pdf>)。其中文文本层提取不完整，本轮逐页渲染阅读，以下按页码整理。

### 2.1 内容要求（第 1–2 页）
- 三大核心能力：情报监测、情报富化、情报问答。
- 监测对象是最新 **AI 安全漏洞信息**，渠道包括 CVE/NVD、安全社区、厂商公告、博客等。
- 富化包括但不限于论文/分析文章、受影响互联网资产、可用 PoC、CVSS 与影响评估。
- 问答需要理解复杂安全意图，支持跨文档语义检索和关联推理，回答影响范围、修复建议、相关攻击链。
- **另外明确要求同步采集 AI 安全学术论文、技术标准、政策法规，构建知识底座。** 这不是仅有论文关联按钮就能替代的要求。
- AI 风险分类只是参考，原题明确“不作为评分依据”；不必照搬四分类，但要说明自己的 AI 安全识别与覆盖方法。
- Agent 的角色、架构不强制特定框架；自研执行器可以用，不能为了框架名硬接 LangGraph。但自主决策、编排、工具调用必须有实际证据。

### 2.2 初赛评分（第 2–3 页）
| 项目 | 分值 | 原题档位 |
|---|---:|---|
| 监测完整性 | 15 | 至少 3 类源合格；5 类以上良好；7 类以上且实时监测优秀 |
| 富化完整性 | 15 | 至少 3 种维度合格；5 种以上良好；准确且自动关联推理优秀 |
| 问答完整性 | 15 | 关键词检索合格；语义理解+多轮良好；跨文档推理+深度分析优秀 |
| 监测时效 | 5 | 发布到采集 ≤24h / ≤12h / ≤6h |
| 富化准确率 | 5 | ≥70% / ≥85% / ≥95% |
| 问答深度与准确率 | 5 | 基础准确率 ≥70%；深度问答推理链良好；多跳准确率 ≥85% 优秀 |
| Agent 架构 | 15 | 基本 Agent；多角色协作+自主编排；精良可扩展 |
| 自动化 | 10 | 核心自动化；全流程+异常处理；全流程+自愈 |
| 文档 | 15 | 结构与表达；详细设计图/流程图及严谨逻辑 |

注意：7 类源、5 维富化是争取更高档位，不是所有队伍的最低提交门槛。原题没有强制 72h 连续运行、20 条黄金问答、必须 Docker、必须 Langfuse；这些属于项目自定验收目标。72h 可作为稳定性证据，但不能写成原题“一票否决”。原题的“类”不能直接解释为配置表行数；建议列出渠道类别、具体 feed、采集器和真实运行证据，避免同一类 CVE 数据源重复凑数。

### 2.3 初赛交付（第 2 页）
技术报告 Word 与 PDF 各一份；建议封面/目录后第 1–2 页为亮点预览。报告需包含总体架构、Agent 方案、三模块设计、选型、工作流、实现细节、核心代码、效果展示、性能测试和创新总结。另交操作演示视频、技术讲解 PPT 的 PDF。

原题注明源码由企业在参赛平台审阅，不单独提交以免泄露；第 4 页又说明不提供统一运行平台、学生自行部署。应向学校确认具体审阅/上传方式，不据这一句自行公开仓库。10/19 截止来自项目现有内部计划，不是这四页 PDF 中写明的时间，须另核实通知。

### 2.4 决赛增量（第 3–4 页）
- 监测看增量、实时与去重；富化看智能关联；问答看多轮、推理与个性化。
- 富化准确率/召回率：合格 ≥80%/≥70%，良好均 ≥90%，优秀均 ≥95%。
- 问答：合格准确率 ≥75% 且响应 ≤5s；良好 ≥90% 且多跳；优秀 ≥95% 且推理可解释。
- 工程化阶梯：基本可部署 → 容器部署+日志监控 → 完整 DevOps+自动运维。
- 决赛答辩 PPT **不能出现队伍单位、人名等识别信息**。初赛是否匿名须另问，不要把决赛规则和全部内部文档混为一谈。

## 3. 当前项目结构与真实数据基线

### 3.1 模块职责
| 模块 | 当前职责 | 审查判断 |
|---|---|---|
| shared | 类型、契约校验、事件总线、SQLite、lineage、页面快照、审核、ctx | 底座较扎实；总线可靠投递/重试仍不完整 |
| gateway | 统一模型出口、角色配置、隔离、计量、限流熔断、降级 | 接口清楚；恢复、计量持久化及测试出网存在问题 |
| ingest | 五个采集器、适配、批内去重、DQ、定时循环、受控单页 | 真采集已具备；不是七类实时监测、不是完整耐久增量 |
| enrich | 论文、CVSS/EPSS/KEV、分值仲裁、F6 收口 | 自动主链两维；F2 仅独立合成资产演示 |
| qa | 规则意图、BM25/Qdrant、引用回答、模型补位、原生任务图 | 有真实检索底座；复杂推理、多轮、工具/人工闭环不足 |
| web / scripts | 大屏、列表/详情、问答、诊断、本地演示与运维入口 | fixture 页面与正式库分离，须统一接线和数据标签 |

### 3.2 本轮只读统计
读取 [当前 SQLite](<D:/AgentPrograms/safetrace/var/safetrace.sqlite>) 的 events，按 seq 取每 ID 最新记录；只对本地 Qdrant 做集合 GET，没有执行 embedding 或写库。

| 指标 | 当前值 | 正确解释 |
|---|---:|---|
| intel.items 事件 | 6970 | append-only 事件，不是 6970 条唯一情报 |
| 唯一 intel_id | 5237 | 不等于已筛选的 AI 安全漏洞数，也未断言都是唯一 CVE |
| dq.verdicts 事件 | 6976 | 最新按 item_id：5237 pass，6 quarantine |
| enrich.items 事件 | 1174 | 包含同 ID 的多次结果 |
| 有结果的唯一 intel_id | 1123 | 约占唯一情报 21.4%；不等于真实富化成功率 |
| 最新结果 paper completed | 1065 | 可能包含 fixture 降级论文；不能算论文关联准确率 |
| 最新结果 cvss completed | 29 | 必须追查评分来源恢复与数据形状，不先用“有记录”掩盖 |
| raw.docs 事件 | 6 | 可能一份批响应含多条漏洞，不能与唯一情报一比一 |
| fallback.events | 1117 | 不同任务/维度混合事件，不直接除以情报数算失败率 |
| Qdrant safetrace_intel_demo | 5237 点 | 数量对上不证明内容/时效/来源/问答准确率验收 |

Qdrant 返回 indexed_vectors_count=0；这是向量索引构建统计，不等于 points 没向量或不能检索。当前是否使用 HNSW、是否达到构建阈值及性能须另外检查，本轮不从该值推断检索故障。

source_ids 成员计数为 cisa_kev 1730、nvd_cve 3507、ubuntu_usn 11（跨源可重叠）；正式库此次没有看到 OSV/cve.org 贡献的最新情报成员。这不否定采集器实现，而是说明实现与正式运行产出要分开验收。

### 3.3 本轮门禁结果
- typecheck：通过。
- 单测：370 项，369 通过，0 失败，1 跳过。日志：[本轮测试记录](<D:/AgentPrograms/safetrace/.tmp/project-review-tests.log#L375-L382>)。
- 契约：8 个 schema、12 个 fixture，通过。
- 离线 smoke：通过；主富化显示 paper/cvss，黄金问答主要围绕 Log4Shell。
- 前端数据来源/SSE smoke：5 项通过。
- **完整 npm run check 未通过**：前端 vue-tsc/600 模块转换后，esbuild 删除 Windows Temp 临时文件报 Access is denied；单独重复 build 同样失败。本轮未修改 ACL 或批准安装脚本，原因仍待隔离，不武断归为 Vue 业务缺陷。
- 测试审查后发现网关用例未 mock 外网，因此本次“测试通过”不能称“严格零网络”。测试入口未显式加载本地 env 文件，未观察到真实付费成功请求，但不能证明网络请求完全没发生。后续已停止重复全量测试，先整改默认禁止出网。

## 4. 赛题覆盖矩阵

| 要求 | 当前状态 | 差距与处理 |
|---|---|---|
| 自动多源监测 | 部分实现 | 7 登记、5 runner、2 planned；按渠道类别与实跑证据重计数 |
| AI 安全专题覆盖 | 证据不足 | 通用 CVE 为主；需专题过滤/标签、AI 组件及无 CVE 安全事件 |
| 博客/社区持续监测 | 未形成主链 | 受控单页是手动入口，不是自动订阅与持续发现 |
| AI 论文/标准/法规知识底座 | 缺口明显 | F1 按漏洞标题关联论文不能替代独立知识采集 |
| 至少 3 维富化 | 主链未达 | paper+cvss；F2 未并入，PoC/修复信息等未自动产出 |
| 五维与智能关联 | 未验收 | 不把 EPSS/KEV/内部 F6 计数机械拆成独立维度 |
| 基于采集+富化的问答 | 断链 | 真索引只读 intel 标题摘要；网页仍 fixture，富化 artifacts 未进 QA |
| 语义检索 | 有实现/历史实测 | Qdrant+bge-m3 底座在；本轮只查集合，未重跑语义质量验收 |
| 多轮 | 界面历史而非语义多轮 | session/history 未从前端传入，新请求新 session |
| 跨文档推理/攻击链 | 部分入口 | 有多文档召回与模型综合，策略标签不能当多跳执行/事实正确证明 |
| 时效 ≤24/12/6h | 有统计工具，未给出达标结论 | 需严格监控期样本、排除历史回填/fixture；时间过滤尚未兑现 |
| 富化/问答准确率 | 缺正式评测 | confidence、DQ分、enrichment_score、关键词冒烟都不是准确率 |
| Agent 自主编排/工具调用 | 部分实现 | 原生任务图+规则/LLM阶梯；角色 tools 多为声明，业务未闭环 |
| 自愈 | 未完整 | 熔断恢复 bug、总线无自动重试、自愈角色工具未实现 |
| 交付材料 | 未可据此验收 | 内部三件套不等于最终技术报告、PPT PDF和视频；需内容一致性核验 |

## 5. 工程完整性问题清单（含代码证据）

严重程度：P0 是先修，否则数据可信性/安全门禁不成立；P1 是初赛主链和可靠性要修；P2 是部署体验、扩展或决赛改进。下面是静态可达路径或纯内存复现，不表示正式库已经发生污染。

### 5.1 P0：质量闸门与索引一致性

**A01 索引重试绕过 DQ，主路径使用历史任意放行。**
- [索引脚本:121–159](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L121-L159>) 的 --retry 直接读 intel.items 写 Qdrant，不查 DQ。
- [索引脚本:161–183](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L161-L183>) 只要历史有一次 pass/degrade 就进 allowed；取同 ID 第一条，不取最新内容/判定。
- [索引脚本:188–190](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L188-L190>) 已有 chunk_id 就跳过，不识别更新/撤回。
- 影响：先 pass 后 quarantine 的对象仍可保留/再入库；修订信息长期不刷新。两条路径必须共用最新版本准入；拒绝对象要撤销已有索引，重建前先做只读对账。

**A02 归并会丢 incoming 的质量红线字段。**
- [dedupe:72–88](<D:/AgentPrograms/safetrace/src/ingest/src/dedupe.ts#L72-L88>) 只展开 existing，未合并 incoming._cve_status 等扩展。
- [pipeline:254–285](<D:/AgentPrograms/safetrace/src/ingest/src/pipeline.ts#L254-L285>) 先合并再 DQ；[DQ:160–165](<D:/AgentPrograms/safetrace/src/ingest/src/dq1.ts#L160-L165>) 只看归并后的状态。
- 影响：先来正常来源、后到同 CVE 的 REJECTED 状态可在归并中丢失。应保留逐源状态与冲突、在原始条目处判定红线或做单调保守归并；不能简单让最长摘要/最高 reliability 压过撤回事实。

### 5.2 P1：富化知识与前后端实际断链

**A03 富化没有进入真实检索知识，主富化仅两维。**
- [F6:16–17](<D:/AgentPrograms/safetrace/src/enrich/src/f6-verify.ts#L16-L17>) 只要求 paper/cvss，F6 是完整度/分值收口而非漏洞复现。
- [真实索引:66–75](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L66-L75>) 只生成 CVE/标题/摘要；[ingest-once:61–79](<D:/AgentPrograms/safetrace/scripts/ingest-once.ts#L61-L79>) 写的是来源 evidence，不是 enrich artifacts。
- F2 当前仅合成资产演示。需要 artifacts → 可检索、可引用、版本化证据块投影；至少新增一种有来源的独立富化维度并接全链。

**A04 真索引缺关键元数据，来源链接与哈希语义弱。**
- [chunk 构造:243–251](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L243-L251>) 漏 published_at/trust/quality_score；原先证据块生成器已具备这些能力，两套路径不一致。
- [URL 映射:32–53](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L32-L53>) 多为目录/搜索页加参数，不等于逐条原文；哈希是拼接/截断文本，不是原始源快照哈希。
- Q4 的 trusted 门禁可能因此不走模型；时效变 unknown；有 min_quality 时可能全排除。应来源级建块、补元数据和原始快照 hash；不能简单把所有内容默认 trusted 来绕门。
- [索引 lineage:198–229](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L198-L229>) 使用 MemoryEventStore，父链主要指向 runner，不是持久化原始 DQ 因果链；退出即丢完整处理记录。

**A05 网页仍是 fixture 演示，不是正式知识库统一应用。**
- [demo 数据载入:21–58](<D:/AgentPrograms/safetrace/scripts/local-demo-server.ts#L21-L58>) 固定 fixture，列表用离线采集/富化，QA 又用独立 readFixtureChunks。
- [demo 问答:263–275](<D:/AgentPrograms/safetrace/scripts/local-demo-server.ts#L263-L275>) 检索该内存索引；[QA server:40–75](<D:/AgentPrograms/safetrace/src/qa/src/server.ts#L40-L75>) 虽有 Qdrant，但不是页面 chat 统一入口。
- 应统一正式 SQLite → 列表/详情/大屏 → 正式 Qdrant → QA，并把 live、fixture、degraded 分开标记。现有诚实横幅要保留，不因接真库就隐去局部 fixture。

**A06 降级/失败富化容易被当完成并永久跳过。**
- [F1:218–235](<D:/AgentPrograms/safetrace/src/enrich/src/f1-papers.ts#L218-L235>) 失败可回放固定论文；[F6:77–81](<D:/AgentPrograms/safetrace/src/enrich/src/f6-verify.ts#L77-L81>) 非空就 completed。
- [pending:23–25](<D:/AgentPrograms/safetrace/src/enrich/src/pending.ts#L23-L25>) 已有任意结果就默认不补；失败维度不自动修复。
- 要用逐维 live/degraded/empty/failed 状态、输入版本和下次重试时间，fixture 不算真实成功；论文零相关不能因为返回非空就通过。

### 5.3 P1：问答深度与指标可信性

**A07 真实多轮、澄清恢复、攻击链推理尚未闭环。**
- [前端会话 store](<D:/AgentPrograms/safetrace/web/src/stores/qa.ts>) 的历史主要用于展示，请求不带 session/history；[demo:238](<D:/AgentPrograms/safetrace/scripts/local-demo-server.ts#L238>) 新建 session。
- [CLI 请求:18–26](<D:/AgentPrograms/safetrace/src/qa/src/cli.ts#L18-L26>) 没把 time_range/strategy 完整转为检索执行；多跳/攻击链名称不代表已做子问题分解与证据 join。
- 要有会话对象延续、澄清补槽、逐子问题检索、事实—证据对应及冲突/缺失标记。展示推理链应是可核对的证据推导，不是把调用日志冒充正确推理。

**A08 多 CVE 覆盖门槛只要求命中一个。**
- [Q4:85–90](<D:/AgentPrograms/safetrace/src/qa/src/q4-answer.ts#L85-L90>) 使用 some。比较两个 CVE 只召回一个也可能作答。
- 应按问题逐对象/逐子任务检查完整覆盖；部分回答必须明示缺失，不能整题表现为已完整回答。

**A09 BM25 归一化让弱命中也固定得 1，0.3 拒答阈值失效。**
- [Q2:164–171](<D:/AgentPrograms/safetrace/src/qa/src/q2-retrieval.ts#L164-L171>) 用本次榜首作归一化分母；任何非空召回的榜首都是 1。
- [Q4:39–49](<D:/AgentPrograms/safetrace/src/qa/src/q4-answer.ts#L39-L49>) 把 sparse/dense 最大值当拒答分，弱词重合也能过门槛。
- 不同模型/检索分数不能当可比较的校准概率；增加覆盖、绝对匹配信号、人工标注校准和无关查询负例。

**A10 published_after 被接受但没有实际过滤。**
- [Q2:236–246](<D:/AgentPrograms/safetrace/src/qa/src/q2-retrieval.ts#L236-L246>)、[Qdrant filter:615–621](<D:/AgentPrograms/safetrace/src/qa/src/q2-retrieval.ts#L615-L621>) 未兑现时间过滤。
- “最近 30 天”可能返回全历史。应 Memory/Qdrant 同一语义，未知发布日期明确排除/单列，接 Q1 time_range，按趋势/影响/修复分别定义时效。

### 5.4 P1：可靠性、自愈与测试边界

**A11 熔断半开探针失败后永久锁死（已纯内存复现）。**
- [circuit:62–81](<D:/AgentPrograms/safetrace/src/gateway/src/circuit.ts#L62-L81>) 半开 flag 设 true，再失败不会更新 openedAt/清 flag。
- 注入时钟的实测：第一次冷却后探针 true → 探针失败 → 再过冷却，探针 false，状态始终 half_open。
- 修成失败回 OPEN、新冷却后允许新探针，成功关熔断；覆盖多轮失败、并发、取消、异常恢复。不要用重建 gateway 实例清熔断代替恢复策略。

**A12 总线“maxRetries”没有自动重试、没有订阅者级可靠交付。**
- [bus:86–111](<D:/AgentPrograms/safetrace/src/shared/src/bus.ts#L86-L111>) 吞 handler 错误，只增加内存 event_id 计数；任意成功 handler 会删它。
- replay 整主题会重做已成功订阅者副作用。需持久 subscriber ID、ack、retry_at、attempt、幂等键、死信和独立重放；若初赛不做，明确仅支持人工重放原语。

**A13 单测可真实出网，部分测试名与断言不一致。**
- [gateway test:100–109](<D:/AgentPrograms/safetrace/src/gateway/test/gateway.test.ts#L100-L109>) 强制 deepseek 未 mock；[provider:67](<D:/AgentPrograms/safetrace/src/gateway/src/providers/openai-compat.ts#L67>) 使用全局 fetch。环境有 key 时可能真调用。
- [gateway test:88–97](<D:/AgentPrograms/safetrace/src/gateway/test/gateway.test.ts#L88-L97>) 名叫熔断跳过，实际直接走 cache，没有制造熔断/断言事件。
- 修复 fetch 注入，全套单测默认拒绝非 loopback 出网；live tests 单独命令+显式授权，不跟 npm test 混用。测试要断言事实、故障和状态转换，不只关键词与调用标签。

**A14 定时采集不是完整增量/可恢复链。**
- [scheduler:134–154](<D:/AgentPrograms/safetrace/src/ingest/src/scheduler.ts#L134-L154>) 运行时间/已查询集合主要内存；逐源调用 pipeline；[pipeline:254](<D:/AgentPrograms/safetrace/src/ingest/src/pipeline.ts#L254>) 只去重本批。
- 固定 NVD 窗口/USN 最新条数不能覆盖长停机；同 CVE 更新不保证重新查。需要持久水位、重叠窗、变更 hash、catch-up 和跨轮 canonical identity，自动排队富化/索引，而非多条脚本人工串接。

### 5.5 P2：配置、部署、接口及交付维护

| 编号 | 问题 | 证据 / 建议 |
|---|---|---|
| A15 | Compose 全栈端口冲突 | [compose:134](<D:/AgentPrograms/safetrace/ops/docker-compose.yml#L134>) 与 [166](<D:/AgentPrograms/safetrace/ops/docker-compose.yml#L166>) 同映射宿主 9000；归档未验收或修复后实测 |
| A16 | Compose 默认全网卡与开发凭据 | [compose](<D:/AgentPrograms/safetrace/ops/docker-compose.yml>)：默认 loopback、secret 必填、生产 profile；已有方案弃用不等于代码可安全复用 |
| A17 | 启停脚本误认/误杀其他服务 | [down:12–22](<D:/AgentPrograms/safetrace/scripts/local/down.ps1#L12-L22>) 按端口强杀；要 PID+exe+启动记录校验，模型探测验证 model ID/维度 |
| A18 | 不同入口读取 env 不一致 | [package:26–42](<D:/AgentPrograms/safetrace/package.json#L26-L42>)：标准 serve/doctor 与 verify/demo 不同；统一配置加载并显示实际 profile/库/模型 |
| A19 | 模型 skip 误报 ready | [ensure:116–151](<D:/AgentPrograms/safetrace/scripts/ensure-models.mjs#L116-L151>)、[up](<D:/AgentPrograms/safetrace/scripts/local/up.ps1>)：缺模型仍 exit0且“全部就绪”，SkipModels仍可能下载；分清 skipped/missing/ready |
| A20 | 索引失败仍 exit0、批参数可不前进 | [index:237–238](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L237-L238>) / [310–337](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts#L310-L337>)：校验正整数、有 skipped 返回非零/partial、持久 manifest |
| A21 | SSE 缺终止/取消闭环 | [api:72–94](<D:/AgentPrograms/safetrace/web/src/api.ts#L72-L94>)：EOF无done可一直thinking，CRLF与残帧、handler异常；客户端abort不取消后端；补协议测试和AbortSignal |
| A22 | 状态机接口大于实际能力 | [native:26–33](<D:/AgentPrograms/safetrace/src/qa/src/orchestrator/backends/native.ts#L26-L33>) 每节点新空state，reducers未执行、无耐久resume；精简承诺或实现checkpoint，不把interrupted当完成 |
| A23 | 计量/限流未完整接线 | [gateway server:28–32](<D:/AgentPrograms/safetrace/src/gateway/src/server.ts#L28-L32>) 未注入SqliteUsageStore；max_tpm只解析、队列无界/无取消；费用未知就继续显示未知 |
| A24 | 工具、人工、自愈多为声明 | [roles](<D:/AgentPrograms/safetrace/src/qa/src/orchestrator/roles.ts>)；决策handler默认无tool/human，人工abstain不等于任务分派+审批+恢复；Langfuse尚未业务上报 |
| A25 | 契约/HTTP门禁不完全一致 | [OpenAPI](<D:/AgentPrograms/safetrace/contracts/openapi.yaml>) 的DecisionReply比schema宽，网关body无大小限制；校验器缺fixture可跳过且format未全部落实；加一致性与负例测试 |

容器化目前主要是基础设施，不是 gateway/QA/ingest/enrich 全业务部署。原题初赛不强制，别让 Docker 安装拖住主链；决赛若争取工程化高档位再安排可复现业务容器和监控告警。

## 6. 不清晰、互相矛盾的文档口径

- [README](<D:/AgentPrograms/safetrace/README.md>) 仍有 compose、旧甲乙丙分工、pi-agent-core 描述；当前是纯本地栈+native，职责以最新团队计划为准。
- [TASKS](<D:/AgentPrograms/safetrace/docs/TASKS.md>) 状态总览明显滞后：E-01/E-07 等已有代码，旧行仍待办；部分“砍单保留证据”还要求说明已验证 LangGraph，与删除未安装后端的事实冲突。
- [P10 验证文档](<D:/AgentPrograms/safetrace/docs/P10-LOCAL-VERIFY.md#L48>) 仍称 Qdrant 不可达；本轮集合 GET 已200，旧结论须标历史，不直接沿用。
- [本机演示说明](<D:/AgentPrograms/safetrace/docs/LOCAL-DEMO.md>) 是 fixture 模式，这个描述与当前网页代码吻合；不要用另一个真实库灌入脚本的成功覆盖这层限制。
- [本地模型配置](<D:/AgentPrograms/safetrace/config/models.local.yml>) 同维度即可切集合的文案不严谨：两个模型均1024维也可能语义空间不同，必须按模型版本重嵌入/重建；维度一致不够。
- 根目录存在未跟踪 Python 运行时目录。本轮未修改；提交前应确认用途并排除运行时/缓存，而不是未经确认删除。不要把它误当项目自研业务代码。

建议把“现状”“目标”“历史记录”分栏：主入口只写当前可执行命令；旧台账有实现但没证据的状态应写“已实现/待验收”，不要继续混用“完成/待办”。

## 7. 正式验收必须补的证据

1. **AI 专题数据集**：AI框架/推理服务、提示注入/越狱、投毒/模型泄露、Agent工具链/供应链样本；有正负例与明确筛选口径，支持无CVE记录。
2. **来源覆盖表**：类别、URL/feed、runner、轮询周期、last successful live、产出、失败/限流、是否独立发现/按号补查，planned单列。
3. **逐维富化评测**：关联正确性而非“返回非空”，fixture排除，失败算入业务覆盖；CVSS按源核对，论文按相关性盲审，资产只用授权/明确合成数据。
4. **问答盲测**：冻结开发集与独立评测集；基础、AI新样本、跨文档、多CVE比较、多轮、时间过滤、无答案、冲突和攻击链；记录事实正确、引用支撑、拒答、响应p50/p95。
5. **真实链路证明**：新的合法AI安全样本，从采集→DQ→富化→索引→网页详情→问答引用，记录同一trace、ID、源hash和数据模式；关闭源/模型/Qdrant后演示真实失败及恢复。
6. **可恢复性**：重启/长停机、半开探针失败再恢复、订阅者失败、重新索引撤回、备份恢复；72h为内部加分证据，并分别统计进程活着、抓取成功、知识更新成功。
7. **交付**：最终报告Word/PDF、PPT PDF、演示视频、限制清单、匿名版本与提交回执；不能以旧内部文档替代。

## 8. 后续执行入口

见 [后续计划与验收标准](<D:/AgentPrograms/safetrace/docs/NEXT-PLAN-2026-10-03.md>)。本报告是审查基线，不自动覆盖现有任务台账或批准新业务/云端/资产接入。修复后应逐项更新证据和状态。

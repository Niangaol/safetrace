# SafeTrace 首批整改记录（2026-10-04）

> 执行依据：[10/3审查报告](<D:/AgentPrograms/safetrace/docs/PROJECT-AUDIT-2026-10-03.md>)、[后续计划](<D:/AgentPrograms/safetrace/docs/NEXT-PLAN-2026-10-03.md>)。
> 本批完成 N01–N04 代码与回归；另修复 N05 中前端构建的临时文件问题。**没有宣称整个项目已修好，也没有重建/删除正式向量或补跑富化。**

## 1. 修复内容

### N01 索引准入、更新、重试与撤销
- [索引规划器](<D:/AgentPrograms/safetrace/src/qa/src/intel-index-plan.ts>)：SQLite seq排序，取最新情报/最新DQ，拒绝未知、未判定、畸形、review/quarantine；判定必须通过causation绑定当前版本，不再用历史任意pass集合。
- 同时兼容主pipeline的intel→DQ和[页面采集](<D:/AgentPrograms/safetrace/src/ingest/src/page-ingest.ts>)的DQ→intel（同trace、一次性绑定）。复用旧DQ发布新版会被拒绝；有真实page producer回归。
- --retry 与正常路径共用准入；重试隔离对象时先撤销已存在的危险点，然后非零退出，不会重新写入。
- 相同ID按文本、内容版本hash、日期、质量、来源元数据、模型身份比较，变化才更新，不再“已有ID永远跳过”；模型/版本不一致拒绝混用，要求另建集合。
- [同步器](<D:/AgentPrograms/safetrace/src/qa/src/intel-index-sync.ts>)：完整滚动读取、鉴权/超时、HTTP与completed检查；不能把401/503当空集合或部分读取当完整计划；参数必须为合法整数，失败非零退出。
- 只在选中对象成功写入规范ID之后清理它的旧非规范ID，避免limit/retry把未选中的唯一副本删掉。
- 新增write owner token和服务器端条件清理，避免旧失败runner删掉另一runner的新结果；PUT前embedding/门禁/lineage失败不删除已有有效点。
- apply采用[单写lease](<D:/AgentPrograms/safetrace/scripts/intel-index-lock.ts>)，覆盖读取、规划、写入和清理。同工作区第二writer被拒；异常退出遗留lease不得根据PID自动抢占，需先核查审计和旧进程。
- 审计存到独立SQLite，记录计划、upsert_attempt和结果；不往正式业务库写lineage。进程被强杀时catch不会执行，需要按残留lease/审计重新对账，**不承诺崩溃瞬间自动回滚**。

[CLI](<D:/AgentPrograms/safetrace/scripts/index-intel-to-qdrant.ts>) 默认变为只读dry-run；--apply才写入与撤销。保留--retry但不得绕准入。只允许字面量loopback模型/向量端点，不意外出云，不清熔断实例来绕恢复。

注意：这仍是派生情报摘要索引，不是原始来源/富化工件重建。补了日期/质量、具体来源URL和内容版本标记，但明确trust=untrusted、hash是派生文本hash，不通过默认trusted绕过Q4门禁。正文富化接入归下一阶段。

### N02 归并与DQ红线
- [归并](<D:/AgentPrograms/safetrace/src/ingest/src/dedupe.ts>)保留逐源内部DQ证据；REJECTED/RESERVED/DISPUTED不因合并顺序消失，POC链接不能借另一个来源的hash洗白。
- [DQ](<D:/AgentPrograms/safetrace/src/ingest/src/dq1.ts>)对未知/畸形metadata fail-closed，对有POC链接但非64hex哈希拦截；这些只说明元数据合法，**不是PoC内容或可用性已验证**。
- PUBLISHED与ANALYZED/MODIFIED等正常机构工作流不误判为撤回冲突。gate_version升到1.0.1，便于区分旧判定；未改变冻结schema/枚举。
- [发布投影](<D:/AgentPrograms/safetrace/src/ingest/src/intel-payload.ts>)在DQ完成后才去掉内部metadata；[pipeline](<D:/AgentPrograms/safetrace/src/ingest/src/pipeline.ts>)不把契约外字段发布到intel.items，原始载荷和内部判定输入留审计。

### N03 熔断恢复
[熔断器](<D:/AgentPrograms/safetrace/src/gateway/src/circuit.ts>)半开失败重新进入OPEN并刷新冷却，冷却后再次允许一个探针；成功关闭。使用null而非0哨兵，注入时钟为0也正常。多次失败、边界和成功恢复回归通过。

### N04 测试出网
- MG1的fetchImpl实际传入唯一provider请求点，实例mock不污染另一实例。
- 云降级默认测试全部mock；单独live用例只在显式test:live运行，未执行该命令。
- [单测网络guard](<D:/AgentPrograms/safetrace/scripts/test-network-guard.mjs>)默认用于npm test及npm run smoke，阻断非loopback的fetch、重定向及Node网络入口。业务catch/fallback吞掉异常仍使测试进程非零。
- 全量初跑还抓到F4评分测试意外查询FIRST EPSS；[评分单测](<D:/AgentPrograms/safetrace/src/enrich/test/f4.test.ts>)已显式offline。不是关掉guard换绿。
- 这是Node测试安全网，不是OS网络沙箱；无法保证恶意代码/native外部程序绝不绕过。安装依赖需要联网时不冒充离线；真实模型用例须另外授权。

### N05 前端构建（部分）
共享Windows Temp中esbuild删除文件持续Access denied；将TEMP/TMP/TMPDIR改到每次构建独有的项目依赖缓存目录后通过。[构建入口](<D:/AgentPrograms/safetrace/web/scripts/build.mjs>)自动设置并清理自己创建的目录，跨平台spawn使用同一Node，失败透传；不改系统ACL或node_modules源码。不把这个结果冒充前端页面业务验收或统一配置已完成。

## 2. 验证证据

- npm run check：typecheck、**437/437单测，0失败/0跳过**、8schema/12fixture校验、前端依赖安装与构建通过。
- npm run smoke：在网络guard下通过，仍明确是离线fixture核心链路。
- 前端smoke:data-source：5/5通过。
- git diff --check：通过。
- 20项索引专项：含最新判定、retry、更新、limit、模型混用、partial结果、实际page producer、互斥lease、PUT前失败保持旧点、跨runner条件清理和真实适配器completed校验。不是只测计划数组。
- 归并整链：真实adapter+内存HTTP mock+临时payload+MemoryEventStore；每个来源红线均不发布intel.items。
- 独立只读review发现的6项索引边界均已补代码与回归；没有依赖“停止采集”的注释来代替单写互斥/条件删除。

完整日志：[四门禁](<D:/AgentPrograms/safetrace/.tmp/remediation-check.log>)、[冒烟](<D:/AgentPrograms/safetrace/.tmp/remediation-smoke.log>)、[前端smoke](<D:/AgentPrograms/safetrace/.tmp/remediation-web-smoke.log>)。这些日志在忽略目录，正式交付前应归档到证据包。

## 3. 正式库只读dry-run

没有加载本地环境文件或调用embedding。以默认本地bge-m3配置，只读取正式SQLite和本地Qdrant滚动接口：
- 最新放行5237、拒绝6、现有向量5237。
- 当前旧payload缺新日期/质量/版本来源标记，预计需要更新5237；预计撤销0。
- **实际written=0、revoked=0**。本批只修程序，正式旧集合未改变。

不能把“预计更新5237”说成灌库已完成。后续先做N06一致性备份与恢复验证，再决定新集合重建/切换方式；优先N07原始来源和富化工件投影，不急着全库重嵌入派生摘要。

## 4. 运维约束与剩余工作

- apply前验证备份，使用独立情报集合，停止业务生产者/其他维护写入。lease只保护同工作区CLI；条件清理防止误删别的write owner，不能替代外部操作者的维护协调。
- 后续DQ撤回仍需再次同步/自动调度才会撤向量；本批没有实现实时事件订阅撤回。
- 历史已丢失的来源状态无法由新代码凭空恢复；历史数据需按保存原文重新判定/对账，不默认全部旧pass安全。
- 派生摘要仍untrusted，富化工件仍未进入正式QA；网页仍fixture，多轮/时间过滤/弱召回/总线自动重试等剩余项按计划继续。
- 统一serve/doctor配置、费用持久化、SSE、资产/第三维、AI主题采集、正式评测和交付仍未完成。
- 没有读取或输出密钥，没有运行真实云模型/真实资产/PoC，也没有commit/push。未跟踪Python运行时未触碰。

**下一包：N06备份恢复验证 → N07来源/富化证据投影 → N08逐维状态与失败补跑。**

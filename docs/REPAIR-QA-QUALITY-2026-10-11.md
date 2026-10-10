# SafeTrace 闭环修复与问答质量验收（2026-10-11）

## 结论摘要

本轮修复了已复现的人工决单一致性、检查点恢复安全、自愈运行错误及问答证据身份问题；通过四门禁与离线冒烟。**并不宣称所有生产能力、比赛准确率或任意副作用 exactly-once 均已完成**。

- 四门禁：npm run check exit 0；全量 **827/827，0 失败/0 跳过**；契约校验、Web 构建/前端 smoke 通过。
- 独立集成审查：自由文本假安全、修复否定放行、多 CVE 借第三个漏洞规则均已复现后修复，最终 focused 15/15。
- 模型服务保持停机；未调用付费模型，未灌向量或维护正式数据库。问答探针只创建短期 loopback HTTP 服务并在 finally 关闭。

## 闭环修复证据

| 范围 | 本轮实现与测试 | 仍须保留的边界 |
|---|---|---|
| A-02 工单 | 同库工单与 DecisionReply 原子提交（SQLite BEGIN IMMEDIATE；Memory 先复制后无 await 原子段）；并发决单唯一赢家；请求 SHA 核对身份；重发返回持久 pending/resolved 回执；入队或事件插入失败全回滚。真实双 OS 进程、跨实例、触发器失败、重启回归均通过。 | 旧工单没有原请求 SHA 时拒绝自动认领新请求身份；规则正常已决通道尚非完整请求级幂等；本地消费失败/进程崩溃后需显式重放持久事件，不承诺消费者 exactly-once。 |
| A-01 检查点 | invoke/resume 前持久 token 租约；图结构/函数/reducer 与显式版本指纹；逐步 running/failed/suspended/completed 状态与业务快照；恢复值绑定记录节点；失败保存前序成功进度；保留键与 reducers 强负例。40项专项通过。 | 不自动过期的崩溃租约需人工审计；闭包/外部依赖变更须 bump spec.version；失败节点已发生的外部副作用仍需业务幂等；状态应为 JSON 兼容，不把任意 JS 对象当跨进程状态。 |
| A-06 自愈 | tick single-flight；周期拒绝显式记录；stop/start 正确退订；whenIdle 等待在途拍后关库；达到重投上限后不再重投。25项专项通过。 | 重试预算仍为 Agent 内存状态，重启会重置；独立 EventBus 没有其他进程业务消费者，不自动接收其他进程 fallback，也不会因此假报恢复。跨进程消费者装配/72h证据仍未验收。 |
| Q4 身份门禁 | 完整 CVE 标识符逐个覆盖，不能借编号前缀；已登记产品别名精确归一；具体版本必须有与请求绑定的结构化判定；多个 CVE 的单汇总版本结论拒答；不推断自由文本安全状态。 | 多 CVE+具体版本的逐漏洞结构化规则结果接口仍待扩展；未知规则保守拒答是刻意边界。 |
| P-03/P-05 live | 已通过原文/hash/DQ/逐记录身份门禁的结构化版本和 v3.1分值元数据保留到投影；派生版本证据可检索；同 CVE 多源分歧进答案（不自行仲裁）；撤销DQ后不再放行。新增 live HTTP 回归通过。 | 不读无原文证明的历史 sidecar 值；CNA排除项/changes与NVD AND/negate等未支持语义判unknown；并未完成所有来源版本规则解析。 |
| 时效与性能 | 多意图最严时效阈值；Q4所有调用方共用默认；Qdrant日期条件用datetime_range；空索引也校验时间参数。BM25索引由Map消除二次方插入；已验证view fingerprint复用baseline缓存。 | BM25相对分不等于绝对相关性或校准概率；产品身份门禁不是完整语义充分性判断；原文bytes核验仍保留；大Web bundle告警仍在。 |

源码与强负例：[工单原子性](<../src/shared/test/human-ticket-atomic.test.ts>)、[HTTP队列](<../src/qa/test/decision-ticket-http.test.ts>)、[检查点](<../src/qa/test/checkpoint-safety.test.ts>)、[自愈](<../src/qa/test/selfheal-daemon.test.ts>)、[问答安全](<../src/qa/test/qa-quality-safety.test.ts>)、[live版本/冲突](<../src/qa/test/live-version-conflict-http.test.ts>)。

## 问答质量：最终安全版本

[逐题报告与完整口径](<evidence/qa-quality/README.md>)、[修复前](<evidence/qa-quality/before.json>)、[最终安全同接线](<evidence/qa-quality/after-safe-func.json>)、[最终安全natural接线](<evidence/qa-quality/after-safe-wired.json>)。

同一冻结24题、17项期望事实，期望SHA未变，不从系统答案反推gold。

| 模式 | 全部机械检查通过 | 指定事实/来源覆盖 | 过拒 / 漏拒 |
|---|---:|---:|---:|
| 修复前直接函数链 | 18/24 | 16/17 | 0 / 4 |
| 最终安全版本，同caller接线 | 21/24 | 14/17 | 2 / 0 |
| 最终安全版本，修正多CVE natural caller | 22/24 | 15/17 | 2 / 0 |

两个版本题的直接probe没有传入绑定的结构化版本规则，因此按安全门禁保守拒答；这是已测出的可用性限制，不把它改标成正确来抬高分数。同caller还缺一个多CVE自然评分标签；新caller已修复。

此前曾测得23/24与24/24的中间版本含不安全的自由文本版本推断，**已弃用，不能沿用为当前成绩**。所有中间原始结果保留以说明安全与可用性权衡。

这里的checks是小型合成契约检查；来源ID/URL支撑是可复核代理，不是自动语义蕴涵或人工盲测。**不把22/24称比赛准确率；不计算真实论文召回率**。

## 真实已保存语料：只读 HTTP 保真与耗时

[实测报告](<evidence/qa-quality/real-http.json>) / [逐题答案](<evidence/qa-quality/real-http.md>)，命令：

~~~bash
node --import ./scripts/test-network-guard.mjs --import tsx scripts/qa-live-quality-probe.ts
~~~

在9653个已验证来源/工件chunk的snapshot上，选择5条原文已证明评分，另测两CVE比较、未知CVE、已知+未知组合、输入注入：**9/9保真与拒答检查通过，模型调用0、正式库bytes SHA前后相同**。

期望评分来自现有已核验来源回执，因此只是“输出是否忠实于来源”的保真验证，**不是独立人工gold的事实准确率**。投影3278项拒绝记录与来源绑定缺口见 [compact snapshot元数据](<evidence/qa-quality/readonly-snapshot.metadata.json>)；不能把这些缺口藏进通过率。

优化前：[报告](<evidence/qa-quality/real-http.pre-optimization.json>)，P50约6422ms、P95约10907ms。
优化后：[报告](<evidence/qa-quality/real-http.json>)，P50约767ms、P95约6899ms；第一条请求约6899ms，后续约731–957ms。

这轮使用预加载只读view；耗时包含实际HTTP、索引、模板与baseline，但不包含初始corpus加载，也不包含模型/Qdrant推理与正式默认路由每次原文bytes核验的全部成本。**不是冷启动或生产SLA**。报告保留首条慢请求，不只报热路径。

## 下一阶段仍待验证

- 真实人工标注/盲测、论文相关性池、语义召回质量与真实模型对照（需授权，不自动付费）。
- 多CVE逐版本规则输出、完整来源版本语义、绝对检索充分性分数契约。
- 跨进程业务消费者和持久自愈退避预算、72h实跑证据、旧工单/旧checkpoint人工迁移审计。
- 三线sign-off由真实成员确认；本轮未追加公共契约。P-05已有source_conflicts登记版本仍为v1.2.2。

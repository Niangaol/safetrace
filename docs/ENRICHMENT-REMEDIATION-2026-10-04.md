# 富化重点整改与当前验收（2026-10-04）

> 用户明确富化是本人负责的模块，当前优先把这一条链做好。基线为 main b860edd 的工作树；未 commit/push。此文接续[首批安全整改](<D:/AgentPrograms/safetrace/docs/REMEDIATION-2026-10-04.md>)，不是宣称整个项目完成。

## 当前工程目标收尾结果

本轮最终 **543/543**，四门禁、冒烟、前端来源/SSE与参考评测通过。下文部分488项/0旧工件是上一检查点的历史记录，不是当前统计。

- 已在正式SQLite追加复核 **10条NIST主CVE v3.1评分**，没有删除旧历史。来源限定为该条情报已验证的原文refs；未验证文件不能借其它proof背书，已有已验证论文/EPSS保留并原子重绑回执。
- 当前知识投影为 **5257来源块 + 10 CVSS工件**；剩余1113条已有旧记录缺证明，仍按unknown，不直接算成功。CVE-2025-21042的9.8分已在详情/证据/引用回答中实测可见。
- 本次追加事件10、lineage20、逐维状态10，公开契约没有改；网络/模型/向量写入均为0。
- 发布前原备份重新验读；发布后新建[恢复检查点](<D:/AgentPrograms/safetrace/.tmp/verified-backups/safetrace-CxQRzC/manifest.json>)，9个表、events17427、lineage11661；向量仍5237，完整内容hash与原备份一致。
- 新增[修复建议模块](<D:/AgentPrograms/safetrace/src/enrich/src/f5-remediation.ts>)，USN同公告CVE与固定包版本、KEV通用行动指引分别提取；51项边界测试通过。
- 通过[独立只读来源工件](<D:/AgentPrograms/safetrace/src/qa/src/remediation-reader.ts>)接入详情证据与修复问答，不强行往冻结EnrichmentResult写新字段。来源声明不是已验证修复；没有安装、扫描、资产匹配或PoC执行。
- 修复建议现在是有效的**只读派生能力**，未伪称已纳入统一耐久富化队列/公用结果契约。参考标签未人工复核、真实联网论文准确率、长期演示服务切换及其它赛题能力另列后续，不属于本轮已验收结果。

最终证据：[门禁](<D:/AgentPrograms/safetrace/.tmp/goal-final-check.log>)、[10条写入](<D:/AgentPrograms/safetrace/.tmp/captured-first-apply.log>)、[实际投影](<D:/AgentPrograms/safetrace/.tmp/captured-first-projection.log>)、[实际引用回答](<D:/AgentPrograms/safetrace/.tmp/captured-score-answer.log>)、[修复建议只读预览](<D:/AgentPrograms/safetrace/.tmp/remediation-main-preview.log>)。

## 1. 已落实的修复

### 每个维度有自己的状态，而不是“有记录就完成”
[sidecar 状态表](<D:/AgentPrograms/safetrace/src/shared/src/enrichment-state.ts>)单独记录论文/CVSS/辅助EPSS的 live、degraded、empty、failed、unknown，以及输入/结果hash、事件回执、来源证据、下次重试时间。
- fixture、缺发表元数据、零相关、不合法EPSS不计真实成功。
- 未知/失败/降级按退避续跑，空命中按24h退避；live也在24h刷新，不永久停旧数据。
- 文件路径不够：评分依赖比较当前原文内容hash、显式评分来源及KEV集合；同路径内容更新、撤回能触发重算。
- 首次获取时间和内部DQ字段不作为事实变更；算法版本进入事实hash。
- 最近好结果 last-good 独立保留。最新尝试失败/为空不毁掉旧值，但旧值不冒充新输入已验证成功。
- 多维状态在同一SQLite事务提交；缺失/错绑发布回执会进入默认pending队列，用缓存修复，不只在手工直接调用时才修复。
- S2事件与sidecar仍是不同连接，非跨连接单事务；发生中断时消费端先拒绝不匹配结果，重跑修回执。不是完全DevOps/outbox已验收。

### 论文来源与关联分别检查
[论文检索](<D:/AgentPrograms/safetrace/src/enrich/src/f1-papers.ts>)保留有界原始Atom、hash、发表日期、标题/摘要元数据，校验协议与arXiv身份；HTTP200错误HTML不能当正常空结果缓存。成功缓存6h，遵守限流与有界重试。
- 先召回候选，再按明确产品/CVE/主题筛选；OpenSSL memory corruption 不会因为心理学论文有 memory/corruption 就关联。
- 已知产品是必需锚点；Log4j等组件别名显式映射，不靠任意子串。
- Prompt injection、adversarial suffix、training-data extraction等主题不只凭 language/model 通用词互相关联。
- 模型建议仅旁路，不自动改写规则结果；不运行攻击/PoC代码。
- **来源真实不等于论文科学结论或关联准确率已由专家验证。** 相关分仍是启发式，待独立人工复核。

### 评分不跨CVE、也不偷换评分者
[评分模块](<D:/AgentPrograms/safetrace/src/enrich/src/f4-cvss.ts>)固定评分对应主CVE；多CVE注入来源缺身份会拒绝，不拿另一个CVE的CVSS配主CVE的EPSS。
- KEV也是主CVE判断，次要CVE/次要来源不能抬高主漏洞评级。
- NVD容器里的CNA Secondary不冒充NIST Primary；交换顺序结果稳定。
- REJECTED/RESERVED/DISPUTED原文评分不再复用。
- EPSS拒绝null/空串/布尔/越界/重复行，只有FIRST原响应receipt与近期有效as-of日期才标live。离线或来源自带但未证明的值不能凭“没有fallback”升级。
- EPSS即使CVSS缺失也可独立取得和保存；不编一个CVSS向量来容纳EPSS。现冻结公开契约主要仍是paper/CVSS，辅助状态不机械算第三种富化。
- 目前主算法仍是CVSS v3.1；其他版本/格式不能猜成3.1。后续需按真实源样本扩展、确认契约方案。

## 2. 富化已经有检索/引用接线，不是两套独立fixture

[原文与工件投影](<D:/AgentPrograms/safetrace/src/qa/src/knowledge-projection.ts>)、[逐维状态适配](<D:/AgentPrograms/safetrace/src/qa/src/knowledge-state-adapter.ts>)、[只读读取器](<D:/AgentPrograms/safetrace/src/qa/src/knowledge-reader.ts>)核对最新DQ、因果绑定、当前事实hash、result/event/lineage以及原始源记录。
- 来源按每条原记录抽取，保留原文hash，不用合并摘要冒充逐源原文。
- 支持NVD/CVE.org/OSV/KEV/Ubuntu USN及受控页面；不支持的格式拒绝，不回退伪证据。
- 论文工件来源回到原始Atom；评分再核CVE、source role、vector和baseScore。派生文本hash与源/artifact hash分开。
- EPSS默认不混进CVSS知识文本；未证明、降级、旧版本、review/quarantine不进回答。
- 临时真实SQLite+真实adapter+mock传输的整链测试证明：只在富化工件里的论文标题被检索并引用；最新隔离后不可再召回。它不是联网准确率测试。

[采集入口](<D:/AgentPrograms/safetrace/scripts/ingest-once.ts>)已注入逐维store、选择待修维度并使用知识投影；向量发布使用新快照集合，不在旧集合盲目append留下撤回块，需手工验收切换。原摘要索引仍保留其派生/未信任标签。

## 3. 正式库只读API和前端

新增[只读API](<D:/AgentPrograms/safetrace/scripts/live-intel-server.ts>)：健康、指标、列表/详情、证据与SSE问答，兼容当前前端接口。每次以当前库/原文代际校验，不静默回fixture。缓存同时检查DB/状态和原文内容hash，源同路径修改也会失效。



启动命令（需要空闲端口；未替换用户现有服务）：

```bash
npm run serve:live
```

- 仅监听loopback；只读，不自动采集/补跑，不调用模型或云端；当前BM25与规则模板，不能宣传语义多跳能力已完成。
- 历史有记录但缺证明显示unknown，CVSS值不偷偷沿用。论文问答仅检索paper工件，没有时拒答。
- 前端根据后端data_mode显示正式只读/fixture/未核验模式；页面级文案也同步。
- SSE补EOF无done、CRLF、UTF-8拆字、残帧和handler错误，异常不再吞掉后一直thinking。
- 未在浏览器做本轮视觉验收；本轮API验证均用短生命周期随机端口，已关闭，不启动另一个长期演示服务。

## 4. 实际数据与验证

### 备份已完成，不只是复制文件
[备份工具](<D:/AgentPrograms/safetrace/scripts/backup-intel.ts>)在线SQLite备份含WAL并验证独立恢复副本；完整导出并逐点重验5237个1024维向量，复制6个原始payload。
- 实际备份目录：[已验证备份清单](<D:/AgentPrograms/safetrace/.tmp/verified-backups/safetrace-h6xjE6/manifest.json>)
- 向量确实恢复到单独新建临时集合，逐点比对通过，临时集合已删除；原正式集合没有覆盖。
- SQL快照：events=17417、lineage=11641、7个业务表；missing_raw_refs=0。
- --apply维护入口要求该数据库的已验证备份与单写lease。不提供直接覆写生产的restore命令。

### 正式库只读实测
- 当前放行情报5237，原文证据块5257，历史富化记录1123。
- **当前可证明的旧富化工件=0**：不是认定1123条都错，而是旧记录缺逐维证明/事件绑定，不能据completed冒充已验证成功。
- 实际API列表5237；论文问题因为没有已验证工件而拒答；模型调用0、业务数据库逻辑hash不变。
- 初次实际探针超时后，修了重复全库proof扫描；后续冷健康读取约2.8s（单次样本），不拿它当问答p95或比赛SLA。

### 门禁
当前 npm run check：**488/488，0失败/0跳过**；typecheck、8schema/12fixture、前端构建通过。冒烟通过；前端来源/SSE 8/8。完整日志：[门禁](<D:/AgentPrograms/safetrace/.tmp/enrichment-final-check.log>)、[冒烟](<D:/AgentPrograms/safetrace/.tmp/enrichment-final-smoke.log>)、[前端](<D:/AgentPrograms/safetrace/.tmp/enrichment-final-web-smoke.log>)、[正式库API只读核对](<D:/AgentPrograms/safetrace/.tmp/live-api-readonly-check.log>)。

## 5. 独立评测与剩余工作

[评测说明](<D:/AgentPrograms/safetrace/docs/ENRICHMENT-EVALUATION.md>)和[参考集](<D:/AgentPrograms/safetrace/fixtures/enrich/evaluation.reference.v1.json>)保存3篇实际核对的官方元数据；标签为agent提议、待人工复核、非盲测。
- 低层候选ranking：returned precision 3/12；实际发布筛选：3/3、recall3/3、exact4/4、负例0/1；固定P@5两者都3/20。
- 这些小样本只说明已知负例拦住，不代表生产准确率达70/85/95%，没有调用模型或正式写库。

下一步优先：
1. 已保存原文能核对的CVSS先做小批复核/发布，仍保留未验证旧记录，不先全库网络补跑。
2. 扩展论文参考负例并由人确认，构造真正未见的评测集；真实检索限流/空命中单独验。
3. 在前两维稳定后补有来源的修复建议/版本影响维度；资产必须合成标注或授权，PoC不得默认执行。
4. 主界面真实服务切换、语义检索与更完整的多轮/自愈/性能，另列验收，不把只读BM25模板当最终能力。

上一只读检查点未写正式库。最终收尾已按恢复前置、当前DQ与来源proof追加10条保存原文CVSS复核，明细见文首；没有联网论文补跑、付费模型、正式向量写入或真实资产/PoC操作。

# 富化质量评测骨架（v1）

富化由用户负责，这里不把“有输出”“completed”或测试绿当质量达标。评测现在分别报告低层候选排序和实际实体/主题关联发布策略；下面保留首次候选基线，不能将它误读为当前生产发布策略。

## 运行与安全边界

仓库根执行：


```bash
node --import ./scripts/test-network-guard.mjs --import tsx scripts/enrich-evaluate.ts
node --import ./scripts/test-network-guard.mjs --import tsx --test src/enrich/test/evaluation.test.ts
```

CLI 只输出 JSON 到 stdout，可指定 `--reference path/to/reference.json`；不提供生产写入、在线采集或模型选项。

[CLI](<D:/AgentPrograms/safetrace/scripts/enrich-evaluate.ts>) 被 import 时不执行 main、不安装 guard、不改环境、不写文件。显式 main 或 [runEnrichmentEvaluation](<D:/AgentPrograms/safetrace/src/enrich/src/evaluation.ts>) 才执行；两者都会安装仓库现有 [网络 guard](<D:/AgentPrograms/safetrace/scripts/test-network-guard.mjs>)，评测期间 global fetch 一律拒绝（含 localhost），EPSS 只用内存 mock。原始评分样本及测试报告写入 mkdtemp 临时目录并 finally 清理，不读正式库，不调用 LLM provider/付费模型，不读取环境凭据文件。

为了检验 EPSS 的输入解析，会临时将 OFFLINE_FIXTURES 设为 false，**同时所有查分调用均注入 mock**；结束恢复环境和 fetch。必须在独立进程运行，不与其他生产逻辑并发；同模块并发评测会拒绝。网络 guard 是误操作防线而非针对恶意 native/subprocess 的安全沙箱。报告 model_calls/live_requests/production_writes=0 是本入口限定调用路径的事实，不是对任意注入代码的审计证明。API metadata 只作文本数据，不作为指令执行。

## 输入、接口与标签

[参考集](<D:/AgentPrograms/safetrace/fixtures/enrich/evaluation.reference.v1.json>) 保存三篇官方页面的 ID、标题、作者、首发日期、摘要、来源 URL、抓取日期（2026-10-04）。已经实际 web_fetch 核对：

- [2307.15043：Universal and Transferable Adversarial Attacks on Aligned Language Models](https://arxiv.org/abs/2307.15043)
- [2302.12173：Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/abs/2302.12173)
- [2012.07805：Extracting Training Data from Large Language Models](https://arxiv.org/abs/2012.07805)

标题/摘要中的 HTML 数字实体已解码；较长摘要改为注明来源的简短改写，避免将大段论文文字直接收入仓库，原始官方URL保留。未运行论文中的攻击代码。论文机制相关性的标签由 agent 提议，**agent-proposed / 待人工复核 / 非盲测**。官方元数据真实不等于关联标签已获专家认可。这是独立 holdout **提议**（未复用既有黄金 Log4Shell），并非统计意义上的隐藏盲测；输入和标签均公开。

[评测模块](<D:/AgentPrograms/safetrace/src/enrich/src/evaluation.ts>) 导出：

- loadEvaluationReference(path?)：加载 JSON，校验版本、标签状态、重复 ID、标签引用及官方 URL/抓取日必填。不会在线核对用户自带文件的声明。
- runEnrichmentEvaluation(reference?)：调用真实 F1 parseArxivAtom、F4 parseCvssV31Vector/loadScoreSourcesFromRawRefs/lookupEpss，返回报告。
- evaluatePaperPredictions(cases, predictions)：可独立评分外部预测，值为有序 paper_id[]；null=abstain，缺键=missing，[]=显式无关联。
- summarizeChecks(cases)、ratio(numerator, denominator)、referenceAtom(papers)。

论文回放不调用 searchPapers 的黄金 fixture；三篇参考 metadata 生成 Atom 候选，分别运行 parseArxivAtom 候选排序与当前 anchoredPapers 实体/主题发布筛选。仅日粒度的参考日期编码为 00:00:00Z 是回放协议编码，不代表官方给出了具体发表时刻。参考候选库很小，不能代表开放世界检索召回率；看过这些案例后完善的策略也不能再把这四题称为盲测。上层模型复核和真正联网检索准确率未测。

## 指标与分母

所有比率均输出 numerator、denominator、value；分母 0 的 value=null，不伪装成 100%。

- precision@5 = 每个 case 前 5 槽位里不同正确 paper_id 数 / 5；聚合分母 = 5 × 全部 case（含负例、missing、abstain）。不足 5 项仍用 5，不给“只返回一项”满分。
- recall@5 = 命中的不同相关 ID 数 / 全部正标签 ID 数；无正标签 case 的 recall=null。
- returned_precision = 正确 ID 数 / 实际返回槽位总数，帮助区分固定槽位损失与误关联。
- exact_case_accuracy：无误报、无漏报、无重复才 correct；显式 [] 可匹配负例，但 missing/abstain 永远不 correct，计入全分母。
- negative_false_positive_rate 与 negative_correct 单独报告负例；前者单看为 0 不说明 abstain 正确，必须结合后者和 missing/abstain。
- 每个 case 输出 expected/actual、误报/漏报/重复、状态及逐 case badcases。

真实参考 metadata 的 paper_association **独立于** synthetic_regressions，不相加为“整体准确率”。

合成回归使用明确标注的虚构 CVE-2099-10001/10002 与 GHSA-synthetic，不声称真实漏洞事实：

- CVSS calculation：5 个有效向量（scope/PR、零 impact、Roundup 等）固定预期分；invalid_vector_rejection：4 个畸形/错误版本向量。依据 [FIRST CVSS v3.1 规范](https://www.first.org/cvss/v3.1/specification-document) 所定义算法，预期值不调用被测函数生成。这是有限回归，不是全向量穷举。
- CVSS identity：5 个多条 NVD、无身份、错身份、OSV alias、CNA case；同时检查 CVE ID、评分来源角色和向量，不允许只因分数相同判正确。
- EPSS invalid_value_rejection：9 个无效/错 CVE/重复行样本；degradation_recognition：2 个离线/传输失败；另 1 个合法 mock 正值样本，共 12。检查无效值返回 null 且标 fixture，拒绝异常值并非 missing 正确冒充。
- EPSS mock 即使产生 receipt 也不是 live，fixture 永远不是 live。报告 live_cases=0、fixture_is_live=false；不使用 Log4Shell 常量作为 holdout 正值。

## 初次 focused 结果与诚实解释

2026-10-04，focused 测试 7/7 与全仓 TypeScript 检查通过。

| 项目 | 分子/分母 |
| --- | --- |
| 论文 precision@5 | 3/20（15%） |
| 论文 recall@5 | 3/3（100%） |
| returned precision | 3/12（25%） |
| exact case accuracy | 0/4 |
| 负例误报 | 1/1 |
| CVSS 有效向量计算 | 5/5 |
| CVSS 非法向量拒绝 | 4/4 |
| CVSS 身份 | 5/5 |
| EPSS 无效值拒绝 | 9/9 |
| EPSS 降级识别 | 2/2 |
| EPSS 综合合成回归 | 12/12 |

初次排名候选的 4 个 badcase：三个正例均返回额外不相关候选，容器内核提权负例仍返回三篇 AI 安全论文。这是低层排序的基线，不是所有候选都会被当前富化编排发布。现在发布策略增加了产品/CVE与特定主题筛选，并保留原始 Atom 和发表元数据证明。

### 当前发布策略回放（2026-10-04）

| 指标 | 低层候选排序 | 发布筛选 |
|---|---:|---:|
| 固定 5 槽位 precision@5 | 3/20 | 3/20 |
| returned precision | 3/12 | 3/3 |
| recall@5 | 3/3 | 3/3 |
| exact case accuracy | 0/4 | 4/4 |
| 负例误报 | 1/1 | 0/1 |

固定 P@5 的低值不等于仍有误关联：每个正例只选一篇、负例选零篇，分母仍为20。**3篇论文、4个参考问题、agent提议标签，不能据此声称70/85/95%真实准确率。** 必须先人工复核标签，另建隐藏且分布更广的评测集，并实测真实检索、限流、无论文、同产品不同机制等场景。所有回放 live_cases=0，模型与正式库写入均为0。

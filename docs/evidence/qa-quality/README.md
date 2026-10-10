# 问答质量评测交接（合成契约探针，不是比赛准确率）

> **最终安全代码的当前成绩：同 caller 21/24；多 CVE natural 接线版 22/24。** 先前23/24、24/24仅为已弃用的自由文本版本兜底中间结果，不再代表当前代码。冻结期望未修改；未为分数放宽门禁。

## 固定基准与口径

- [独立期望](<../../../fixtures/qa-quality/reference.v1.json>)：24 题、12 个合成证据块、17 项期望事实。首次运行前手工设定，未从系统实际答案反推；SHA256：  `1e9f07cef10e032cb1ba4270ecc7bfa0c74a2cd60b79c4e083e1d63358febec2`。测试锁定该 SHA；不要为修复后的答案调整期望。
- 合成 CVE / 产品 / 论文均为测试数据，`qa.invalid` 非真实来源。证据中显式列出版本边界，因而版本题通过只能说明事实搬运未丢失，不代表执行了通用版本推理。
- 固定评测时钟为 2026-10-10T14:00:00Z。覆盖 concept、version 边界/未知、remediation/未知、multi-CVE、time/stale、paper、有冲突的 CVSS、输入/证据 injection、clarify/refusal。
- 评分：每题每项 check 等权，题内通过 check 比例为 score；汇总为所有题 score 算术平均。`fully_passing` 是全部机械检查通过的题数，不是现实世界准确率。
- fact coverage：独立正则在 actual answer 中命中，且非 abstained；先去除整段原问题以防回显作弊。包含证据全文也会命中，**不保证答案理解或结论正确**。
- citation support：期望事实指定的 source ID 必须出现在 citations，且 ID/URL 与本轮检索块绑定。是可核查的来源代理检查，不是自动语义蕴涵验证。
- q21/q22 的期望采用严格拒答契约：未知具体版本/具体修复版本应 abstain；实际给出有用但保守的“未知/无已核验版本”也可能被记为该契约不匹配，不自动证明发生幻觉。
- 论文题只检查合成标题/来源与缺资料拒答。没有人工标注真实论文相关性池，**不计算论文 recall / precision**。
- 延迟为单暖进程 Q1→检索→Q4→natural→评分，不含索引构建、HTTP、真实模型与 Qdrant；不是端到端 SLA。BM25 分数 top 归一为 1，不能当作校准相关性/概率。

## 实际执行链路

[runner](<../../../scripts/qa-quality-evaluate.ts>) 直接调用生产 Q1 / MemoryIndex BM25 / buildRetrievalRequest / Q4 / naturalConclusion；paper_related 使用生产 live 的 paper 过滤，abstained 时不追加自然结论。它**不调用 HTTP live server**，不接 live 的基线缺口、只读 guidance、资产 assessment、runtime model review/UI，所以这些接线不在本 probe 的验证范围。

已检查 [live server](<../../../scripts/live-intel-server.ts>)、[preview](<../../../scripts/knowledge-preview.ts>)、[natural](<../../../scripts/natural-answer.ts>)、[review](<../../../scripts/final-answer-review.ts>)、[knowledge reader](<../../../src/qa/src/knowledge-reader.ts>)、[baseline reader](<../../../src/qa/src/baseline-reader.ts>)、[remediation reader](<../../../src/qa/src/remediation-reader.ts>) 和 [现有黄金问答](<../../../fixtures/golden-qa.v0.json>)。旧黄金集以意图/CVE 字样为主，对版本/冲突事实不充分，且历史热点题依赖旧 fixture，故这里独立定义新事实。

模型复核器只是结构/引用片段/数字约束，不是独立事实评审；本次未启用模型复核。没有恢复/checkpoint/幂等安全指标。

## 修复前结果

[before.json](<before.json>) / [before.md](<before.md>) 保存逐题实际答案、期望、检索证据、计划、引用、评分/失败理由和延迟。首次结果：18/24 全检查通过；mean check score 0.9003；fact coverage 16/17；expected-source-backed facts 16/17；过度拒答 0，漏拒答 4；p50 0.1905ms、p95 2.6235ms。

六题失败：q08/q09 多 CVE 部分覆盖却放行；q18 无冲突显式披露；q21 未知 version 不拒答；q22 缺具体修复版本不拒答；q24 第二 CVE 的自然评分覆盖不全。代码检查另发现潜在跨 CVE 身份错配，但此 baseline 的两个错配禁用检查实际均通过，不能称为在 q24 复现了错配。生产缺陷已报告 Lead，由 Lead 修复；评测者不改生产代码。

## 修复后直接函数链（保持原 runner 接线）

[after-func.json](<after-func.json>) / [after-func.md](<after-func.md>)：19/24 全检查通过；mean check score 0.9003（并未提升）；fact coverage 14/17；有期待来源支持 14/17；过度拒答 2，漏拒答 1；p50 0.1620ms、p95 1.6481ms。期望 SHA 完全相同。

q08/q09/q21 已按严格拒答契约关闭；但 q03/q04 原文有明确版本事实却没有传 version_impact，被新门禁拒答（原 runner 不提供该规则接线），所以不能宣称整体质量全面改善。q18 未显式解释冲突；q22 的具体升级版本仍未拒答；q24 只输出首 CVE 的自然分数，第二个分数缺失；本题 before/after 错配禁用断言都通过，实际复现的是缺失而非错误身份。后续如果新增 live 接线，必须另记模式，与原 before/after-func 不能混称完全相同链路。

## 中间已弃用的自由文本版本兜底结果与 caller 差异

| 模式 | 全 check 通过题数 | mean check score | fact/source coverage | 过拒 / 漏拒 | p50 / p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| [修复前](<before.json>) legacy-first-cve | 18/24 | 0.9003 | 16/17 | 0 / 4 | 0.1905 / 2.6235 |
| [中间直接链](<after-func.json>) legacy-first-cve | 19/24 | 0.9003 | 14/17 | 2 / 1 | 0.1620 / 1.6481 |
| [中间直接链（已弃用）](<after-func-final.json>) legacy-first-cve | 23/24 | 0.9896 | 16/17 | 0 / 0 | 0.2424 / 1.8900 |
| [中间 caller 接线（已弃用）](<after-wired.json>) live-multi-cve | 24/24 | 1.0000 | 17/17 | 0 / 0 | 0.2349 / 1.7802 |

每行均使用同一冻结期望 SHA。完整历史答案/检查见 [中间直接链 Markdown](<after-func-final.md>) / [中间接线版 Markdown](<after-wired.md>)。历史文件保留不覆盖；不安全的自由文本版本兜底已删除，因此该阶段的高分不能作为当前安全实现成绩。

上述中间直接链当时仅 q24 第二个 CVE 的自然评分事实缺失；本集错配禁用断言均通过，但这不表示穷尽了所有排序/跨 CVE 组合。当时的自由文本逐版本状态兜底降低了过拒，独立 review 后证明它能被非结构化/不可信文字误导，Lead 已彻底移除。exact/all-CVE、显式冲突提示、具体修复版本否定句门禁保留；版本判定现在只接受绑定的结构化 version_impact。

`--live-natural-scope` 的**唯一 caller 差异**：多 CVE 时给 naturalConclusion 的 cve_id 从首个 CVE 改为 null（仅一个 CVE 仍严格绑定）；这与修后的生产 live caller 一致。它不改期望、不添加模型、不人工塞 source_conflicts/version_impact。`metadata.runner_wiring` 明确区分 `legacy-first-cve` 与 `live-multi-cve`。before→after-func-final 为同 caller 接线比较；after-wired 是功能接线后成绩，**不能将它与 before 说成完全相同链路的因果对照**。

该已弃用中间阶段的 24/24 只表示当时此小型合成契约集所有定义的机械 checks 满足，**不是比赛准确率 100%、真实安全知识正确率或论文召回**。完整 live HTTP / baseline/guidance / 真实库端到端回归由 Lead 另外执行登记。

## 最终安全代码结果（权威现状）

安全 review 发现自由文本版本状态兜底存在 P1 风险后，Lead 删除 explicitVersionImpact。评测者只复跑生产函数，**不调整冻结期望、不人工传 version_impact、不以通过率为理由恢复不安全兜底**。

| 最终模式 | 全 check 通过题数 | mean check score | fact/source coverage | 冻结契约过拒 / 漏拒 | invalid citations | p50 / p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [after-safe-func](<after-safe-func.json>) legacy-first-cve | 21/24 | 0.927083 | 14/17 | 2 / 0 | 0 | 0.2180 / 1.7066 |
| [after-safe-wired](<after-safe-wired.json>) live-multi-cve | 22/24 | 0.937500 | 15/17 | 2 / 0 | 0 | 0.2095 / 1.6987 |

逐题 actual answer、期望、引用与检查见 [安全直接链 Markdown](<after-safe-func.md>) / [安全 natural 接线版 Markdown](<after-safe-wired.md>)。两模式期望 SHA 仍为 `1e9f07cef10e032cb1ba4270ecc7bfa0c74a2cd60b79c4e083e1d63358febec2`；evaluator 测试再次 8/8。

两模式都失败 q03/q04：合成原文有“2.4.0 受影响 / 2.5.0 不受影响”，独立原始契约期望可答，但当前安全门禁不把自由文字当结构版本依据，且此 probe **没有接入绑定的 version_impact**，所以实际保守拒答，按冻结契约记为2项 overrefusal。这是安全性与该 probe 回答覆盖的权衡，**不是错误的版本结论或新幻觉**。不能为避免计分下降改期望。

安全 legacy 模式另失败 q24：仍用首 CVE 调 natural，第二 CVE 的自然分值缺失；安全 wired 模式仅更改多 CVE 的自然 caller 为 null，解决 q24，没有额外注入版本规则。

同 caller 比较 before→after-safe-func：18/24→21/24，漏拒4→0，但契约过拒0→2、事实/指定来源覆盖16/17→14/17。natural 接线版从已弃用的24/24下降到最终22/24。这些下降必须如实报告；不表示应该放宽安全门禁。结构 citation_binding 的 invalid 数为0也不等于自动语义蕴涵正确。

**与产品实际 live 入口的区别**：Lead 另有实际 HTTP 回归验证基于 source/DQ/projection 绑定的结构化版本规则。那条入口传入 bound version_impact，本 probe 只接 production Q1/BM25/Q4/natural，没有该版本适配层，因此这里的2项保守拒答不能直接推断为 live 产品同样拒答；反之，HTTP 回归通过也不能当作这24题全部通过。我没有在本次重跑中自行执行或验证 Lead 的 HTTP 回归。

## 可复跑命令

工作目录仓库根，无 .env 加载，不启动服务、不重启模型或 Qdrant：

```sh
node --import ./scripts/test-network-guard.mjs --import tsx --test scripts/test/qa-quality-evaluate.test.ts
node --import ./scripts/test-network-guard.mjs --import tsx scripts/qa-quality-evaluate.ts --output docs/evidence/qa-quality/local-func
node --import ./scripts/test-network-guard.mjs --import tsx scripts/qa-quality-evaluate.ts --live-natural-scope --output docs/evidence/qa-quality/local-wired
```

输出 `--output` 指定前缀的 JSON + MD；不要覆盖 before。`--reference` 可指定同结构自建 reference（mode/evaluation_now/provenance/chunks/cases），但必须先独立标注事实、支持 source IDs，再评测；不能直接把 actual answer 当 gold。

## 正式库只读捕获

[readonly-snapshot.metadata.json](<readonly-snapshot.metadata.json>) 是可登记的 compact 元数据：不含原文或私有 paths；拒绝原因统计 missing intel=8、enrichment state missing or ambiguous=2828、artifact metadata missing/ambiguous=442。**不提交** [readonly-snapshot.json](<readonly-snapshot.json>)，完整文件仅本地保存真实 corpus（非真实质量评分）：`readKnowledgeProjection` 使用 `DatabaseSync({readOnly:true})` + transaction/ROLLBACK，不初始化 schema、不调用网络/embedding、不写业务/向量库。snapshot 序列 29665；9653 chunks、3278 rejected；初次 projection fingerprint `22c821423b7ed0e2dd0d835d053f0d48170dccd3c8315fe93f321103b0b9a344`；Lead 为 projection 新增只读元数据接线后的 fingerprint 为 `28a42784eee79524e73c6fce0dd04ae57034b4bf59e41dc2bf5ac314e969a32e`（chunks 的 corpus hash 未变）；corpus hash `9f8bd77a9725aab4374c15c9c0f03c8787d53db5d251dab68df7c2c498e16ca4`。

原始 SQLite bytes SHA256 读取前后均为 `5512cb7539668068761f8b461c04a40621a39d7134507603dd37ae6d8cc6a83f`（不是把二进制解码成 UTF-8 后计算）。前后相等仅为观测，不宣称排除了所有并发/WAL 写入。

```sh
node --import ./scripts/test-network-guard.mjs --import tsx scripts/qa-quality-evaluate.ts --capture-sqlite var/safetrace.sqlite --output docs/evidence/qa-quality/readonly-snapshot
```

可选 `--payload-root` 指定单个允许的 captured source root；默认 tmp/ingest-cache。捕获模式不运行题目，不生成期望，不给真实 corpus 事实准确率。要离线复跑真实 corpus：人工从独立来源标注问题/期望，构造自定义 reference，复用 snapshot.chunks；使用 --reference 运行。Snapshot 文件较大，可按项目证据管理策略归档，不能用合成题的成绩冒充真实 corpus 评估。

本次 8 项 evaluator 测试通过：冻结 SHA、独立来源要求、精确 ID+URL、伪造引用拒绝、查询回显排除、拒答证据不计覆盖、注入/错配禁用断言、完整逐题输出与指标边界。未 commit/push。

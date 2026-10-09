# 富化扩展：独立证据收据与修复建议接入

## 架构边界

原有 paper/cvss/epss 和 EnrichmentResult 严格 schema 保持原样。新维度使用独立 typed sidecar，由 runEnrichment 的显式 extensionDimensions/extensionRunner 编排；不默认联网、调用模型、扫描资产或执行 PoC。extensions-only 通过 dimensions:[] 跳过旧主链，既不查 arXiv/FIRST，也不重绑历史 enrich.items。

当前实现 remediation、asset 与 poc。新维度不得用共享 enrichment_dimension_state 伪造旧 enrich.items 发布回执。独立表 enrichment_extension_receipts 保存当前状态，enrichment_extension_history 追加历史；receipt_id 是独立标识。

## 修复建议来源与验证

复用 F5 纯函数和 QA 的来源投影闸门，输入限最新 DQ 放行的情报及其已捕获、已校验原文。

每张收据绑定：当前 Intel 事件与内容哈希、当前 DQ 事件与内容哈希、逐源 URL/raw_ref/SHA256/父血缘、F5 操作版本、artifact 与 dependency 哈希。

- live 表示存在来源明确的厂商/机构建议，不表示修复有效或已经安装。
- empty 表示本次没有合格指导，不表示安全。
- CISA KEV 只标 agency_guidance，不造 fixed version；Ubuntu USN 只标 vendor_statement。
- 发布前在 SQLite BEGIN IMMEDIATE 内重验当前 Intel/DQ 和原文哈希，失败回滚。
- dependency 一致时复用原 receipt_id，不重复追加历史。
- 读取时重新投影原文与当前 DQ，并核对整张收据。陈旧/伪造收据不悄悄退回成功的派生结果。
- 旧库没有收据表时保持只读派生兼容，不隐式建表。

详情 API evidence 可选附带 receipt_id，storage 区分 verified-extension-receipt 与 readonly-source-derived。修复问答复用同一验证读取器。

## 运行

    # 默认只读预览，不写库，不联网，不调用模型。
    node --import tsx scripts/enrich-extensions.ts --dimension=remediation --limit=2

    # 写入需已验证备份和单写 lease；--backup 指定本机备份目录。
    node --import tsx scripts/enrich-extensions.ts --apply --dimension=remediation --limit=2 --backup=.tmp/verified-backups/<verified-directory>

    # 仅查看指定条目的证据及收据，零写入。
    node --import tsx scripts/remediation-preview.ts --ids=<intel-id> --limit=1

可选 --ids 只接受当前 DQ 已放行的 ID，--limit 为 1–50。CLI 不提供隐式备份门禁绕过。

## 2026-10-09 实际验收

- 恢复既有 Qdrant 1.19.1，使用原 qdrant-storage，核对 safetrace_intel_demo/safetrace_sources；未创建替代生产库。
- 新备份 .tmp/verified-backups/safetrace-Yfv6o0：5237 点、1024 维、8 份原文、missing_raw_refs=0，SQLite/向量/原文校验通过。
- 原维护锁 PID140696、2026-10-06 创建，进程已停止且无其他维护写入者；在备份和证据预览后核对锁 token，原文件归档至 .tmp/reconciled-locks，没有抢占活跃 lease。
- 正式库仅发布两张 remediation 收据：CVE-2026-86950 / CVE-2026-88772，分别 rx_0mv0qaruu002 / rx_0mv0qawbi004。来源是 CISA KEV agency_guidance，无固定包版本断言。
- trace：tr_extensions_0mv0qanqe001；processed=2，network_calls=0，model_calls=0，frozen_result_writes=0。
- 正式库读取重验 stored_receipts_verified=2，rejected=[]。
- 端到端测试覆盖重启、幂等、旧库、提交前/提交后 DQ 撤销与原文变更、伪造 hash、扩展缺省不执行、缺 runner、失败不报成功、详情 API receipt_id/storage。

## 真实资产影响接入（第三步已完成）

- CLI/watch/API 统一复用最新 Intel/DQ 准入快照。全局 SQLite seq 保序，缺 DQ、旧版本判定、隔离/撤销全部拒绝；不使用时间戳拼造跨 topic 顺序。
- 告警写入在同步 Intel writer reservation 内执行，避免扫描期间 DQ 已变但仍落旧风险。只锁定，不写情报内容。
- 历史告警不删除；当前告警列表、分组/概览未读数、CLI 列表按最新 DQ 与最新扫描重新判定。读视图不可用时明确失败/未核验，不回放旧告警为当前风险。超过1000条历史加载会显式标 alerts_truncated。
- AssetsStore 支持只读模式，证据读取不初始化/迁移数据库；group/run/component 的一致快照全量哈希进入资产收据。
- asset 收据要求独立校验的原文 Intel 来源，绑定来源哈希、当前 DQ 与真实资产快照。提交时按 Intel -> Assets 锁顺序重验两库，快照变化即拒绝。
- 资产状态区分 potentially_affected / version_outside_declared_range / not_matching / unknown；不冒充确认受影响。厂商身份未核实、范围下界、跨生态同名、扫描降级、2000组件上限均显式表达。
- 私有项目/文件路径仅进入哈希绑定，不送模型或 SSE。资产收据不产生云端请求。
- 详情 API/页面识别有效资产快照收据；snapshot 改变、分组停用、原文变更、DQ 撤销后失效。标签改为资产影响评估，不再硬编码未实现。

    node --import tsx scripts/enrich-extensions.ts --dimension=asset --limit=1
    node --import tsx scripts/enrich-extensions.ts --apply --dimension=asset --limit=1 --backup=.tmp/verified-backups/<latest-verified-directory>
    node --import tsx scripts/asset-impact-preview.ts --id=<intel-id>

可选 --assets-db 指定已有资产快照库。缺失库不会被证据读取自动创建。

### 正式库受控验收

新备份 .tmp/verified-backups/safetrace-DrhhXx 已包含前两张修复收据，5237向量点/8原文/missing0。

仅新增一张真实资产评估收据：intel_kev_cve_2014_8361 / rx_0mv0rk5wr002，trace tr_extensions_0mv0rk20c001。绑定 adhoc、agentprograms、safetrace 三组最新快照，共564个组件。读取重验 verified，未截断；分布是 not_matching=560、unknown=4，**没有确认受影响、没有制造安全结论**。业务旧 enrich.items 未重写，网络/模型调用均为0。

回归验证覆盖 API DQ撤销/视图失败不回放、CLI缺DQ/隔离/新版本、资产快照变化、范围下界/跨生态碰撞、私有路径、分组停用、原文失效、收据幂等及旧修复兼容。全量663项测试、类型、旧契约校验和前端构建通过。构建仍有既有 tsconfig 重复路径键和 chunk-size 提示；没有宣称正在运行的旧 Web 进程已经自动更新。

后续：资产相关 triage（第五步），只基于已收据的资产影响与来源证据排序，不新增扫描、不猜严重度。
## 资产相关 triage（第五步已完成）

- src/enrich/src/triage.ts 只汇总**已收据**的三维证据：资产影响、修复指导、PoC 候选。
- 分层规则：资产可能受影响 + 有修复指导 → review_first；资产可能受影响但无指导 → review_first；
  资产 unknown → review_next（unknown 不是安全）；仅有 PoC 候选 → review_next；未命中 → informational（不表示无风险）。
- 不猜严重度/优先级分数；没有收据的维度不参与排序；输出是人工复核顺序建议，不是结论。
- 零写入、零网络、零模型调用；digest 可用于跨运行对比。

    node --import tsx scripts/triage-preview.ts --limit=10

### 正式库实测（6 条收据）

- review_next 4 条：intel_kev_cve_2014_8361（资产 unknown×4，需补版本）；
  intel_nvd_cve_2022_25863 / intel_nvd_cve_2023_22491 / intel_nvd_cve_2023_30548（各 8 个 PoC 候选，资产未命中）。
- informational 2 条：intel_kev_cve_2026_86950 / intel_kev_cve_2026_88772（有机构修复指导，资产未命中）。
- advisory_supported 全为 0：没有任何 PoC 候选达到 0.9 保留线，与第四步一致。
- digest：0270ccef80ef5124ab82521e8c5d26f80d2f87129c1d0ccf8a6c0c6f8a389b17。


## Jev 进主链：决策阶梯的本地兜底通道（2026-10-09）

用户决策：Jev 不再是纯 advisory sidecar，而是接进 A-02 四层兜底阶梯的 LLM 层。

链序：tool → rule → 云 StepPlan → 本地 Open-Jev → human。任一级弃权或不可用都显式下坠，
decided_by 如实记录（llm 层记 llm_fallback，人工层记 human，不冒充规则层）。

### 实现

- src/enrich/src/jev-decision-client.ts 重写为通用候选集客户端：候选键由请求 criteria 声明，
  服务端必须原样返回该集合、归一化概率且 argmax 一致；问题 ID 参数化（不再硬编码 relevance）。
- src/qa/src/ladder/openjev-decision.ts：本地决策通道，复用 StepFun 的同一投影闸门 buildProjection，
  因此只有公开结构化事实加可信上游校准概率能进模型。
- calibrated_prob 永远来自上游 calibrated_option_probabilities，绝不采用模型自评——与云通道纪律一致；
  模型只负责选哪个选项。
- src/qa/src/ladder/stepfun-decision.ts：createStepPlanDecisionHandler 新增 openjev 选项，
  内部用 chainLlmResolvers(cloud, local) 按序竞争。
- scripts/qa-decision-server.ts：设 JEV_MODEL_ID 即启用本地兜底；JEV_PROVENANCE_FILE 可钉死
  服务端 checkpoint/base/code/device，不符即拒。启动日志如实说明兜底是否启用、provenance 是否钉住。

### 为什么这样接是安全的

- 真实 A/B 已证明该模型在 paper 与 PoC 判定上最高 P 仅 0.56-0.84，全部低于 0.9 保留线。
  因此本地通道的采纳门槛沿用云通道的 0.65（上游校准概率），模型自评只用于弃权判断。
- 即使模型给出选项，calibrated_prob 仍取自上游表；模型判断错误时上游概率不足会挡下它。
- 服务不可达、provenance 不符、候选集不符、概率不归一，全部抛错，由 ladder 转 degraded 后继续下坠人工层。
- 本地通道只走 loopback HTTP、禁重定向、32KB 输入预算、钉模型版本。

### 启用方式

    JEV_MODEL_ID=Open-Jev-2B@0c7aa49 JEV_PROVENANCE_FILE=tmp/jev-provenance.json npm run qa:decision:serve

不设 JEV_MODEL_ID 时行为与之前完全一致（仅云通道），不改变现有默认链路。

### 验收

- 新增 src/qa/test/openjev-decision.test.ts 共 7 条：选中合法选项且概率取自上游、
  弃权或越界或上游概率不足返回 null、服务不可达与 provenance 不符抛错、
  云弃权后本地接棒、全弃权下坠人工且 decided_by=human、投影闸门不过不触达模型、
  请求体只含公开事实与 typed 选项并带 uncertain 出口。
- 全量 680/680 单测、typecheck、契约校验通过。
## 总体状态

五个步骤全部完成并有真实验收记录：GPU Jev 部署与 paper A/B（真实 51 次推理，全部弃权，advisory-only 保持）、
修复建议主链接入（2 条机构指导收据）、真实资产影响接入（1 条收据，564 组件，0 确认受影响）、
只读 PoC 候选与 Jev 审核（3 条收据，24 候选，最高 0.5647，无确认 PoC）、资产相关 triage（6 条收据分层）。

全量 673/673 单测、typecheck、契约校验、前端构建均通过。所有新维度都是独立 typed sidecar，
旧 EnrichmentResult 契约与评分语义未改；正式库写入均走 verified backup + 单写 lease 门禁。

## 只读 PoC 候选来源与 Jev 审核（第四步已完成）

- src/enrich/src/poc-candidates.ts 只从**已验证原文**里显式标注 Exploit/PoC/proof-of-concept 的引用提取候选元数据；零网络、零执行。
- 每条候选绑定自己的 raw_ref / source_sha256 / parent_lineage_ids / CVE 归属；缺一即拒。KEV 在野利用标记、厂商公告、补丁链接都不算 PoC 候选。
- 每个 CVE 单独计数，重复引用去重，单源引用上限 50；非 https 或带凭据 URL 拒收。
- 本地 Jev 逐候选给出 related/unrelated/uncertain 建议（最多 5 个），并落盘 checkpoint/base/code/device provenance；provenance 不符即拒。
- 建议永不当事实：live 只表示存在候选，不表示 PoC 可用；不抓取链接内容、不执行代码、不校验可达性或可利用性。
- 幂等按来源+候选绑定判定；复用旧收据前仍重验当前 Intel/DQ 与原文哈希。
- 读取端只重算来源绑定，不请求模型；DQ 撤销、原文变更、快照失效一律拒绝。

    node --import tsx scripts/enrich-extensions.ts --dimension=poc --limit=3 --jev-model-id=Open-Jev-2B@0c7aa49 --jev-provenance=tmp/jev-provenance.json
    node --import tsx scripts/enrich-extensions.ts --apply --dimension=poc --limit=3 --backup=.tmp/verified-backups/<latest> --jev-model-id=Open-Jev-2B@0c7aa49 --jev-provenance=tmp/jev-provenance.json
    node --import tsx scripts/poc-preview.ts --ids=<intel-id>

### 正式库受控验收（真实 GPU 推理）

新备份 safetrace-cMpFna（含 3 条既有扩展收据；5237 点 / 8 原文 / missing 0）。

对 3 条 NVD 情报发布 PoC 收据，共 24 个候选、15 条真实模型建议：

- intel_nvd_cve_2022_25863 / rx_0mv0um344002：related 0.48/0.49/0.56，uncertain 0.41/0.24
- intel_nvd_cve_2023_22491 / rx_0mv0umaej004：uncertain 0.14/0.30/0.13/0.32/0.32
- intel_nvd_cve_2023_30548 / rx_0mv0umicx006：uncertain 0.27/0.28/0.09/0.12/0.31

最高 P(related) 仅 0.5647，无一达到 0.9 保留线，因此没有任何候选被提升为确认 PoC。与 paper A/B 结论一致：该模型在此类判定上不给高置信输出，保持 advisory-only 是正确的。

数据质量实测发现：CVE-2023-30548 的候选混入了 openml.org 的 GHSA 公告（NVD 同 CVE 引用混杂），进一步证明不能把标签命中当 PoC 证明。

业务旧 enrich.items 未重写；候选提取零网络，模型调用仅本地 loopback。读取复验三条均 verified。
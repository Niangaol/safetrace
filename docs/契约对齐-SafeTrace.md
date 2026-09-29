# 契约对齐设计：SafeTrace 契约为准，本仓为运行时实现

> 决策（2026-09-29）：以 SafeTrace `contracts/` 为**唯一权威规格**，本仓（`ai-threat-intel`）作为
> 该规格的**运行时实现**。不重写语言，不放弃已跑通的 FastAPI + LangGraph + Vue 链路。
> 依据：本仓 `docs/交接说明.md` 早已把「TypeScript+pi-agent-core → Python+FastAPI+LangGraph」
> 登记为已知偏差，本次只是把该偏差正式契约化。

---

## 0. 权威来源与不可变约束

| 项 | 路径 | 状态 |
| --- | --- | --- |
| 权威契约件 | `D:\TrueDownload\safetrace-main\safetrace-main\contracts\` | v1.0.0 冻结（CHANGELOG 2026-09-28） |
| 本仓契约件 | `contracts/` | 改造后须**逐字一致** + 扩展件 |
| 冻结纪律 | `contracts/schemas/CHANGELOG.md` 第五节 | 只允许「新字段追加 + 旧字段标 deprecated」；禁止改语义、删字段、改枚举含义 |

**因此本仓不得修改 SafeTrace 已冻结的 8 个 Schema 任何字节。** 我们的增量一律走「新契约 + 新主题」。

---

## 1. 8 个权威 Schema（逐字引入，不改）

| Schema | 生产者 → 消费者 | 关键约束 | 本仓现状 |
| --- | --- | --- | --- |
| `RawDoc.json` | Y1/Y2 → Y3 | 7 必填；`source_type` 11 值枚举 | 无，需新建 |
| `IntelItem.json` | Y3 → F 线 | `intel_id` 前缀 `intel_`；`first_seen_at`/`published_at` 双时钟；`entities` 五件套；`aliases` 只建关联不合并 | 无，需新建 |
| `EnrichmentResult.json` | F 线 → S1 | `additionalProperties:false`；维度枚举**仅 6 值**；`artifacts` 仅 `papers`+`score_assessment` | 有同名文件，**维度不同，必须替换** |
| `DecisionRequest.json` | Y5/Q1/Q3 → MG1 | `kind` 四值；question 三元组 `choice|score|noul`；`cardinality_max ≤ 255` | 无，需新建 |
| `DecisionReply.json` | MG1 → 调用方 | `decided_by` 四通道必填；`fallback_reason` 条件化必填 | 无，需新建 |
| `RetrievalRequest.json` | Q2 入口 | `min_quality` 下限防脏数据入检索 | 无，需新建 |
| `RetrievalResponse.json` | Q2 → Q3/Q4 | `provenance` 必填 `url+section`；`embedder_model_id` 绑定 S3 | 无，需新建 |
| `ToolRegistration.json` | S4 → 编排层 | `permissions.exec` 默认 false（F3 合规红线） | 有 `/agents/tools` 端点但无契约 |

> 修正此前记录：README/ROADMAP 写「7 个 JSON Schema」，实际目录为 **8 个**。

---

## 2. 事件信封：字段级差异与改造

他的（权威）：
```
Envelope{ event_id, topic, occurred_at, trace_id, causation_id, payload, schema_version }
```

我们的（现状 `core/events.py`）：`{ event_id, topic, ts, trace_id, payload }`

| 差异 | 处理 |
| --- | --- |
| `ts` → `occurred_at` | 改名。`ts` 保留为 **deprecated 别名**，同步写入，防前端与存量消费者断裂 |
| 缺 `causation_id` | **新增**。用于因果链：`raw.docs → intel.items → enrich.items → qa.answers`。为 `None` 时省略该键（遵守「键要么不存在、要么有值」纪律） |
| 缺 `schema_version` | **新增**，固定 `"1.0"`，与其 Schema 的 `^[0-9]+\.[0-9]+$` 对齐 |
| 幂等 | 他的规范要求「消费者按 `event_id` 去重」。我们现状每次 `uuid4()`，**无幂等键**。→ `event_id` 改为**内容派生确定性 ID**（见 §6） |

---

## 3. 主题映射表

他的 10 个主题为准；我们有 9 个，逐个映射：

| 他的主题 | 我们的现状主题 | 处理 |
| --- | --- | --- |
| `raw.docs` | `intel.raw.collected` | 改名，payload 改用 `RawDoc.json` |
| `intel.items` | `intel.dedup.merged` | 改名，payload 改用 `IntelItem.json` |
| `dq.verdicts` | — | **全新**，payload 用内联 `QualityVerdict` |
| `enrich.triage` | `intel.risk.triaged` | 改名，payload 改用内联 `TriageOrder`（P0-P3 + route） |
| `enrich.papers` | — | **全新**，从 F1 论文维度单独出 |
| `enrich.items` | `intel.enrich.completed` | 改名，payload 改用 `EnrichmentResult.json` |
| `qa.queries` | `intel.qa.asked` | 改名，payload 用内联 `QueryTurn` |
| `qa.answers` | — | **全新**，payload 用内联 `Answer`（含 `abstained`） |
| `decision.replies` | — | **全新**，payload 用 `DecisionReply.json` |
| `fallback.events` | `intel.enrich.degraded` | 改名，payload 用内联 `FallbackEvent`。**降级从此是一等公民事件** |

我们独有、**无对手方、作为扩展保留**（不改名、不删除）：

`intel.enrich.requested`、`intel.alert.raised`、`intel.report.daily`、`intel.budget.exceeded`、`intel.selfheal.action`

理由：告警、日报、成本预算、自愈是本仓的真实运行能力，砍掉等于放弃我们的优势；扩展主题不违反他的冻结纪律（他的 CHANGELOG 只约束 `contracts/schemas/*`）。

---

## 4. 降级标记：值映射（本仓最大的语义风险点）

他的 `degraded_to` 是**封闭 6 值枚举**，我们的实际取值不在其中。映射方案：

| 我们的实际通道 | 我们的现值 | 映射到他的枚举 | 说明 |
| --- | --- | --- | --- |
| 确定性规则兜底 | `rule` | `template` | 均为「无 LLM 的确定性通道」 |
| 预置/样本数据 | `mock` | `fixture` | 语义**完全一致** |
| 云端→本地模型切换 | — | `provider_switch` | 精确匹配 |
| 词法/内存索引替代向量 | — | `memory_index` | 精确匹配 |
| 缓存命中 | — | `cache` | 精确匹配 |
| 换源采集 | — | `source_switch` | 精确匹配 |

**实现方式**：`core/degrade.py` 提供 `DegradeMarker` 与 `to_contract()`。契约字段只出他的 6 值之一；
我们更精确的原始通道名保留在 `degraded_state.detail_ref`（指向 trace）与 `recovery_hint`，
并新增本仓自有的 `degraded_detail` 扩展字段（仅本仓内部/前端消费，不进 SafeTrace 契约件）。

`degraded_state` 固定形状：`{ label, since, detail_ref }`，`label` 为**用户可见文案**。

---

## 5. 维度映射：以他的 6 维为契约主键

他的 `EnrichmentResult` 枚举仅 6 值且 `additionalProperties:false`，**`ai_risk` 无法进入该契约**。
按已定决策「6 维为主键 + `ai_risk` 为可选第 7 维」，落地方式：

| 我们的维度 | 契约主键（他的） | 我们的实现模块 | 契约内位置 |
| --- | --- | --- | --- |
| `paper` | `paper` | `services/enrich/paper.py` | `artifacts.papers` |
| `asset` | `asset` | `services/enrich/asset.py` | 仅进 `dimensions_completed` |
| `poc` | `poc` | `services/enrich/poc.py` | 仅进 `dimensions_completed` |
| `cvss` | `cvss` | `services/enrich/cvss_impact.py` | `artifacts.score_assessment` |
| `fix` | **`remediation`** | `services/enrich/fix.py` | 仅进 `dimensions_completed` |
| `consistency` | **`triage`** | `services/enrich/consistency.py` | 仅进 `dimensions_completed` |
| `ai_risk` | **无（扩展）** | `dimensions.py::ai_risk_dimension` | 走扩展契约 `DimensionEvidence` |

**关键决策**：`ai_risk` 及 asset/poc/remediation/triage 的**明细证据不进 `EnrichmentResult`**
（该契约 `additionalProperties:false`，塞进去即违约）。改为新增本仓扩展契约：

### 新增扩展契约 `contracts/schemas/DimensionEvidence.json`（本仓自有，不属他的冻结集）

承载 7 维的完整证据链：`dimension`(7 值枚举) / `intel_id` / `summary` / `confidence` /
`sources[]` / `evidence[]`（`url`+`snippet`+`fetched_at`）/ `degraded_to` / `degraded_reason` / `mock` / `quality_score`。

对应主题：`enrich.evidence`（扩展主题）。
前端详情页改为消费本契约，从而**不丢失**我们现有的 7 维证据链展示能力。

**结论：`EnrichmentResult` 做跨线交接口（权威、瘦、可校验），`DimensionEvidence` 做展示与审计口（本仓、胖）。两者用 `intel_id` 关联。**

---

## 6. 幂等键设计（他的规范要求，我们缺失）

`event_id` 改为确定性派生，避免重放产生重复消费：

```
event_id = "evt_" + sha256(f"{topic}|{dedup_key}|{schema_version}")[:32]
```

`dedup_key` 取各主题的业务唯一键：
`raw.docs`→`external_id`；`intel.items`→`intel_id`；`enrich.items`→`f"{intel_id}|{dimension}"`；
`qa.answers`→`turn_id`；`fallback.events`→`f"{layer}|{trigger}|{ts_bucket}"`。

同键重放 → 同 `event_id` → 消费者可安全去重（Redis 侧用 SETNX + TTL 去重表落地）。

---

## 7. DQ1 质量闸门（全新实现，形状照抄他的内联契约）

```json
{
  "item_id": "...", "item_kind": "intel | enriched",
  "quality_score": 0.0,
  "dimension_scores": { "structure":0, "completeness":0, "consistency":0, "timeliness":0, "sourcing":0 },
  "flags": ["ts_no_tz","reject_status","poc_dead_link","key5_missing","boilerplate","multi_id_mismatch"],
  "verdict": "pass | degrade | review | quarantine",
  "quarantine_ref": null, "reviewer": null, "reviewed_at": null,
  "gate_version": "1.0.0"
}
```

- **6 类 flag 全部实现**，且 flag 与分数**解耦**：命中即置位，`quarantine` 判定不受分数影响
- 权重版本化随 `gate_version`；**同版本同输入必须同输出（可复算）**
- 与我们现有 `dimensions.py::dimensions_for_quality()` 的关系：**替换**。旧的两个阈值
  （`enrich_min_quality_partial=0.4` / `enrich_min_quality_full=0.7`）映射为
  `review=0.5` / `degrade=0.7` 的判定线，保留配置项名以免破坏现有测试
- **顺带修复**：`Vuln.quality_score` 此前无运行时写入方（仅 `demo_seed.py` 硬编码 `0.78`），
  本次由 DQ1 在 `node_persist` 前写入

---

## 8. 拒答（abstain）机制

他的 `Answer` 含 `abstained: bool`；我们无此字段。补 4 条拒答条件（与 `q4-answer.ts` 对齐）：

1. 检索证据集为空
2. 最高重排分 `< 0.3`
3. Q1 意图不明确（`needs_clarify`）
4. 证据未覆盖问题点名的 CVE

拒答时**仍输出四段式结构**（结论/证据/推理链/置信度），`confidence=0.00`，
不调用 LLM。我们已有「无证据时固定话术不调 LLM」，本项是把它升级为**可判定、可测试**的机制。

---

## 9. 实施顺序（每步都可独立验收、可回滚）

| 步 | 内容 | 验收 |
| --- | --- | --- |
| S1 | `contracts/` 拷入他的 8 个 Schema + 新增 `DimensionEvidence` + `CHANGELOG` | `validate_contracts.py` 全绿 |
| S2 | `core/degrade.py` | 单测：6 枚举映射全通、`degraded_state` 形状正确 |
| S3 | `core/events.py` 信封与主题改造 | 单测：`occurred_at`/`causation_id`/`schema_version`、幂等确定性 |
| S4 | `services/dq1.py` | 单测：6 flag、四档边界、gate_version 可复算 |
| S5 | `quality_score` 写入 + 入口闸门接 DQ1 | 单测 + Demo 数据核对 |
| S6 | QA `abstained` + 4 拒答条件 | 单测：4 条各触发一次。**进度：第 1 条（证据为空）已实现**（`qa/agent.py:224`），余 3 条归 Q 线 |
| S7 | 检索响应补 `embedder_model_id`/`degraded_to`/`min_quality` 过滤 | 单测 |
| S8 | 文档更新（README / 交接说明） | 人工 |

---

## 10. 与他对接需协商的 3 件事

1. **`degraded_to` 缺 `rule` 值**：我们用 `template` 承载「规则兜底」。若他认为语义失真，
   需在其冻结枚举上**追加** `rule`（属契约变更，需其 sign-off）。
2. **`EnrichmentResult` 无法承载 7 维明细**：我们新增扩展契约规避，未违反其纪律，但需他确认
   扩展契约不进他的 `contracts/schemas/` 冻结集。
3. **本仓 5 个扩展主题 + `enrich.evidence`**：需他确认扩展主题不影响他的 10 主题拓扑。

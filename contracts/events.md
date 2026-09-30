# 事件主题契约

> 权威来源：SafeTrace `contracts/events.md` + `contracts/schemas/*.json`。
> 事件信封 schema：`contracts/schemas/EventEnvelope.json`（本仓扩展件）。
> 本仓**不得改动**权威主题名；新增主题必须先在 §3 登记，并同步 `EventEnvelope.json`
> 的 `topic` 枚举与 `tests/test_events_alerts.py::test_every_topic_is_declared_in_the_envelope_schema`。
> 三线之间**只通过事件与 REST 解耦，禁止跨模块直接调用内部函数**。

## 1. 信封格式（权威）

```jsonc
{
  "event_id": "evt_3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c",
  "topic": "enrich.items",
  "occurred_at": "2026-09-30T21:10:00+08:00",
  "trace_id": "8a1b…",
  "causation_id": "evt_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", // 根事件省略此键
  "schema_version": "1.0",
  "payload": {}
}
```

- `event_id`：给了 `dedup_key` 时为 `evt_` + `sha256(topic|dedup_key|schema_version)[:32]`，
  **同键重放得同一 ID**，消费者据此幂等去重；未给 `dedup_key` 则退化为随机 ID
  （心跳、预算超限这类状态事件本就不该被去重）。
- `occurred_at` 取代旧字段名 `ts`。`ts` 仅在 schema 中作为 deprecated 兼容位保留，
  **新代码禁止写入**。
- `causation_id` 指向触发本事件的上游 `event_id`，构成因果链
  `raw.docs → intel.items → enrich.items → enrich.triage → qa.answers`。
- `additionalProperties: false`：信封多一个键就是违约。

样例：`fixtures/eventenvelope.sample.json`。

## 2. 权威主题（10 个，一字不改）

| topic | payload 契约 | 生产者 | 消费者 | 本仓落点 |
| --- | --- | --- | --- | --- |
| `raw.docs` | RawDoc.json | Y1/Y2 | Y3 | `agents/nodes.py::node_collect` |
| `intel.items` | IntelItem.json | Y3 | F 线 / DQ1 | `agents/nodes.py::node_dedup` |
| `dq.verdicts` | QualityVerdict（内联） | DQ1 | S1 / A1 | `agents/nodes.py::node_dq1` |
| `enrich.triage` | TriageOrder（内联） | Y5 | F 线 | `agents/nodes.py::node_alert` |
| `enrich.papers` | EnrichmentResult（papers 维） | F1 | F6 | `agents/nodes.py::publish_papers_payload` |
| `enrich.items` | EnrichmentResult.json | F6 | S1 | `nodes.py::node_enrich`、`services/enrich/s2_events.py` |
| `qa.queries` | QueryTurn（内联） | 编排层 | Q1 | `services/qa/agent.py` |
| `qa.answers` | Answer（内联） | Q4 | 前端/编排层 | `services/qa/agent.py` |
| `decision.replies` | DecisionReply.json | D4 | Y5/Q1/Q3 | 本仓暂无 D4 |
| `fallback.events` | FallbackEvent（内联） | FB1 各层 | A1 | `services/enrich/s2_events.py::publish_degraded` |

> `dq.verdicts` 载荷（QualityVerdict，机读契约在 `LocalPayloads.json` 的 definitions）为本仓对齐上游
> 的**纯追加**增量：`flags` 登记 `unknown_version`；可选 `injection_score`（0-1）与 `injection_flags`
> （十类注入迹象枚举，样例 `fixtures/qualityverdict.injection.sample.json`）。
> **缺省 = 未做注入筛查**：任何调用方禁止把缺省当作"已筛查且干净"。
> **A-04 已落地（2026-09-30）**：本仓**有**检测器（`services/injection.py`），
> DQ1 的 `evaluate()` 现在**会填**这两个字段，且高风险命中会同时落进 `flags`
> 的 `injection_suspect`（`decide_verdict` 是"flag 优先于分数"，因此检出即转
> `quarantine`）。旧生产者不带这两字段的载荷**仍然合法**（纯追加、向后兼容）。
> ⚠️ 检测为**规则匹配**，不覆盖全部注入手法；"未检出"不等于"一定安全"。

> `qa.answers` 载荷（Answer，内联）对齐上游 v1.1.3 / C-04 的**纯追加**增量，可选字段：
> `stale_warning`（时效评估）与 `injection_guard`（注入筛查状态）。缺省语义两意：
> **`stale_warning` 缺省 = 未做时效评估**，禁止当作证据新鲜；**`injection_guard.screened=false`
> 必须显式出现**，禁止把未筛查读成“已筛查干净”。
> 形状（本仓 `services/qa/freshness.py` 产出，`qa/agent.py` 在 `qa.answers` 与 SSE `done` 统一发出）：
>
> ```jsonc
> {
>   "stale_warning": {
>     "threshold_days": 365,              // 时效阈值（天），本仓取统一保守值
>     "oldest_published_at": "ISO-8601",  // 最早证据发布时间；全部为未知时省略
>     "unknown_published_at": 0,          // 缺 published_at 的证据条数
>     "note": "用户可见提示（全部未知时措辞更重）"
>   }?,
>   "injection_guard": {
>     "screened": true,                   // A-04 已落地：有引用即做规则筛查（检出危险时也是 true，含义是"筛过"）；仅无引用时为 false
>     "max_score": 0.0,                   // 注入迹象最高分（0-1），无检出为 0
>     "flags": [],                        // 命中的注入迹象枚举（十类，与上游 InjectionFlag 一致），无检出为空
>     "untrusted_evidence": 0,            // trust=untrusted 的证据条数（外部文本暴露面）
>     "note": "用户可见说明（规则匹配，不保证覆盖全部注入手法）"
>   }
> }
> ```
>
> `stale_warning` 显式发出 `null`（值为 null，键始终在场，不允许省略）是唯一
> “证据新鲜且时效全已知”的情形，此时允许不提示；其余任何过龄/未知情形必须给出用户可见提示。

## 3. 本仓扩展主题（6 个）

权威 10 主题覆盖不到本仓能力，以下为登记在案的扩展：

| topic | payload | 生产者 | 消费者 | 登记理由 |
| --- | --- | --- | --- | --- |
| `intel.enrich.requested` | `{vuln_id, dimensions[]}` | F 线 | EnrichAgent | 权威无富化派发口 |
| `enrich.evidence` | DimensionEvidence.json | F 线 | 知识库/前端 | 权威 `EnrichmentResult` 是 `additionalProperties:false` 瘦交接口，装不下 7 维明细 |
| `intel.alert.raised` | `{level, title, message, vuln_id}` | `core/alerts.py` | notifier | 权威无告警主题 |
| `intel.report.daily` | `{markdown}` | `agents/report.py` | api / 前端 | 权威无日报主题 |
| `intel.budget.exceeded` | `{day, spent_cny, budget_cny}` | `core/cost.py` | WatchAgent | 权威无成本主题 |
| `intel.selfheal.action` | `{action, target, reason, detail}` | `agents/watchdog.py` | WatchAgent | 权威无自愈主题 |

## 4. 已迁移的旧主题名

存量主题名仍可发布（`EventBus.normalize_topic` 会改写为权威主题并记 warning），
但新代码禁止使用：

| 旧名 | 权威主题 |
| --- | --- |
| `intel.raw.collected` | `raw.docs` |
| `intel.dedup.merged` | `intel.items` |
| `intel.enrich.completed` | `enrich.items` |
| `intel.enrich.degraded` | `fallback.events` |
| `intel.risk.triaged` | `enrich.triage` |
| `intel.qa.asked` | `qa.queries` |

## 5. F 线的事件责任边界

- F 线**发布**：`intel.enrich.requested`、`enrich.items`、`enrich.papers`、`enrich.evidence`、`fallback.events`。
- F 线**订阅**：不订阅任何 topic（由编排层 `agents/nodes.py::node_enrich` 调用 `EnrichAgent.run()` 驱动）。
- F 线**禁止**发布 `raw.docs` / `intel.items` / `enrich.triage`
  （那是 Y 线与编排层的职责）；`services/enrich/s2_events.py::ALLOWED_TOPICS` 会硬拦。
- 事件发布失败**不得阻断**主链路（`EventBus` 降级语义），但必须记 warning。
- 主题非法属于**契约错误**而非基础设施故障，`try_publish` 直接抛 `UnknownTopicError` ——
  契约错误被 warning 吞掉等于契约形同虚设。

## 6. 降级标记（红线：禁止静默兜底）

任何降级响应必须携带（权威形状）：

```json
{
  "degraded_to": "cache|memory_index|template|fixture|source_switch|provider_switch",
  "degraded_state": { "label": "用户可见文案", "since": "ISO-8601", "detail_ref": "trace_id" },
  "recovery_hint": "人工恢复提示（可空）"
}
```

用户在界面必须看到降级横幅或答案尾部标注；缺标记视为缺陷。
本仓统一出口：`core/degrade.py`。

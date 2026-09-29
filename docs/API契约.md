# API 契约（v1）

> Day 1 冻结。三条线并行开发期间，接口变更必须走契约评审并更新本文档版本号。
> Base URL：`http://<host>:8000/api/v1`，鉴权：`Authorization: Bearer <API_TOKEN>`（开发期可关闭）。

---

## 1. 通用约定

- 编码 UTF-8；请求/响应 `application/json`，流式接口 `text/event-stream`。
- 时间一律 ISO-8601 带时区，如 `2026-09-28T10:00:00+08:00`。
- 分页：`?page=1&page_size=20`，响应包裹 `{"items":[], "total":0, "page":1, "page_size":20}`。
- 错误体：`{"error": {"code": "VULN_NOT_FOUND", "message": "…", "detail": {}}}`。

| code | HTTP | 含义 |
|---|---|---|
| `UNAUTHORIZED` | 401 | Token 缺失或错误 |
| `VULN_NOT_FOUND` | 404 | 漏洞不存在 |
| `BUDGET_EXCEEDED` | 429 | 当日 LLM 预算熔断（已自动降级本地模型） |
| `SOURCE_UNAVAILABLE` | 503 | 数据源不可用且无备用 |
| `ENRICHMENT_IN_PROGRESS` | 202 | 富化任务排队中 |

---

## 2. 采集与任务

### `POST /collect/sync`
手动触发一轮采集（Demo / 补数用）。异步执行，立即返回任务 id。

```jsonc
// request
{ "sources": ["nvd", "ghsa", "arxiv", "community_rss"], "mode": "incremental" } // mode: incremental|full
// response 202
{ "task_id": "tsk_20260928_001", "accepted_sources": ["nvd", "ghsa"] }
```

### `POST /collect/hook/ghsa`
GitHub webhook 接收端（实时链路）。需校验 `X-Hub-Signature-256`。

```jsonc
// request (GitHub 事件体)
// response 202
{ "received": 3, "enqueued": 3 }
```

### `GET /collect/status`
```jsonc
{
  "watermarks": [
    { "source": "nvd", "last_sync_at": "2026-09-28T09:30:00+08:00", "last_published_at": "2026-09-28T08:10:00+08:00", "items_last_run": 42, "success": true, "error": null }
  ],
  "queue_depth": 0
}
```

---

## 3. 漏洞与富化

### `GET /vulns`
查询参数：`q`（关键词）、`severity`（逗号分隔）、`ai_risk_category`、`cwe`、`vendor`、`has_poc`(bool)、`published_from` / `published_to`、`enriched`(bool)、`page` / `page_size`、`sort`（`published_at` | `cvss_score` | `fetched_at`）。

```jsonc
{
  "items": [
    {
      "id": "v_01J...",
      "cve_id": "CVE-2026-12345",
      "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
      "title": "vLLM 中 RCE 漏洞",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cwe": ["CWE-78"],
      "cpe": ["cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*"],
      "ai_risk_category": "ai_infrastructure",
      "exploit_status": "poc_available",
      "published_at": "2026-09-20T08:00:00+08:00",
      "fetched_at": "2026-09-20T10:12:00+08:00",
      "collect_latency_seconds": 7920,
      "source_count": 3,
      "enriched": true
    }
  ],
  "total": 1284,
  "page": 1,
  "page_size": 20
}
```

### `GET /vulns/{vuln_id}`
返回单条漏洞完整信息，字段同上并附 `summary`（LLM 生成摘要）与 `related`（关联的论文/POC/标准 id 列表）。

### `GET /vulns/{vuln_id}/evidence`
**证据链接口（富化准确率与可解释性的核心）**。

```jsonc
{
  "enrichments": [
    {
      "dimension": "poc",
      "value": { "repo": "https://github.com/x/y", "language": "Python", "verified": true, "tier": "confirmed", "runtime_verified": false },
      "source": ["github", "nvd"],
      "evidence": [
        { "source": "github", "url": "https://github.com/x/y", "snippet": "PoC for CVE-2026-...", "fetched_at": "2026-09-21T03:20:00+08:00" }
      ],
      "confidence": 0.86,
      "model": "deepseek-v4-flash",
      "agent": "EnrichAgent",
      "version": 2,
      "degraded_to": null,
      "degraded_reason": "",
      "quality_score": 0.83,
      "created_at": "2026-09-21T03:21:00+08:00"
    }
  ],
  "graph": {
    "nodes": [ { "id": "v_01J", "type": "Vuln" }, { "id": "p_vllm", "type": "Product" } ],
    "edges": [ { "src": "v_01J", "rel": "AFFECTS", "dst": "p_vllm" } ]
  }
}
```

`dimension` 枚举（**7 个，与 `services/enrich/dimensions.py::DIMENSIONS` 严格一致**）：

| 维度 | 计划模块 | 含义 |
|---|---|---|
| `paper` | F1 | 论文关联 |
| `asset` | F2 | 受影响资产与版本区间（资产画像为 Mock） |
| `poc` | F3 | POC / 模板 / 利用情报（带 `tier` 可信度分级） |
| `cvss` | F4 | CVSS 与影响评估（分数本地计算） |
| `fix` | F5 | 修复建议（立即缓解 / 升级 / 加固 / 检测） |
| `consistency` | F6 | 汇总与一致性校验（`consensus` / `conflicts` / `quality_score` / `timeline`） |
| `ai_risk` | —（专项） | AI 风险四级分类 + MITRE ATT&CK 映射 |

字段说明：

- `source`：本次结论实际依据的数据源列表（赛题硬要求「每条富化带 source」）。
- `degraded_to`：`null` \| `cache` \| `fixture` \| `rule` \| `mock` \| `local`；非 `null` 时前端必须打降级徽标，且 `confidence ≤ 0.6`。
- `quality_score`：仅 `consistency` 维度产出，公式见 `docs/富化线详细设计.md` §3 F6。
- `verified` 表示"可信度分级 ≥ likely"；**是否真的运行过**看 `runtime_verified`（初赛恒 `false`）。

关系边 `rel` 枚举：`AFFECTS` | `MENTIONED_IN` | `HAS_POC` | `MAPS_TO` | `CATEGORY` | `FIXED_BY` | `CONFLICTS_WITH`。

### `POST /enrich/backfill`
对已有漏洞批量补富化（离线跑批，钉在闲时执行）。

```jsonc
// request
{ "vuln_ids": ["v_01J", "v_02J"], "dimensions": ["poc", "ai_risk"], "force": false }
// response 202
{ "task_id": "tsk_20260928_007", "queued": 2 }
```

---

## 4. 问答（SSE 流式）

### `POST /qa/chat`

```jsonc
// request
{
  "session_id": "sess_abc123",     // 省略则新建
  "question": "最近影响 vLLM 的高危漏洞有哪些，攻击条件是什么？",
  "top_k": 8,
  "stream": true,
  "filters": { "severity": ["critical", "high"], "published_from": "2026-08-01T00:00:00+08:00" }
}
```

`stream: true` 响应 `text/event-stream`，事件序列：

```
event: stage
data: {"stage":"rewrite","message":"正在理解问题意图…"}

event: stage
data: {"stage":"retrieve","round":1,"hit":8}

event: stage
data: {"stage":"retrieve","round":2,"hit":5}

event: citation
data: {"id":"S1","title":"...","url":"...","score":0.87}

event: token
data: {"text":"最近影响 vLLM 的高危漏洞包括…"}

event: reasoning
data: {"step":1,"sub_question":"vLLM 近 30 天高危漏洞有哪些？","finding":"共 3 个，均为 CVSS ≥ 9.0"}

event: done
data: {"session_id":"sess_abc123","answer_id":"ans_01J","elapsed_ms":4200,"citations":7,"cost_cny":0.031,"model":"deepseek-v4-pro","degraded":false}
```

`stream: false` 时直接返回 `{ "answer": "...", "citations": [...], "reasoning": [...], "elapsed_ms": 4200 }`。

`done` 事件中 `degraded=true` 表示当日前端已超预算、本次由本地模型兜底（大屏同步展示降级标识）。

### `GET /qa/sessions` / `GET /qa/sessions/{session_id}`
会话列表与历史消息（含当时引用的文档快照，保证复现）。

---

## 5. 关系图查询（多跳）

### `GET /graph/neighbors`
参数：`node_id`（或 `vuln_id` / `product`）、`hops`（1~3，默认 2）、`rels`（逗号分隔，默认全部）、`limit`。

```jsonc
{
  "nodes": [ { "id": "p_vllm", "type": "Product", "label": "vLLM", "depth": 0 },
             { "id": "v_01J", "type": "Vuln", "label": "CVE-2026-12345", "depth": 1 } ],
  "edges": [ { "src": "v_01J", "rel": "AFFECTS", "dst": "p_vllm", "depth": 1 } ]
}
```

---

## 6. 指标与可观测

### `GET /metrics/overview`
```jsonc
{
  "collect": { "raw_items": 5230, "vulns": 1284, "merge_ratio": 0.754, "sources": 7, "healthy": 7 },
  "latency": { "p50_seconds": 6300, "p95_seconds": 19800, "sla_6h_ratio": 0.71 },
  "enrich": {
    "dimensions": 7,
    "coverage_ratio": 0.96,
    "accuracy": 0.91,
    "recall": 0.89,
    "degraded_ratio": 0.08,
    "per_dimension": {
      "paper": { "coverage": 0.72, "confidence_avg": 0.68, "degraded_ratio": 0.0 },
      "asset": { "coverage": 0.95, "confidence_avg": 0.50, "degraded_ratio": 1.0 },
      "poc": { "coverage": 0.61, "confidence_avg": 0.77, "degraded_ratio": 0.12 },
      "cvss": { "coverage": 0.98, "confidence_avg": 0.88, "degraded_ratio": 0.0 },
      "fix": { "coverage": 0.83, "confidence_avg": 0.79, "degraded_ratio": 0.15 },
      "consistency": { "coverage": 0.94, "confidence_avg": 0.85, "degraded_ratio": 0.06 },
      "ai_risk": { "coverage": 0.97, "confidence_avg": 0.75, "degraded_ratio": 0.02 }
    }
  },
  "qa": { "accuracy": 0.86, "p95_seconds": 4.2, "sessions": 214 },
  "agents": { "runs": 86, "failed": 3, "self_heal_actions": 5, "avg_tokens_per_run": 4210 },
  "cost": { "total_cny": 62.4, "today_cny": 3.1, "daily_budget_cny": 20.0, "degraded": false }
}
```

### `GET /agents/runs` / `GET /agents/runs/{run_id}`
Agent 执行轨迹（答辩演示"自主编排"用）。`run_id` 返回每个 node 的 `state / input摘要 / output摘要 / tokens / cost / latency / error`。

### `GET /alerts` / `POST /alerts/test`
告警列表与告警通道自检（现场演示飞书/钉钉推送）。

### `GET /reports/daily?date=2026-09-28`
Agent 自动生成的日报（新增漏洞 TOP、时效、富化完成率、异常摘要）。

---

## 7. 事件总线（Redis Pub/Sub）

三条线之间只通过事件与 REST 解耦，禁止跨模块直接调用内部函数。

主题与信封以 SafeTrace `contracts/events.md` 为权威，完整清单（含本仓 6 个扩展主题、
旧名迁移表）见 `contracts/events.md`。这里只列常用主题。

### 7.1 信封

```jsonc
{
  "event_id": "evt_3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c",
  "topic": "enrich.items",
  "occurred_at": "2026-09-30T21:10:00+08:00",
  "trace_id": "8a1b…",
  "causation_id": "evt_1a2b…",  // 触发本事件的上游 event_id，根事件省略
  "schema_version": "1.0",
  "payload": {}
}
```

- `event_id` 由 `dedup_key` 内容派生（`evt_` + `sha256(topic|dedup_key|schema_version)[:32]`），
  同键重放得同一 ID，消费者据此幂等去重；未给 `dedup_key` 则为随机 ID。
- `occurred_at` 取代旧字段名 `ts`（`ts` 仅为 deprecated 兼容位保留，新代码不写）。
- Schema：`contracts/schemas/EventEnvelope.json`，`additionalProperties: false`。

### 7.2 主题

| topic | payload | 订阅方 |
|---|---|---|
| `raw.docs` | `{raw_item_id, source, vuln_id?}` | dedup / enrich |
| `intel.items` | `{vuln_id, merged_raw_ids[], merge_type}` | enrich / metrics |
| `intel.enrich.requested` | `{vuln_id, dimensions[]}` | EnrichAgent |
| `enrich.items` | `{vuln_id, dimension, confidence, source[], degraded_to}` | knowledge / metrics |
| `fallback.events` | FallbackEvent（权威内联契约） | metrics / 告警 / 日报（FB1 降级可见） |
| `enrich.triage` | `{vuln_id, priority, ai_risk_category, severity}` | alert / qa |
| `qa.queries` | QueryTurn（权威内联契约） | Q 线 |
| `qa.answers` | Answer（权威内联契约） | 前端 / metrics / eval |
| `intel.alert.raised` | `{level, vuln_id, message}` | notifier |
| `intel.report.daily` | `{markdown}` | api / 前端 |
| `intel.budget.exceeded` | `{day, spent_cny, budget_cny}` | WatchAgent / alert |
| `intel.selfheal.action` | `{action, target, reason}` | WatchAgent / metrics |

## 8. 事件与源码的对应关系

| topic | 生产者 | 文件 |
|---|---|---|
| `raw.docs` / `intel.items` | 采集与去重 | `src/aiintel/agents/nodes.py` |
| `intel.enrich.requested` / `enrich.items` / `fallback.events` | 富化 Agent | `src/aiintel/services/enrich/s2_events.py` |
| `enrich.triage` | Triage | `src/aiintel/agents/nodes.py` |
| `intel.alert.raised` | 告警 | `src/aiintel/core/alerts.py` |
| `intel.report.daily` | 报告 | `src/aiintel/agents/report.py` |
| `qa.queries` / `qa.answers` | 问答 | `src/aiintel/services/qa/agent.py` |
| `intel.budget.exceeded` / `intel.selfheal.action` | 成本与自愈 | `src/aiintel/core/cost.py` / `agents/watchdog.py` |

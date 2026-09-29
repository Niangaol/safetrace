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
查询参数：`q`（关键词）、`severity`（逗号分隔）、`ai_risk_category`、`cwe`、`vendor`、`has_poc`(bool)、`published_from` / `published_to`、`enriched`(bool)、`page` / `page_size`、
`sort`（`published_at` | `cvss_score` | `epss` | `kev` | `fetched_at`）。

> **`sort=epss|kev` 是 2026-09-29 夜新增的**：动态优先级（`services/triage.py`）按 **KEV + EPSS + CVSS** 加权，
> 但这两个字段此前只落库、不外发，前端因此看不到"为什么这条排前面"。现在：
> - 响应体补 `epss` / `kev` / `kev_due_date` 三个字段；
> - `sort=epss` 用 `coalesce(epss, -1.0)` 降序，保证"无 EPSS"的条目排在最后
>   （SQLite 与 PG 对 NULL 在 DESC 下的位置处理不同，必须显式处理）；
> - 实测同样 13 条数据下 `sort=epss` 与 `sort=cvss_score` 的**首条不同**，
>   即"CVSS 单因子"与"被利用概率优先"会给出不同结论。

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
      // 动态优先级信号（KEV/EPSS 采集器写入；triage 用它们加权）
      "epss": 0.87,              // 0~1，未来 30 天被利用概率；未覆盖时为 null
      "kev": true,               // 是否已列入 CISA KEV（真 bool，不是 0/1/None）
      "kev_due_date": "2026-10-15",  // KEV 官方强制修复截止日，仅 KEV 源提供，否则 null
      "cwe": ["CWE-78"],
      "cpe": ["cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*"],
      "ai_risk_category": "ai_infrastructure",
      "exploit_status": "poc_available",
      "quality_score": 0.92,      // DQ1 质量闸门输出
      "published_at": "2026-09-20T08:00:00+08:00",
      "fetched_at": "2026-09-20T10:12:00+08:00",
      "collect_latency_seconds": 7920,
      "source_count": 3,
      "enriched": true
    }
  ],
  "total": 13,
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

`stream: true` 响应 `text/event-stream`。**帧格式**（`dumps_event()`）：每帧两行，
`event: <名>` + `data: <整个事件对象的 JSON>` —— 注意 **JSON 里也带一个 `event` 字段**，
前端解析请以 `data:` 载荷里的 `event` 为准（`event:` 行是同名的冗余，用于调试与 curl 可读性）。

> ⚠️ 实测校准（2026-09-29 夜）：本节的示例原先与实现不一致（`stage` 事件缺 `event` 字段、
> `citation` 用 `citations` 递增数、`done` 里写 `answer_id`）。下面按
> `src/aiintel/services/qa/agent.py` 的**实际产出**重写；前端 `api.ts` 的 SSE 解析
> 也必须按"逐行找 `data:`"来做 —— 早期实现只取每帧第一行，会把这类多行帧整帧丢掉。

```
event: trace
data: {"event":"trace","step":"recv","tool":"chat","elapsed_ms":0,
       "input":{"question":"CVE-2026-31001 怎么修复？","top_k":8}}

event: stage
data: {"event":"stage","stage":"rewrite","message":"正在理解问题意图…"}

event: trace
data: {"event":"trace","step":"plan","tool":"QAAgent.plan","elapsed_ms":3950,"ok":true,
       "output":"拆出 3 个子问题 / 4 条检索式","sub_questions":["…"],"queries":["…"]}

event: trace
data: {"event":"trace","step":"retrieve.1","tool":"hybrid_search","elapsed_ms":3950,
       "input":{"queries":["CVE-2026-31001"],"top_k":8,"round":1}}
event: trace
data: {"event":"trace","step":"retrieve.1","tool":"hybrid_search","elapsed_ms":3981,"ok":true,
       "output":"合并后 3 条，其中新增 3 条","round":1,"fetched":3,"new":3,"total":3}

event: stage
data: {"event":"stage","stage":"retrieve","round":1,"hit":0}      ← hit 是**当前累计**命中数

event: stage
data: {"event":"stage","stage":"retrieve","round":3,"hit":1}

event: citation
data: {"event":"citation","id":"S1","title":"vuln:CVE-2026-31001","url":"https://nvd.nist.gov/vuln/detail/CVE-2026-31001","owner_type":"vuln","owner_id":"CVE-2026-31001","score":0.0}

event: token
data: {"event":"token","text":"结论：…"}      ← 增量文本，前端累加

event: reasoning
data: {"event":"reasoning","step":1,"sub_question":"识别与提问相关的漏洞","finding":""}

event: reasoning
data: {"event":"reasoning","step":2,"sub_question":"汇总其可利用性与影响面","finding":"证据支持"}

event: done
data: {"event":"done","session_id":"sess_…","elapsed_ms":25190,"citations":3,
       "citation_count":3,"model":"deepseek-v4-pro","cost_cny":0.0316,
       "degraded":false,"reasoning":[{"step":1,"sub_question":"…","finding":"证据支持"}]}
```

### `trace` 事件（轨迹 / 过程可视化）

**每个关键步骤发两帧**：开始帧（只有 `input`）与结束帧（带 `ok`/`output`），
前端按 `step` 合并即可画出"哪一步在跑、拿到什么、花多久"。

| 字段 | 说明 |
| --- | --- |
| `step` | 步骤标识：`recv` / `plan` / `retrieve.<n>` / `citations` / `generate` / `reasoning` / `check` / `regenerate` / `no_evidence` / `failed` |
| `tool` | 该步实际调用的工具或函数名（如 `hybrid_search`、`LLM.stream`、`check_answer`） |
| `input` | 工具入参（开始帧） |
| `ok` / `output` | 是否成功 / 结果摘要（结束帧） |
| `elapsed_ms` | **自请求开始**的累计耗时（不是单步耗时）。单步耗时 = 本步耗时 − 上一步耗时 |
| 其余键 | 步骤特有信息（`fetched`/`new`/`total`、`chars`/`model`、`score` 等），原样透传 |

**两条设计约束**：

1. **第一帧必须是 `trace:recv`（`elapsed_ms=0`）** —— 让用户在 0ms 就看到反馈，
   而不是盯空白等 20 多秒；有测试 `test_answer_stream_event_sequence` 钉住。
2. **`trace` 与答案正文是两条并行的流**：`token` 照旧边走边发，`trace` 只描述过程。
   不要为了等轨迹而缓冲正文 —— 那会把"先有什么发什么"的意义抵消掉。

多条**容易被误读**的地方：

1. **`reasoning` 事件会发两轮**：先在 `token` 段之后发一遍（`finding` 通常为空），
   自检完成后再发一遍**补全 `finding`**。前端应按 `step` 覆盖而非追加，否则会看到重复步骤。
2. **`citation.score` 在当前环境恒为 `0.0`** —— 未装 `sentence_transformers` 时检索降级为关键词匹配，
   没有语义分。这不是 bug，但**不应当**在页面上伪装成有意义的排序分（演示页已注明）。
3. **`done.reasoning` 也带完整推理链**，可直接以它为准做最终渲染。

`stream: false` 时返回同一个 `done` 事件对象。

**成本实测**：一次问答（8 条证据 + 四段式答案）约 **¥0.03**（`deepseek-v4-pro`）；
`cost_cny` 为真实计费值，未配 key 走 cache provider 时为 `0.0`。

> ⚠️ **`max_tokens` 陷阱（配好 key 后必读）**：本仓所用模型强制输出思维链，思维 token 计入 `completion`。
> `max_tokens` 给小了（如 500）时推理会吃满额度、`content` 为空串，**HTTP 仍是 200**，
> 于是规划/自检静默失败、答案为空。当前取 2500（JSON 类）/ 3000（答案），
> 并可用 `LLMResult.truncated` / `LLMResult.reasoning_tokens` 判断是否被截断。

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

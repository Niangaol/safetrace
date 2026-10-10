# S2 情报总线 · 主题清单（契约件 v1）

> 唯一真相来源：本文件 + `schemas/*.json`。事件信封统一为：
> `Envelope{ event_id, topic, occurred_at, trace_id, causation_id, payload, schema_version }`
> 消费者幂等按 `event_id` 去重；死信自动重试 3 次后进人工队列。

## 主题表

| 主题 | payload 契约 | 生产者 | 消费者 | 说明 |
|---|---|---|---|---|
| `raw.docs` | RawDoc.json | Y1/Y2 | Y3 | 原始抓取文档，`external_id` 幂等回放 |
| `intel.items` | IntelItem.json | Y3 | F 线 / DQ1 | 不可变情报对象，归并后多源引用 |
| `dq.verdicts` | QualityVerdict（内联） | DQ1 | S1 / A1 | 四档判定：pass/degrade/review/quarantine |
| `enrich.triage` | TriageOrder（内联） | Y5 | F 线 | 分级派发口，P0-P3 + route |
| `enrich.papers` | EnrichmentResult.json（papers 维度） | F1 | F6 | 论文关联结果 |
| `enrich.items` | EnrichmentResult.json | F6 | S1 | 富化收口产物，带 evidence_refs |
| `qa.queries` | QueryTurn（内联） | 编排层 | Q1 | 问答入口 |
| `qa.answers` | Answer（内联） | Q4 | 前端/编排层 | 带引用与推理链的答案 |
| `decision.replies` | DecisionReply.json | D4 | Y5/Q1/Q3 | 结构化决策回复，decided_by 必填 |
| `fallback.events` | FallbackEvent（内联） | FB1 各层 | A1 | 兜底事件，兜底透明率 100% 的证据源 |
| `asset.scans` | AssetScanRun（内联） | A 线扫描器 | 前端 / A1 | 本地资产扫描轮次摘要（分组/仓库/组件计数与显式降级） |
| `asset.alerts` | AssetAlertRecord（内联） | A 线匹配器 | 前端 / A1 | 组件命中情报受影响版本区间产生的提醒（按 group_id+component_key+cve_id 去重） |

## 降级标记（红线：禁止静默兜底）

任何降级响应必须携带：

```json
{
  "degraded_to": "cache|memory_index|template|fixture|source_switch|provider_switch",
  "degraded_state": { "label": "用户可见文案", "since": "ISO-8601", "detail_ref": "trace_id" },
  "recovery_hint": "人工恢复提示（可空）"
}
```

用户在界面必须看到降级横幅或答案尾部标注；缺标记视为缺陷。

## 内联契约（QualityVerdict / TriageOrder / QueryTurn / Answer / FallbackEvent）

```json
// QualityVerdict（dq.verdicts）
{
  "item_id": "string",
  "item_kind": "intel | enriched",
  "quality_score": "0-1",
  "dimension_scores": { "structure": 0, "completeness": 0, "consistency": 0, "timeliness": 0, "sourcing": 0 },
  "flags": ["ts_no_tz", "reject_status", "poc_dead_link", "key5_missing", "boilerplate", "multi_id_mismatch", "unknown_version"],
  "injection_score": "0-1?",
  "injection_flags": ["instruction_override","role_confusion","zero_width_chars","base64_hidden","html_entity_encoded","comment_embedded","exfil_instruction","fake_system_prompt","citation_spoof","multi_stage"]?,
  "verdict": "pass | degrade | review | quarantine",
  "quarantine_ref": "string?",
  "reviewer": "string?",
  "reviewed_at": "ISO-8601?",
  "gate_version": "1.0.0"
}

// TriageOrder（enrich.triage）
{
  "intel_id": "string",
  "level": "P0 | P1 | P2 | P3",
  "reason": "string",
  "route": "full_enrich | lite_enrich | index_only",
  "enrich_plan": [{ "dimension": "paper|asset|poc|cvss|remediation|triage", "required": true }],
  "sla_deadline": "ISO-8601"
}

// QueryTurn（qa.queries）
{
  "session_id": "string",
  "turn_id": "string",
  "text": "string",
  "history": [{ "role": "user|assistant", "text": "string" }]
}

// Answer（qa.answers）
{
  "session_id": "string",
  "turn_id": "string",
  "text_md": "string（结论—证据—推理链—置信度 四段式）",
  "citations": [{ "chunk_id": "string", "url": "string" }],
  "reasoning_chain": ["string"],
  "confidence": "0-1",
  "abstained": false,
  "degraded_to": "string?",
  "stale_warning": { "threshold_days": 0, "oldest_published_at": "ISO-8601?", "unknown_published_at": 0, "note": "string" }?,
  "injection_guard": { "screened": false, "max_score": "0-1?", "flags": ["instruction_override"], "untrusted_evidence": 0, "note": "string" }?,
  "source_conflicts": [{ "field": "cvss_v3_base", "values": [{ "source": "nvd|cna|ghsa|adp|system_derived", "score": 0 }], "resolved": false, "rationale": "string?" }]?
}

// AssetScanRun（asset.scans）
{
  "run_id": "string",
  "group_id": "string（监控分组 id；一次性扫描为 adhoc）",
  "group_name": "string",
  "started_at": "ISO-8601",
  "finished_at": "ISO-8601",
  "roots": ["string"],
  "status": "ok | partial",
  "degraded_to": "git_unavailable | timeout | read_error | repo_limit | component_limit | null",
  "note": "string?",
  "repo_count": 0,
  "component_count": 0,
  "skipped": [{ "path": "string", "reason": "string" }]
}

// AssetAlertRecord（asset.alerts）
{
  "alert_id": "string",
  "created_at": "ISO-8601",
  "group_id": "string（告警所属分组；同一组件同一 CVE 在每个分组各提醒一次）",
  "component_key": "string（ecosystem:归一化组件名，与 group_id+cve_id 共同去重）",
  "ecosystem": "npm | pypi | go | cargo | maven | composer | gem | docker | github-actions",
  "name": "string",
  "version": "string（空 = 未锁定）",
  "repo_path": "string",
  "cve_id": "string",
  "intel_id": "string",
  "severity": "string?（展示层富化，匹配器不产出）",
  "matched_rule": "string",
  "matched_ranges": ["string"],
  "reason": "string",
  "vendor_unverified": true,
  "status": "new | seen",
  "first_run_id": "string"
}

// FallbackEvent（fallback.events）
{
  "event_id": "string",
  "layer": "L1 | L2 | L3 | L4",
  "trigger": "string",
  "action_taken": "string",
  "degraded_of": "string",
  "user_visible": true,
  "degraded_state": { "label": "string", "since": "ISO-8601", "detail_ref": "string" },
  "recovery_hint": "string?",
  "trace_id": "string"
}
```

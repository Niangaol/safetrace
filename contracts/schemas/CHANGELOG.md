# contracts/schemas CHANGELOG

> 纪律（docs/GITHUB-FLOW.md 第五节）：只允许「新字段追加 + 旧字段标 deprecated」；
> 禁止改语义、改枚举值含义、删字段。每次契约改动必须在此登记，并在 PR 中三线 sign-off。

## v1.1.0（2026-09-29，D2；契约冻结前增量）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| DecisionReply | D4/MG1 → Y5/Q1/Q3 调用方、`decision.replies` 订阅方 | `decided_by` 追加 `human`，为人工接管预留通道；同步 OpenAPI、TypeScript 类型和样例。原有四个值及必填字段不变，旧生产者兼容；按旧枚举严格校验的消费者需升级后才能接收人工决策。此处仅扩展契约，人工兜底运行链路归 A-02。 |

## v1.0.0（2026-09-28，D1 冻结）

| 契约 | 生产者 → 消费者 | 要点 |
|---|---|---|
| RawDoc | Y1/Y2 → Y3 | 7 必填 + parse_warnings；source_type 11 枚举 |
| IntelItem | Y3 → F 线 | first_seen_at/published_at 双时钟分离；entities 五件套；aliases 建关联不合并 |
| EnrichmentResult | F 线 → S1 | 每维度强制 source+confidence；source_of_score 六枚举禁静默覆盖 |
| DecisionRequest | Y5/Q1/Q3 → MG1 | typed question 三元组 choice/score/noul，cardinality_max 255 |
| DecisionReply | MG1 → 调用方 | decided_by 四通道如实记录，fallback_reason 必填条件化 |
| RetrievalRequest | Q2 入口 | min_quality 下限防脏数据入检索；doc_type 过滤 |
| RetrievalResponse | Q2 → Q3/Q4 | provenance 必填（url+section）；embedder_model_id 绑定 S3 |
| ToolRegistration | S4 → 编排层 | 三层契约中契约层落体；exec 默认 false（F3 合规红线） |

内联契约（events.md）：QualityVerdict / TriageOrder / QueryTurn / Answer / FallbackEvent。

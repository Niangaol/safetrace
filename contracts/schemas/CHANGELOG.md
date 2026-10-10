# contracts/schemas CHANGELOG

> 纪律（docs/GITHUB-FLOW.md 第五节）：只允许「新字段追加 + 旧字段标 deprecated」；
> 禁止改语义、改枚举值含义、删字段。每次契约改动必须在此登记，并在 PR 中三线 sign-off。

## v1.2.2（2026-10-10，D6 冻结后增量；P-05）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| Answer（events.md 内联） | Q4 → 前端/编排层 | 追加**可选** `source_conflicts` 数组字段；既有必填集合不变，旧生产者合法（纯追加、无破坏性）。元素形状 `{ field: "cvss_v3_base", values: [{ source, score }], resolved, rationale? }` 与富化 F6 的 ScoreConflict 一致（shared 为权威定义，enrich re-export 兼容）。缺省语义：缺省 = 本轮未提供冲突信息，**禁止当作无冲突**；`resolved=false` 表示多源分差未仲裁，分歧本身必须原样呈现，消费方不得把多源分值压成单一结论。实现：Q4 `synthesizeAnswer` 新增 `source_conflicts` 选项，经 fail-closed 归一化校验后在正文输出「## 来源冲突」段落并进 reasoning_chain，拒答路径同样保留；富化侧 `runEnrichment` 返回类型 widen 为 EnrichmentOutcome（内存侧带 conflicts，总线发布的 EnrichmentResult 契约不变）。schema 文件数仍为 8。 |
## v1.2.1（2026-10-09，D6 冻结后增量；A 线多分组监控）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| events.md 两个内联契约 | A 线扫描器/匹配器 → 前端 / A1 | **纯追加**：AssetScanRun 追加 group_id/group_name；AssetAlertRecord 追加 group_id。去重语义收窄为 group_id + component_key + cve_id（同一组件同一 CVE 在每个分组各提醒一次，分组即监控边界）。缺省语义：group_id=adhoc = 一次性扫描（旧行为），旧生产者合法；degraded_to=null = 无降级，禁止把缺省读成"扫描完整"。schema 文件数仍为 8。 |

## v1.2.0（2026-10-09，D6 冻结后增量；A 线本地资产扫描）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| events.md 主题表 + 两个内联契约 | A 线扫描器/匹配器 → 前端 / A1 | **纯追加**：新增主题 `asset.scans`（AssetScanRun）与 `asset.alerts`（AssetAlertRecord）。既有主题、payload 契约、schema 文件（仍为 8 个）均未改动，旧生产者/消费者不受影响。缺省语义：`degraded_to=null` = 无降级，禁止把缺省读成"扫描完整"；`vendor_unverified` 恒为 true（本地扫描不携带厂商身份）；`severity` 由展示层富化，匹配器不产出，缺省 = 未富化。告警幂等键 = `component_key + cve_id`（存储层 UNIQUE 约束），重复扫描/重复匹配不产生重复提醒。 |

## v1.1 汇总（D6 = 2026-10-03 契约冻结前增量，C-01～C-06）

> 全部为**纯追加**：既有必填字段、枚举语义、字段含义均未改动；旧生产者与旧消费者保持兼容。
> 缺省语义一律按"未提供/未知"处理，禁止消费者把缺省当作"已筛查/已评估/可信/新鲜"。

| 台账 | 契约/配置 | 追加内容 | 状态 |
|---|---|---|---|
| C-01 | DecisionReply.json + openapi | `decided_by` 追加 `human` 枚举 | 代码完成，待三线 sign-off |
| C-02 | RetrievalResponse.json（chunk） | 可选 `published_at` + `trust` | 代码完成，待三线 sign-off |
| C-03 | QualityVerdict（events.md 内联） | 可选 `injection_score` + `injection_flags` | 代码完成，待三线 sign-off；A-04 检测已落地（2026-10-09，见 v1.1.2 条目） |
| C-04 | Answer（events.md 内联） | 可选 `stale_warning` + `injection_guard` | 代码完成，待三线 sign-off |
| C-05 | config/models.yml + openapi 请求体 | provider `trust_boundary` + role `data_domain` + 隔离闸门 | 代码完成，待三线 sign-off |
| C-06 | CHANGELOG + validate_contracts.py | v1.1.x 逐条登记 + expected 集合/CHANGELOG 交叉校验 | 本轮落地 |

> schema 文件数仍为 8（C-03/C-04 为 events.md 内联契约，C-05 为配置文件，均不新增 schema 文件）。

## v1.1.4（2026-09-30，D6 冻结前增量；C-05）

| 契约/配置 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| 模型清单 + openapi 请求体（C-05，非 schemas/ 目录，登记备查） | MG1 调用方 → MG1 | `config/models.yml` 的 provider 追加可声明 `trust_boundary`(cloud/local/cache)、role 追加 `data_domain`(public/private)；openapi `/v1/chat/complete` 与 `/v1/embed` 请求体追加可选 `data_domain`。均为**新增可选字段**，缺省向后兼容（trust_boundary 按 provider type 推断、data_domain 缺省 public）。隔离闸门行为：`data_domain=private` 遇到 `trust_boundary=cloud` 的 provider 时**硬拒**（非 warning）并登记 FallbackEvent（degraded_of=`isolation:private->cloud`）与 lineage，不降级改投云端；仅逐级尝试 local/cache，全链无 local provider 时显式失败。数据隔离的完整实现（private 标记扫描、全链无 local 的显式失败路径）归 A-03。 |

## v1.1.3（2026-09-30，D6 冻结前增量；C-04）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| Answer（events.md 内联） | Q4 → 前端/编排层 | 追加**可选** `stale_warning` 与 `injection_guard` 两个对象字段；既有必填集合不变，旧生产者合法（纯追加、无破坏性）。缺省语义：`stale_warning` 缺省 = 未做时效评估，禁止当作证据新鲜；`injection_guard.screened=false` 必须显式出现，禁止把未筛查读成已筛查干净。实现上 Q4 依据 C-02 的 `published_at` 判定过龄或未知并在正文输出用户可见提示，A-04 落地前 `screened` 恒为 false 并如实统计 untrusted 证据条数；A-05 将按意图细化时效阈值，本条只保证过龄或未知必须显式可见。 |

## v1.1.2（2026-09-30，D6 冻结前增量；C-03）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| QualityVerdict（events.md 内联） | DQ1 → S1/A1、注入防护消费方 | 追加**可选** `injection_score`（0-1）与 `injection_flags`（十类注入迹象枚举）；`required` 与既有字段不变，旧生产者合法（纯追加、无破坏性）。`flags` 同步登记既有实现已在用的 `unknown_version`。**缺省 = 未做注入筛查**，禁止调用方当作“已筛查且干净”。**A-04 已于 2026-10-09 落地**：DQ1（gate 1.1.0）对 title+summary 跑共享本地启发式 `screenPromptInjection` 并如实填充两字段；命中迹象时 verdict 至少为 `review`（路由人工复核，pipeline 不放行），无法筛查时 fail-closed 同样至少 `review` 且不填字段（保持“未筛查”缺省语义）。这是**有界启发式，不是 prompt-injection 防护保证**。样例见 `fixtures/qualityverdict.injection.sample.json`，对抗样本见 `fixtures/injection/`。 |

## v1.1.1（2026-09-30，D6 冻结前增量；C-02）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
|---|---|---|
| RetrievalResponse（chunk） | Q2/来源证据构建 → Q3/Q4、前端 | chunk 追加**可选** `published_at`（date-time）与 `trust`（trusted/untrusted）；`required` 与既有字段不变，旧生产者仍合法（纯追加、无破坏性）。`published_at` 只取上游已归一化的 IntelItem.published_at（适配器已按 UTC 归一化无时区值），缺失即留空；`trust` 按来源判定：结构化权威源（NVD/KEV/CVE.org/OSV/GHSA/arXiv）及其系统派生为 trusted，网页/文档类外部文本为 untrusted。**缺省 = 未知**，消费者不得把缺省当作 trusted 或新鲜。迁移动作：Q2 已在 Qdrant 载荷中同步携带并回填两字段；消费方可在过滤/展示中按需读取，无需立即改造。 |

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

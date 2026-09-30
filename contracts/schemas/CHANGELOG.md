# Schema 变更登记（CHANGELOG）

> 纪律：只允许「新字段追加 + 旧字段标 deprecated」；禁止改语义、改枚举值含义、删字段。
> 权威 8 个 Schema **逐字冻结**（字节级指纹在 `FROZEN_MANIFEST.json`），本仓无权修改；
> 本仓自有 3 个可演进，但每次改动必须在此登记（C-06 交叉校验的权威面）。
> 登记表与 `scripts/validate_contracts.py` 的 `AUTHORITATIVE_SCHEMAS` / `LOCAL_SCHEMAS`
> 必须一致，校验器会做三方防漂（目录 ↔ 登记集合 ↔ 本文件）。

## 注册表（当前）

| 集合 | schema 数 | 文件 |
| --- | --- | --- |
| 权威冻结 | 8 | RawDoc.json、IntelItem.json、EnrichmentResult.json、DecisionRequest.json、DecisionReply.json、RetrievalRequest.json、RetrievalResponse.json、ToolRegistration.json |
| 本仓自有 | 3 | EventEnvelope.json、DimensionEvidence.json、LocalPayloads.json |
| 非 schema | 1 | FROZEN_MANIFEST.json（指纹表，不计入 schema 数） |

合计 **11 个 schema（权威 8 + 本仓 3）**；fixtures 目录样例与 `validate_contracts.py::FIXTURE_SCHEMA`
登记逐一对应。

## 变更条目

### v1.1.1（2026-09-30，C-03 对齐；BigPickel）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
| --- | --- | --- |
| `LocalPayloads.json` → `definitions.QualityVerdict` | DQ1 → S1/A1/注入消费方 | 追加**可选** `injection_score`（0-1）与 `injection_flags`（十类注入迹象枚举）；`flags` 枚举登记 `unknown_version`。纯追加，`required` 与既有字段不变，旧生产者合法。**缺省 = 未做注入筛查**，禁止调用方当作"已筛查且干净"；检测实现不在本仓（A-04 约定），DQ1 不填。样例 `fixtures/qualityverdict.injection.sample.json`（fixture 12→13）。 |

### v1.1.0（2026-09-30，上游 C-02 同步；DeepSeek）

| 契约 | 生产者 → 消费者 | 变更与兼容性 |
| --- | --- | --- |
| `RetrievalResponse.json` → `chunk` | Q2 → 前端/自检 | 追加可选 `published_at`（已归一化时间，缺省=未知）与 `trust`（trusted/untrusted 二值，缺省=未知）。纯追加，旧生产者合法。对应 `services/knowledge/trust.py` 与 `RetrievalResponse` 类型镜像。 |

### v1.0.0（2026-09-28，正式冻结）

权威 8 个 Schema 从 SafeTrace `contracts/schemas` 逐字引入并冻结字节级指纹；
本仓自有 3 个建成（EventEnvelope 扩展信封 / DimensionEvidence 7 维明细 /
LocalPayloads 内联载荷定义）。主题契约见 `contracts/events.md`（权威 10 + 本仓扩展 6）。
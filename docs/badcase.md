# 富化线 badcase 库

> 计划 D12 交付物（`docs/富化线详细设计.md` §7）。**每条错例必须有归因与修复动作**，
> 答辩时这张表比"准确率 95%"更有说服力：它证明我们知道自己在哪会错。
>
> 维护规则：每发现一条错例，当天登记；修复后在「状态」列写 `已修(commit/日期)`，不要删除记录。

## 一、登记模板

```markdown
### BC-00X 一句话标题

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-10-XX |
| 漏洞 | CVE-2026-XXXXX（vuln_id `v_xxx`） |
| 维度 | paper / asset / poc / cvss / fix / consistency / ai_risk |
| 现象 | 系统给出的结论是什么（原文照抄） |
| 期望 | 正确结论应该是什么 |
| 归因 | ① 数据源问题 ② 提示词问题 ③ 解析/规则问题 ④ 阈值问题 ⑤ 数据模型缺字段 |
| 影响 | 单条错 / 系统性错（影响多少条） |
| 修复动作 | 具体改哪个文件哪一行，或"接受并降级标注" |
| 状态 | 待修 / 已修(日期) / 已知限制（写进报告） |

**证据**：`GET /vulns/{id}/evidence` 截图或 JSON 片段
```

## 二、已登记错例

### BC-001 POC `verified` 被硬编码为 true

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-09-30 |
| 漏洞 | 全部走 F3 的漏洞（系统性） |
| 维度 | `poc` |
| 现象 | `services/enrich/dimensions.py` 第 184 行：只要 LLM 判定 `is_poc=true`，就写入 `"verified": True`。前端据此可能显示"已验证"，但系统**从未运行过**任何 POC |
| 期望 | 区分三件事：`listed`（检索到）、`tier`（可信度分级）、`runtime_verified`（真的运行过，初赛恒 `false`） |
| 归因 | ④ 口径问题：把"检索到"当成了"已验证" |
| 影响 | 系统性（所有 POC 结论），且属于"看起来像造假"的高风险表述 |
| 修复动作 | 按 `docs/富化线详细设计.md` §3 F3 改造：`value.pocs[]` 增加 `tier` / `evidence_kind` / `runtime_verified`；`verified` 语义收紧为 `tier >= likely`；前端禁止出现"已验证"字样 |
| 状态 | 待修（计划 D9–D10） |

**证据**：`dimensions.py:184` — `"verified": True,`

### BC-002 富化结论没进检索空间

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-09-30 |
| 漏洞 | 全部（系统性，影响 Q 线问答质量） |
| 维度 | `fix` / `consistency` / `cvss` |
| 现象 | Q 线问"这个漏洞怎么修"，召回不到修复建议：`services/knowledge/indexer.py::persist_vuln` 只索引 `vuln.title + description + summary`，富化结论从未写入 `chunk` 表 |
| 期望 | 富化结论（修复建议、一致性共识、影响说明）以 `owner_type="enrichment"` 入向量库，可被混合检索命中并被引用 |
| 归因 | ⑤ 数据模型/写入链路缺一步（不是模型能力问题） |
| 影响 | 系统性；直接削弱"情报富化"在问答中的可见度 |
| 修复动作 | `persist_vuln` 中增加 `index_owner("enrichment", ...)`；`RetrievalRequest/Response` 证据包增加 `enrichment_dimension` 字段 |
| 状态 | 待修（计划 D11） |

**证据**：`indexer.py:234-236` — 仅 `await index_owner(session, "vuln", row.id, row.title or "", f"{row.description}\n{row.summary or ''}")`

### BC-003 `references` 抽取后未入库

| 项 | 内容 |
| --- | --- |
| 发现日期 | 2026-09-30 |
| 漏洞 | 全部（系统性，阻塞 F3/F5） |
| 维度 | `fix` / `poc` |
| 现象 | `services/ingest/pipeline.py::normalize_item` 已经抽出 `references` 与 `affected_products`，但 `indexer.py::_upsert_vuln` 的字段循环里没有它们 → F 线读不到补丁链接与受影响产品 |
| 期望 | `Vuln` 表持久化 `references` / `affected_products`（并追加 `version_ranges` / `quality_score`） |
| 归因 | ⑤ Y 线（监测线）与 F 线的接口缺口 |
| 影响 | 系统性；阻塞 F5 修复建议（无法定位官方补丁）与 F1/F2 检索质量 |
| 修复动作 | `db/models.py` 给 `Vuln` 加 4 个可空列；`_upsert_vuln` 写入；F 线读到 `None` 时走降级路径 |
| 状态 | 待修（计划 D3–D5，责任：甲 + 乙） |

**证据**：`pipeline.py:131` 产出 `references`；`models.py::Vuln` 无对应列

## 三、统计（随时间更新）

| 维度 | 已登记 | 已修 | 已知限制 |
| --- | --- | --- | --- |
| `paper` | 0 | 0 | — |
| `asset` | 0 | 0 | 资产画像为 Mock（合规） |
| `poc` | 1 | 0 | — |
| `cvss` | 0 | 0 | — |
| `fix` | 1 | 0 | 无官方补丁时只给通用建议 |
| `consistency` | 1 | 0 | — |
| `ai_risk` | 0 | 0 | — |

> 三条 BC-001~003 是**接手时的既存问题**，登记目的是"先承认，再修"，不是本轮的返工。

# 路线评估：动态优先级（F5+KEV/EPSS）与 深化 RAG（F5/F6）

> **这是一份决策记录，不是任务清单。** 目的是让下一个 AI 知道这两条提案**为什么是这个结论**，
> 不要重新评估一遍。
>
> 编写日期：2026-09-29　评估基线：466 passed / 11 schema / 冻结指纹 8-8
> 关联：`docs/任务指示-Y线.md`（任务清单）、`docs/契约对齐-SafeTrace.md`（契约设计）
>
> **✅ 2026-09-29 夜更新：提案① 已按本文的改写版实施完毕**（见 §7 实施结果）。
> **✅ 同时补上了 KEV 数据源本身**（见 §8）—— §1 曾断言「KEV 已接通」，那说的是
> 管道；KEV 标记一直取自 NVD 二手镜像，覆盖不全。官方目录已接入。
> 提案② 的结论未变：前置条件仍缺（桩底座 + 无 embedding + 无 Key + 无真库），**不要开工**。

---

## 0. 结论速览

| 提案 | 原始定级 | 本次结论 | 一句话理由 |
| --- | --- | --- | --- |
| 引入动态优先级 | P0 立即 | ✅ **已实施（见 §7）** | KEV/EPSS **早就接好了**，真实缺口只是排序逻辑 + 一条数据路径 —— 工作量比预想小得多 |
| 深化 RAG 应用 | P0 立即 | ⚠️ **不建议按原描述做** | 与 F5 版本号红线、F6 确定性设计**两处冲突**，且知识底座目前是**桩模式**（无库可检索） |

**两条不应并列。** ① 已做完；② 的前置条件仍未满足。

---

## 1. 核实前置：KEV/EPSS 早已全链路接通

提案① 原文说「**集成** CISA KEV 与 EPSS 数据」。**这一步不需要做，已经完成了。**

| 层 | 位置 | 现状 |
| --- | --- | --- |
| DB 列 | `db/models.py` L123 `epss`(Float)、L124 `kev`(Boolean) | ✅ 存在 |
| 解析（富化侧） | `services/enrich/nvd.py:77-79` | ✅ 已解析 |
| 解析（采集侧） | `services/collectors/nvd.py` | ✅ 有一条关键警告，见下 |
| 已被使用 | `consistency.py:452`（时间线）、`cvss_impact.py:64` | ✅ 在用 |
| 契约投影 | `core/contracts.py:578-582` → `epss_score` / `kev_flag` | ✅ 已导出 |

> ⚠️ `services/collectors/nvd.py:52` 有一条必须知道的警告：
> **不能用 `hasKev` 兜底 —— KEV 只有约 1% 的漏洞**，会漏掉绝大多数 AI 组件漏洞。
> 这条约束对提案① 的权重设计是决定性的（见 §2.3）。
>
> 📌 **注意本树里有两个 `nvd.py`**：`services/collectors/nvd.py`（采集器）与
> `services/enrich/nvd.py`（F4 解析器）。改代码/查证时务必写全路径，别看错文件。

**所以提案① 的真实内容是：让 `node_triage` 用这些数据排序，而不是新增数据管道。**

---

## 2. 提案①：引入动态优先级 —— ✅ 建议做（改描述后）

### 2.1 改写后的准确表述

> **用 EPSS / KEV / CVSS 重写 `node_triage` 的优先级排序，替代当前的单因子 CVSS 排序。**
> 不涉及任何新数据集成。

### 2.2 当前排序逻辑（`agents/nodes.py::node_triage`）

```python
SEVERITY_PRIORITY = {"critical": "urgent", "high": "high", "medium": "normal", "low": "normal"}
# nodes.py L42
target = max(pool, key=lambda i: i.get("cvss_score") or 0.0)  # 单因子，且只挑一条
priority = SEVERITY_PRIORITY.get(severity)  # L274
```

**两个缺陷**：

1. **单因子**：只看 CVSS，完全没用已在库的 `epss` / `kev`。
2. **一次只处理一条**（`max(...)` 取单个）—— 这也是 F 线「富化完整性」分数上不去的原因
   （`docs/交接说明.md` §12 记为三个阻塞项之一）。

> 📌 注意别混淆两个 `priority`：`Vuln.priority` 是 `Integer`（`db/models.py` L99，default=100），
> 与 `node_triage` 产出的**字符串** `priority`（urgent/high/normal）是两回事。

### 2.3 必须避开的坑

| 坑 | 说明 |
| --- | --- |
| **不能用 KEV 单独排序** | KEV 覆盖约 1%（`collectors/nvd.py:52` 警告）。99% 的条目拿不到信号，会导致绝大多数条目同分 |
| **职责别塞进 F5** | 见下 |
| **权重必须版本化 + 可复算** | 与 DQ1 的 `gate_version` 同一套要求：同输入同输出，否则无法解释「为什么这条排第一」 |
| **有两个 `nvd.py`** | `collectors/` 与 `enrich/` 各一个，别改错文件 |

**职责归属（提案原文有错配）**：提案写「升级 **F5 修复建议模块**的排序逻辑」。
但 F5 回答「**怎么修**」，「**先修哪个**」是 triage/派单的职责 —— `TriageOrder` 契约和 P0-P3 就在那儿。

**正确切分**：

- `node_triage` **决定**优先级（它能看全批次，是唯一有这个视角的节点）
- F5 **消费**优先级：同批里排第一的漏洞，给更详细的版本号、补丁链接、缓解措施；排后的给通用模板

### 2.4 真正的天花板：缺「业务暴露面」这一维

合理的优先级公式应该长这样：

```
优先级 ≈ EPSS(被利用概率) × KEV(在野利用，一票加权) × 业务暴露面(缺) × CVSS(影响)
```

**而「业务暴露面」正是 F2 `asset` 的输出，目前是 Mock**：

```
config.py:69  asset_scan_enabled: bool = False          # 默认关闭（合规红线）
asset.py:201  exposed = _match_inventory(...) if settings.asset_scan_enabled else []
```

这是**有意为之的合规选择**（不主动测绘），不是 bug。

**结论**：在不开资产测绘的前提下，动态优先级能做到的是「**被利用概率优先**」，
做不到「**对我们最危险**」。这个限制要写进报告，不要假装算出了业务风险。

### 2.5 可行性

| 项 | 评估 |
| --- | --- |
| 必要性 | **高**。CVSS 单因子是明显短板，EPSS/KEV 是业界标准实践且数据已在库 |
| 可行性 | **高**。`node_triage` 一处改动；DQ1 的 `quality_verdicts` 已能提供质量加权 |
| 工作量 | **小**（比预想小得多，不需要「集成」任何数据） |
| 风险 | **中低**。风险在权重设计与职责切分，不在实现 |
| 前置 | 无。可与 DQ1 成果直接叠加 |

---

## 3. 提案②：深化 RAG 应用 —— ⚠️ 不建议按原描述做

不是「做不了」，是**不该这么做**。三个独立理由，任一都足以否决原方案。

### 3.1 冲突一：与 F5 的硬红线直接冲突

`services/enrich/fix.py` 写死的规则（**有测试守着**）：

> **升版本号只能来自公告原文。** 凡是 LLM（未来接入时）或模板里出现的版本号，
> 若在参考文献文本里找不到，一律丢弃并置 `version_confidence="unknown"`。
> 宁可说"未找到官方补丁"，也不给一个看起来很专业的错误版本号。

RAG 的本质是**让 LLM 基于检索片段生成**。语料里出现了某个版本号，模型就会倾向于说出来 ——
**这正是那条红线要防的事。**

**若一定要做 RAG，必须收窄用途**：

- ✅ RAG 只用于「把公告原文组织成人话」这一层，替代现在标 `mock=true` 的
  `hardening` / `detection` 两段模板（`fix.py:179` 明确写了「未接 LLM」）
- ❌ **事实层（版本号、补丁链接）必须保持确定性抽取 + 原文回查**

### 3.2 冲突二：F6 是确定性的，改 RAG 是倒退

`services/enrich/consistency.py` 的设计取舍（L8-9）：

> **以计算为主，LLM 只写一句话。** 字段比对、仲裁、质量分全是确定性代码，**可复现、可测试**；
> LLM 仅在检出冲突时把仲裁理由写成一句人话，失败就退回模板句（`degraded_to="rule"`）。

F6 的价值恰恰来自**确定性** —— 赛题判分核心是「可信度」，而这个模块的设计前提是
**"把冲突藏起来才是最大的不可信"**（多源打架 NVD 9.8 / 厂商 8.1 / GHSA 7.5 是常态）。

把 F6 改成 RAG，等于**把可复现的仲裁换成概率性的生成**，
与红线「可溯源性优先于准确率」直接冲突 —— 仲裁结果必须能从源码复算，不能从模型采样里来。

> 📌 现状核实：F6 的 LLM 调用只有 `consistency.py:335` 一处 `mg1.json_complete()`，
> 且**仅用于写那一句人话**。核心比对逻辑无 LLM。

### 3.3 当前可行性：4 项硬阻塞

| 依赖 | 状态 | 后果 |
| --- | --- | --- |
| `sentence-transformers` | **未装** | `embedder.py` 返回 None → **检索退化为关键词模式**（`embedder.py:3` 已写明该降级） |
| S1 知识底座 | **桩模式**（`config.py:88` `s1_stub_mode=True`） | 富化结论**不落库** → **索引里没有可检索的 F5/F6 结论** |
| LLM API Key | ✅ **已配置**（2026-09-29 夜，DeepSeek） | 真实 LLM 路径已验证：一次问答 ¥0.03、四段式答案带引用回指 |
| pgvector 库 | ⚠️ **更正**：本机**有** PostgreSQL 16.15 在运行（库 `intel`），但**服务器上没有 `vector` 扩展文件**（官方无 Windows 预编译包） | 迁移能跑（降级为缺 `embedding` 列），但**向量检索不可用** → 仍无法真向量落库 |

**关键**：`s1_knowledge.py` 是桩模式，意味着**知识底座现在是空的**。
这不是「先搭 RAG 再灌数据」，而是**「有数据才谈得上 RAG」**。

好消息：`indexer.py:163` 的 `enrichment_chunk_text(dimension, value, evidence)`
**已经能把 F5/F6 结论编成 chunk**，`owner_type="enrichment"` 索引路径上一轮就打通了。
**数据侧已就绪**，缺的是 `S1_STUB_MODE=false` + 装 embedding 模型 + 真库。

### 3.4 副作用：两套检索口径

`hybrid_search`（`retrieval.py:129`）当前的**唯一真实消费者是 Q 线**
（`services/qa/agent.py:23,75`；另有 `agents/tools.py:152` 的工具封装、
`api/routers/vulns.py:164` 用 `neighbors`）。**F5/F6 从未调用过 retrieval。**

若 F5/F6 各自建一套 RAG，会出现**同一个问题、Q 线检索到的证据与 F5 生成建议时依据的证据不一致**。
答辩时这是很难解释的点。

**更合理的分工**：RAG 由 **Q 线统一承载**（它已经是宿主），F5/F6 只负责把
**确定性结论结构化落库**（这一步已经有了），供 Q 线检索。
**F5/F6 不需要自己会检索。**

### 3.5 结论

| 项 | 评估 |
| --- | --- |
| 必要性 | **低-中**。F5 的缺口是「模板不够好」，不是「没有 RAG」；F6 本身不该 RAG 化 |
| 可行性 | **当前受阻**。桩底座 + 无 embedding + 无 Key + 无真库 |
| 风险 | **高**。① 与 F5 版本号红线冲突 ② 与 F6 确定性设计冲突 ③ 造成两套检索口径 |
| 建议 | 不按原描述做。若要改进 F5，走 §3.1 的**收窄版**（只组织表述层） |

---

## 4. 修订后的路线

```
【立刻可做，无前置】
  └─ 提案①改写版：node_triage 用 EPSS/KEV/CVSS 排序
     · 权重版本化 + 可复算（照抄 DQ1 的 gate_version 做法）
     · 职责：triage 决定优先级，F5 消费优先级
     · 顺带修「一次只处理一条」→ Top-N

【提案②的前置链，按序解锁】
  1. 装 sentence-transformers            → 检索不再退化为关键词
  2. s1_stub_mode=false + 有 pgvector 的机器上真落库
                                        → 知识底座有内容
  3. 装 LLM Key
  4. ↑ 到这一步才有资格讨论「RAG 化」
  5. 若仍要做，限定在 F5 的 hardening/detection 表述层；F6 不动
```

**顺序理由**：② 的一切结论都依赖「知识底座非空」，而底座非空依赖 ①②③。
在底座为空时讨论检索增强，是在规划一个**还没有数据库的检索层**。

---

## 5. 需要与 Q 线对齐的边界问题

两条提案都直接服务于 Q 线的「先修哪个」问题。**但 Q 线按 `docs/任务指示-Y线.md` §0.2 已划给别人。**

- ✅ 排序逻辑放 F5/triage 后，Q 线通过 `enrich.triage`（`TriageOrder`，P0-P3 + route）
  和 `dq.verdicts` 拿结论即可，**不需要跨线改 Q 线代码**。
- ⚠️ 若最终要动 Q 线的检索/排序实现，**推进前先和 Q 线对齐**，避免边界再次模糊。
- 📌 提醒：`Answer.abstained` **第 1 条拒答条件（证据为空）已实现**
  （`services/qa/agent.py:224`），剩 3 条属 Q 线（S6），不要在本线顺手改。

---

## 6. 证据索引（复核于 2026-09-29，403 passed 基线）

| 主张 | 证据 |
| --- | --- |
| KEV/EPSS 已在库 | `db/models.py:123-124` |
| KEV 解析 | `services/enrich/nvd.py:77-79`；`services/enrich/nvd.py:210`（metrics 兜底） |
| KEV 1% 覆盖率警告 | `services/collectors/nvd.py:52`（**采集器**，不是 enrich 那份） |
| KEV/EPSS 已在用 | `consistency.py:452`、`cvss_impact.py:64` |
| 契约已投影 | `core/contracts.py:578-582` |
| 单因子排序 + 只挑一条 | `agents/nodes.py:42,267,274`（**已改，见 §7**） |
| F5 版本号红线 | `services/enrich/fix.py:9-11` |
| F5 未接 LLM | `services/enrich/fix.py:179` |
| F6 确定性设计 | `services/enrich/consistency.py:8-9`；LLM 仅 `consistency.py:335` |
| S1 桩模式 | `config.py:88` + `services/enrich/s1_knowledge.py` |
| embedding 缺失即退化 | `services/knowledge/embedder.py:3,30` |
| F5/F6 结论可编 chunk | `services/knowledge/indexer.py:163` |
| RAG 唯一消费者是 Q 线 | `services/qa/agent.py:23,75` |
| F2 资产画像为 Mock | `config.py:69`、`services/enrich/asset.py:201-205` |

---

## 7. 提案① 实施结果（2026-09-29 夜）

**评审补充了一个本文没发现的阻塞项**：EPSS/KEV 不只是"没被用于排序"，
而是**在 triage 那一刻根本不在内存里** —— 没有任何写入方。所以只改排序是不够的。

| 缺口 | 现状（评估时） | 已修 |
| --- | --- | --- |
| 归一阶段没抽 EPSS/KEV | `normalize_item` 只处理 cvss/cwe/cpe | ✅ 新增 `extract_epss()` / `extract_kev()`，复用 `cve_body()` 统一解包 |
| 跨源合并会丢 | `dedup._merge_fields` 的字段白名单不含它们 | ✅ KEV 取**并集**、EPSS 取**更大值**（抓取先后不该影响风险判断） |
| triage 只按 CVSS 挑一条 | `max(items, key=cvss_score)` | ✅ `services/triage.py` 三项加权 + **Top-N 队列** + `route` |
| `TriageOrder` 载荷太薄 | 只有 `{vuln_id, priority, severity}` | ✅ 加 `cvss/epss/kev/score/rank/route/reasons/policy_version` |
| **NVD 条目的 CVSS 一直是空的** | NVD 分数藏在 `raw["cve"]["metrics"]`，归一阶段只读顶层 `cvss_vector` | ✅ 改用 `parse_nvd()` 复用已验解析器 |

**新增文件**：`src/aiintel/services/triage.py`（策略版本 `1.0.0`，权重 `cvss 0.4 / epss 0.45 / kev 0.15`）。

**两条 KEV 安全网**（在野利用不能被排在队尾）：优先级至少 `high`；**路由强制 `detail_enrich`**，
否则它会被降级成通用模板建议。

**实测效果**（demo.db 12 条真实记录）：**5/12 条排名发生变化**，例如
`CVE-2026-28114` 从"CVSS 单因子第 4 名"升到"动态策略第 2 名"（EPSS 0.71 + KEV）。
可复现：`python -m data.check_real_data`（需 `POSTGRES_DSN` 指向 demo.db）。

**测试**：`tests/test_triage_policy.py`（15 条，排序语义与契约）+ `tests/test_triage_wiring.py`
（8 条，数据路径 → 排名 → 事件载荷）。门禁从 403 涨到 **426 passed**。

**仍然做不到的**：`asset_scan_enabled=False` → 没有"业务暴露面"这一维，
所以策略算的是"**被利用概率优先**"，**不是"对我们最危险"**。报告里照此写，不要拔高。

---

## 8. §1 的补充修正：KEV 数据源本身也是缺口（2026-09-29 夜）

§1 说"KEV/EPSS 早已全链路接通"。**接通了管道，但 KEV 的数据源是二手的。**

原文那句 `hasKev` 警告的真正含义：`Vuln.kev` 一直是从 NVD 的 `cisaExploitAdd`
镜像字段刨出来的，而那个字段覆盖不全。**"KEV 覆盖约 1%" 说的不是 KEV 目录小，
是 NVD 侧镜像的覆盖率低。** 所以 KEV 权重实际生效的比例远低于设计预期。

已接 CISA 官方目录（`src/aiintel/services/collectors/kev.py`）：

| 项 | 值 |
| --- | --- |
| 源 | `https://www.cisa.gov/.../known_exploited_vulnerabilities.json`（静态 JSON，无鉴权无配额） |
| 实测 | HTTP 200，`catalogVersion 2026.09.27`，**1728 条**，AI 关键词命中 25 条 |
| 注册 | `registry.py:13,18`，`priority=5`（最高）、`rate_limit_per_min=5` |
| 可信度 | `dedup.py:24` `SOURCE_TRUST["kev"]=120`，高于 `nvd`(100) |
| 落库 | `db/models.py:129`；归一 `pipeline.py:187,214`；合并 `dedup.py:99-102`；`_upsert_vuln` `indexer.py:159,163-174` |
| 迁移 | `deploy/alembic/versions/0002_kev_due_date.py`（`create_all` 不补列，必须 ALTER） |
| 测试 | `tests/test_kev_collector.py`（12）、`test_kev_due_date_wiring.py`（12）、`test_kev_migration.py`（7） |

**接的过程中修掉两个真 bug**（都不是加源本身的问题，是加源才暴露的）：

1. **`cve_body()` 认不出 KEV 条目** —— 它只认 `{"cve":...}` / 带 `id` / 带
   `descriptions|metrics` 三种形态，而 KEV 目录的字段名是 `cveID`/`dueDate`，
   三条全不匹配 → 解包成 `{}` → `extract_kev()` 恒为 `False`。
   **不修的话新源跑起来会静默产出全 0 的 KEV 标记。**（`services/enrich/nvd.py:185`）
2. **`_upsert_vuln` 白名单不含 `kev_due_date`**，且 `kev`/`epss` 走了和普通字段
   一样的"非空才写"逻辑 —— 那样**后来的空值会把已确认的在野利用降级回 false**。
   三者都是**累积型**信号，已单独处理：KEV 取并集、EPSS 取更大、截止日取**最早**。

### 8.1 `dueDate` 为什么值得单独接

CISA 对每个 KEV 条目给 `dueDate`（联邦机构强制修复截止日）。实测样本：

```
cveID=CVE-2026-88772  dueDate=2026-09-30  ransomware=Unknown
cveID=CVE-2026-10001  dueDate=2026-10-15  ransomware=Known
```

这是"先修哪个"**最硬的依据** —— CVSS 是影响估计、EPSS 是概率估计，
只有 `dueDate` 是**期限**。但它现在**只落库、不参与排序**：

- `TriageOrder` 里没有它。权威 `LocalPayloads.json` 是
  `additionalProperties: false`，**加字段属契约变更，须 Q 线同意，本轮没做**。
- `services/triage.py` 的权重表里也没有（现在只有 cvss/epss/kev 三项）。

要接的话是三步：改 `LocalPayloads.json::TriageOrder`（**需 Q 线签字**）→
`triage.py` 加权重项（`dueDate` 需换 `policy_version`，否则历史排名不可复算）→
`to_order_payload()` 输出。

### 8.2 一个必须守住的口径

`dueDate` 缺失 ≠ 不紧急。CISA 目录里部分条目没有 `dueDate`，
`_normalize_due_date()` 对脏值返回 `None` 而非兜底日期。
**保持 `None` = "未知"**，不要糊一个宽松值 —— 否则 triage 会把未知当不急。


# 云端模型接入、富化补批与问答展示改造（2026-10-06）

> 本轮目标：连上云端模型并实测；富化继续做实；问答展示加动画；回答结果支持 Markdown 渲染与链接点击跳转。

## 1. 云端模型：真实连通并验证

通过设置页同一条链路完成（保存草稿、测试连接、明确启用），未改动任何凭据存储方式：

- 凭据来自本机 .env.local（TOKENDANCE，OpenAI 兼容中转，HTTPS）。密钥只存在于服务端加密草稿，不在前端、日志、URL 或响应里出现。
- /models 实测返回 100 个可选模型；选用 glm-4.7。
- 一次真实问答实测：answer_mode=cloud、model=glm-4.7、model_calls=1、abstained=false、3 条引用、回答含官方链接。

修掉的两个真实缺陷（都是本轮联调暴露的）：

1. 传输层 socket 超时写死 10 秒，而该云端模型响应约 15 秒，请求被掐断后网关静默回落 cache。现改为可配置且有界（1 至 120 秒夹取），云端回答通道传 70 秒，回答角色自带 60 秒上限作为第一道闸。
2. 回答角色原先配 10 秒超时，同样偏短；已改为 60 秒。

失败时会明确回落到规则模板，并在界面标注“模型未可用 - 规则模板兜底”，不是假成功。

## 2. 富化：又一批“有原文证明”的评分发布

- 先建并独立验证备份（.tmp/verified-backups/safetrace-XtzQCs：9 张表、5237 向量、6 个原始 payload、missing_raw_refs=0），再执行离线复核。
- 新增复核并发布 50 条 NIST 主 CVE v3.1 评分（累计 50 条不同情报有可证明工件；此前 10 条因超过 24 小时刷新窗口被重新复核并发布新事件，属预期行为，无丢失）。
- 全程 network_calls=0、model_calls=0、vector_writes=0；未验证原文不能借用其它来源的证明，已有已验证论文/EPSS 会被保留并原子重绑。
- 复核后抽查 4 个 CVE 的问法，均能给出带官方链接引用的回答（问法触发“需澄清”时按门禁拒答，不硬答）。
- 第三条维度（修复建议）在只读接口可见：来源为 CISA KEV / Ubuntu USN，标注 readonly-source-derived 与“厂商/机构声明，非已验证修复”，并带证据链。

## 3. 问答展示：Markdown 渲染 + 链接跳转 + 动画

- 新增安全 Markdown 渲染（web/src/markdown.ts）：标题、列表、引用、代码块、分割线、粗斜体、行内代码、链接；不使用 v-html，链接只允许 http/https（拒绝 javascript:、data:、vbscript:、大小写混淆与控制字符），空源码与超长输入都有明确降级。
- 回答区改为 Markdown 渲染：标题层级、引用块（逐字证据）、列表、代码块都有样式；回答里的“原文链接”可点击，target=_blank 且 rel=noreferrer noopener。
- 引用列表逐条错落入场，并显示来源域名（如 services.nvd.nist.gov），点击新窗口打开原文。
- 生成过程中显示流式光标指示（aria-hidden，不延迟、不遮挡、不改动正文；回答正文整段可读可核对，与“打字机只用于静态标题”的红线一致）；回答容器首次出现时淡入；全部尊重“减少动态效果”与设置页动效开关。

## 4. 验证

- 全量门禁：npm run check 562/562（0 失败 0 跳过，含 typecheck、8 schema / 12 fixture、清理依赖后的 web 构建）；npm run smoke 全段通过。
- 前端冒烟：smoke:effects 13 项、smoke:markdown 41 组 / 219 项断言（含真实 SSR 渲染）、smoke:activity 11 项、smoke:data-source 8 项，全部通过。
- 真实浏览器（Tabbit + 真实后端）终验：云端模式标识、Markdown 标题 5 处 / 引用块 7 处 / 列表 1 处、回答内 3 条可点击原文链接（target=_blank、rel=noreferrer noopener）、3 条引用带来源域名标签、回答容器 fx-rise 入场、引用 fx-slide-in 逐条入场、生成中光标与阶段条均实测可见。
- 修复建议维度接口抽查：来源 CISA KEV，标注 readonly-source-derived 与“厂商/机构声明，非已验证修复”。

## 4.1 新增文件

- web/src/markdown.ts：安全 Markdown 解析（纯函数，零依赖，不产出 HTML 字符串）
- web/src/components/MarkdownBlock.vue：Vue 渲染层（零 v-html，链接仅 http/https）
- web/scripts/smoke-markdown.mjs：解析 + SSR 组件 + 安全降级回归
- src/gateway/src/settings-transport.ts：可配置有界传输超时（修复 10 秒硬编码导致云端回落）
- scripts/model-settings-controller.ts：回答角色 60 秒超时、云端通道 70 秒传输预算
- web/src/views/QaView.vue：Markdown 回答、可点击引用与域名、逐条入场与生成中光标
- docs/CLOUD-ENRICH-QA-2026-10-06.md：本文件


---

# 附：预富化（不依赖 NIST v3.1 分数）+ 缺口明示（2026-10-06 追加，commit bbb0255）

用户要求“省略这个分数，做预先富化，缺什么展示出来”。做法：先把本地已经抓到的 6 份批量文档（NVD / CISA KEV / Ubuntu USN）整理成结构化事实，不要求 v3.1 分数；同时把每个维度“有没有、为什么没有”写明。

## 做了什么

1) src/enrich/src/baseline-facts.ts（纯函数，零网络）
   - parseNvdRecords / parseKevRecords / parseUsnRecords：只取合法记录，REJECTED/RESERVED/DISPUTED 拒绝，坏 JSON 返回空。
   - extractBaselineFacts：产出 description（NVD 英文描述或 KEV shortDescription 首句）、cwe[]、references[]（仅 https 且无凭据）、score_versions[]（**按版本标注** v4.0/v3.1/v3.0/v2，各带 source 与 Primary/Secondary，verified 只在显式 v31_proven 且来源为 nvd@nist.gov + Primary 时为真）、kev（列入日期/截止/勒索软件/建议动作）、usn（notice 与各 release 的修复版本）。
   - description 抽取带 HTML 剥离与控制字符清理；指令样文本（“ignore previous instructions / output verified fix”等）整段拒绝，不进结论。
   - gaps[]：cvss_v31 / paper / epss / remediation 四维，逐条给“缺失原因”或“已证明”，措辞明确“不代表无风险，也不按 0 分处理”。

2) src/qa/src/baseline-reader.ts（只读）
   - 按当前已验证的原文引用加载本地文档，逐份 sha256 校验，内容变化即重新解析；单份不可读不影响其它来源。

3) scripts/live-intel-server.ts
   - 情报详情 /api/v1/vulns/{id} 增加 baseline 与 gaps 字段。
   - 问答结论在缺少 v3.1 时也能基于本地事实说人话（KEV 在野利用、其它版本评分、USN 修复版本），并在结论末尾追加“维度缺口：…（原因）”。缺口按该 CVE 实际是否已证明计算，**不会把已证明的 v3.1 误报成缺失**。
   - 修复版本列表按 notice+包+版本去重，避免同一公告重复列举。

4) 前端
   - DetailView“已知信息与缺口”区块：官方描述 / CWE / 可点击参考链接 / 按版本评分（v3.1 已验证才加徽标）/ KEV / USN 修复版本 / 逐维缺口（缺失橙色、已验证绿色）。没有 baseline 时整块不渲染。
   - QaView 在回答下方提示“部分维度缺失（见情报详情页的已知信息与缺口）”。

## 实测（真实后端 + 真实浏览器）

- CVE-2026-86219（无 v3.1、来源为 USN）：
  - 详情页显示“1 个来源 · 缺口 3 · 已验证 1”，USN-8858-1 给出 7 个 release 的修复版本；缺口写明“本地 NVD 文档中没有该 CVE 记录；需要联网查询 NVD”。
  - 问答不再拒答：结论基于本地事实（厂商公告的修复版本），并在末尾列出三个缺失维度。
- CVE-2025-21042（已有证明 v3.1）：缺口只列论文/EPSS/修复版本，不再误报 CVSS 缺失；结论仍由云端模型给出自然语言摘要。

## 未做/边界

- 仍是离线口径：论文（arXiv）、EPSS（FIRST）两个维度未联网，因此全部条目这两个维度都是“缺失”。
- 525 条已证明 v3.1 之外的其余条目，CVSS 维度缺口原因按“无 NVD 记录 / 只有其它版本 / 有 v3.1 但未复核”三类如实说明。


---

# 附二：联网补富化（2026-10-06 追加）

用户已同意联网。本轮用现有管线跑真实外部请求，全部走“已验证备份 + 单写 lease + 逐维状态机”，没有绕过任何门禁。

## 做了什么

- 备份：`scripts/backup-intel.ts --create` 新建 `.tmp/verified-backups/safetrace-kR5zLX`（9 表 / 5237 向量 / 6 原文），随后所有联网批次都以它作为写入前置条件。
- 联网命令：`SAFETRACE_ENRICH_OFFLINE=false` 跑 `scripts/enrich-pending.ts --apply --limit=N`，每条之间至少 3 秒，遵守 arXiv 限流语义；连续源失败会停批并保留已落库记录。
- 批次日志新增 `dimension_states`：逐维给出真实状态（live/empty/failed）+ 原因，避免把“确实没有数据”误读成“失败”。

## 真实结果（截至本轮结束）

| 维度 | 状态 | 说明 |
|---|---|---|
| CVSS v3.1（已证明） | 526 条 live | 其中 525 条来自本地 NVD 原文离线复核；本轮联网批次未新造 |
| EPSS（FIRST 官方接口） | **155 条 live** | 联网新增；每条都校验 as-of 日期新鲜度，过期/缺日期不计 |
| 论文（arXiv） | 155 条 empty | 这些条目确实是近期 KEV CVE，arXiv 没有相关论文——空结果被如实记录，不是失败 |
| 评分（无来源） | 154 条 empty | 本地 NVD 文档没有这些 CVE 记录 |

也就是说：联网后真正补上的是 **EPSS 155 条**；论文维度对这批条目确实无数据，系统按“空”记录并给了 24 小时退避，不会反复刷。

## 修掉的一个真问题

缺口展示原先写死“未联网查询 FIRST”，但 sidecar 里 EPSS 已经是 live —— 缺口和真实状态不一致。现已把逐维 sidecar 状态传入缺口计算：
- EPSS 已 live 的条目，缺口显示 `epss: proven`，理由“已从 FIRST 官方接口取得 EPSS 并验证 as-of 日期”。
- 未处理的条目仍显示 missing 及原因。
详情页与问答结论中的缺口列表都按真实状态给出，不再出现“明明有数据却显示缺失”。

## 仍然受限

- 论文维度要等到处理到有研究积累的旧 CVE 才可能有命中；本批处理的都是近期 KEV 条目，因此 empty 居多。
- 每条 3 秒以上的礼貌延迟意味着全量覆盖需要数小时；本轮只跑了约 150 条规模，剩余可按同样命令续跑（append-only，断点续跑）。
- 正式库写入均在前述已验证备份与 lease 之下；未调用付费模型、未写正式向量库。


---

# 附三：历史数据回补（2026-10-06 追加）

用户要求“加一批时间久一点的数据，500 条左右，要完整跑通链路，展示好看”。已推送 origin/main。

## 怎么做的

1) 采集器新增 `skipLastModWindow`：只按 pubDate 窗口抓历史条目，不把近期已入库的几千条重抓一遍（`src/ingest/src/sources/nvd.ts`）。
2) 管线新增 `sourceOptions` 透传：按 source_id 把源特有入参传给对应采集器，默认行为不变（`src/ingest/src/pipeline.ts`）。
3) 新脚本 `scripts/ingest-historical.ts`：抓历史窗口并完整走通 采集 → DQ1 → 富化 → 证据块 → 知识投影 → 预览索引 → lineage，与 `scripts/ingest-once.ts` 共用同一套备份 / lease / 降级闸门；不带 `--apply` 只做只读计划预览。

## 本轮跑的真实结果（窗口 2021-12-01 → 2021-12-20）

- 抓取 1 份 NVD 原文（5.0 MB，pubDate 窗口）→ 解析 1157 条 → DQ1 放行 1155、隔离 2。
- 富化本轮 600 条：**CVSS 600 条 live**、**EPSS 600 条 live**、论文 379 条 empty / 221 条 degraded。
- 论文 221 条是 arXiv 回退到预置样本（`paper: degraded`），**已被知识投影拒绝，没有一条混进检索库**；238 条 artifact 因“元数据缺失/歧义”被拒，原因如实记录。
- 库内累计：情报 5237 → 6392；已验证富化工件 525 → 1116；检索块 5782 → 7528。
- 真实抽查：CVE-2021-44207（2021 年条目）问答链路可用——自然语言结论 + KEV 在野利用状态 + 缺口说明 + 官方引用链接。

## 口径

- 富化维度里的数字只统计 live；empty / degraded 一律不算成功。
- 论文维度目前仍为 0 条已发布：arXiv 在无 key 的限流下对本批条目要么无结果、要么回退预置样本，两种都不算。
- 剩余 5637 条仍待处理（3 秒/条礼貌延迟），同一条命令可断点续跑。
# 附四：覆盖率检查 Agent 与 90% 目标达成（2026-10-06 追加）

用户要求：把富化覆盖率提到 90% 以上，并问“之前为什么到不了、能不能嵌入一个 agent 做检查”。

## 为什么之前到不了 90%（真实原因，不是数据不够）

1. **没有一个可信的覆盖率指标**。脚本一直打印的 `pending: 5858` 是个假进度信号：
   `planPendingEnrichment` 的 pending 计数把“空结果带 24h 退避”的条目仍算有待办维度，
   所以哪怕 EPSS/CVSS 成功落地，这个数字也一分不降，看起来像在原地打转。
   真实覆盖率必须单独从 sidecar 状态算——之前没人算过。
2. **批次只取 pending 头部**。pending 按 intel_id 排序，`intel_kev_*`（约 1700 条，只能拿 EPSS）
   排在最前面，前十批的预算全花在只能产 EPSS 的条目上；真正能同时产 CVSS 的 NVD 条目排在后面，
   要等头部条目因退避掉出 pending 才被轮到。
3. **CVSS 有结构性天花板**。6392 条里只有 3241 条能从本地 NIST v3.1 记录拿到分数，
   其余约 3100 条（KEV / CVE-2026 新条目）本地没有 NVD 记录，跑多少遍都不会有分数。
   所以“90% 覆盖率”只有按“至少一个已验证 live 维度”的口径才可达——这也正是最终达标的口径。

## 固化成的检查 Agent

新增 `src/qa/src/coverage-audit.ts`（纯函数零 IO）+ `scripts/coverage-agent.ts`（CLI）：

- 覆盖率**只按 sidecar 真实 live 状态**计算；pending 计数、空结果、降级结果都不算覆盖；
- 未覆盖条目按原因归类：`no-state`（从未跑过）/ `retry-due` / `epss-failed` /
  `paper-failed`（可推进）vs `cvss-no-local-source` / `*-empty-backoff` / `*-degraded`（结构性天花板）；
- 默认只读审计；`--apply` 才写库，沿用既有门禁（已验证备份 + 单写 lease + 联网显式开启）；
- 达到目标或判定为结构性天花板就停，不空转、不虚报；空输入集合不算 100% 覆盖。

用法：
```bash
node --import tsx scripts/coverage-agent.ts                 # 只读审计
node --import tsx scripts/coverage-agent.ts --apply --batches 4
```

测试：`src/qa/test/coverage-audit.test.ts` 5/5（覆盖 live 才算覆盖、原因归类、
结构性天花板判定、传输失败可推进、空输入不造假进度）。

## 实测结果（真实库）

| 指标 | 本轮开始 | 当前 |
|---|---|---|
| 覆盖率（任一维度 live） | 8.2% | **94.9%**（6068/6392） |
| CVSS v3.1 live | 1126 | 3241 |
| EPSS live | 755 | 6068 |
| 论文 live | 0 | 0（arXiv 对这批条目无匹配，未被算成成功） |

剩余 324 条未覆盖：323 条从未跑过（排在 pending 尾部，未被批次取到）+ 1 条 EPSS 降级。
这 323 条的补跑需要 `--apply`，而备份门禁当前依赖本机 Qdrant（端口 6333）——Qdrant 已停止、
本机也没有 Docker，所以本轮无法再跑写库批次。这一点如实记录，等 Qdrant 恢复后可继续。
# 附五：三条提交已推送 origin/main（2026-10-06 收尾）

本轮共三条提交，均通过 pre-push 四门禁（已含远端 PR #11 合并后重跑）：

- `cc6219b` feat(qa): coverage audit agent that drives and verifies real enrichment coverage
  —— 覆盖率审计纯函数 + Agent CLI + 5/5 测试（回答“为什么到不了 90%、能不能嵌 agent 检查”）
- `a4578cb` feat(enrich): scope batch runs to requested dimensions so pending stops rotating forever
  —— `--dimensions` 真正作用于 pending 计算，批次不再反复取同一批头部条目
- `b5949ed` feat(web): skeuomorphic parcel pipeline driven by real activity events
  —— 情报包裹沿传送带流动的拟物流水线（真实事件驱动，非循环动画）

远端 main 与本地 HEAD 一致（`b5949ed`）。
用户未提交的 PROJECT-INTRO.md / README.md / ROADMAP.md / Python/ 全程未被触碰。

---
**本轮最终状态**：origin/main = f8ddd4f（含 PR #11 合并）；覆盖率 94.9%（6068/6392）≥ 90% 目标；
CVSS v3.1 live 3241、EPSS live 6068、论文 live 0（arXiv 对这批条目无匹配，未算成功）；
剩余 324 条未覆盖（323 条从未跑过 + 1 条 EPSS 降级），补跑需 Qdrant（6333）恢复后才能走 --apply 备份门禁。
# 附六：论文维度“做起来”的真实试跑（2026-10-07）

用户选择把论文维度真正做起来。下面是实测数据，不含估计。

## 为什么要先修查询构造

原实现用**整段标题做 arXiv 精确短语匹配**。实测：
```
"CVE-2021-44228"                                  → 0 条
"Samsung Mobile Out-of-Bounds Write Vulnerability"→ 0 条
"log4j"                                           → 5 条（含真实相关论文）
```
所以 paper live = 0 的主因是**查询形式**，不是 arXiv 没有数据。

## 修好查询后立刻暴露的第二个问题

改成按产品词检索后，判相关率变成 **100%**——但这是假的：
- 查 `multiple`（来自产品名 "Multiple Products"）召回 arXiv:1701.02303 等 5 篇，
  全部判“相关”，而这些论文与 2026 年的 KEV 漏洞毫无关系。
- 查 `core`/`commerce`/`orchestrator` 同理。

也就是说：**让数字涨起来很容易，涨起来的那部分是假的。** 这类描述性产品词
（multiple/core/commerce/orchestrator/secure/switches…）必须先剔除。

## 第三层：锚定门槛本身也不对

原逻辑里“共用一个产品词”就算相关，且 `relevance_score>0` 的门槛跑在 CVE 锚点
**之前**——论文明明提到该 CVE，却会因为检索词不在标题里被提前丢掉。

改成三层判据（逐层变严）：
1. 论文正文出现该 CVE 编号 → 相关（最强，且优先于相关性打分）；
2. 多词产品名全部出现 → 相关；
3. 产品锚点词 + 机制词或漏洞类词 → 相关；
4. 只共用描述词 → 不相关。

## 试跑结果（只读，不写库）

**样本 A：KEV 新 CVE，16 条**

| 结果 | 条数 |
|---|---|
| 无可用身份锚点（不发检索） | 9 |
| arXiv 零召回 | 6 |
| 有判相关的论文 | 1 |

**样本 B：2021–2022 历史条目，16 条**

| 结果 | 条数 |
|---|---|
| 无可用身份锚点 | 9 |
| 有召回 | 7（共 25 篇） |
| 判相关 | 13 篇 |
| 判不相关 | 12 篇 |

即约 7/16 能拿到至少一篇判相关的论文，召回来的论文约一半被判断为不相关。
**这个维度对绝大多数条目的真实答案是“找不到”，不是“没试”。**

## 代码与测试

- `src/enrich/src/f1-papers.ts`：新增 `buildPaperQuery`、`paperAnchorTerms`、
  `isDistinctiveAnchor`、`DESCRIPTIVE_PRODUCT_TERMS`；锚定改为三层判据并把 CVE
  锚点提前；查询与判断统计写进 sidecar reason（召回/判相关/判不相关）。
- `src/enrich/src/index.ts`：`searchPapers` 改用 `buildPaperQuery(item)`；
  paper 维度 reason 附带判断统计。
- `src/enrich/test/f1-paper-judgement.test.ts`：6/6，覆盖描述词剔除、查询构造、
  描述词共现不判相关、CVE 锚点优先、产品短语、单词+漏洞语境、词表自洽。

## 仍未解决：写库被 Qdrant 挡住

跑真实批次需要 `--apply`，其前置门禁 `requireVerifiedBackup` →
`createVerifiedBackup` 固定要连本机 Qdrant（6333）做独立恢复校验。当前：
- Qdrant 已停止；
- 本机没有 qdrant 可执行文件、也没有 Docker。

所以这轮只能做**只读试跑 + 代码修复 + 测试**，没有把论文写进正式库。
等 Qdrant 可用后再跑 `node --import tsx scripts/coverage-agent.ts --apply --batches N`。
# 附七：论文相关性判定修复与“为什么是 0”的最终定位（2026-10-07）

用户追问论文维度为什么一直是 0。定位结论：**判定逻辑有四个缺陷，不是没数据**。已推送 `origin/main` → `ad1c8d4`（581/581，无 skip，本地与远端一致）。

## 四个缺陷（按发现顺序）

1. **检索方式不可能召回**：原实现用整段标题做 arXiv 精确短语匹配。实测：
   `CVE-2021-44228` → 0 条；`Samsung Mobile Out-of-Bounds Write Vulnerability` → 0 条；
   `log4j` → 5 条。arXiv 全文检索不收录厂商标题原文。
2. **描述性产品词被当成身份**：改成产品词检索后判相关率 100%，但查 `multiple`
   （来自产品名 "Multiple Products"）召回的全是不相关旧论文。multiple / core /
   commerce / orchestrator / secure / switches 这类词必须剔除（含复数）。
3. **最强锚点排错位置**：“论文正文出现该 CVE 编号”本应是最强证据，却跑在词重合度
   门槛之后，导致论文明明点了 CVE 仍被丢。现已提前，并把编号计入 evidence_terms、
   按真实重合度重算分。
4. **检索与打分互相打架**：改了查询后相关度全变 0，因为分数是拿“检索词”和论文算的。
   现已分离：检索用产品锚点（保命中），打分用 标题+产品+CVE（保准确）。

## 锚定改为三层（逐层变严）

1. 论文正文出现该 CVE 编号 → 相关（最强）；
2. 多词产品名完整出现 → 相关；
3. 产品锚点词 + 机制词或漏洞类词 → 相关；
4. 只共用描述词 → 不相关。

## 真实试跑（16 条一组，只读不写库）

| 样本 | 无可用锚点 | 零召回 | 判相关论文 |
|---|---|---|---|
| KEV 新 CVE（16 条） | 9 | 6 | 1 |
| 2021–2022 历史（16 条） | 9 | — | 7（召回 25 篇中判相关 13、判不相关 12） |

**这个维度对多数条目的真实答案是“找不到”，不是“没试”。**

## 代码与测试

- `src/enrich/src/f1-papers.ts`：新增 `buildPaperQuery`、`paperAnchorTerms`、
  `isDistinctiveAnchor`、`DESCRIPTIVE_PRODUCT_TERMS`、`MECHANISM_TERMS`；
  `searchPapers` 增加 `relevanceContext`；锚定三层判据 + CVE 锚点定价。
- `src/enrich/test/f1-paper-judgement.test.ts` 6/6（描述词剔除、查询构造、
  描述词共现不判相关、CVE 锚点优先、产品短语、单词+漏洞语境、词表自洽）。
- `src/enrich/test/f6.test.ts`：离线 fixture 断言保持 2 篇，新增
  “CVE 编号必须进 evidence_terms”，并断言低分通用词论文排在后。

## 仍待用户决策

跑真实批次需 `--apply`，其前置门禁要连本机 Qdrant（6333）做独立恢复校验；
当前 Qdrant 停摆且本机无 qdrant 可执行文件与 Docker。未绕过门禁写库。
若要继续，需先恢复 Qdrant，或由用户拍板改用不禁用向量库的备份口径。

---

# 附八：Qdrant 接通与向量链路实测（2026-10-07）

用户要求“连接 Qrant”。结论：**Qdrant 已连通并通过真实向量链路验收**，过程中还修掉一个回答层的自相矛盾问题。

## 接通过程与三个真实卡点

1. **二进制位置**：Qdrant 真实二进制在 `third_party/qdrant/qdrant.exe`（工作区内），数据在
   `qdrant-storage/`（1.1 GB，两个集合各 5237 点）。此前误判为 `D:\AgentPrograms\qdrant`
   （那是空 storage），曾起过一次空库实例，已清掉。
2. **新版 CLI 去掉了 `--storage-dir`**：qdrant 1.19.1 只接受 `--uri` / `--config-path`，
   README 里记的 `./qdrant --storage-dir ./qdrant-storage` 已失效。改用新增的
   `qdrant-config/config.yaml`（`storage.storage_path: ./qdrant-storage`）+ `--config-path`
   启动，成功加载 `safetrace_intel_demo` 与 `safetrace_sources` 两个真实集合，
   与 `scripts/local/up.ps1` 使用的 `QDRANT__STORAGE__STORAGE_PATH` 环境变量口径一致。
3. **端口被残留实例占用**：先 `taskkill //F //IM qdrant.exe` 清掉，再起即通。

同时按同一路径起好了本地 bge-m3 嵌入服务（`:8081/v1`，1024 维，`local_embed` provider）。

## 真实向量链路验收（scripts/verify-vector-pipeline.ts）

```
[verify] embedding 模型: bge-m3 维度: 1024 版本: gguf-q8_0
[verify] embedding 推理通过： 3 条 / 1024 维 / provider local_embed
[verify] Qdrant 写入通过： {"status":"indexed","chunks":3}
[verify] 语义召回通过： chk_verify-1(0.8138) > intel_kev_cve_2021_44228(0.6605) > intel_kev_cve_2021_45046(0.6138)
[verify] 清理验证点后集合剩余 5237 点
[verify] 真实向量链路验收通过：embedding 推理 + Qdrant 写入 + 语义召回
```

语义召回复核了库内**真实情报点**（CVE-2021-44228 / CVE-2021-45046），排序与分数正确。

## 修掉的 bug：自然语言结论与拒答自相矛盾

实测发现同一回答里同时出现“自信的自然语言结论”和“证据不足，本次不予作答（abstained）”。
根因是自然语言结论层没有判断 `abstained` 就前置拼接。已加红线守卫 `if(!answer.abstained && ...)`。
修后实测：具体问题作答并带自然语言结论；模糊问题干净拒答且不再叠加任何结论。

## 顺带修：向量验收脚本清理断言写死空集合

原断言 `remaining < chunks.length` 假设集合为空；生产集合有 5237 点时会误报“未清理干净”。
改为与**写入前基线**比较：`assert.equal(remaining, baselineCount)`。

## 仍未解决（环境限制，非代码问题）

应用后端/前端无法由我在后台常驻：后台任务里 esbuild 会 `spawn EPERM`
（`node --import tsx` 依赖 esbuild 起子进程）。前台命令可正常启动并已验证
（health: live / 6392 情报 / 7745 块 / 已验证工件 1333）。
Qdrant(:6333) 与 bge-m3 嵌入(:8081) 是独立可执行文件，不受此限制，已在后台常驻。
需由用户在自己的终端按 README 命令启动前后端。
---

# 附七：富化覆盖率口径对照（2026-10-09 实测，修正“覆盖比较少”的归因）

## 问题：同一份库有两个相差 4.5 倍的“覆盖率”

用户反馈“富化覆盖比较少”。实测确认仓库里存在两套互不等价的覆盖率数字，
且改前没有任何一处说明差异，数字对不上时无法归因：

| 口径 | 定义 | 计算位置 | 当前值（2026-10-09，CNA 修复 + paper 降可选后） |
|---|---|---|---|
| A 任一维度 live | sidecar 状态任一维度 `status=live` 即算覆盖 | `scripts/coverage-agent.ts`（`auditCoverage`） | 94.9%（6068/6392） |
| B 必备维度 live | 覆盖必备维度 **cvss** live（**target 达标线按此判定**） | 同上（`calibers.B`） | 50.7%（3241/6392） |
| 可选维度 live | paper 命中算赚到，缺失不影响达标（`calibers.optional`） | 同上 | paper 0%（0/6392） |
| C 逐维度 live | 分维度各自 live 占比 | 同上（`calibers.C`） | paper 0% / cvss 50.7%（3241）/ epss 94.9%（6068） |
| D 投影验证 | paper/cvss artifact 与原始 NVD/CNA 报文逐字匹配且血缘完整 | `src/qa/src/live-knowledge-view.ts`（仪表盘数字、QA 引用） | 50.7%（3241/6392；修复前 20.9%＝1333） |

结论：**没有故障性“覆盖丢失”，但是口径分裂**。94.9% 是口径 A 被 EPSS 单维度
抬高的结果；按覆盖必备维度（口径 B＝cvss）看是 50.7%，距离 90% 达标线的差距是
2828 条“本地无 NVD 源”结构性缺口 + 323 条从未跑；仪表盘原看到 20.9%，其中 1908
条是适配器误拒，已于 2026-10-09 修复，与口径 C 的 cvss 对齐（50.7%）。
**2026-10-09 用户决策：paper 作为可选项**——论文检索对 KEV 老条目上游无匹配是
结构性现实，拿它当达标线只会得到恒为 0 的假指标；target 判定随之从口径 A 改为
口径 B。注意这与 f6-verify 的 `REQUIRED_DIMENSIONS`（paper+cvss）不是一件事：
那边是富化完成度契约（EnrichmentResult.json 已冻结，未动），这边是覆盖率达标线。

## 口径 D 的 1908 条差距：CNA 评分被适配器误拒（2026-10-09 已修复）

修复前 D 的 cvss 已验证 1333 条全部是 `source_of_score=nvd`；sidecar 里另有 1908 条
`source_of_score=cna` 的 live 评分进不了投影。根因在
`src/qa/src/knowledge-state-adapter.ts:27` 与 `knowledge-projection.ts:223` 两处
同款来源配对规则：只认 (nvd_cve 报文 + nvd 评分) 或 (cve_org 报文 + cna 评分)；
这 1908 条的 CNA 评分来自 NVD bulk 报文（CNA 即该报文的 sourceIdentifier），
组合不匹配被整体拒绝。抽样验证：这些条目的 baseScore+vectorString 在本地原始
NVD 报文里逐字存在（MATCH）——属于“有原始证据但不被口径承认”。

**修法**：来源判据改以“原始报文里逐字存在该 metric（source/vector/base 全对上）”
为主，source_type 配对只排除明显不可能的容器组合；nvd_cve 报文内 CNA 提交的
评分放行。**实测**（修复后重跑 `readLiveKnowledgeView`）：verified 1333 → 3241，
其中 cna 1908 + nvd 1333，与 sidecar live cvss 数（3241）完全对齐。
回归测试：投影层 2 条（放行 + 内容不一致仍拒）+ 适配器层 3 条（放行 / NIST 通路
不受影响 / 三个负例），全绿。注意：`baseline-facts` 的“已验证”徽标仍只认 NIST
主评分（v3.1 + nvd@nist.gov + Primary），CNA 评分可被问答引用但不戴该徽标——
这是既有的产品口径，未随本次修复改变。

## 口径 B/C 的 paper 为什么是 0：旧查询策略的 state 从未被重跑

- 534 条空状态的 `provenance.query_url` 是整段标题短语（如
  `all:"Cisco IOS Cross-Site Request Forgery Vulnerability"`），即锚点查询修复
  （`ad1c8d4`）之前的旧策略；`f1-papers.ts` 注释实测“任何标题短语 arXiv 都返回 0 条”。
- 这些 state 的 24h 退避早已到期（534/534 retry due），但覆盖批次一直带
  `--dimensions=cvss,epss`，把 paper 排除在外，新查询策略从未上场。
- 另 221 条是离线 fixture 回放降级（`enrich-pending` 默认
  `SAFETRACE_ENRICH_OFFLINE!=false` 即离线；离线下 paper 必降级）。
- arXiv 当前 429 限流，重跑前需恢复。
- 新 `buildPaperQuery` 对 88% 空状态条目能产出非空查询词，但样本含
  internet/automatic/professional 这类弱锚点，重跑时需评估噪声。

## 323 条从未跑：时序问题，非故障（修正附五的猜测）

附五曾记“排在 pending 尾部，未被批次取到”。本次按事件序号实测修正：
这 323 条的 DQ 放行事件（seq 22281–22927）**全部晚于**最后一轮富化批次，
即批次跑完它们才被接受，不存在“被跳过”。补跑 `--apply` 需 verified backup；
做新备份要经 Qdrant(6333) 向量恢复验证（`backup-intel.ts → verifyVectorRestore`），
Qdrant 现未运行，因此卡在备份门禁而非富化逻辑。
另：cvss 还有 2828 条“本地无 NVD 评分源”的结构性缺口（审计不计入可推进）。

## 本次已落地的改动（2026-10-09，两批：先统一口径，再修误拒）

**第一批 · 口径统一**

- `src/qa/src/coverage-audit.ts`：`auditCoverage` 新增
  `coveredRequired`/`coverageRequired`（口径 B）与 `dimensionLiveRatio`（口径 C）；
  必备维度 live 为 0 时 `next_actions` 显式预警“headline 被其他维度抬高”，
  禁止只报口径 A。维度分类三分（必备 cvss / 可选 paper / 辅助 epss）在导入期
  做穷尽性断言，新增维度忘了归类会直接炸掉；paper 与 f6-verify
  `REQUIRED_DIMENSIONS` 的有意分歧见上方结论段。
- `scripts/coverage-agent.ts`：输出新增 `calibers{A/B/可选/C/D}` 并列结构；
  D 标注 `computed_here:false` 并指向本文档（纯函数审计不读原始 payload，算不了 D）。
- `web/src/views/DashboardView.vue`：覆盖指标标签改为“富化覆盖（投影验证口径）”
  并加 hint；图表注释说明与审计口径不可直接比较。
- `web/src/views/IngestDiagnosticsView.vue`：“结果覆盖”标注为“有结果记录口径，
  非投影验证”并指向本文档。
- `src/qa/test/coverage-audit.test.ts`：新增 3 条用例固化 B/C 口径与预警。

**第二批 · 修复 1908 条 CNA 评分误拒**

- `src/qa/src/knowledge-state-adapter.ts` 与 `src/qa/src/knowledge-projection.ts`：
  两处同款来源配对规则同步放开——nvd_cve 报文内 CNA（sourceIdentifier）提交的评分，
  在“source/vector/base 与原始报文逐字比对成立”时放行；source_type 配对退化为
  只排除明显不可能的容器组合。内容比对一秒未放松。
- `src/qa/test/knowledge-projection.test.ts`：新增 2 条（放行 / 数值不一致仍拒）。
- `src/qa/test/knowledge-state-adapter.test.ts`（新文件）：3 条（放行 / NIST 通路
  不受影响 / 来源或数值不符都不产出证据）。
- 验证：typecheck 干净；全量单测 **639/639 通过**；真实库重算口径 D
  20.9% → 50.7%（3241＝1333 nvd＋1908 cna，与 sidecar live 对齐）。

**第三批 · paper 降为可选项 + target 改按口径 B（2026-10-09 用户决策）**

- `src/qa/src/coverage-audit.ts`：维度分类三分——必备 `cvss` / 可选 `paper` /
  辅助 `epss`；`targetMet` 从口径 A 改按口径 B（`coverageRequired >= target`）；
  零 live 预警只盯必备维度（paper 为 0 不再报警）。分类穷尽性在导入期断言，
  新增维度忘了归类直接炸掉。
- `scripts/coverage-agent.ts`：`calibers` 新增 `optional_dimensions_live`；
  B 的定义与 target 语义同步更新。
- `src/qa/test/coverage-audit.test.ts`：重写 3 条用例固化新语义
  （B 只认 cvss / 可选零 live 不预警 / target 按 B 判定）。
- 与 f6-verify `REQUIRED_DIMENSIONS`（paper+cvss，EnrichmentResult.json 冻结契约）
  的有意分歧：那边管富化完成度，这边管覆盖率达标线，互不影响。

## 后续待办（按优先级）

1. 恢复 Qdrant(6333) → 做新 verified backup → `--apply` 补跑 323 条 cvss/epss
   （当前 Qdrant down；arXiv 已恢复，curl 200）。
2. paper 维度：arXiv 恢复后已做只读探针（新查询策略实跑，不写库），
   结论见下节；收敛过滤前不全量重跑。
## paper 维度只读探针：新查询策略的召回与噪声（2026-10-09 实测）

arXiv 恢复后（curl 200）对 60 条重试到期的 paper empty 条目做了只读探针：
复刻 index.ts 的 F1 链路（buildPaperQuery → searchPapers 在线 → anchoredPapers →
metadata 过滤），**不写任何库**。结果：

| 阶段 | 条数 | 占比 |
|---|---|---|
| live（会记为论文命中） | 29 | 48.3% |
| no-related（arXiv 无匹配/全被滤掉） | 15 | 25.0% |
| empty-query（buildPaperQuery 返回空） | 16 | 26.7% |

**但质量不及格**：71 篇保留论文中，CVE 锚点命中 **0 篇**（没有一篇论文
提到对应 CVE 编号）；按锚点词看，generic 英文词贡献了过半保留量——
catalyst 10 篇（催化/物理论文）、internet 9 篇、appliances 8 篇、
authorization 5 篇、defender 5 篇、communications 3 篇、center 2 篇、
automatic/professional 各 1 篇，全部与漏洞无关。真实产品名锚点同样大量
假阳性（directx → 手势库论文、acrobat → 深度学习自动批处理论文）。

**结论：现过滤器下直接全量重跑，会把约一半条目标成 paper live，但绝大多数
是噪声论文——比没有论文更糟（会污染问答引用）。** 收敛方向（待用户确认）：

1. 锚点必须来自产品身份（entities.product），拒绝标题衍生词；
2. 扩充通用词表（探针实测的 catalyst/internet/appliances/authorization/
   defender/communications/center/automatic/professional 等先进表）；
3. 锚点要求命中论文**标题**而非仅摘要，且与机制词共现；
4. 改完后用小样本复跑探针验证假阳性率，再决定是否全量。

在收敛完成前，**不做 paper 全量重跑**——paper 已降为可选维度，
不阻塞任何达标判定。

3. cvss 2828 条“本地无 NVD 源”结构性缺口：需要补 NVD 全量源或接受缺口，
   继续跑不涨（审计已标 structural）。

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

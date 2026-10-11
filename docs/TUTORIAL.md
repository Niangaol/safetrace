# SafeTrace 项目 Tutorial（从零到演示）

> 这份文档是**动手向**的唯一手册：原来的 `LOCAL-STACK` / `LOCAL-DEMO` / `MONITORING-METRICS` / `GITHUB-FLOW` /
> `HANDOVER` / `TEAM-PLAN` / `TASKS` / `ASSET-SCAN` / `QA-ADAPTIVE-UI` / `ENRICHMENT-*` / `P10-LOCAL-VERIFY` /
> `P07-DEMO-PLAN` / `JEV-*` / `FRONTEND-COMPETITION-UI` / `EFFECTS-LAYER` / 各日期报告等已全部合并到这里。
> 想先"看懂项目"请看 [`PROJECT-ANALYSIS.md`](PROJECT-ANALYSIS.md) + [`PROJECT-OVERVIEW.svg`](PROJECT-OVERVIEW.svg)，
> 门面与现状看仓库根 [`README.md`](../README.md)。
>
> **三条路线**：只想看项目 → PROJECT-ANALYSIS；想跑起来 → 本文件 §2–§4；想改代码 → 本文件 §5–§13。

---

## 1. 开始之前

### 1.1 环境要求

| 项 | 要求 | 说明 |
|---|---|---|
| Node | **>= 24** | `node -v` 确认；`npm ci` 一次即可 |
 | Git hooks | `git config core.hooksPath .githooks` | **每次 clone 后都要执行一次**，否则提交信息/推送门禁不生效 |
 | 磁盘 | 本地推理栈另需约 5 GB | 模型目录默认 `../safetrace-models`，Qdrant 二进制在 `D:\AgentPrograms\qdrant\` |
 | NVD API key | 可选但建议 | 免费，邮箱激活链接 7 天有效；无 key 限流 5 req/30s |

### 1.2 环境坑（都踩过，别再踩）

| 症状 | 原因 | 处理 |
|---|---|---|
 | `tsc: command not found` / 找不到 typescript | 依赖没装全 | `npm ci`（根目录） |
 | esbuild 报 `Access is denied` / 无法建临时文件 | esbuild 在系统 TEMP 建临时文件被安全策略拒 | 先 `mkdir -p .tmp`，再把 `TEMP`/`TMP` 指到仓库内 `.tmp` |
 | 测试报 `EXDEV: cross-device link not permitted` | 临时目录与工作盘不在同一卷（如 `C:\Users\...\Temp` vs `D:\AgentPrograms\safetrace`） | 把 `TMPDIR` 指到工作区所在卷，或在该测试里改用同卷临时目录 |
 | `bash: couldn't create signal pipe` | Windows 上 Git Bash 的信号管道被环境限制 | 用 `pwsh`/`cmd` 或直接在 Node 里 `spawnSync` |
 | 前端请求 5xx / 白屏 | 后端没起，或用了静态演示模式 | 前端**默认只请求真实后端，拿不到就报错，不静默回退假数据**；要静态演示必须显式 `VITE_DEMO_MODE=true` |

---

## 2. 第一次跑起来（10 分钟）

```bash
npm ci && npm ci --prefix web

npm run check      # 门禁四件套：typecheck + 全量单测 + 契约校验 + 前端构建
npm run smoke      # 端到端冒烟：fixture 回放跑完整链路，逐项 PASS（含"零静默兜底"断言）
npm run cli:ask -- "Log4Shell 影响哪些版本？怎么修复？"
npm run trace:lineage -- <上一步输出的 trace_id>   # 看这条答案的处理 DAG
```

冒烟脚本覆盖的关键断言（演示时可以直接念）：20 条黄金问答、零静默兜底、A-06 自愈演练、
A-05 时效过滤、P-05 多源冲突、P-03 版本影响、A-01 挂起/恢复、A-02 人工工单、A-06 常驻自愈。

---

## 3. 本机演示（双窗口）

```powershell
npm run demo:serve        # 窗口 A：127.0.0.1:8000 只读情报 API（启动即实跑离线采集→DQ1→富化）
npm run dev --prefix web  # 窗口 B：127.0.0.1:5173 前端
```

建议手测清单：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
Invoke-RestMethod 'http://127.0.0.1:8000/api/v1/vulns?page=1&page_size=10'
Invoke-RestMethod http://127.0.0.1:8000/api/v1/metrics/overview
# 问答（SSE 流式）
$body = @{ question = "CVE-2021-44228 如何修复？" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/qa/chat" -ContentType "application/json" -Body $body
```

**LLM 调用边界**：演示链路默认 `cache` provider + fixture 回放，`answer_mode=template`，`model_calls=0`，不产生任何费用；
要接真实模型只在设置页保存密钥并显式 apply，且 `data_domain=private` 的上下文硬拒出云。

**前端数据来源规则（最容易被误解的一处）**：默认只请求真实后端，失败即报错；
只有 `VITE_DEMO_MODE=true` 才进静态演示模式，并且全站横幅标注。fixture 必须带 `data_mode`/`mock` 标识，费用显示 `—`。

---

## 4. 本地推理栈（Qdrant + bge-m3 + llama.cpp，无 Docker）

```powershell
npm run local:up     # 起 Qdrant :6333 / embedding :8081 / chat :8080；首次自动下载缺失模型（约 5GB，国内镜像源）
npm run local:down   # 全停
npm run pilot:doctor # 只读就绪检查（--strict 可作门禁）
npm run vector:verify# 实测：embedding 推理 + Qdrant 写入 + 语义召回
```

- 模型：`bge-m3-Q8_0`（实测 1024 维）与 `Qwen2.5-7B-Q4_K_M`；llama.cpp 用 winget 的 `ggml.llamacpp`（Vulkan 后端）。
- **出网默认人工拒绝**：`trust_boundary: local` 必填；下载模型/转云端都要显式确认，不允许静默出网。
- **向量入库默认关闭**：`SAFETRACE_INDEX_QDRANT=true` 才经 MG1 写 Qdrant；该路径拒绝离线/fixture 降级、cache/hash 向量、缺模型版本或维度配置，写失败会报错而不是冒充成功。
- 备选路径（本机装不了 Docker，compose 已降级为补验项）：`docker compose -f ops/docker-compose.yml up -d` + `bash ops/scripts/wait-healthy.sh`。
- 端口表：8000 live API ｜ 5173 web ｜ 8317 MG1 ｜ 8318 检索服务 ｜ 6333 Qdrant ｜ 8081 embedding ｜ 8080 本地 chat。

---

## 5. 每条线怎么用

### 5.1 Y 监测线（`src/ingest`）

```bash
npm run ingest:once                 # 离线跑一次 采集→解析→去重→DQ1（持久化到 var/safetrace.sqlite）
npm run ingest:once -- --source nvd_cve --limit 5
npm run quarantine:list             # DQ1 隔离区：可查可导出（--json 含完整判定）
npm run backup:intel                # 动索引/正式库之前先备份
node --import tsx src/ingest/src/cli/report.ts   # 时效与可用率报告（双口径，见 §7）
```

- 7 类源登记，5 个连接器在跑：CISA KEV / NVD / OSV / cve.org / Ubuntu USN；GHSA、arXiv 计划中。
- 联网采集需显式 `SAFETRACE_INGEST_OFFLINE=false`；默认离线走 fixture。
- 同一漏洞被多源重复记录是正常的——事件库 append-only，**别把 `event` 数量当成漏洞数**。

### 5.2 F 富化线（`src/enrich`）

```bash
npm run enrich:pending             # 对待富化情报跑富化（默认离线）
npm run enrich:evaluate            # 富化质量评测（全程网络 guard）
npm run enrich:captured:cvss       # 已保存原文的 CVSS 核对
npm run remediation:preview        # 修复建议只读派生预览
npm run knowledge:preview          # 知识投影预览
npm run qa:quality                 # 问答质量合成探针（24 题，非比赛准确率）
npm run qa:quality:live            # 对真实已保存语料跑 HTTP 回归
```

- 六个维度：F1 论文关联 / F2 资产定位 / F3 POC / F4 CVSS+EPSS / F5 修复建议 / F6 一致性校验。
- **逐维状态 sidecar**：旧 `EnrichmentResult` 不动，新增结果写独立收据表；提交前重验 Intel/DQ 与原文哈希，零联网零模型零 PoC 执行。
- **覆盖率有两把尺**：headline（sidecar 任一维度 live）与投影验证（paper/cvss 与原始报文逐字匹配且血缘完整）。两者数值不可直接比较，仪表盘与 `coverage-agent` 各自标注口径。
- **EPSS 只有拿到 FIRST 回执且带 as-of 才算 live**；mock 一律标注，分母为 0 时输出 `null` 而不是 0。
- 小样本禁止声称"70%/85%/95%"；标签系 agent 提议，**待人工复核**。

### 5.3 Q 问答线（`src/qa`）

```bash
npm run cli:ask -- "<问题>"         # CLI 问答
npm run qa:serve                   # 检索服务 :8318（/healthz /v1/retrieve）
npm run human:queue -- list        # 人工工单：list / claim / decide
npm run review:queue -- list       # 受控网页人工复核队列
npm run selfheal:drill             # 自愈演练：检测→降级→退避→恢复→重放→验证
npm run selfheal:daemon            # 常驻自愈（SQLITE_PATH / SELFHEAL_INTERVAL_MS 可配）
```

- 链路：Q1 意图（规则 + 可选 Jev 旁路）→ Q2 混合检索（BM25-lite 默认，dense 需本地栈）→ Q4 四段式带引用答案。
- **Q5 三个方向的解决方案**（2026-10-11 新增）：问题里能对齐到 CVE/产品时，答案末尾追加基于本地仓库快照的三段方案——
  升级修复 / 临时缓解 / 替换或移除。实现见 `src/qa/src/solution-plan.ts`，只读 `var/assets.sqlite`，仓库路径只出哈希指纹，拒答答案一律不追加。
- **自适应交互界面**：模型只编排白名单组件与**已有证据 ID**，不产新文字/评分/动作；服务端绑定检索原文，前端独立校验，非法整份回退文字。
- 兜底阶梯：工具 → 规则 → 本地 Jev → 云 LLM → 人工工单；任何降级都带 `degraded_to` 且用户可见。

### 5.4 A 资产线（`src/assets`，本地仓库快照）

```bash
npm run assets:scan -- --list-groups     # 列分组（仓库/组件/未读统计）
npm run assets:scan                      # 扫描所有启用分组 + 匹配 + 落库
npm run assets:scan -- --group safetrace # 只扫指定分组
npm run assets:scan -- --json            # 机器可读输出
npm run assets:demo                      # 20 条合成资产版本匹配（不扫网络）
```

- 分组是**运行时真相源**（`var/assets.sqlite` 的 groups 表），`config/assets-scan.json` 只在空库时播种；Web 资产页可增删改。
- 三态判定：`affected` / `not_affected` / `unknown`；**范围约束下界（`^3.5.0`）与未锁版本一律 unknown**，不猜"实际装的就是下界"。
- `vendor_unverified` 恒为 true（本地扫描不携带厂商身份）；**没有告警不代表不受影响**。
- API：`GET /api/v1/assets/groups|overview|repos|components|alerts`，`POST /api/v1/assets/scan|groups|groups/delete|alerts/read`（都要本机页面来源）。

### 5.5 MG1 模型网关（`src/gateway`）

- 所有模型调用的唯一出口；业务代码禁止 import 任何 provider SDK，切换只改 `config/models.yml` + `.env`。
- 管角色路由、cache/openai_compat 双 provider、令牌桶、熔断、降级链、token 计量。
- **隔离闸门**：`data_domain=private` + `trust_boundary=cloud` 硬拒；模型出云前还要过来源白名单与注入筛查。
- `npm run llm:context -- list|show|put|activate|deactivate` 管理结构化 ctx（版本化，停用即 fail-closed）。

### 5.6 受控采集 P-10（单页入库）

```powershell
npm run crawl:page -- https://vendor.example/advisory     # 默认仅预览，不入库
npm run page:demo                                        # 零网络验证 规则→DQ1→SQLite 原文→证据块→BM25
npm run review:queue -- list
npm run review:queue -- decide <review_id> accept <reviewer> "已核对来源"
```

- 门禁：精确 host allowlist、HTTPS/同 host 重定向、`robots.txt` 校验；日期必须用**源声明**的发布日期，不能拿抓取时间顶。
- 显式入库要 `PAGE_INGEST_ENABLED=true` + `PAGE_INGEST_METADATA` 元数据文件（联网前校验），DQ1 放行才发布 IntelItem。
- 成功也标记 `not_indexed`，不自动写 Qdrant；单页声明不改全局 SourceRegistry；SQLite 不是 WORM。

---

## 6. 自愈与可观测

- **A-06 自愈**：`src/qa/src/orchestrator/selfheal.ts` 三角色工具（replay / dead_letter_drain 指数退避重投 / healthcheck 聚合）+ `fallback.events` 全量登记（兜底透明率 100%）；`selfheal-daemon.ts` 常驻化，每拍 JSON 摘要落 `var/selfheal-daemon.log`。
- **A-01 挂起/恢复**：`runMachine` / `resumeMachine`，检查点落 `machine_threads`，持久 token 租约 + 图版本指纹；崩溃租约需人工解锁。
- **A-06 Langfuse 外发默认关闭**，只发元数据；密钥不得硬编码。
- 全链溯源：`npm run trace:lineage -- <trace_id>`；lineage 是追加式审计元数据，**不是不可篡改存储**。

---
## 7. 时效与指标口径（评分类指标唯一口径）

`BT`bash
node --import tsx src/ingest/src/cli/report.ts      # 时效/可用率报告
`BT`

- **监测延迟 lag** = `first_seen_at − published_at`，按 CVE 去重；SLA 口径 21600s（6h）。
- **双口径必须都看**：只截图一个数字会误导。`data_basis` 三态：`live` / `fixture` / `fixture_only`；
  **`fixture_only` 不得上报为真实成绩**。
- 排除规则（红线：宁可少一条，不可错一条）：REJECT/RESERVED 状态、时区不可解析、重复记录、源侧缺发布日期。
- 已知不可达：本机到 `cisa.gov` 不通，KEV 走 fixture——所有 KEV 相关数字都要带这个前提。
- 连续运行与可用率（E-07）：72h 挂机证据仍未补跑，**不许把代码合入说成已验收**。
- 第 7 源 `ubuntu_usn` 的选型依据与线路可达性实测矩阵见 git 历史中的 MONITORING-METRICS 版本（已合并至本节）。

### 富化覆盖率口径（最容易被问住的地方）

| 口径 | 定义 | 参考值（带日期，别混用） |
|---|---|---|
| A headline | sidecar 任一维度 live | 2026-10-06：94.9% |
| B 投影验证 | paper/cvss 与原始报文逐字匹配且血缘完整 | 2026-10-06：50.7% |
| C 持久 trace | 最后一条持久 trace 的覆盖率 | 2026-10-09：1098/3727 = 29.5%（其中 1074 条论文是 fixture 降级） |

基线规模（不同日期快照，引用时必须带日期）：情报 6392 条 / CVSS 3241 / EPSS 6068 / paper 0（2026-10-06）。
**两把尺数值不可直接比较**，仪表盘与 `coverage-agent` 各自标注口径。

### 问答质量评测（免责声明必须一起念）

`npm run qa:quality` 是**合成契约探针**，冻结 24 题，测的是「证据绑定 / 拒答 / 冲突披露」等契约行为，
**不是比赛准确率**：修复前 18/24 → 安全合成版 21/24 → 新 natural 接线 22/24（早期的 23/24、24/24 自由文本兜底结果已弃用，不得引用）。
`npm run qa:quality:live` 对真实已保存语料跑 HTTP 回归（来源保真 9/9，模型调用 0）。
证据与成绩记录在 `docs/evidence/qa-quality/`（脚本自动产出，`before` / `after-safe-func` / `after-safe-wired` / `real-http` 为有效版本，其余为历史对照）。

---

## 8. 契约怎么改（D6 = 10/3 已形式化冻结）

- **只允许「新字段追加 + 旧字段标 deprecated」**；禁止改语义、改枚举、删字段。
  变更须另外两人各一个「同意」，并更新 [`contracts/schemas/CHANGELOG.md`](../contracts/schemas/CHANGELOG.md)。
- **缺省 = 未知**：字段缺失禁止读成「已筛查 / 可信 / 新鲜」。
- 动 `contracts/` 前先跑 `npm run validate:contracts`；冲突时停下在群里喊，不要自行取舍。
- 当前契约版本 v1.2.x；8 个 JSON Schema + `events.md` + `openapi.yaml`。

---

## 9. 协作规范

### 9.1 单线制（D3 起）

- 只在 `main` 工作，**不新建 feature/contract/docs 分支**；push 被拒就 `git pull --rebase`，**禁 force push**。
- 提交信息用 Conventional Commits，且**必须带台账编号**（hook 强制，见 `.githooks/commit-msg`）。
- 推送前门禁与 CI 同口径（`.githooks/pre-push`）：`npm run typecheck && npm test`。
- 里程碑打 tag：`submission-v1`（D20）。紧急情况见 git 历史中的 GITHUB-FLOW 第七节（已合并至本节）。

### 9.2 分工

| 成员 | 主责 | 边界 |
|---|---|---|
| 李念（队长） | MG1 / Q 线 / 编排 / 契约 / ops / 安全核查 | 契约最终口径 |
| KKK9747human | web 全部 + 端到端演示 | 只改 `web/`；浏览器录屏验收 |
| XueXuhang | Y 线第 7 源 + 时效看板 | 只改 `src/ingest` 与 `web`；礼貌爬取；看板数字必须真实，宁显示「未达标」不许手填 |
| 乙 | F 线富化 | 每条富化带 `source`；badcase 归档 |

每周五 20 分钟照台账对齐；22:00 三句话日报时间待确认。

### 9.3 五条红线

1. 契约先行；2. 禁止 import provider SDK（一律走 MG1）；3. 兜底必须显式（`degraded_to` + 用户可见）；
4. 脏数据不进 Qdrant（先过 DQ1）；5. Mock 必须说出口并写入报告「已知限制」。

---

## 10. 前端规范

- **`data_mode` / `qa_mode` 不写死**：未实现的功能不许美化；密钥只做本地加密存储，拒内网/IP/明文 http 请求，禁管理端口。
- **动效层是纯装饰**：不承载语义、`prefers-reduced-motion` 默认关、粒子与 DPR 设上限、隐藏即停帧、数字终值精确、打字机不用于回答与引用、装饰节点 `aria-hidden`。
- 首页 → 大屏已**删除过场动画**（试过 three.js 地球推进与 2D 克隆放大两版，都有实测结论后删除）；`.dash-grid` 网格 168px/42px、亮度 0.20/0.10 为对齐基准。
- Markdown 渲染全链路无 `v-html`/`innerHTML`，链接协议白名单只放行 http/https。
- 工作台只信真实 SSE 事件；多行帧（`event:` 与 `data:` 同帧）已修，丢事件即失败。

---

## 11. 排障 FAQ

| 症状 | 处理 |
|---|---|
| `npm run check` 在 typecheck 阶段就红 | 先看是不是 `node_modules` 没装全（`npm ci`）；再看是不是别人未跟踪的新文件报错 |
| 单测偶发 `EXDEV` | 临时目录与工作盘不同卷，见 §1.2 |
| 问答页一直转圈 | 看 `demo:serve` 是否起着；SSE 需要 `cache-control: no-transform`，代理会缓冲 |
| 语义检索没效果 | 默认 BM25；`npm run pilot:doctor` 四项就绪 + `npm run local:up` 起栈 + `SAFETRACE_INDEX_QDRANT=true` |
| Qdrant 写入被拒 | 检查是不是 cache/hash 向量、缺 `model_id`/维度配置，或有来源 fallback 到 fixture |
| 富化「没跑」 | `enrich:pending` 只补**没有任何富化记录**的情报；失败维度要单独重跑 |
| 资产扫描没有提醒 | ① 分组没启用 ② 情报缺 `version_range`（存量 NVD 需重跑该源）③ 版本是范围下界 → unknown ④ 同名跨生态 → unknown |
| 设置页保存后不生效 | 设置是草稿 + `apply` 两段式；`expected_revision` 过期会 409，刷新后重试 |

---

## 12. 当前待办与验收命令

### 12.1 硬节点

| 节点 | 日期 | 内容 |
|---|---|---|
| D16 彩排 | 10/13 | 20 问全过 + 7 源登记 + 时效看板 |
| D18 报名截止 | 10/15 | 独立流程 |
| D19 脱敏终审 | 10/16 | 全仓 PII 扫描 |
| D20 功能冻结 | 10/17 | 打 tag `submission-v1`，只修 bug |
| **D22 交件** | **10/19 24:00** | 回执双人复核 |

### 12.2 待办（分三类，别把「等签字」当成「没做」）

**A 类 · 代码已完成，只差三线 sign-off**（禁砍）：C-01~C-06 契约扩展、A-01~A-06、E-04 隔离区、P-03 版本影响、P-05 来源冲突。
遗留边界：A-04 待工具权限审计与人工复核队列接线；A-06 待 Langfuse 密钥去硬编码 + 72h 证据；A-05 待 `score_sparse` 原始分与真实语料时间窗演示。

**B 类 · 真待办 / 进行中**：

| ID | 事项 | 负责人 | 验收要点 |
|---|---|---|---|
| R-07 | 前端假数据清理 | 李念 | 浏览器级验收：横幅/大屏数字/问答页目视 + 录屏 |
| E-01 | 第 7 源 ubuntu_usn | XueXuhang | registry 断言 7 源 + smoke 全绿（**台账与 TEAM-PLAN 口径矛盾，以代码已合入为准并回写**） |
| E-02 | 真实采集留痕 | XueXuhang | fixture 对比正式验收、富化收尾、NVD key、72h |
| E-03 | F1 recall@5 | 乙 | 20 条标注集出数并纳入冒烟门槛 |
| E-07 | 72h 挂机 | XueXuhang | 可用率截图 ≥72h，降级与 FallbackEvent 对齐 |
| D-05/09/10 | 文档与配置口径 | 李念 | README 的 Langfuse/A1 自愈口径；`models.yml` 补注 rerank 无标准端点会报错 |
| D-07 | asktrace9 四篇报告 | 李念 | 源目录已不存在，需重建或从合订本导出（阻塞升级，S-03 依赖） |
| P-01 | F2 资产闭环 | 乙+李念 | 补产品别名/版本语义/资产导入，20 条带可核验规则证据且持续标「演示数据」 |
| P-02 | AI 安全分类 | 乙 | 带版本规则 + 产品标签 + 来源证据 + 人工复核态，抽样可解释 |
| P-04 | 证据六字段 | 李念 | document_id/source_url/fetched_at/content_hash/chunk_id/索引版本 |
| P-06 | POC 不执行 | 乙+李念 | 仅展示引用元数据；修复建议无可靠来源标「待核实」 |
| P-07 | 前端真数据 | KKK9747human | Q2 接本次采集结果、Trace/诊断页、录屏验收，不得称生产实时系统 |
| P-08 | 指标口径 | 全员 | 每指标样本规模/时间窗/统计方法；无实测不得写「已达成」 |
| P-09 | R1–R8 决策 | 全员 | 负责人逐项定案并留决策记录（禁砍） |
| P-10 | 受控抓取 | 李念+Xue+KKK | 72h 索引保鲜、真实语义质量人工标注、SourceRegistry 正式调度 |
| S-01~S-04 | 交件四件套 | 全员 | 台账清零 + 三绿；报告+视频+PPT+Mock 清单逐条对得上（禁砍） |

**C 类 · 阻塞（要人）**：E-05 Docker 未装（降级为补验项）；E-06 NVD API key 未申请（限流 5req/30s）；
云端模型 key（已定暂不接，只留 MG1 接线位）；Ollama/vLLM 未装（已定 cache provider 占位）。

### 12.3 砍单顺序（落后时从上往下砍）

多轮对话 → 资产被动信号 → Q3 自动化 → embedding 热切换演练 → 看板美化。
**禁砍（一票否决）**：模块缺席、脱敏合规、稳定运行时长证据。

### 12.4 验收命令

`BT`bash
npm run check && npm run smoke        # 主线门禁
npm run validate:contracts            # 契约
npm run selfheal:drill                # 自愈全链路
npm run pilot:doctor -- --strict      # 向量链就绪（可选门禁）
npm run qa:quality                    # 问答契约探针（24 题）
`BT`

---

## 13. 读代码的顺序

1. [`../README.md`](../README.md) §1 — 建立全局观
2. [`PROJECT-ANALYSIS.md`](PROJECT-ANALYSIS.md) — 说人话的全景 + 为什么这么设计
3. [`../contracts/schemas`](../contracts/schemas) — 系统的「法律」，先看契约再看代码省很多时间
4. `src/ingest/src/pipeline.ts` — 数据从进到出去的完整旅程，最好的入口文件
5. `src/qa/src/q4-answer.ts` — 答案怎么合成；`src/qa/src/solution-plan.ts` — 三个方向的解决方案怎么来
6. `src/enrich/src/f5-remediation.ts` — 只读派生与「不验证修复」的边界怎么写
7. `src/assets/src/matcher.ts` — 版本判定原语（问答与资产线共用）

> 最后一句：这个项目里**最值钱的不是功能，是口径**。每条结论能说清「从哪来、验到哪一步、哪一步没验」，
> 比多做一个功能更能扛住评委的追问。

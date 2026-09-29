# SafeTrace · 落地项目指导（内部版 · 照着就能开工）

> 本目录是**真实工程骨架**：契约已定义、目录已分好、compose 已写好。
> 参赛人：李念（队长，MG1/Q/编排/契约/ops）｜KKK9747human（web 前端/演示）｜XueXuhang（第 7 源/时效或 F2 被动信号，待最终认领）
> 学校/专业：杭州电子科技大学 · 2026 级 智能科学与技术
> **作品截止：2026 年 10 月 19 日 24:00**｜D3 当前基线见 [`docs/TEAM-PLAN.md`](docs/TEAM-PLAN.md)

## 0. 先读这五条

1. **契约先行**：`contracts/` 是唯一接口真相来源；D6（10/3）形式化冻结，届时三线 sign-off；之后只追加字段或标 deprecated，须另两人同意并更新 CHANGELOG。按 D3 `TEAM-PLAN.md` 单线制在 `main` 工作，不新建 feature/contract/docs 分支。谁的实现没跟上，谁用 `fixtures/` 顶。
2. **禁止 import provider SDK**：所有模型调用走 `src/gateway`（MG1），本地/云端切换只改 `.env` 与 `config/models.yml`。
3. **兜底必须显式**：任何降级响应必须带 `degraded_to` 与用户可见标记，禁止静默兜底。
4. **脏数据不进底座**：进 Qdrant 前必过 DQ1 质量闸门，宁可少一条，不可错一条。
5. **Mock 要说出口**：演示时明示"此处为预置数据"，并写进报告「已知限制」。

## 1. 目录结构与责任人

```
safetrace/
├── contracts/            # D6 冻结的接口契约（全员只读）
│   ├── schemas/*.json    # 8 个 JSON Schema：RawDoc / IntelItem / Enrichment / Decision* / Retrieval* / ToolRegistration
│   ├── openapi.yaml      # MG1 与检索服务的 HTTP 接口
│   └── events.md         # S2 情报总线事件清单（主题名 + payload）
├── fixtures/             # 假数据：不依赖真实源即可开发自测
├── src/
│   ├── gateway/          # MG1 Model Gateway（H 组：模型接入）★必须与采集同步开工
│   ├── ingest/           # Y 线：Y1 采集 / Y2 适配 / Y3 去重 / DQ1 质量闸门（甲）
│   ├── enrich/           # F 线：F1-F6 富化 + D1/D2/D3 深度功能（乙）
│   └── qa/               # Q 线：Q1-Q4 问答 + pi-agent-core 编排（丙）
├── ops/                  # compose、监控、自愈脚本（甲/乙分担）
└── scripts/validate_contracts.py   # 契约校验（CI 里跑）
```

**8 个 JSON Schema**（D6 冻结件；事件清单和 OpenAPI 另计）：

| 文件 | 定义 | 生产者 → 消费者 |
|---|---|---|
| `RawDoc.json` | 原始抓取文档（source_id/external_id/fetched_at/payload_ref） | Y1/Y2 → Y3 |
| `IntelItem.json` | 不可变情报对象（含 first_seen_at/published_at/aliases） | Y3 → F 线 |
| `EnrichmentResult.json` | 富化结果（每维度带 source + confidence） | F 线 → S1 |
| `DecisionRequest/Reply.json` | D4 Jev 决策（typed question schema + 置信度） | Y5/Q1/Q3 → MG1 |
| `RetrievalRequest/Response.json` | 检索请求与带引用的证据包 | Q2 → Q4 |
| `ToolRegistration.json` | 工具注册项（schema + 权限 + 灰度状态） | S4 → 编排层 |

| 优先级 | 模块 | 交付标准 |
|---|---|---|
| P0 | Y1/Y2/Y3 + DQ1 | ≥7 类源接入；24h 连续运行截图；脏数据隔离区有实例 |
| P0 | Q1/Q2/Q4 + S1 | 20 条黄金问答全过，答案带引用与推理链展开 |
| P0 | MG1 + S2 | 一键起 compose；provider 切换不改代码；trace_id 全链贯穿，Langfuse 外发按 A-06 验收 |
| P1 | Y4/Y5 + F1/F4/F6 | 时效看板有真实数字；论文关联与 CVSS 带来源 |
| P1 | A1（自愈） | L1/L2 自愈演练录像；降级状态显式可见 |
| P2 | F2/F3/F5、D1-D4、Q3 | Mock/演示态即可，决赛做实 |

## 2. 三周日历（对齐 03-roadmap.md D1–D22）

- **D1–D8 立项期**：今天申请 NVD API key（唯一要等的商务项）；搭 compose；**D6 契约冻结**；每线用 fixtures 跑通骨架。
- **D9–D16 冲刺期**：D11 首源贯通 + 问答闭环彩排；D12 badcase 归档 + 降级路径落地；D16 完整彩排（20 问全过 + 7 源登记 + 时效看板）。
- **D17–D22 交件期**：D18 报名截止（独立流程，别忘）；D20 功能冻结；D22 24:00 前提交，回执双人复核。

**砍单顺序**（落后时从上往下砍）：多轮对话 → 资产被动信号 → Q3 自动化 → 热切换演练 → 看板美化。**禁砍**：模块缺席、脱敏合规、稳定运行时长证据。

## 3. 环境准备（今天做）

```bash
# 1) 申请 NVD API key（免费，邮箱激活链接 7 天有效）
#    https://nvd.nist.gov/developers/request-an-api-key

# 2) 起基础设施（Qdrant + Postgres + Langfuse）
cp .env.example .env      # 填 NVD_API_KEY 与模型 provider
docker compose up -d qdrant postgres langfuse
docker compose ps         # 三个都 healthy 再往下走

# 3) 装依赖（三线各自目录）
cd src/gateway && npm install && npm test
cd src/ingest   && npm install
cd src/qa       && npm install

# 4) 契约自检（每次改动契约后必跑）
python scripts/validate_contracts.py
```

> 没有 Docker 的机器：Qdrant 可下单文件二进制版（`./qdrant --storage-dir ./qdrant_data`），
> Postgres 可换 SQLite（改 `src/gateway/src/store.ts` 的连接串），**但交件前必须在 compose 上验一遍**。

## 4. 每条线的第一天怎么开始

- **甲（监测线）**：`src/ingest` 里跑 `cvelistV5` git 差分，产出第一条 `RawDoc` 并写进 S2；用 `fixtures/rawdoc.sample.json` 做单测。
- **乙（富化线）**：拿 fixture 里的 `IntelItem` 跑通 F1（arXiv API 关联）与 F4（CVSS 解析），产出带 `source` 字段的富化结果。
- **丙（问答线）**：`src/gateway` 起一个 `cache` provider 的假模型，把 Q1→Q2→Q4 链路用 fixture 文档跑通，答案带 `[证据ID]`。
- **H 组（模型接入，由丙兼）**：D1 就冻结 `contracts/schemas/Decision*.json` 与 `models.yml` 的 `ModelProfile` 结构。

## 5. 交件前 checklist（D20–D22）

- [ ] `python scripts/validate_contracts.py` 全绿
- [ ] compose 一键拉起成功，端口健康检查通过（截图）
- [ ] 连续运行 ≥72h 的可用率截图（7×24 证据）
- [ ] 20 条黄金问答录屏，答案可见引用与推理链
- [ ] 脱敏检查：PPT/视频/公开仓库无真实单位名、人名、内网地址、密钥
- [ ] 报告「已知限制」写明 Mock 清单
- [ ] 交件回执双人复核

## 6. 常见问题

- **模型 API 不可用？** MG1 把 provider 切成 `cache` 或本地 Ollama，**配置改一行**，演示不中断。
- **数据源挂了？** Y 线单源故障隔离 + Y4 补偿采集；S2 死信可重放。
- **某个模块写不完？** 按第 1 节 P0/P1/P2 降级，并在报告里按 4.5 分级口径诚实折算完成度。

---

## 7. P0 落地状态（2026-09-28 D1 晚交付，main 可演示）

本目录已从「只有文档」变为「可运行的工程骨架」。核心链路（采集→解析→去重→质量闸门→富化→入库→带引用问答）**离线可复现**：

```bash
npm install                 # 一次性（Node ≥24，免原生编译）
npm run check               # 门禁 = typecheck + 单测 + 契约校验 + 前端构建
npm run smoke               # 端到端冒烟：fixture 回放跑完整链路，逐项 PASS
npm run cli:ask -- "Log4Shell 影响哪些版本？怎么修复？"   # 问答线 CLI 演示
npm run assets:demo                                         # 20 条本地合成资产版本匹配，不扫描网络
npm run gateway:serve       # MG1 HTTP :8317（/healthz /v1/chat/complete /v1/embed /v1/rerank）
npm run qa:serve            # 检索服务 :8318（/healthz /v1/retrieve）
```

**零外部依赖即可演示**：不装 Docker、不配 key、不联外网（默认 `cache` provider + fixtures 回放）；
所有降级路径经 `degrade()` 统一登记 `fallback.events` 并在响应带 `degraded_to`——冒烟第 7 项断言零静默兜底。

| 模块 | 状态 | 测试 | 说明 |
|---|---|---|---|
| contracts/ | **v1.1 冻结待 D6** | 校验器当前全绿 | 8 schemas + events.md + openapi.yaml；C-01 待三线 sign-off，C-02~C-06 待完成；D3 起 main 单线，D6 后只追加/标 deprecated并经另两人同意 |
| src/shared | S2 总线 v0 | 8/8 | Envelope/幂等总线/SQLite+内存双存储/降级统一出口 |
| src/gateway（MG1） | 红线模块 | 9/9 | 角色路由、cache/openai_compat 双 provider、令牌桶、熔断、降级链、token 计量 |
| src/ingest（Y 线） | 首期 | 29/29 | 6 源登记、4 连接器（KEV/NVD/OSV/cve.org）、fixture 回放、Y3 强标识去重、DQ1 四档闸门（10 条脏样本全捕获） |
| src/enrich（F 线） | 最小闭环 | 50/50 | F1 arXiv 关联、F4 CVSS v3.1 规范计分 + EPSS + 多源仲裁、F6 冲突仲裁 |
| src/qa（Q 线） | 最小闭环 | 36/36 | Q1 规则意图、Q2 BM25-lite + MG1/Qdrant dense RRF（默认 BM25，拒绝 cache/hash 向量）；Q4 四段式带引用答案、CLI + HTTP |
| ops/ | compose 就位待验 | 脚本自测过 | qdrant + postgres + langfuse 全家桶（Docker 未装，装好后 `bash ops/scripts/wait-healthy.sh`） |

**已知限制（须同步进报告「已知限制」）**：① 默认 `cache` provider 是确定性占位，未配真实模型时没有 LLM 推理；② Q2 已接 MG1 真实 embedding 接口，但默认 cache 向量会被拒绝写入/查询语义集合，显式退回 BM25-lite；只有配置真实 embedder、Qdrant 和数据索引后才有 dense 召回；③ 新增单页 allowlist crawler 与规则抽取模块，但尚未接 ingest 定时任务、DQ1 持久化入库或可恢复 last-good 存储；④ A-03/A-04 完成前，不可信网页不会送进真实云 LLM，当前只留安全门接口；⑤ Firecrawl / 云 LLM / embedding 默认关闭，Firecrawl 按页消耗 credits；⑥ Docker/Qdrant/本地模型环境尚未完成真实运行验收；⑦ `published_after`、完整 Langfuse Trace 和前端真实 API 仍按任务台账推进，不得宣称已完成。

**D3 分工与新增方向**：李念负责 MG1/Q/编排/契约/ops，D6 前收口 C-01~C-06，D8 前完成 R-04/R-05/R-03/A-02；KKK9747human 主责前端及端到端演示；XueXuhang 在方案 A（第 7 源+时效看板）与方案 B（F2 被动信号）中认领。P-10 受控 Firecrawl + 规则/受控 LLM/人工复核 + Qdrant 语义向量小切片见 [`docs/TEAM-PLAN.md`](docs/TEAM-PLAN.md) 与 [`docs/TASKS.md`](docs/TASKS.md)。A-03/A-04 未完成前，真实 LLM 网页抽取保持关闭。

## 8. P-10：受控采集与可审计语义证据库

本地工作树已实现可单测的小切片，但还不是接入 ingest 的端到端生产功能：

- `src/ingest/src/firecrawl.ts` 提供单 URL 精确 host allowlist、HTTPS/同 host 重定向与 `robots.txt` 校验、直连重试 → Firecrawl（须 API key）→ last-good 快照兜底；默认 `enabled=false`，不爬链接、不执行脚本、不回放 fixture。
- `scripts/crawl-page.ts` 提供单页手动入口，只输出不可信页面预览，不入库、不发问答。可用 `FIRECRAWL_ENABLED=true FIRECRAWL_ALLOWED_HOSTS=vendor.example npm run crawl:page -- https://vendor.example/advisory` 做授权域名的试跑；若需 Firecrawl，设置 API key 前请注意按页计费。
- `src/ingest/src/extraction-fallback.ts` 先做 CVE/原文规则抽取；规则不完整才可走注入的安全门与 LLM adapter，输出还需通过原文引用验证，否则返回 `needs_human_review`。A-03/A-04 未完成，当前没有生产 MG1 LLM adapter，也没有持久化/前端人工复核队列。
- Q2 通过 `ModelGateway.embed` 接真实 embedding，拒绝 `cache`/降级/模型 ID 或维度不符的向量；有 Qdrant 时使用 dense + BM25-lite RRF，分数分别标为 `score_dense` / `score_sparse`，不伪装成 reranker 分数。
- 默认 embedder 仍为 cache，因此 QA 服务默认显式回退到 BM25-lite。需配置真实模型服务、准确 `model_id` / `capability_flags.dim` 和 Qdrant 才可测语义召回；`QDRANT_SEED_FIXTURES=true` 仅用于向新集合写入演示 fixtures，不代表真实知识源 ingestion。
- 结构化记录与 RawDoc 仍是事实主库；Qdrant 是可重建证据索引。真实来源到 DQ1、RawDoc 持久化及 Qdrant 的生产索引桥接仍未完成；不得编造来源/引用。
- 网页是不可信输入；A-03/A-04 安全边界通过前，真实 LLM 网页抽取保持关闭。Firecrawl / 云 LLM / embedding 默认关闭。

本地体验 BM25 演示链（PowerShell；不需要 Qdrant 或云 key）：

```powershell
$env:PORT = "8318"
$env:OFFLINE_FIXTURES = "true"
npm run qa:serve
```

另开一个终端请求：

```powershell
$body = @{ query_id = "manual"; query_text = "Log4Shell 影响哪些版本？"; top_k = 3; trace_id = "manual"; schema_version = "1.0" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8318/v1/retrieve" -ContentType "application/json" -Body $body
```

这只验证 fixture + BM25-lite HTTP 链路，不代表真实 embedding/Qdrant 已运行。

自动化检查：`npm test`、`npm run typecheck`、`npm run validate:contracts`。真实 Qdrant/模型服务是否可运行取决于本机部署，当前没有实际联网或付费调用记录。

实施状态、负责人、依赖和验收以 [`docs/TEAM-PLAN.md`](docs/TEAM-PLAN.md) / [`docs/TASKS.md`](docs/TASKS.md) 为准。

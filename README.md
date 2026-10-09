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
   前端规则：默认只请求真实后端（拿不到即报错，**不静默回退假数据**）；`VITE_DEMO_MODE=true` 才进静态演示模式，且全站横幅标注（规则见 [`docs/HANDOVER.md`](docs/HANDOVER.md) §2）。
   **不许为了让界面好看而伪造指标**——评委一句"跑个新数据看看"就能验伪。

> 📌 **接手先看 [`docs/HANDOVER.md`](docs/HANDOVER.md)**：当前状态 / 怎么验 / 已知限制 / 别踩的坑。
> 任务清单以 [`docs/TASKS.md`](docs/TASKS.md) 为准（唯一可执行台账）。

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

**已知限制（须同步进报告「已知限制」）**：① 默认 `cache` provider 是确定性占位，未配真实模型时没有 LLM 推理；② Q2 已接 MG1 embedding 接口，但默认 cache 向量会被拒绝写入/查询语义集合，显式退回 BM25-lite；只有真实 embedder、Qdrant 和来源索引均配置后才有实际 dense 召回；③ 受控页面工具已有 SQLite last-good 和人工复核队列，已有需操作方显式来源元数据的网页→DQ1 API，但尚未接正式 SourceRegistry 调度；复核决定也不会自动产生 IntelItem；④ `runIngestOnce` / `runEnrichment` 的持久入口是 `ingest:once`，离线 smoke 使用的内存 store 不代表重启持久；⑤ A-03/A-04 完成前，不可信网页不会送真实云 LLM；⑥ Firecrawl / 云 LLM / embedding 默认关闭，Firecrawl 按页计费；⑦ 本地推理栈（llama.cpp + bge-m3 + Qdrant）D4 已验收（见 [`docs/LOCAL-STACK.md`](docs/LOCAL-STACK.md)），来源 Qdrant 生产入库仍未实跑；`published_after`、Langfuse 完整 Trace 与生产级前端 API 接线仍待办（本机演示 API 见 [`docs/LOCAL-DEMO.md`](docs/LOCAL-DEMO.md)）。

**D3 分工与新增方向**：李念负责 MG1/Q/编排/契约/ops，D6 前收口 C-01~C-06，D8 前完成 R-04/R-05/R-03/A-02；KKK9747human 主责前端及端到端演示；XueXuhang 在方案 A（第 7 源+时效看板）与方案 B（F2 被动信号）中认领。P-10 受控 Firecrawl + 规则/受控 LLM/人工复核 + Qdrant 语义向量小切片见 [`docs/TEAM-PLAN.md`](docs/TEAM-PLAN.md) 与 [`docs/TASKS.md`](docs/TASKS.md)。A-03/A-04 未完成前，真实 LLM 网页抽取保持关闭。

**本机演示（2026-10-01 合入）**：`npm run demo:serve`（启动即实跑离线采集→DQ1→富化，问答实跑 Q1→Q2→Q4）+ `npm run dev --prefix web`，手测清单见 [`docs/LOCAL-DEMO.md`](docs/LOCAL-DEMO.md)；前端默认请求真实后端，仅 `VITE_DEMO_MODE=true` 时退回内置静态 mock。

**D4 分工更新**：分工与优先级以 [`docs/TEAM-PLAN.md`](docs/TEAM-PLAN.md) §3.7 为准——KKK9747human 先交付完整基础 demo（施工口径 `docs/P07-DEMO-PLAN.md`，本机直起），李念 review；A-04/E-04 安全核查顺延至 D9–D11 重启。

## 8. P-10：受控采集与可审计语义证据库

本地工作树实现了可单测的小切片；这不是已经接入官方数据源的生产端到端链路。

- 全链路溯源使用现有 SQLite EventStore 的独立 `lineage_records` 表，不改冻结的公开 event/schema 契约。每条记录包含 `trace_id`、多父 `parent_lineage_ids`、causation ID、步骤/版本/状态/时间、输入输出对象 ID 与 SHA-256、来源/模型/降级或审核决定；MG1 还逐 provider attempt 记录 input/output hash、provider、model_id/model_version 与 fallback。lineage 不复制 RawDoc、网页、prompt 或用户 query 正文。`qa:serve`、`gateway:serve`、`cli:ask`、`crawl:page` 默认共用 `SQLITE_PATH`；用 `npm run trace:lineage -- <trace_id>` 检查处理 DAG。
- `runIngestOnce` 会追踪 fetch → parse → dedupe → DQ1；DQ1 lineage parent 可交给富化继续链路。`npm run ingest:once` 已封装成默认离线的 SQLite runner；其他调用方要跨重启保留记录，仍须注入 `SqliteEventStore`。测试/smoke 使用的 MemoryEventStore 是临时的。
- 本地可用 `npm run ingest:once` 启动一次持久化 ingest→DQ1→enrich，默认离线且不访问网络；输出的 `trace_id` 可用 `npm run trace:lineage -- <trace_id>` 检查。只有显式设置 `SAFETRACE_INGEST_OFFLINE=false` 才会请求已登记官方数据源。该 runner 已按解析前来源生成 EvidenceChunk，并记录 DQ1→chunk 构建→临时 BM25 预览的 lineage；每块保留对应 RawDoc URL/载荷 SHA，不把合并后的多来源文本挂到单一来源。临时索引随进程退出丢失。显式设置 `SAFETRACE_INDEX_QDRANT=true` 才经 MG1 向 Qdrant 写入；该路径拒绝离线/fixture 降级、cache/hash、缺模型版本或维度配置，写失败会报错而非冒充入库成功。
- `src/ingest/src/firecrawl.ts` 提供单 URL 精确 host allowlist、HTTPS/同 host 重定向与 `robots.txt` 校验、直连重试 → Firecrawl（须 API key）→ SHA-256 验证的 last-good 快照；成功页面写入 SQLite，后续失败可跨重启 stale 回退，每级均留 lineage。默认 `enabled=false`，不爬链接、不执行脚本、不回放 fixture。
- `scripts/crawl-page.ts` 提供单页手动入口：抓取后运行确定性规则抽取；不完整时把 case 和页面 SHA 入 SQLite 人工队列。默认仅预览；单页入库需再设 `PAGE_INGEST_ENABLED=true` 并提供 `PAGE_INGEST_METADATA` 文件，元数据在联网前校验，DQ1 放行才发布 IntelItem。成功只构建来源证据块，不自动索引或发问答。操作步骤见 [本地验证指南](docs/P10-LOCAL-VERIFY.md)。用 `npm run review:queue -- list` 查看页面预览，再用 `npm run review:queue -- decide <review_id> accept <reviewer_id> "已核对来源"` 记录决定；action 可选 `accept`、`reject` 或 `defer`。Firecrawl 仍需显式 allowlist/开关并按页计费。
- `src/ingest/src/extraction-fallback.ts` 先做 CVE/原文规则抽取；规则不完整才可走注入的安全门与 LLM adapter，输出须通过原文引用验证，否则 enqueue 持久 review case。SQLite 队列与 `review:queue` CLI 可记录接受/拒绝/延期及审计 lineage；尚无前端队列，审批决定不会自动写入 DQ1。A-03/A-04 未完成，生产 MG1 网页抽取仍关闭。
- `ingestCollectedPage` 仅接收明确的 active vendor 来源、带时区发布日期与可靠性；再次验证原文证据/SHA，stale 或待复核项不发布。运行 `npm run page:demo` 可零网络验证规则→DQ1→SQLite 原文→来源证据块→BM25 检索，并校验证据哈希与重启读取；它明确输出 `mock: true`。`sqlite-page:<hash>` 原文引用通过 EventBus 快照 API 读取，来源证据转换已支持此引用，并核对快照哈希、来源 URL 和摘录证据；文件式富化适配器仍不支持它，真实 embedding API 已单文本验证，但 Qdrant 持久写入/召回仍未实测，不能宣称生产富化/向量链已验收。
- Q2 通过 `ModelGateway.embed` 接真实 embedding，拒绝 `cache`/hash、降级、模型 ID 或维度不符的向量；Qdrant upsert、dense/BM25 检索、RRF 融合、Q4 答案均记录对象引用与内容 hash。分数标为 `score_dense` / `score_sparse`，不伪装成 reranker 分数。
- 默认 embedder 仍为 cache，因此 QA 服务默认显式回退到 BM25-lite。需配置真实模型服务、准确 `model_id` / `capability_flags.dim` 和 Qdrant 才可测语义召回；`QDRANT_SEED_FIXTURES=true` 只写演示 fixtures，不代表真实来源 ingestion。真实 Qdrant 持久写入/检索尚未实测；2026-09-30 已用两次单文本请求验证 Tokendance 的 `qwen3.7-text-embedding`（直连接口一次、MG1一次），返回 1024 维非零有限向量，无 cache 降级。独立配置为 [真实 embedder profile](config/models.tokendance.yml)，默认配置仍离线。运行 `npm run embedding:verify -- --live` 显式发一条合成短文本并记录 MG1 lineage，可能消耗 credits；不传 `--live` 不调用模型。本地 key 仅在忽略的 `.env.local`，不在模型清单。API 未给 revision，版本标为 `unversioned-api`，服务换版须重建集合。
- 运行 `npm run pilot:doctor` 做只读本地启动检查：读取 embedder 的 provider/model_id/model_version/dim，GET 探测 loopback Qdrant `/collections`、已有 dense 集合的维度/距离及本地模型 `/models`。远程或带凭据 URL 不探测，不发送 key，不做 embedding/chat 请求。`--strict` 在前置条件不齐时退出 1。`prerequisites_ready=true` 仅说明可开始实测，`embedding_inference_verified` / `vector_persistence_verified` 仍是 false，不能当作验收结论。
- 真实向量试跑前须自行启动 Qdrant 与本地 embedding 服务，在 `config/models.yml` 的 embedder 配置服务真实注册名/版本/实测维度，并通过环境变量设置 loopback 基址。入库与 QA 必须使用相同 `QDRANT_COLLECTION`、模型和维度。需联网官方来源时再显式设置 `SAFETRACE_INGEST_OFFLINE=false`，需向量写入再设 `SAFETRACE_INDEX_QDRANT=true`；任一来源 fallback 到 fixture 会阻止生产入库。本轮 doctor 实测仍是 cache 配置 + 本地 Qdrant 不可达，未进行模型推理。
- SQLite lineage 是追加式审计元数据，不是不可篡改的 WORM 存储；last-good 最新缓存、按来源/内容 SHA 保留的历史页面快照与 review 状态保存在独立 sidecar 表；URL 更新不覆盖旧审核证据，旧 URL-only 缓存会自动迁入历史表。需为共享生产路径固定 `SQLITE_PATH` 并配置备份/保留策略。RawDoc/IntelItem 仍是结构化事实主数据，网页→DQ1 API 与零网络演示已实现，正式采集调度接线仍待完成；结构化来源到 Qdrant 的 opt-in 桥接已实现，真实服务验收仍待完成。

本地体验 BM25 演示链（PowerShell；不需要 Qdrant 或云 key）：

```powershell
$env:PORT = "8318"
$env:OFFLINE_FIXTURES = "true"
npm run qa:serve
```

另开一个终端请求并查看该次 lineage：

```powershell
$body = @{ query_id = "manual"; query_text = "Log4Shell 影响哪些版本？"; top_k = 3; trace_id = "manual"; schema_version = "1.0" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8318/v1/retrieve" -ContentType "application/json" -Body $body
npm run trace:lineage -- manual
```

这只验证 fixture + BM25-lite HTTP 链路和 lineage 记录，不代表真实 embedding/Qdrant 已运行。

自动化检查：`npm test`、`npm run typecheck`、`npm run validate:contracts`。未调用实际 Firecrawl 或云 chat/网页抽取；已按用户提供服务信息进行两次单文本 embedding 验证，计费由服务方决定（首次响应报告 22 tokens），未做批量索引。

实施状态、负责人、依赖和验收以 [`docs/TEAM-PLAN.md`](docs/TEAM-PLAN.md) / [`docs/TASKS.md`](docs/TASKS.md) 为准。

## 9. 本地资产扫描与多分组监控（A 线，2026-10-09）

按分组监控本机 git 仓库/项目目录：每组独立扫描根目录、独立技术栈快照（var/assets.sqlite）；新情报入库后自动比对，命中受影响组件即生成提醒（Web 铃铛 + /assets 页 + CLI + watch 常驻匹配）。

```bash
npm run assets:scan -- --list-groups     # 列分组（含仓库/组件/未读统计）
npm run assets:scan                      # 扫描所有启用分组 + 匹配 + 落库
```

分组可在 Web 资产页「分组管理」维护（config/assets-scan.json 仅在空库时播种一次）。设计与合规边界（只读本地、零网络探测、不猜结论、降级显式）见 [`docs/ASSET-SCAN.md`](docs/ASSET-SCAN.md)。已知限制：存量 NVD 情报需重跑该源后 version_range 才入库（适配器已修复，见文档 §4）。

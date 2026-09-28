# SafeTrace · 落地项目指导（内部版 · 照着就能开工）

> 本目录是**真实工程骨架**：契约已定义、目录已分好、compose 已写好。
> 参赛人：李念（队长，问答线+编排+底座）｜甲（监测线+运维）｜乙（富化线）
> 学校/专业：杭州电子科技大学 · 2026 级 智能科学与技术
> **作品截止：2026 年 10 月 19 日 24:00**｜今天 9/28，剩 21 天

## 0. 先读这五条

1. **契约先行**：`contracts/` 是唯一接口真相来源。任何人改契约必须走 `contract:` PR 并 @三线负责人，**D8 后冻结**。谁的实现没跟上，谁用 `fixtures/` 顶。
2. **禁止 import provider SDK**：所有模型调用走 `src/gateway`（MG1），本地/云端切换只改 `.env` 与 `config/models.yml`。
3. **兜底必须显式**：任何降级响应必须带 `degraded_to` 与用户可见标记，禁止静默兜底。
4. **脏数据不进底座**：进 Qdrant 前必过 DQ1 质量闸门，宁可少一条，不可错一条。
5. **Mock 要说出口**：演示时明示"此处为预置数据"，并写进报告「已知限制」。

## 1. 目录结构与责任人

```
safetrace/
├── contracts/            # D6 冻结的接口契约（全员只读）
│   ├── schemas/*.json    # 7 个 JSON Schema：RawDoc / IntelItem / Decision* / Retrieval* / ToolRegistration
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

**七个契约文件**（D6 冻结件）：

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
| P0 | MG1 + S2 | 一键起 compose；provider 切换不改代码；Trace 全落 Langfuse |
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
npm run check               # 门禁 = typecheck + 132 单测 + 契约校验（全绿）
npm run smoke               # 端到端冒烟：fixture 回放跑完整链路，逐项 PASS
npm run cli:ask -- "Log4Shell 影响哪些版本？怎么修复？"   # 问答线 CLI 演示
npm run gateway:serve       # MG1 HTTP :8317（/healthz /v1/chat/complete /v1/embed /v1/rerank）
npm run qa:serve            # 检索服务 :8318（/healthz /v1/retrieve）
```

**零外部依赖即可演示**：不装 Docker、不配 key、不联外网（默认 `cache` provider + fixtures 回放）；
所有降级路径经 `degrade()` 统一登记 `fallback.events` 并在响应带 `degraded_to`——冒烟第 7 项断言零静默兜底。

| 模块 | 状态 | 测试 | 说明 |
|---|---|---|---|
| contracts/ | **D1 冻结 v1** | 校验器全绿 | 8 schema + events.md + openapi.yaml；改契约走 `contract/` PR 三线 sign-off |
| src/shared | S2 总线 v0 | 8/8 | Envelope/幂等总线/SQLite+内存双存储/降级统一出口 |
| src/gateway（MG1） | 红线模块 | 9/9 | 角色路由、cache/openai_compat 双 provider、令牌桶、熔断、降级链、token 计量 |
| src/ingest（Y 线） | 首期 | 29/29 | 6 源登记、4 连接器（KEV/NVD/OSV/cve.org）、fixture 回放、Y3 强标识去重、DQ1 四档闸门（10 条脏样本全捕获） |
| src/enrich（F 线） | 最小闭环 | 50/50 | F1 arXiv 关联、F4 CVSS v3.1 规范计分 + EPSS + 多源仲裁、F6 冲突仲裁 |
| src/qa（Q 线） | 最小闭环 | 36/36 | Q1 规则意图、Q2 BM25 内存索引 + Qdrant REST、Q4 四段式带引用答案（四条件 abstain）、四 Agent 任务图、CLI + HTTP |
| ops/ | compose 就位待验 | 脚本自测过 | qdrant + postgres + langfuse 全家桶（Docker 未装，装好后 `bash ops/scripts/wait-healthy.sh`） |

**已知限制（须同步进报告「已知限制」）**：① 默认 `cache` provider 为确定性占位，真实 LLM 合成待配 key；② Embed 为 `hash-256` 占位向量，Qdrant 接入后换 BGE-M3（S3 绑定已留 `model_id` 校验）；③ 无独立 rerank 通道（MemoryIndex 的 `score_rerank` 为查询内归一分）；④ F2/F3/F5、Q3、D1–D4 按初赛分级口径只留契约位；⑤ `published_after` 在 chunk 级暂不生效（EvidenceChunk 契约无时间字段，需走 contract PR）。

**D2 起任务单**：甲——cvelistV5 git 差分补第 5 源、72h 挂机；乙——F1 真跑调参（recall@5 基线）、黄金集 200 条启动；丙（队长）——pi-agent-core 实测决定是否替换自研 TaskGraph、Langfuse 接入、20 条黄金问答扩量。全员：今天申请 NVD API key。

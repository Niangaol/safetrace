# AI 安全知识情报系统（赛题九）

智能体驱动的 AI 安全知识情报系统：自动监测 AI 相关漏洞/论文/社区情报，做多维富化与证据链溯源，
并用 LangGraph 编排的 Triage → Enrich → QA 三个 Agent 产出可溯源答案。

## 能力一览

| 能力 | 实现 | 关键指标 |
| --- | --- | --- |
| 情报监测 | NVD、GHSA(+webhook)、arXiv、社区 RSS 四源采集（目标 7 类） | 采集延迟 P50/P95、6h SLA 达成率 |
| 情报富化 | F1 论文关联 / F2 受影响资产 / F3 POC 搜集 / F4 CVSS+影响 / F5 修复建议 / F6 一致性校验 + AI 风险分类与 ATT&CK。**每条结论带 `source` 与证据链** | 富化覆盖率、逐维准确率/召回率、降级率 |
| 情报问答 | pgvector 向量检索 + RRF 融合 + bge-reranker | 问答准确率、引用率、P95 延迟 |
| 可观测 | Prometheus 指标、结构化日志、Agent 轨迹入库 | 成本、token、降级次数 |
| 自愈 | 预算熔断、模型降级、源失败隔离、定时健康巡检 | 降级率、告警级别 |

## 架构

```
采集器(NVD/GHSA/arXiv/RSS) → 抽取 → 去重合并(SimHash+跨源) → 标准化 Vuln
        ↓ publish topic: collect
   TriageAgent(风险打分) → EnrichAgent(4维富化) → QAAgent(检索+溯源) → DailyReport
        ↓                       ↓
   PostgreSQL 16 + pgvector  ← Chunk/Embedding/GraphEdge
   Redis(事件总线) · DeepSeek API(主) · Ollama(兜底) · bge-m3 + reranker(本地)
```

- 详细设计：`docs/设计文档.md`（含四线 Y/F/S/Q 兼容性矩阵）
- 富化线详细设计：`docs/富化线详细设计.md`（F1–F6 落地设计、降级口径、验收判据）
- 接口契约：`docs/API契约.md`
- 分工与排期：`docs/任务看板.md`（三周冲刺 D1–D22）
- 富化 badcase 库：`docs/badcase.md`

## 快速开始

### 1. 本地开发

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

cp .env.example .env        # 填入 LLM_API_KEY
docker compose up -d postgres redis ollama
alembic upgrade head
uvicorn aiintel.api.main:app --reload
```

### 2. Docker 一键起全套

```bash
docker compose up -d
docker compose exec ollama ollama pull qwen2.5:7b-instruct
```

服务：API `:8000`、Postgres `:5432`、Redis `:6379`、Ollama `:11434`、Prometheus `:9090`。

### 3. CLI

```bash
python -m aiintel.cli collect --sources nvd,ghsa   # 跑一轮采集-去重-富化
python -m aiintel.cli enrich --vuln-id v_xxx        # 补富化
python -m aiintel.cli ask "最近影响 vLLM 的高危漏洞"  # 命令行问答
python -m aiintel.cli cost                          # 成本与今日花费分布
python -m aiintel.cli health                        # 健康检查与自愈建议
```

### 4. 前端

`web/` 为 Vue3 + Vite + Pinia 工程（`npm install && npm run dev`，默认 5173，已配 `/api` 代理到 8000），四个视图：态势大屏、情报列表、情报详情（含可展开证据链与关系表）、流式问答（含引用来源与降级标识）。

## 成本治理（重要）

对话式系统的成本陷阱是"无脑全量跑"。本项目的闸门：

- **分层模型**：默认只用 `deepseek-v4-flash` 做抽取/分类；`deepseek-v4-pro` 仅在置信度 < 0.7 时升级复核。
- **闲时优先**：计价表按本地时间分峰谷（高峰 9:00–12:00、14:00–18:00，价约为闲时 2 倍；见 `src/aiintel/core/cost.py`），批处理/补数据一律钉在闲时。
- **硬熔断**：`CostGuard` 每日预算 `COST_DAILY_BUDGET_CNY`（默认 20 元），达 80% 告警，超额直接走本地兜底并停止调云。
- **Prompt Cache**：系统提示词与 few-shot 前置，复用率高时输入成本降一个数量级。
- **分层降级**：预算耗尽 / 网络故障 / 超时 → `qwen2.5:7b-instruct` 本地兜底；采集源失败只跳过该源，不阻断链路。

`python -m aiintel.cli cost` 可随时查看当日花费与分布。

## 评测

```bash
python -m eval.run_all                 # 三个指标一起跑
python -m eval.collect_latency
python -m eval.enrich_accuracy
python -m eval.qa_accuracy
```

标注集放 `eval/datasets/*.jsonl`（`*_cases.sample.jsonl` 为模板，复制后填写标注）。
准确率不足时：调 prompt 与 few-shot → 调高 top_k/rerank → 再考虑换 Pro 模型，成本逐级上探。

## 配置

见 `.env.example`。关键项：

| 变量 | 说明 |
| --- | --- |
| `LLM_API_KEY` | 主模型（DeepSeek）API Key |
| `LLM_LOCAL_BASE_URL` | Ollama 地址，用于兜底 |
| `COST_DAILY_BUDGET_CNY` | 日预算上限，超出即熔断（默认 20） |
| `POSTGRES_DSN` / `REDIS_URL` | 存储与事件总线 |
| `EMBEDDING_BACKEND` | `local`（本地 bge-m3）或 `ollama` |
| `API_TOKEN` | 非 dev 环境的 Bearer 鉴权 Token |
| `GITHUB_WEBHOOK_SECRET` | GHSA webhook 签名密钥 |
| `GITHUB_TOKEN` | GitHub PAT，GHSA 采集必需（GraphQL 必须鉴权） |

## 测试

```bash
ruff check . && ruff format --check . && mypy src
pytest -q                      # 单测不需要数据库/网络
pytest tests/test_live_server.py   # 真实起 uvicorn，验证 lifespan / 路由 / SSE 帧
cd web && npm run build            # 前端类型检查 + 构建
```

带库的跑批评测需要 `POSTGRES_DSN` 指向真实 PostgreSQL（`python -m eval.run_all`）。

## 验收

```bash
python -m scripts.accept
```

一条命令跑完所有可自动判定的验收项，输出 `[ OK ]/[FAIL]/[SKIP]` 清单，退出码非 0 表示有未通过项。

- `[ OK ]` 静态检查、单元测试（含真实启动 uvicorn）、前端构建
- `[SKIP]` 需要外部服务的项：数据库迁移与评测脚本（需 `POSTGRES_DSN` 可连的 pgvector 库）、采集联调（需 `LLM_API_KEY`）、本地兜底（需 Ollama）。**SKIP 表示"没测"，不是"测过了"**——交付前这些必须由人工在有服务的环境里跑通。

人工验收清单见 `docs/验收清单.md`，不用 Docker 的手动配置步骤见 `docs/手动配置指南.md`。

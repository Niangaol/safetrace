# SafeTrace · 智能体驱动的 AI 安全知识情报系统

> 「中国电子杯」第三届高校 ICT 产教融合创新大赛 · 网信产业应用赛道 · **赛题九** ｜ 命题单位：奇安信科技集团股份有限公司
> **作品提交截止：2026-10-19 24:00**
>
> **一句话**：安全工程师在对话框里问一句"Ollama 那个未授权访问漏洞影响我们哪些服务？今晚先修哪个？"，
> 系统自己决定查漏洞库还是翻文档，几秒后给出一个**带出处、带推理链、带修复优先级**的答案。
>
> 团队：李念（队长 · 问答线/编排/MG1/契约）｜甲（监测线/运维）｜乙（富化线）｜KKK9747human（前端/演示）｜XueXuhang（第 7 源/时效看板）
> 学校/专业：杭州电子科技大学 · 2026 级 智能科学与技术 ｜ 工程目录：`D:\AgentPrograms\safetrace`

## 文档导航（人写的文档只有这三份 + 一张图）

| 文档 | 适合谁 | 内容 |
|---|---|---|
| [`README.md`](README.md)（本文件） | 所有人 | 是什么、怎么跑、现状、红线、命令速查 |
| [`docs/PROJECT-ANALYSIS.md`](docs/PROJECT-ANALYSIS.md) + [`docs/PROJECT-OVERVIEW.svg`](docs/PROJECT-OVERVIEW.svg) | 第一次接手的人、要对外讲项目的人 | **说人话**的全景解读（十分钟看懂）+ 项目全景图（浏览器直接打开） |
| [`docs/TUTORIAL.md`](docs/TUTORIAL.md) | 要动手改代码的人 | 从零跑起来、每条线怎么用、演示脚本、排障、协作规范、当前待办 |

> `contracts/`（D6 冻结的接口契约）与 `docs/evidence/`（评测/验收证据，由脚本自动产出）不是说明书，是**工件**，
> 不随文档合并而改动；改 `contracts/` 前必读 [`contracts/schemas/CHANGELOG.md`](contracts/schemas/CHANGELOG.md)。

---

## 1. 三十秒看懂

```
7 类情报源 → Y 监测线 → 情报对象 → F 富化线 → S 知识底座 → Q 问答线 → 网页
（收件）     （分拣）     （贴单）     （加工）     （上架）     （查件）    （取件）
```

| 步骤 | 干什么 | 代码 |
|---|---|---|
| ① 收件 | CISA KEV / NVD / OSV / cve.org / Ubuntu USN 等源采集（7 类登记、5 个连接器在跑） | `src/ingest` |
| ② 分拣 | 统一格式 → 强标识去重归并（同一漏洞四套编号合成一条）→ **DQ1 质量闸门**，脏货进隔离区 | `src/ingest` |
| ③ 贴单 | 不可变 `IntelItem`，带来源与 SHA-256 | `contracts/schemas` |
| ④ 加工 | 论文关联 / CVSS+EPSS / 修复建议（USN·KEV 只读派生）/ 多源冲突仲裁 / 本地资产影响 | `src/enrich` |
| ⑤ 上架 | 切块 → BGE-M3 向量化 → Qdrant；默认 BM25，真实 dense 需本地栈 | `src/qa` + Qdrant |
| ⑥ 查件 | 意图理解 → 混合检索 → 四段式带引用答案；**再结合本地仓库快照给出三个方向的解决方案** | `src/qa` |
| ⑦ 取件 | 态势大屏 / 情报列表 / 问答页 / 资产监控等页面 | `web/` |

另有四根"承重墙"，不属于某一条线但每条线都靠它：

- **MG1 模型网关**（`src/gateway`）：所有模型调用的唯一出口，换本地/云端只改配置不改代码，兼管限流、熔断、降级、计量与 `data_domain × trust_boundary` 隔离闸门。
- **自研 TaskGraph 编排**（`src/qa/src/orchestrator`）：把监测/富化/问答/自愈当成四个 Agent 编排，支持挂起-恢复（A-01）。
- **兜底阶梯**（`src/qa/src/ladder`）：工具 → 规则 → 本地 Jev → 云 LLM → 人工工单。任何一层拿不准就**明说**，不硬编。
- **Lineage 溯源账**（`src/shared`）：`trace_id` 从采集贯穿到答案，每步记输入输出哈希，可查"这个数字从哪来"。

---

## 2. 五分钟跑起来

```bash
git clone https://github.com/Niangaol/safetrace.git && cd safetrace
git config core.hooksPath .githooks     # 每次 clone 后都要执行一次
npm ci && npm ci --prefix web           # Node >= 24，只需一次

npm run check        # 门禁四件套：typecheck + 全量单测 + 契约校验 + 前端构建
npm run smoke        # 端到端冒烟：fixture 回放跑完整链路，逐项 PASS
npm run cli:ask -- "Log4Shell 影响哪些版本？怎么修复？"   # 问答线 CLI 演示

npm run demo:serve   # 窗口 A：本机只读情报 API :8000（启动即实跑采集→DQ1→富化）
npm run dev --prefix web   # 窗口 B：前端 :5173
```

要真实语义检索（BM25 → dense）再起本地推理栈：`npm run local:up`（Qdrant :6333 + bge-m3 :8081），
就绪检查 `npm run pilot:doctor`，实测 `npm run vector:verify`。详细步骤、环境坑、演示手测清单见 [`docs/TUTORIAL.md`](docs/TUTORIAL.md)。

---

## 3. 命令速查

| 目的 | 命令 |
|---|---|
| 全量门禁 | `npm run check` |
| 端到端冒烟（含"零静默兜底"断言） | `npm run smoke` |
| 问答 CLI | `npm run cli:ask -- "<问题>"` |
| 本机演示 API + 前端 | `npm run demo:serve` + `npm run dev --prefix web` |
| 本地推理栈起停 | `npm run local:up` / `npm run local:down` |
| 向量链就绪检查 / 实测 | `npm run pilot:doctor` / `npm run vector:verify` |
| 采集一次（离线） | `npm run ingest:once` |
| 内部 Agent 情报交接（隔离离线） | `npm run intel:agents`（fixture 无来源证明时明确 partial） |
| 内部 Agent 正式持续更新 | `npm run intel:agents:live -- --cycles 0 --sqlite <已备份库>`（单 leader、备份门禁；不会自动启用 LLM） |
| 资产扫描（本地仓库快照） | `npm run assets:scan`（`--list-groups` / `--group <id>` / `--json`） |
| 隔离区 / 人工工单 / 页面复核 | `npm run quarantine:list` / `npm run human:queue -- list` / `npm run review:queue -- list` |
| 自愈演练 / 常驻自愈 | `npm run selfheal:drill` / `npm run selfheal:daemon` |
| 溯源查询 | `npm run trace:lineage -- <trace_id>` |
| 契约校验 | `npm run validate:contracts` |
| 富化质量评测 | `npm run qa:quality` / `npm run qa:quality:live` |

完整清单（含端口、环境变量、各线专用命令）见 [`docs/TUTORIAL.md`](docs/TUTORIAL.md) §3 与 §12。

---

## 4. 目录结构与责任人

```
safetrace/
├── contracts/          # D6（10/3）冻结的接口契约：8 个 JSON Schema + events.md + openapi.yaml（全员只读）
├── fixtures/           # 假数据：不依赖真实源即可开发自测
├── src/
│   ├── shared/         # S2 情报总线 + lineage 账 + 降级统一出口 + 注入筛查 + 逐维富化状态
│   ├── gateway/        # MG1 模型网关（红线模块：禁止 import provider SDK）
│   ├── ingest/         # Y 线：Y1 采集 / Y2 适配 / Y3 去重 / DQ1 闸门 / 受控网页（P-10）
│   ├── enrich/         # F 线：F1 论文 / F2 资产 / F3 POC / F4 CVSS+EPSS / F5 修复 / F6 冲突
│   ├── qa/             # Q 线：Q1 意图 / Q2 检索 / Q4 答案 / 决策阶梯 / TaskGraph 编排 / 自愈
│   └── assets/         # A 线：本地仓库扫描 → 技术栈快照 → 漏洞匹配 → 分组监控
├── web/                # 前端（Vue）：大屏 / 情报 / 问答 / 资产 / 采集诊断
├── ops/                # compose（本机无 Docker，已降级为补验项）
├── scripts/            # 演示、评测、运维、自愈等入口
└── var/                # 运行产物（*.sqlite 已 gitignore）
```

---

## 5. 当前状态（诚实口径，2026-10-11）

### ✅ 真跑通的（可以现场演示）

- 采集 → 去重 → DQ1 → 富化 → 入库 → 带引用问答，**全链离线可复现**（`npm run smoke`）
- 四道门禁通过：typecheck + 全量单测 + 契约校验 + 前端构建
- 真实联网采过：**74.08 小时**连续监测无缺口，新漏洞监测延迟 P95 = 4.99 小时；归并率 91.2%（71,712 条原始 → 6,314 条情报）
- 20 条黄金问答全过；无证据时**显式拒答**，不编答案
- 本地资产扫描（A 线）：分组监控 + 确定性版本匹配；问答可结合仓库快照给出**三个方向的解决方案**
- 本地推理栈 D4 已验收：Qdrant :6333 + bge-m3 :8081，集合 5,237 点、1024 维
- 全量单测：2026-10-11 闭环轮 **827/827**；同日 Q5 与内部 Agent 时效改进整合后 **909/909 通过、0 失败/0 跳过**，四门禁及离线冒烟通过；跨卷硬链接测试已改为同卷临时目标
- 内部 Agent 时效：新增持久交接、重启续接、失败退避和当前版本提交闸门；新原始来源先可问答，不等慢 EPSS/论文。新入口 timely 档 NVD **30分钟**、KEV **15分钟**（旧 registry 2小时/1小时保持兼容），官方请求限流仍生效；这是配置与受控测试，不是实源6h SLA，见 [教程§7](docs/TUTORIAL.md#7-时效与指标口径评分类指标唯一口径)

### 🟡 只做了一部分的（别对外说"完成"）

- **语义检索默认走 BM25**；真实 embedding + Qdrant 需另起本地栈并配置，默认 `cache` 向量会被拒绝写入
- **富化覆盖率**：最后记录的持久 trace 为 1098/3727（29.5%），其中 1074 条论文是 fixture 降级
- **注入防护是启发式 v1**（A-04），不是完整防护保证
- **72 小时挂机的端到端实测**仍未补跑（调度器代码已合入）
- 受控网页（P-10）真实 LLM 抽取保持显式 opt-in 关闭态；正式 SourceRegistry 调度未接

### 🔵 Mock / 还在规划的（演示时要明说"此处为预置数据"）

- F2 资产定位的**真实**链路（当前本地扫描版已真跑，合规红线不允许扫未授权目标）
- Q3 攻击链自动化推理；GitHub GHSA、arXiv 两个源还没接
- compose 一键拉起（本机没装 Docker，改本地二进制直起，降级为补验项）

---

## 6. 三条工程红线（每项设计前自查）

1. **模型接入标准化解耦**：任何模型调用必须经 `src/gateway`（MG1）；业务代码禁止 import 任何 provider SDK。切换 provider 只改 `config/models.yml` + `.env`。
2. **脏数据不进知识底座**：进 Qdrant 前必过 DQ1 质量闸门。**宁可少一条，不可错一条。**
3. **兜底必须显式可见，禁止静默兜底**：任何降级必须经 `shared/src/degrade.ts` 的 `degrade()` 登记 FallbackEvent，响应带 `degraded_to`，`user_visible=true`；冒烟断言零静默兜底。

另外两条口径纪律：**Mock 要说出口**（演示明示"此处为预置数据"并写进报告「已知限制」）；
**不许为了让界面好看而伪造指标**——评委一句"跑个新数据看看"就能验伪。

---

## 7. 已知限制（必须同步进报告「已知限制」）

1. 默认 `cache` provider 是确定性占位，未配真实模型时没有 LLM 推理。
2. Q2 已接 MG1 embedding 接口，但默认 cache 向量会被拒绝写入/查询语义集合，显式退回 BM25-lite；只有真实 embedder + Qdrant + 来源索引都配置后才有实际 dense 召回。
3. 富化覆盖率约 29.5%，多个维度靠 fixture 顶；论文关联 recall@5 是零基线，**没有任何公开准确率数字**。
4. A-04 注入防护是本地有界启发式；混淆/编码/多阶段攻击的完整覆盖与工具权限边界审计未闭环。
5. Firecrawl / 云 LLM / embedding 默认关闭；Firecrawl 按页计费。
6. 来源 Qdrant 的生产入库仍未实跑；Langfuse 完整 Trace 外发默认关闭。
7. 72h 连续运行只有代码与调度器，没有端到端实测证据。

---

## 8. 交件节点

| 节点 | 日期 | 内容 |
|---|---|---|
| D16 彩排 | 10/13 | 20 问全过 + 7 源登记 + 时效看板 |
| D18 报名截止 | 10/15 | 独立流程，别忘 |
| D20 功能冻结 | 10/17 | 只修 bug 不加功能 |
| **D22 交件** | **10/19 24:00** | 技术报告 Word+PDF、演示视频、讲解 PPT（PDF）、报名表+汇总表 |

> 硬规则：主办方不提供统一参赛平台，自行部署运行；决赛 PPT **不得出现队伍单位、人名**。

---

*历史文档（PROJECT-INTRO / HANDOVER / TASKS / TEAM-PLAN / LOCAL-STACK / MONITORING-METRICS / 各日期报告等）已按内容合并进本文件与 [`docs/TUTORIAL.md`](docs/TUTORIAL.md)、[`docs/PROJECT-ANALYSIS.md`](docs/PROJECT-ANALYSIS.md)；`contracts/` 与 `docs/evidence/` 为工件，保持原样。*

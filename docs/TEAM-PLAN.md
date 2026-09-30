# SafeTrace · 后续分工与协作规范（D3 起生效）

> 制定于 **D3 = 2026-09-29 19:12**｜制定人：李念（队长）
> 依据：`docs/TASKS.md` 台账 + `docs/GITHUB-FLOW.md` 流程 + 仓库实际提交历史
> **本文档是 D3 之后分工的唯一口径**，与台账冲突时以本文为准并同步改台账。
>
> **最近更新：D4 = 2026-09-30（李念）** —— 见 §1.2「D3→D4 增量」。核心变化：
> ① 本地推理栈落地，真实向量链路已验收；② 云端降级加人工关卡；③ 删除 langgraph 后端；
> ④ **弃用 Docker 改全本地跑**（原 ops 的 compose 方案不再是部署口径）。

---

## 一、现状盘点（谁做了什么）

### 1.1 状态基线（D3 最新 main @ d628729；下表为 D3 19:00 工程盘点）

| 模块 | 内容 | 测试 |
|---|---|---|
| **工程基座** | TS workspaces / tsconfig / models.yml / 行尾规范 / CI / PR 模板 / 本地钩子 | 门禁可用 |
| **契约 v1** | 8 个 JSON Schema + events 主题清单 + openapi + 校验器；`DecisionReply.decided_by` 追加 `human` 枚举 | 校验器跑通 |
| **shared（S2 总线）** | 事件总线 + 存储双实现 + 降级统一出口 + 脏数据样本 fixtures | 1 组 |
| **gateway（MG1）** | 角色路由 / 双 provider / 限流熔断 / 降级链 / token 计量 | 1 组 |
| **ingest（Y 线 + DQ1）** | 6 源登记 / 4 连接器 / 适配 / 去重 / 质量闸门 / 流水线 | 5 组（29 断言） |
| **enrich（F 线）** | CVSS v3.1 规范计分 / EPSS / arXiv 关联 / 多源仲裁 / F2 合成资产匹配 | 4 组（50 断言） |
| **qa（Q 线）** | 意图 / 双引擎检索 / 四段式答案 / 任务图 / CLI / HTTP / 20 条黄金问答 | 5 组（36 断言） |
| **web（前端）** | full frontend redesign，modern dark theme，14 个 vue/ts 文件 | — |
| **ops（运维）** | **D4 起改为纯本地栈**：llama.cpp + Qdrant Windows 二进制 + 本地 GGUF 模型 + 一键启停脚本 + 端到端冒烟脚本（原 docker compose 方案因本机无 Docker 而废弃，见 §1.2） | 全链路可复现 |
| **台账** | D2–D22 任务单 + 硬节点准入条件 + 砍单层级 | — |

### 提交归属

| 成员 | 主要产出 |
|---|---|
| **李念** | 上述除 web 外全部（契约 / 基座 / MG1 / S2 / Y / F / Q / ops / 冒烟 / 台账 / 门禁修复） |
| **KKK9747human** | 前端全量重设计（PR #3）、台账计数修订（PR #2）；**D3 夜**：前端真实接线与诚实降级标识、一次性问答演示页（执行轨迹/证据可点开/答案关键内容高亮）、KEV·EPSS 排序依据外发与展示、`SystemFactory` 数字接真实指标；**并修掉 5 个真 bug**（流水线阶段缺口、引用 URL 缺失、`max_tokens` 截断致正文为空、模型 ID 写错、测试依赖本机 `.env`）。详见 §3.4（载体：fork 的 `demo-v1-python` 分支，落库方式待拍板） |
| **XueXuhang** | Y 线第 7 源接入、监测实效看板（D3 确认选 A，见 3.3）；**D4**：E-07 周期调度器 + E-09 实效看板已合入（PR #7） |

### 1.2 D3 → D4 增量（2026-09-30，李念）

这一天的重心从"堆功能"转向**把已有链路验真**，并解决本地跑不起来的问题。

| 事项 | 结论 | 证据 / 说明 |
|---|---|---|
| **弃用 Docker，改全本地跑** | ✅ 已落地 | 本机无 Docker、装 Docker Desktop 要 WSL2+UAC+可能重启；改为 llama.cpp（winget `ggml.llamacpp`）+ Qdrant Windows 二进制 + 本地 GGUF 模型。一键起停 `npm run local:up\` / `local:down`，见 `docs/LOCAL-STACK.md` |
| **真实 embedding + 向量链路验收** | ✅ 已验收 | 本地 bge-m3（实测 1024 维）替代云端 Tokendance；`npm run vector:verify` 跑通「真实推理 → Qdrant 写入 → 语义召回」，排序正确且跑完自动清场。**此前 doctor 全绿但两个 verified 恒为 false 的状态就此解除** |
| **模型本地化与自动就绪** | ✅ 已落地 | 模型不入 git（GitHub 单文件 100MB 上限）；改为内置下载链接，源走 **hf-mirror 国内镜像 → huggingface 官方**自动探测，下载后校验 sha256。缺模型时 `local:up` 自动补 |
| **云端降级加人工关卡** | ✅ 已落地 | 转云端=出网+可能计费，**不允许程序自行决定**：未注入确认钩子 / 钩子返回 false / 抛异常 / 非 TTY 环境 → 一律拒绝（fail closed），并记 `rejected` lineage + `user_visible` FallbackEvent。安全阀 `SAFETRACE_CLOUD_FALLBACK` 默认 `never` |
| **删除 langgraph 后端** | ✅ 已落地 | `@langchain/langgraph` 从未进 `package.json`，对应用例永久 skip，是死代码。只留 native，4 条核心断言一条未少。同期修掉 `compile()` 对注入 config 不校验导致非法 backend 静默放过的问题 |
| **PR #6 冲突解决并合并** | ✅ 已合并 | XueXuhang 的第 7 源 Ubuntu USN 接入与 main 的 P-10 改动在 `pipeline.ts` 冲突；保留双方能力，并同步因此过期的计数断言 |
| **PR #7 合入** | ✅ 已合入 | XueXuhang 的 E-07 周期调度器 + E-09 实效看板，测试数 262→281，无冲突 |

**当前测试基线**：276 项 / 275 过 / 0 败 / 1 跳（跳过项为未配 `TOKENDANCE_API_KEY` 时 cloud-gate 的云端一跳）。四项门禁（typecheck + 全量 test + 契约校验 + web 构建）全绿。

**仍未验收**（如实标注，勿当已完成）：

- **真实网页抓取**：`npm run page:demo` 输出 `mock: true`、0 网络请求，只验证了「规则→DQ1→SQLite→证据块→BM25」协议
- **QA / gateway 的 HTTP 服务入口**：有单测覆盖，尚未做端到端实测
- **E-07 / E-09**：目前只有单测，未做端到端实测
- `answerer` 角色仍是 cache provider（可复现但非真实模型生成）

---

## 二、分支策略变更：单线制

::: warning D3 起改为单线制
**D3 起所有新工作只在 `main` 单线推进，不新建 feat/* / contract/* / docs/* 分支**。历史分支仅保留作审计/恢复，不作为新任务工作区。原因：三周交付 + 三人规模，分支开销大于收益，且单线能让「谁的改动在跑」一目了然。
:::

### 单线制作业规范

```bash
git switch main
git pull --rebase origin main     # 开工前必做
# ...改代码...
npm run typecheck && npm test     # 本地门禁全绿才准提交
git commit -m "类型(模块): 干了什么（对应台账 R-XX）"
git push origin main              # 被拒就 pull --rebase 后再推
```

**三条铁律**：

1. **push 被拒是常态**（三人同时推），`git pull --rebase origin main` 后再推，**不要 `git push --force`**。
2. **rebase 报冲突就停下来在三人群喊一声**——尤其 `contracts/` 下的文件，冲突绝不能自己猜着解。
3. **提交信息必须带台账编号**（如 `R-04`、`E-01`），否则周五对齐会无法回溯。

### 契约不再单独走分支，但纪律升级

D6（10/3）契约冻结后：**只允许新字段追加 + 旧字段标 `deprecated`**，禁止改语义、改枚举、删字段。确有必要的契约变更，须在三人群获得**另外两人各一个"同意"**后才可提交，并在 `contracts/schemas/CHANGELOG.md` 追加一行。

---

## 三、后续分工（D3 → D22）

### 3.1 主责划分

| 成员 | 主责范围 | 从责 |
|---|---|---|
| **李念** | MG1 网关、Q 问答线、编排层、契约管理、ops 运维（**D4 起重写为本地栈**） | 冒烟脚本、台账维护、对外件脱敏终审、安全核查（A-04/E-04） |
| **KKK9747human** | **web 前端全部页面 + 端到端演示链路对接 + 演示环境**（本人确认专注前端） | — |
| **XueXuhang** | **Y 监测线第 7 源 + 时效看板**（D3 本人口头确认选 A） | F2 资产被动信号补强（P2 选做） |

### 3.2 李念（D3–D8 必做）

| 任务 | 台账号 | 状态（D4） | 验收口径 |
|---|---|---|---|
| 契约冻结收口，三线 sign-off | `C-01`~`C-06` | ✅ 已推 main，校验器全绿 | D6 前全部完成，`validate_contracts.py` 全绿 |
| 冒烟脚本第 5 段：黄金问答 20 条全过 | `R-04` | ✅ 20/20 通过 | 20/20 通过，答案带引用 |
| Q4 可解释答案：每条结论绑定证据 ID | `R-05` | ✅ 引用完整率 100% | 抽 10 条人工核对"每句话有出处" |
| usage 计量补齐 | `R-03` | ✅ 已完成 | latency_ms/cached 如实落库 |
| 观测埋点补全，Langfuse trace 可回放 | `A-02` | ✅ 阶梯留痕 + lineage 可 replay | 一次问答的 6 步全部可点开 |
| **本地推理栈 + 真实向量链路**（D4 新增） | — | ✅ 已验收 | `vector:verify` 通过；`local:up` 一键起；模型自动下载 + sha256 校验 |
| **云端降级人工关卡**（D4 新增） | — | ✅ 已落地 | 默认 `never` 一律拒绝；四路径回归测试在 |
| **A-04 / E-04 安全核查**（D4 新增） | `A-04`/`E-04` | 🔴 只读排查完成，待定方案 | 见 §六 未闭合项：DQ1 未持久化 / 角色白名单未成边界 / Q4 可绕过安检 |
| 编排层收敛 | — | ✅ langgraph 已删，只留 native | 4 条核心断言一条未少 |

### 3.3 XueXuhang（D3 确认选 A：Y 线第 7 源 + 时效看板）

**任务已确认，以下为正式交付要求**：

| 任务 | 台账号 | 状态（D4） | 验收口径 |
|---|---|---|---|
| 第 7 源接入 | `E-01` | ✅ 已合入（PR #6，Ubuntu USN） | 接入成功并在源登记表标注 `source_type`；连接器沿用 Y2 骨架，不新造架构 |
| 监测时效看板 | `E-02` | ✅ 代码已合入（PR #7） | 展示 `published_at → first_seen_at` 的 P50/P95，**必须来自真实抓取数据**（非手填）；能截图作为交件证据 |
| P95 ≤6h 达成路径 | `E-03` | ✅ 代码已合入（PR #7） | 若当前 P95 >6h，需在台账写明原因与优化动作（例如轮询间隔、事件流接入），决赛前达标 |
| 周期调度器 | `E-07` | ✅ 已合入（PR #7） | 与 E-09 一同落地，单测覆盖；**端到端实测待补** |

> **D4 说明**：E-07/E-09 已进 main 且单测全绿，但**尚未做端到端实测**（调度器真实触发一轮 + 看板数字来自真实抓取）。
> 按"看板数字必须真实"的纪律，验收时请补一次真跑，别只拿单测结果当交付证据。

**三条纪律**：

1. **只许在 `src/ingest` 与 `web`（看板页）内改代码**；Y 线内部结构已由 DQ1 闸门串联，不要动 `contracts/`。若确需契约变更，按第二节"契约纪律升级"流程走。
2. **第 7 源必须遵守礼貌爬取**：固定 User-Agent、遵守 robots.txt、失败退避，间隔不低于同域数秒级（见 04 开源图鉴坑⑥）。
3. **看板数字必须真实**：宁可显示"当前 P95 = 9.4h，未达标"也不许手填一个 5.8h——评委问到怎么测的，答不上来比数字难看更致命。

**可选加分（P2，D13 后视进度）**：F2 资产被动信号补强（crt.sh / 公开备案 / 公开指纹三类被动口径），仍禁止任何主动扫描。

### 3.4 KKK9747human（D3–D8 必做）

> **进度更新（2026-09-29 夜，KKK9747human 本人填报）**
> 本轮工作的**载体是 fork 上的 `demo-v1-python` 分支**（`github.com/KKK9747human/safetrace`）：
> 那是 `-demo-v1` 目录对应的独立仓（Python 后端 + 前端，含本机演示所需的演示库与脚本）。
> 之所以推分支而非直接推 main：该仓是 `git init` 新建的、与 upstream **无共同祖先**
> （upstream 已是 TS 单体仓，含本仓全部源码）。直接推 main 需要 force-push，
> **会抹掉团队现有提交**，所以按分支推送、不碰 main。下面的验收口径均已在该分支上实测。

| 任务 | 状态 | 实测证据 / 说明 |
|---|---|---|
| 前端对接 Q 线 HTTP 接口，问答页用真数据 | ✅ **已完成** | `/api/v1/qa/chat` 真 SSE；实测 `model=deepseek-v4-pro`、8 条引用、四段式答案（¥0.0316/次）。数据来源规则：默认**先请求真实后端**，仅"不可达/未实现(404/5xx)"才回退预置数据并全站标注（业务错误 401/422 一律如实报错、不回退）。可复跑：`npm run probe:live-wiring` 判定 `dataSource=live` |
| **「一次完整问答」演示页**（答辩核心） | ✅ **已完成** | 一屏形态：提问 → **执行轨迹**（8 步，带工具名/入参/结果/每步耗时）→ 检索证据（可点开原始出处）→ 推理链（可展开）→ 带引用答案（关键内容高亮）。深链 `/qa?q=…` 可直接跑；`/qa?demo=1` 用固定样例秒级渲染便于验收排版 |
| 降级状态可视化 | ✅ **已完成** | ① 数据来源降级：全站横幅 + 导航栏「实时数据/预置数据」；② 答案降级：`degraded=true` 时显式提示；③ 占位答案（无 LLM 凭据走 cache provider）明示"不是模型分析结果"，并标注 `cost_cny=0`；④ 无证据时如实答"知识库中暂无可支撑该问题的证据"并标 `ok=false` |
| 演示环境跑在 compose 上 | ✅ **已完成（全栈端到端实测通过）** | **6 个服务全部起来**（api / postgres / redis / web / prometheus / ollama），运行期冒烟 **10/10 通过**：`/health` 200、容器内迁移自动执行（19 张表、`alembic=0003_simhash_bigint`）、**`/api/v1/vulns` total=13**、**Redis PING 成功**（本项目第一次在真 Redis 上跑通）、**web 首页 200 且 nginx 反代 `/api` 返回 total=13**、**Prometheus 抓取 `aiintel=up`**、**问答 SSE `citation=True`**（端到端有引用）。排掉的坑：① `wsl --install`（含 `--web-download`）报 403，但两个 Windows 功能经复核**本就是 Enabled** —— 是**下载**被拒（本机为此白重启过一次），可靠解法是直连 GitHub release 的 MSI → `msiexec /i /qn /norestart`（判据 `WslService` 变 Running，**不需要重启**）；② 本仓缺 **`.dockerignore`**，`web/node_modules`(128.8MB)+`.git` 发给 daemon 会导致构建卡死；③ 容器**连不上 registry.npmjs.org**（npm error network，782s 超时）→ 加**可选** `NPM_REGISTRY` 构建参数（传镜像源后构建立刻通过）；④ 新增 `scripts/seed_from_demo.py` 方言中立灌数（`demo_seed.py` 只会建 SQLite，导致 PG 一直是空的）；⑤ 嵌入器**无失败记忆**致容器内单次问答白等 **3.5 分钟** → 改失败熔断。**另修一个只在 PG 暴露的真 bug**：`raw_item.simhash` 是 64 位指纹但模型是 `Integer`（PG int4）→ 22/22 行 `NumericValueOutOfRange`，SQLite 不校验宽度所以一直没暴露；已改 `BigInteger` + 迁移 `0003`。脚本：`install-wsl-msi.ps1`、`run-compose.ps1`、`smoke_runtime.py`（运行期冒烟；`accept.py` 是开发机门禁，勿在容器跑）。与台账 `E-05` 同一项 ✅ |

**本轮顺带修掉的用户可见缺陷与真 bug**（都在上面那个分支里，含可复跑验收）：

1. **检索流水线"走不到头"**：后端当时只发 `rewrite`/`retrieve` 两种 stage，而前端进度条画了五步。
   已在 `qa/agent.py` 的实际执行点补齐 `generate`/`reasoning`/`check`/`done`，两侧对齐。
2. **引用来源点不开**：`Vuln.references` 全为 `[]`，而 `citation.url` 取的是内部切片标识
   （`CVE-2026-31001`）。已补 NVD 出处链接（实测 200）+ 前端渲染为可点链接；
   **不拼 GitHub Advisory 链接**——演示 GHSA 编号是编的，实测 404，
   且格式校验（三段各 4 位）拦不住，故宁可少一条也不给死链。
3. **模型正文恒为空**：`max_tokens=500` 被**强制思维链**吃满（`finish_reason=length`、
   `reasoning_tokens=500`、`content=""`），HTTP 仍 200 → 规划/自检静默失败。
   已提到 2500/3000，并给 `LLMResult` 加 `truncated`/`reasoning_tokens` 以便诊断。
4. **模型 ID 写错**：`deepseek-v4-flash` 不存在，服务端实际是 `deepseek-flash`（配好 key 就 400）。
5. **测试依赖本机 `.env`**：本机把 `REDIS_URL` 写成空 / `LLM_LOCAL_ENABLED=false`
   会让 15 条既有用例失败（事件总线"已禁用"会丢弃全部事件）。已在 `conftest.py` 固定测试默认值。

6. **`QAAgent.answer()` 不接受 `stream` 参数**：`eval/qa_accuracy.py` 调
   `agent.answer(q, stream=False)`，而 `answer` 把 `**kwargs` 透传给无 `stream` 参数的
   `answer_stream` → `TypeError`。**问答准确率这个指标从建立起从未跑通过**，
   这也是技术报告里该指标只能手写数字的直接原因。已修，并加
   `tests/test_qa_answer_kwargs.py` 钉住。
7. **`collect_latency` 只读恒为 NULL 的 `latency_seconds`**：`published_at`/`fetched_at`
   都有真值却不去推导 → 报 `samples: 0`、`sla_tier: "fail"`（数据明明在库里）。
   改为可由时间戳推导后：22 条样本、档位 `excellent`。已加 `tests/test_eval_collect.py`。
8. **采集时效指标口径修复**（同上第 7 条的延伸）：`enrich_accuracy` 的
   `precision` 曾算出 `23.667`（>1，数学上不可能）——根因是把 **case 级**计数与
   **元素级**计数混进同一个公式，`total - correct - hits` 实测为 **-68**。
   另有两个同源 bug：`{'poc': False}` 被判成正例（非空 dict 的 `bool()` 为 True）、
   集合维度 `accuracy = 1.5`。三处已修，并加 `tests/test_eval_metrics.py`。

**可复跑验收命令**（在 `demo-v1-python` 分支）：

```bash
python -m ruff check . && python -m ruff format --check . && python -m mypy src
python -m pytest -q --no-cov          # 491 passed / 8 skipped / 0 failed
cd web && npm run build                # vue-tsc + vite build，exit 0
cd web && npm run smoke:data-source    # 6/6：先真后假 / 显式标注 / 业务错误不掩盖
cd web && npm run check:answer-format  # 关键内容标注正确且不吞字
python -m scripts.accept               # 9 passed / 0 failed / 2 skipped（需 POSTGRES_DSN）

# 评测（第三个指标此前跑不通，现已可跑）
export POSTGRES_DSN='sqlite:///.../data/demo.db'
python -m eval.qa_accuracy             # 20 条黄金集，约 20 分钟、约 ¥1
python -m eval.enrich_accuracy         # 76 条基线，秒级、不调 LLM
python -m eval.collect_latency         # 22 条时效，秒级
```

**本轮首次跑出的真实指标**（详见 `docs/评测实测结果.md` 与 `docs/技术报告-修正版/`）：

| 指标 | 实测 | 目标 | 达标 |
| --- | --- | --- | --- |
| 问答整体准确率（20 题黄金集） | **0.575** | ≥0.85 | ❌ |
| ├ 单跳（11 题） | 0.727 | — | — |
| └ 多跳（7 题） | **0.357**（4 题 0 分） | — | ❌ |
| 问答响应 P95 | **95.9 秒** | ≤5 秒 | ❌ |
| 答案引用率 | **0.65**（13/20 题无引用） | >0.95 | ❌ |
| 采集时效 P50 / P95 | **3.0h / 5.0h** | ≤6h | ✅ |
| 富化一致率（**回归基线，非准确率**） | 1.0（76/76） | — | — |
| 证据链覆盖率 | **100%**（76/76 有 source+evidence） | — | ✅ |

> ⚠️ **两条必须注意的口径**：
> 1. `enrich_cases.jsonl` 是把**当前产出**固化成期望值生成的**回归基线**，
>    一致率 1.0 是必然的，**不能当"富化准确率"写进报告**。真正的准确率需人工标注集（`E-03`/`E-04`）。
> 2. **本机没有嵌入模型**（未装 `sentence_transformers`/`torch`，PG 也无 `vector` 扩展文件），
>    检索退化为 **ILIKE 关键词匹配**，`citation.score` 恒为 0。
>    报告里**不能**写"混合检索（向量+全文+RRF）已生效"——向量那一路没跑起来。

### 3.5 共同事项

| 事项 | 负责人 | 时点 |
|---|---|---|
| 契约冻结三线 sign-off | 全员 | **D6（10/3）** |
| 20 分钟周对齐会（照台账过，不口述） | 全员 | 每周五晚 |
| 报名表 + 汇总表交学校 | 李念 | **D18（10/15）截止** |
| 脱敏自查（PPT/视频/公开仓库无人名单位） | 李念（终审） | D19 |
| 功能冻结 | 全员 | **D20（10/17）** |
| 交件 + 回执双人复核 | 李念 + 1 人 | **D22（10/19）24:00** |

### 3.6 李念新增试点：受控抓取 + 分级兜底 + 语义证据库（P-10）

这条路线作为小切片试点推进，不得挤占 D6 契约冻结、R-04/R-05 和 A-02 等 D3–D8 必做验收。完整任务与状态见 `docs/TASKS.md` 的 P-10。

当前本地工作树已完成受控单页抓取、规则优先/安全门抽取接口、MG1 embedding→Qdrant、BM25+dense RRF 与 SQLite append-only lineage sidecar 的可单测切片。Lineage 记录 ingest fetch/parse/dedupe/DQ1、enrich F1/F4/F6、crawler/extractor、Q2 index/search/fusion、MG1 provider attempts 及 CLI/HTTP Q1/Q2/Q4；保存 trace/parent/cause ID、版本、输入输出 ID/hash、source/model/fallback/review 元数据，不复制正文。现有官方结构化源有默认离线的 `npm run ingest:once` SQLite runner；受控页面 CLI 现可持久化 last-good 与按 SHA 保留的历史页面快照（URL 更新不丢旧审核证据），并把规则不完整项送入 SQLite review queue，`review:queue` 可列出并记录人工决定。网页→DQ1 的显式来源 API、crawl:page 的独立元数据入库开关及 page:demo 零网络演示已实现；元数据缺失/URL不匹配在联网前拒绝，默认预览，步骤见 [本地验证指南](P10-LOCAL-VERIFY.md)；sqlite-page 已接入来源证据转换与 BM25 检索演示；SourceRegistry 正式调度、网页原文到文件式富化适配器的桥接仍未接入，人工批准也不会自动入库；结构化来源到 Qdrant 的 opt-in 入库桥接已实现（拒绝离线/fixture、cache/hash），只读 loopback pilot:doctor 已加入并确认当前 cache 配置/Qdrant 不可达；2026-09-30 已实测 Tokendance qwen3.7-text-embedding API 及 MG1 单文本调用（1024维、无降级），独立配置 opt-in，密钥不入库；Qdrant 持久写入/召回与真实语义质量验收仍待办。下面仍是目标链路，不应读成完整生产交付。

- **采集顺序**：官方 API/RSS/结构化源优先；仅对人工登记的安全公告域名调用 Firecrawl。首版只抓明确 URL，不做无边界整站递归，不绕登录、访问控制或 robots 限制。
- **采集/解析兜底**：直连 + 指数退避/ETag/最近一次成功快照 → source-specific 规则解析 → 允许列表内 Firecrawl 网页提取（适合 JS 页面）→ MG1 结构化 LLM 抽取（契约校验、逐字段保留来源）→ 人工复核/隔离区。在线失败不得静默回放 fixture；fixture 只用于显式离线模式。旧快照可以用但必须标 stale/降级原因。
- **规则与模型边界**：CVSS、版本范围、来源权威级别等可确定事实继续由规则/权威字段计算；LLM 只做缺结构页面的字段抽取、归一和有引用摘要，输出必须过 JSON Schema/字段来源校验，不得覆盖权威事实或补造值。公开网页是 `untrusted` 输入；A-03 数据边界和 A-04 注入防护通过前，LLM 阶段保持关闭，只用 parser/stub，不把原始网页发给云模型。低置信度、冲突或校验失败进入独立人工复核/隔离队列，不复用 `DecisionReply` 冒充 ingest 审核。
- **知识库与 lineage**：RawDoc/IntelItem 与结构化事实是可审计主数据；Qdrant 只保存可重建的 EvidenceChunk 向量索引。当前本地 Q2 切片已通过 MG1 接入真实 embedding，使用 BM25 + dense RRF 并记录 `embedding_model_id`；cache/hash 降级向量会被拒绝。各处理阶段把对象 ID/SHA-256 和模型/操作版本写入 EventStore 的独立 SQLite `lineage_records` 表，不改冻结的公共事件/schema。网页→DQ1 API 已实现，但 SourceRegistry 正式调度、人工批准到 DQ1 的转接仍待办；source-derived EvidenceChunk 已接入 ingest:once 的临时 BM25 预览并记录 lineage；Qdrant opt-in 桥接已实现；SQLite snapshots/review queue 的保留/备份策略及真实 Qdrant/模型验收仍待办；Qdrant/embedding 不可用时显式退回 MemoryIndex。
- **成本/安全**：Firecrawl 云 API 按抓取页消耗 credits；Firecrawl、云 LLM 与 embedding 出网全部 opt-in，默认不开启。密钥只从 `.env` 读且不得提交；自动化测试 stub 外部服务。当前没有云模型 key，不得宣称 LLM 已实跑。
- **负责与验收**：李念负责 MG1/Q2/兜底编排；数据源域名和第七源与 XueXuhang 的方案 A 对齐；演示状态由 KKK9747human 接入前端。验收至少覆盖：域名拒绝、每级降级均留痕、LLM 输出 JSON 契约校验/低置信度进入独立人工态、BM25+dense 可切换且 hash 降级可见、引用保留 source_url 与 chunk_id。新增人工审核载体/事件须走契约评审，不能把 `DecisionReply.decided_by=human` 当作采集审核队列。


---

## 四、落后时的砍单顺序（不变，重申）

从上往下砍，**禁砍项一票否决**：

| 序 | 动作 | 砍掉后怎么交代 |
|---|---|---|
| 砍① | 多轮对话打磨 | 降级单轮 + 说明多轮已在路线图 |
| 砍② | 资产被动信号 | 降级 Mock 清单 + 合规边界说明 |
| 砍③ | Q3 攻击链自动化 | 降级预置 fixture 推演演示 |
| 砍④ | embedding 热切换演练 | 降级文档设计 + 干跑截图 |
| 砍⑤ | 看板美化 | 保留 Langfuse 原生 trace |
| **禁砍** | 模块彻底缺席 / 脱敏合规 / 稳定运行时长证据 | 一票否决，无例外 |

---

## 五、五条工程红线（与落地指导一致）

1. **契约先行**：`contracts/` 是唯一接口真相来源；D6 后只追加不改语义。
2. **禁止 import provider SDK**：模型调用一律走 MG1，本地/云端切换只改 `config/models.yml`。
3. **兜底必须显式**：降级响应必须带 `degraded_to` 与用户可见标记，**禁止静默兜底**。
4. **脏数据不进底座**：进 Qdrant 前必过 DQ1 质量闸门，宁可少一条不可错一条。
5. **Mock 要说出口**：演示时明示"此处为预置数据"，并写进报告「已知限制」。

---

## 六、待决事项

- [x] ✅ KKK9747human 主责方向已确认：**专注前端**（D3 本人确认）
- [x] ✅ XueXuhang 已确认选**方案 A**：Y 线第 7 源 + 时效看板（D3 确认，见 3.3）

### 仍未闭合

- [ ] 🔴 **KKK9747human 夜间工作的落库方式需队长拍板**：本轮前端工作在 fork 的 `demo-v1-python` 分支（`-demo-v1` 目录对应的独立仓，Python 后端 + 前端），**尚未进入 upstream/main**。原因是该仓与 upstream **无共同祖先**，直接推 main 需 force-push、会抹掉团队提交。两个选项：**(a) 把前端改动摘成补丁提到 upstream（推荐）**；**(b) 保留为独立演示仓、upstream 只做说明**。确认前，main 上的前端仍是旧行为（`IS_DEMO_MODE` 硬编码、界面不请求后端）。
- [ ] **D6 契约冻结的三线 sign-off**（10/3，建议 D4 或 D5 开 20 分钟会——三人分工都已定，可以直接过）
- [ ] **每晚 22:00 三句话日报的固定时间确认**（今天完成 / 明天要做 / 阻塞；微信群里即可，不用开会）
- [ ] 🔴 **A-04 / E-04 只读安全核查发现的三处问题待处理**（2026-09-30 只读排查，未改任何文件）：① DQ1 判定结果**未持久化**到 S2/S1，只留在内存里，问"这条为什么被拦"时查不到依据；② 角色白名单**没有成为真正的权限边界**，只做展示不做拦截；③ Q4 合成器存在**绕过安全处理**的路径。均需先定方案再动源码，且不得改动权威契约。
- [ ] **部署口径变更需同步给 KKK9747human**：D4 起**弃用 Docker / compose 改全本地跑**（本机装不了 Docker Desktop）。其 §3.4 里"6 服务跑在 compose 上"的验收是在另一台机器/另一个仓上做的，**不代表本仓 main 现在的部署方式**；两边的演示环境口径需要对一下，避免答辩时说的和跑的不是一套。

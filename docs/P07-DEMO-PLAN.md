# P-07 · KKK 基础 Demo 施工指南（2026-09-30 队长拍板）

> 决策：**先把完整基础 demo 做好，安全加固等后续迭代。** 本文是 KKK9747human 的唯一施工口径，分工配套见 `docs/TEAM-PLAN.md` §3.7。
> 分工：demo 全栈 KKK 写（含本机 API 路由），李念只 review。全程本机直起，不依赖 Docker（D4 已拍板弃用 compose，见 TEAM-PLAN §六）。

## 0. 好消息：大半已经写好了

分支 `feat/qa-local-live-demo`（b30c9a5）已 **rebase 合入 main**（commit `2aeec7c`，2026-10-01；`npm run check` + `npm run smoke` 全绿）。其内容是：

| 资产 | 内容 | 状态 |
|---|---|---|
| `scripts/local-demo-server.ts` | 本机 API（127.0.0.1:8000，`PORT` 可覆盖）：启动时真跑 离线采集→去重→DQ1→富化；每次问答真跑 Q1→Q2→Q4 模板链路 | ✅ 255 行 |
| 端点 | `/api/v1/health`、`/metrics/overview`、`/collect/status`、`/vulns`（分页/筛选/排序）、`/vulns/:id`、`/vulns/:id/evidence`、`POST /api/v1/qa/chat`（SSE） | ✅ |
| 前端 | `web/src/api.ts` 开关改为 `VITE_DEMO_MODE` 环境变量（默认真后端，预置模式才用 mock）；大屏/列表/详情/问答页已接 | ✅ 基本接好 |
| 测试 | `src/qa/test/local-demo-server.test.ts`（82 行，随机端口可测） | ✅ |
| 文档 | `docs/LOCAL-DEMO.md`（运行手册 + 手测清单，含拒答/澄清用例） | ✅ |
| 诚实标识 | 全接口带 `data_mode=fixture`、`degraded_to=fixture`；未实测的时效/费用显示 null/“—”；富化维度带 `mock:true` | ✅ 符合红线 3/5 |

分支自曝限制（`docs/LOCAL-DEMO.md` 写明，演示时照念）：Q2 目前只检索 fixture 证据索引，**尚未接入本次采集结果**；不是联网采集、无 LLM、无真实资产。

## 1. KKK 要做的事（按顺序）

> **2026-10-01 合入后状态**：第 1、2 步已完成（分支 rebase 合入 main `2aeec7c`，3 处冲突按“保留 main 侧 + 折叠分支侧”解决；`demo:serve` 脚本断点已随合入修复）。门禁已过。**剩余：第 3 步 SSE 字段核对 + 浏览器手动验收（P-07 验收核心，见 §2）**。

### 第 1 步：拉取分支并 rebase 到最新 main ✅ 已完成（2026-10-01 由队长合入 main `2aeec7c`）

```bash
# 方式一：本地已有该分支（李念机器）
git fetch origin && git switch feat/qa-local-live-demo && git rebase origin/main

# 方式二：KKK 在 fork 上（origin 指向 KKK9747human/safetrace，fork 里没有这个分支）
git remote add upstream https://github.com/Niangaol/safetrace.git   # 已配过就跳过
git fetch upstream
git switch -c feat/qa-local-live-demo upstream/feat/qa-local-live-demo
git rebase upstream/main
```

- 分支基于 f03f808，落后 main **4 个提交**（41fa23a 删 langgraph、3bc6c99 文档、a171059 TEAM-PLAN、79eb97c 施工指南）。四个提交都是代码/文档侧改动，与本分支的 web/scripts 重合面小，预计只有 `docs/TASKS.md` 会冲突——**保留 main 的行，把分支那 4 行改动作为追加说明重新落**（台账历史行不改写）。
- 冲突解不了（尤其 `contracts/`）→ 停手在三人群喊，不自己猜。

### 第 2 步：修一个已知断点 ✅ 已完成（合入时保留分支侧 `demo:serve` 行，`package.json` 已补脚本，手册命令可直接用）

分支 `docs/LOCAL-DEMO.md` 写的启动命令是 `npm run demo:serve`，但那次提交的 `package.json` **没有加这个脚本**（只加了 allowScripts 一行），命令会报 missing script。二选一：

- 在 `package.json` 的 scripts 里补 `"demo:serve": "tsx scripts/local-demo-server.ts"`（推荐，跟手册一致）；或
- 把手册命令改成 `npx tsx scripts/local-demo-server.ts`。

### 第 3 步：对齐 SSE 事件字段（前后端各看一眼）

后端已实现的事件流（`scripts/local-demo-server.ts`）：

```
stage(plan/retrieve/generate) → citation{id,title,url,score}* → token{text} → done{abstained,confidence,degraded,degraded_to,data_mode,trace_id,cost_cny} / error{message}
```

前端客户端在 `web/src/api.ts` 的 `streamChat`，事件参考在 `web/src/mock.ts`。逐字段核对（尤其 citation 与 done），不一致改前端映射层，不动后端语义。

### 第 4 步（可选加分，不阻塞验收）：Q2 接入本次采集结果

现在问答只搜 fixture 证据索引，会出现“列表里有、问答答不了”的错位。把启动时 ingest 产出的 IntelItem 构建成 EvidenceChunk 入同一索引（参照 `src/ingest/src/evidence-chunks.ts` 现成构建器）。时间不够就保持现状，手册已有如实说明。

### 第 5 步：门禁与交付 ✅ 门禁已过（合入提交 `2aeec7c` 上 `npm run check` + `npm run smoke` 全绿）；剩余=浏览器验收证据

```bash
npm ci && npm ci --prefix web   # 只需一次
npm run check    # typecheck + 单测 + 契约校验 + web build
npm run smoke
```

- 全绿后**直推 main**（单线制）：提交信息带台账编号 `P-07`；push 被拒就 `git pull --rebase` 再推，**不 force**。
- 若 Windows TEMP 导致 esbuild `Access is denied`：`New-Item -ItemType Directory -Force .tmp; $env:TEMP=(Resolve-Path .tmp).Path; $env:TMP=$env:TEMP`（见分支 `docs/LOCAL-DEMO.md`）。
- 证据留痕：录屏 ≤3 分钟（起服务→“Log4Shell 影响哪些版本？怎么修复？”→轨迹→点开引用→“CVE-2099-4321”拒答）+ 截图 2 张（真实问答、fixture 标识可见）；记录 commit hash 与命令退出码。

## 2. 验收标准（做到即算基础 demo 完成）

1. 本机两个窗口：后端（8000）+ `npm run dev --prefix web`（5173），浏览器完整问答可复现、可录屏。
2. 答案来自真 Q1→Q2→Q4（模板合成），引用可点开、chunk_id 可回溯；“CVE-2099-4321 影响哪些版本？”显式拒答、“嗯”走澄清路径。
3. `npm run check` + `npm run smoke` 全绿；`local-demo-server.test.ts` 保留并通过。
4. 真实模式零 mock 混入；`VITE_DEMO_MODE=true` 才是预置模式，且页面有“预置数据”标识。
5. 答案明示“确定性模板，非模型生成”（红线 3/5）；费用/时效未实测处显示“—”，不编数字。

## 3. 边界：demo 阶段不做的事（后续慢慢改）

| 不做 | 去向 |
|---|---|
| A-04 注入防护、E-04 隔离落库 | 已顺延；**禁砍，最迟 D9–D11（10/6–10/8）重启**，否则撞 D13；三处问题清单见 TEAM-PLAN §六 |
| A-05 时间过滤（published_after） | demo 后做 |
| 云端模型接入 | 无 key；真模型合成后续经 MG1 注入 AnswerSynthesizer，口径不变 |
| compose / Docker | D4 拍板弃用，全本地跑（TEAM-PLAN §六） |
| 大屏/列表接真实监测数据 | 等 Xue 的 72h 真跑数据出来再接 |
| 改 contracts/、新增事件主题 | 不动权威契约；新需求走契约评审 |

演示“已知限制”口径（报告/答辩照念）：fixture 输入；模板合成、无 LLM；Q2 未接本次采集结果（若未做第 4 步）；无注入防护（答案 `injection_guard.screened=false` 如实显示）。

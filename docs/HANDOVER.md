# SafeTrace · 交接说明（Handover）

> 建立于 **2026-10-01**｜摘编自 KKK9747human 的交接提交（`aab1488` / `e970620`，fork 分支 `ui-redesign-proper`），
> 并按 main 当前实际状态改写。面向：接手 `web/` 前端或下一班接力的人。
> 本文件**只写"现在是什么状态、怎么验、别踩什么"**；任务清单在 `docs/TASKS.md`（唯一可执行台账），
> 工作流在 `docs/GITHUB-FLOW.md`，施工口径在 `docs/P07-DEMO-PLAN.md`。四者不重复。

---

## 1. 30 秒接手 checklist

```bash
git clone https://github.com/Niangaol/safetrace.git && cd safetrace
git config core.hooksPath .githooks     # 每 clone 一次；pre-push 会跑全量门禁

npm ci && npm ci --prefix web           # Node >= 24，只需一次
npm run check                           # 门禁 = typecheck + 全量单测 + 契约校验 + web 构建
npm run smoke                           # 端到端 fixture 回放（含"零静默兜底"断言）

# 本机可操作演示（P-07 验收对象）
npm run demo:serve                      # 窗口 A：127.0.0.1:8000，启动实跑离线采集→DQ1→富化
npm run dev --prefix web                # 窗口 B：127.0.0.1:5173
```

**提交纪律**：D3 起**单线制**——所有改动直推 `main`（队长 2026-09-30 拍板，不走分支/PR 流程）；
提交信息带台账编号（如 `P-07`）；push 被拒先 `git pull --rebase`，**不 force**。

---

## 2. 前端数据来源规则（**最容易被误解的一处**）

入口：`web/src/api.ts`。开关是环境变量 **`VITE_DEMO_MODE`**（构建期读取）：

| 取值 | 行为 |
| --- | --- |
| 未设置（默认） | **只请求真实后端**（本机 demo API :8000）；不可达即显示错误，**不静默回退假数据** |
| `true` | 静态演示模式：全部页面用前端内置 mock，`App.vue` 全站横幅 + `TopNav` 标注"静态演示" |
| 其他任意值 | 等同未设置（按真实后端处理） |

诚实三条（与 README 五条红线对应）：

1. **没有"自动回退"分支**——后端不在就报错，不把"连不上"伪装成"数据正常"。业务错误（401/422/5xx）同样如实呈现。
2. **模式必须可见**——两种模式都有全站横幅（`App.vue`）：静态演示模式明示“不请求后端”；本地模式明示采集/检索证据为 fixture、不代表实时态势。启用 StepPlan 后，Q1/Q2 仅在低置信/低召回时发送问题与查询词，Q4 会发送公开 fixture 证据；采集原文不出云，页面提示不要输入敏感信息。
3. **不许为了让界面好看而伪造数据**——大屏"采集趋势"由 `genTrendData()` 按情报列表真实 `published_at` 聚合（无随机数、无写死日期）；没有真实数据时不编造。

> 备注：KKK 在 fork 上的 `aab1488` 曾实现三态开关（`VITE_USE_MOCK` + 自动回退 + `DataSourceBanner.vue` +
> `web/scripts/smoke-data-source.mjs` 6/6 烟测）。main 最终采用更简单的二值开关（显式模式、无静默回退），
> 该脚本**未移植**；若将来要恢复"自动回退"能力，需连同该脚本一起移植并重跑其 6 项断言。

### 采集诊断页（2026-10-01 修复）

`/ingest-diagnostics` 通过 `GET /api/v1/ingest/diagnostics` 只读 `var/safetrace.sqlite` 的最近 trace，与 `demo:serve` 的内存 fixture 列表分开。页面逐源标记 live / partial / fixture / no_new_data / failed，显示 DQ、富化覆盖、F1 fixture 降级和 fallback 原因；无 SQLite 时明确提示。静态 `VITE_DEMO_MODE=true` 会显示该页不可读取本机 SQLite 的说明。状态对应历史 trace，代码修复不会回写旧数据。

---

## 3. 已知限制（**必须同步进报告「已知限制」，不要在汇报里说成已完成**）

1. **演示输入全部是 fixture**：`npm run demo:serve` 启动时真跑 离线采集→去重→DQ1→富化、每次问答真跑 Q1→Q2→Q4，
   但输入是仓库 fixtures，**不是联网采集、不是实时情报**。全接口带 `data_mode=fixture`，未实测的时效/费用显示 null / "—"。
2. **问答索引独立于采集结果**：Q2 检索 fixture 证据索引，尚未接入本次采集产物（"列表里有、问答答不了"的错位已知）。
3. **StepPlan 已按需接入 Q1/Q2/Q4**：本机 `.env.local` 选择 `config/models.tokendance.yml`；Q1 只对低置信意图补判/澄清，Q2 只在空/弱召回时改写查询，Q4 负责结论。每层都校验输出，失败回规则或原 Q4 模板并登记 user-visible fallback；引用始终由检索结果提供。仓库默认 `config/models.yml` 仍离线。Q2 仍检索 fixture；采集/富化原文不发送云端，A-04 注入筛查未完成前保持如此；费用尚未计量。 A-02 `/v1/decide` 仍需调用方注入 handler；`DecisionRequest.state` 可含任意/私有字段，未定义 public opt-in 前不把决策状态送云。
4. **F2 资产定位是 Mock**：20 条合成演示资产，不接真实清单/扫描（合规红线：不扫未授权目标）。
5. **注入防护未落地**：答案 `injection_guard.screened=false` 如实显示；A-04/E-04 已排期最迟 D9–D11（10/6–10/8）重启。
6. **72h 连续运行证据未产生**：调度器/看板代码已合入，端到端实测待 XueXuhang 补跑。
7. **E-02 最新 SQLite trace 是修复前历史**：其 OSV/cve.org 为 no_new_data，代码现已传入 CVE IDs，但历史事件不回写。真实端到端内存探测（不写 SQLite）已证明 KEV→OSV/cve.org 各抓取并解析 1 条，且两条都与 KEV 对应 CVE 归并；正式比较表仍待补。
8. **富化未完成且 fallback 不等于成功**：最新持久 trace 富化结果 1098/3727（29.5%），其中 1074 条 arXiv 论文为 fixture 降级。未富化项可用 `SAFETRACE_ENRICH_OFFLINE=false npm run enrich:pending -- --limit=20` 分批跑；已产生 fixture 结果不会自动覆盖。
9. **事件库仍 append-only**：SQLite seq 现已原子唯一，但重复 ingest 仍可产生重复业务事件。诊断页面按 trace 展示并给出 unique intel_id 数；不要跨 runs 将 event 数量当作唯一漏洞数。

---

## 4. 环境坑（踩过的，别再踩）

| 现象 | 原因 / 处置 |
| --- | --- |
| `npm run check` 报 `'tsc' is not recognized` | 根 `node_modules` 缺失。先 `npm ci`（pre-push 会拦并提示） |
| web 构建报 esbuild `Access is denied` | esbuild 在系统 TEMP 建临时文件被拒。**先 `mkdir -p .tmp` 再 `export TEMP="$PWD/.tmp" TMP="$PWD/.tmp"`**，然后跑原命令（本机必现） |
| `git push origin --delete <branch>` 失败 | pre-push 钩子对 delete 推送也会触发，且该环境起子进程偶发 EPERM。用 `gh api -X DELETE repos/Niangaol/safetrace/git/refs/heads/<branch>` 绕开 |
| `git commit -m` 里带 `/` 的长信息被 PowerShell 吞 | 用 `git commit -F <文件>` |
| `PROJECT-INTRO.md` §七 / 正文指向 `C:\Users\niangao\...`、`asktrace9\docs\` | 仓库内不存在，台账 **D-06 / D-07** 未修；找文件以本仓库为准 |
| `vue-tsc` 报 TS7016 echarts 缺声明 | 曾因 echarts 残缺安装；重装 `npm install echarts@5.6.0` 可复原（已修） |

---

## 5. 下一步该做什么（按优先级）

| 序 | 事项 | 依据 |
| ---|---|---|
| 1 | **E-02 持久化验收与富化收尾**：真实 pipeline 已用 MemoryEventStore 验证 OSV/cve.org 都取到 CVE 并归并；正式 SQLite/fixture 对比尚缺。避免再向 `var/safetrace.sqlite` 盲目全量重跑，优先用 disposable `SQLITE_PATH=tmp/...`；未富化项用 `npm run enrich:pending -- --limit=20` | `docs/TASKS.md` E-02、`docs/E-02-REAL-RUN-2026-10-01.md` |
| 2 | **P-07 其余浏览器手动验收**：Log4Shell 带引用问答 / CVE-2099-4321 拒答 / “嗯”澄清 + 截图录屏；采集诊断页本轮已用 Tabbit 目视验证，但不能代替整套 P-07 验收 | 本文件 §1、`docs/P07-DEMO-PLAN.md` §2 |
| 3 | **D6（10/3）契约冻结三线 sign-off**：C-01~C-06 代码侧早已完成，卡在签字 | `docs/TASKS.md` §4 |
| 4 | **A-04 / E-04 安全加固**：DQ1 隔离落库、注入检测、Q4 入口闸门（禁砍，最迟 D9–D11） | `docs/TASKS.md` §5 |
| 5 | compose 最小验证（Qdrant + Postgres + demo 全栈）——D16 彩排前 | 台账 E-05 降级口径 |
| 6 | D 系列文档口径同步（README/PROJECT-INTRO 与代码不符的 12 处） | 台账 §7 |

---

## 6. 最近一次交接（2026-10-01）

**分支 `feat/qa-local-live-demo`（b30c9a5）rebase 合入 main**（commit `2aeec7c`，门禁全绿；随后 `5624a1b` 同步状态文档）。
合入内容：`scripts/local-demo-server.ts`（本机 API，启动实跑采集→DQ1→富化，问答真跑 Q1→Q2→Q4，SSE 事件流）、
`docs/LOCAL-DEMO.md` 手册、前端 `VITE_DEMO_MODE` 二值开关、大屏/列表/详情/问答页接线、82 行 demo server 测试。
合入后远端分支已删，origin 只剩 `main`。

**R-07（前端"假数据"可信度缺陷）在 main 的实现状态**：三处缺陷均已消——
① `api.ts` 硬编码 mock → 环境变量开关、默认真实后端；② 大屏趋势 `Math.random()` + 写死日期伪造 → 按真实 `published_at` 聚合；
③ TopNav 恒绿"系统运行中"无标识 → 真实模式状态 + 全站横幅。实现来自 b30c9a5 一系（与 KKK 的 `aab1488` 目标等价、路径不同）。

**验证证据**（可复跑）：

```
npm run check                    → exit 0（typecheck + 全量单测 + 契约校验 + web 构建）
npm run smoke                    → 全段 PASS
src/qa/test/local-demo-server.test.ts → 82 行断言随全量测试通过
```

**仍待办**：采集诊断页已用 Tabbit 目视验证；P-07 整体浏览器验收仍未完成（大屏、情报列表和三种问答场景 + 录屏尚欠），完成前不得将 P-07 表述为"已验收"。

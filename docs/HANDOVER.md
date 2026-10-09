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
2. **模式必须可见**——两种模式都有全站横幅（`App.vue`）：静态演示模式明示“不请求后端”；本地 demo 明示采集/检索证据来自 fixture、不代表实时态势。Q1/Q2 只在门槛满足时发送问题/查询词，Q4 发送公开 fixture 证据。单独运行受控页面采集时，只有显式入库/LLM opt-in、精确 HTTPS host 和本地 heuristic/hash attestation 都通过后，原文才可能发送到 StepPlan；启发式并非完整防护。不要输入敏感信息。
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
3. **StepPlan 接入范围已扩到适用层**：Q1/Q2/Q4 仍按需调用并回退原规则/模板；新增 A-02 `npm run qa:decision:serve`（仅监听 `127.0.0.1:8317`）；默认先用精确匹配 `public_facts.rule_candidate` 的本地规则结果，只有规则弃权且显式 public opt-in、allowlist 事实、单选题和上游校准概率表齐备才触发 StepPlan，最终 `calibrated_prob` 来自上游而非模型自评。决策角色 profiles 默认 private；当前 QA UI 尚无 `calibrated_option_probabilities` 的业务生产者，只有调用方按该子 schema 显式提供概率/候选时才会给出决策，否则转人工/挂起。受控网页抽取可在 `PAGE_INGEST_ENABLED=true`、`SAFETRACE_INGEST_LLM_ENABLED=true`、精确 host/元数据和 StepPlan key 均具备时，规则失败后尝试模型；页面须经本地 A-04 heuristic/hash attestation，候选仍经引用校验与 DQ1。F1 另有 opt-in 的标题/规则词项二次建议，只记 lineage/CLI，不改变论文分数/顺序或 F4/F6。新增数据库 ctx 管理：`llm_context_sets`/`llm_context_blocks` 按 task_key+role+data_domain 组装每层提示词，稳定规则在前、易变事实在后以命中 prompt-prefix 缓存，版本不可变、lineage 只留 hash，缺 active ctx 时 fail-closed 不发请求；运维用 `npm run llm:context`（list/show/put/activate/deactivate）。A-04 是有界启发式、不是完整防护保证；不要发送未知/敏感内容。默认 `config/models.yml` 仍离线；Q2 仍检索 fixture；费用尚未计量。本轮新增的 A-02/采集/F1 路径仅用 mock 测试，未做真实云端调用。
4. **F2 资产定位是 Mock**：20 条合成演示资产，不接真实清单/扫描（合规红线：不扫未授权目标）。
5. **A-04 启发式已全链路落地，但完整安全闭环仍未完成（2026-10-09 更新）**：共享本地启发式筛查已接到 Q1/Q2/Q4、A-02 public projection、受控网页抽取与 F1 reviewer；网页模型调用需显式 opt-in、exact-host、24k cap、hash-bound attestation，F1 只送论文标题/规则词项且建议不写入评分。DQ1（gate 1.1.0）现已填 `QualityVerdict.injection_score/injection_flags`：命中 → verdict 至少 review（人工复核、pipeline 不放行），无法筛查 → fail-closed 至少 review 且不填字段（缺省=未筛查）；`fixtures/injection/` 有十类对抗样本 + 2 良性对照，`src/ingest/test/injection.test.ts` 15 条 + `src/qa/test/injection.test.ts` 6 条反向验收全绿。检测器只覆盖已知模式，**不能保证发现所有 prompt injection**；元内容误判（描述攻击手法的正常内容）会转 review 而非 quarantine（数据不丢、人工可判）。**仍待做**：更强证据 envelope/出处界线核查、完整 tool 权限边界审计、E-04 隔离区落库。不得把 A-04 表述为"防护保证"。
6. **72h 连续运行证据未产生**：调度器/看板代码已合入，端到端实测待 XueXuhang 补跑。
7. **E-02 最新 SQLite trace 是修复前历史**：其 OSV/cve.org 为 no_new_data，代码现已传入 CVE IDs，但历史事件不回写。真实端到端内存探测（不写 SQLite）已证明 KEV→OSV/cve.org 各抓取并解析 1 条，且两条都与 KEV 对应 CVE 归并；正式比较表仍待补。
8. **富化未完成且 fallback 不等于成功**：最后记录的持久 trace 为 1098/3727（29.5%），其中 1074 条 arXiv 论文为 fixture 降级；本轮未重跑该 SQLite 数据库，数字仍是历史观测。PowerShell 在线补跑：`$env:SAFETRACE_ENRICH_OFFLINE="false"; npm run enrich:pending -- --limit=20`。额外设置 `SAFETRACE_ENRICH_LLM_ENABLED=true` 且 planner/key 为 StepPlan 时，F1 仅对 live 且规则排序含糊的候选生成建议；建议不改变已发布结果。已产生 fixture 结果不会自动覆盖。
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
| 4 | **A-04 / E-04 安全加固收尾**：DQ1 注入筛查已落地（2026-10-09），剩隔离区落库（E-04）、证据 envelope 界线核查与工具权限边界审计 | `docs/TASKS.md` §5 |
| 4b | **A-06 自愈已落地**（2026-10-09）：`npm run selfheal:drill` 全链路 + 冒烟第 [9] 段；剩真实 Langfuse 面板验收与 72h 常驻证据（E-07） | `docs/TASKS.md` A-06 |
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

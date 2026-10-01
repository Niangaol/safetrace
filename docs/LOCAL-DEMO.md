# 本机可操作演示（fixture 实链）

此模式的采集、列表和 Q2 检索证据仍来自仓库 fixture，不是联网采集、实时威胁情报或真实企业资产。Q1 规则低置信时 StepPlan 可辅助分类/澄清；Q2 无命中或多跳证据偏少时可改写查询并重检；Q4 用 StepPlan 生成结论，未配置、失败或证据不足就保留原规则/模板。Q1/Q2 云端只接收问题与查询词，Q4 会发送公开 fixture 证据；不要输入敏感信息。费用暂未计量，显示“—”；页面横幅会保留 fixture 边界。

## LLM 调用边界

本机 `.env.local` 选择 `config/models.tokendance.yml` 时，`planner`/`answerer` 才会走 StepPlan；默认 `config/models.yml` 仍离线。每层最多发起一次 StepPlan 请求，不自动重试；费用未接计量。

- **Q1 意图层**：规则先跑；只有需要澄清或启发式置信度低于 0.55、且问题不是极短输入时才调用。StepPlan 只能返回受限 intent/澄清 JSON；若规则已有候选，模型只能从候选中选择；若模型给自评置信度且低于阈值，就继续澄清。CVE/产品/版本槽位始终由规则抽取；输出不合格就保留原规则并显示降级。
- **Q2 检索层**：只在无命中、分数低于阈值，或多跳/时间线/攻击链的证据少于两条时改写查询。发送问题、计划和命中统计，不发送检索原文；新增 CVE 会被拒绝。改写后的查询必须重新检索，且只有结果变好才替换原结果，否则保留原检索。
- **Q4 答案层**：证据门禁通过后才调用；StepPlan 只生成结论，citation 与证据原文仍来自 Q2。证据不足先拒答，不调用模型。
- **受控采集解析**：默认规则优先。只有同时打开 `PAGE_INGEST_ENABLED=true` 和 `SAFETRACE_INGEST_LLM_ENABLED=true`，并提供来源元数据、精确 HTTPS host allowlist、StepPlan planner/key 时，规则不完整才会尝试模型。原文须经本地 A-04 启发式筛查、hash-bound attestation 和 24,000 字符限制；过期快照、筛查失败或模型输出未通过逐字引用校验都转人工，候选还必须进入原有 DQ1，模型不能直接发布。
- **F1 富化**：默认离线/fixture 不调用模型。仅在显式 live 模式、`SAFETRACE_ENRICH_LLM_ENABLED=true`、StepPlan planner/key 齐备且 arXiv 结果规则排序不明确时，发送查询标题、论文标题/年份/规则词项（不发摘要全文或 URL）做二次建议。建议只记 lineage/CLI，不改变 PaperLink 顺序或分数、F4 CVSS/EPSS、F6 总分或发布契约。
- **A-02 决策**：`npm run qa:decision:serve` 在 `127.0.0.1:8317` 挂载 `/v1/decide`。决策 role profiles 默认 private；handler 先尝试本地确定性 rule（仅当 typed option 与 `public_facts.rule_candidate` 精确匹配，且来自 rule 的上游选项分布对应概率 ≥0.65），再考虑 StepPlan。StepPlan 只可在调用方显式 public opt-in、单个 choice 问题、allowlist 公共事实和来自 rule/tool/policy 的完整校准概率分布齐备后参与选择；模型自评只用于拒答阈值，最终 `calibrated_prob` 来自上游分布。缺条件、规则/模型弃权或无效输出都显式落到人工/挂起。

A-02 请求需由上游提供真实校准分布；下面的概率仅为 JSON 形状示例，不可照抄当作已校准事实：

```json
{
  "decision_id": "dec_example",
  "kind": "q1_route",
  "trace_id": "tr_example",
  "schema_version": "1.0",
  "questions": [{ "q_id": "route", "type": "choice", "options": ["impact_range", "remediation"] }],
  "state": {
    "data_domain": "public",
    "stepfun_opt_in": true,
    "injection_screened": true,
    "calibration_source": "rule",
    "calibrated_option_probabilities": { "impact_range": 0.88, "remediation": 0.12 },
    "public_facts": { "cve_ids": ["CVE-2021-44228"], "severity": "critical" }
  }
}
```

本地 handler 会检查请求形状和 public-facts allowlist；传给 StepPlan 的载荷不包含原始 `state`、`calibrated_option_probabilities`、问题 ID 或未允许字段。示例故意省略 `rule_candidate` 以演示 StepPlan 分支；正常请求若 `public_facts.rule_candidate` 与 typed option 一致且 rule 概率 ≥0.65，会先由本地规则短路，不调模型。缺少上游校准分布时不会发请求，并沿阶梯挂起/转人工；handler 只做数值/总和校验，不能替上游证明概率已统计校准。

### 数据库结构化 ctx（每次模型接入都带关联 ctx）

所有 `chat` 调用都由 MG1 在发请求前解析一份**数据库里的 ctx 快照**，而不是把提示词散落在各家 adapter 里。默认落库在 `var/safetrace.sqlite`（`SQLITE_PATH` 可覆盖）的两张表：`llm_context_sets`（context_id + version + task_key + role + data_domain + priority + active）与 `llm_context_blocks`（block 内容及 SHA-256）。

- **关联口径**：每次调用按 `task_key`（如 `qa.q1.intent`、`qa.q2.rewrite`、`qa.q4.answer`、`qa.decision.choice`、`ingest.advisory.extract`、`enrich.f1.paper_review`）+ `role` + `data_domain` 取用；`task_key`/`role` 为 `*` 的公共规则会先拼进去。
- **顺序固定**：稳定块（通用规则 → 任务规则）拼成一个 `system` 消息放最前，变化快的块（带 `max_age_seconds` 的易变事实）紧随其后，真实问题和检索证据永远排在最后，保证**稳定前缀逐字节不变**、尽量命中 prompt-prefix 缓存。
- **版本与留痕**：ctx 版本不可变，改内容必须发新版本；`mg1.chat` lineage 会记录 `LlmContextSet`、`LlmPromptStablePrefix`、`LlmContextSnapshot` 三类引用（只存 SHA-256，不复制提示词正文）。
- **出云边界**：`data_domain=public` 的调用只会看到 public ctx，private ctx 不会被拼进公网请求；`private` 调用可以额外看到 public 规则。
- **fail-closed**：显式要求某个 task_key 但库里没有对应 active 版本时，直接拒绝并记 `llm-context:unavailable` 降级事件，**不发 provider 请求**，由上层沿用规则/模板/人工兜底，避免缺 ctx 的“裸提示词”悄悄出云。

```powershell
npm run llm:context -- list                       # 看 role/task/domain/版本/块 hash（不输出正文）
npm run llm:context -- show safetrace.qa.q1.intent 2   # 查看某版本完整内容
npm run llm:context -- put .\my-context.json      # 发新版本并激活（JSON 需带 task_key/role/data_domain/description/blocks）
npm run llm:context -- activate safetrace.qa.q1.intent 1   # 回滚到旧版本
npm run llm:context -- deactivate safetrace.qa.q1.intent   # 停用；相关 task 调用立即 fail-closed
```

内置默认 ctx 只写“边界纪律”（不得编造、只从允许选项里选、证据不足要弃权），**不是**新的安全保证；A-04 仍是部分启发式。

**安全边界说明**：A-04 当前是有界本地启发式检测器，能挡住已知注入标记，不是完整的 prompt-injection 防护保证；不要把未知/敏感资料发送到云端。DQ1、去重、契约校验、F4 与 F6 仍由确定性逻辑负责。以上新模型路径有 mock 测试；除此前记录的 Q4 验证外，本轮不代表真实云端调用已完成。

## 启动

先在仓库根目录准备依赖（只需一次）：

```powershell
npm ci
npm ci --prefix web
```

开两个 PowerShell 窗口，都切到仓库根目录 `D:\AgentPrograms\safetrace`：

**窗口 A：启动本机后端**

```powershell
npm run demo:serve
```

等它显示 `SafeTrace 本地链路已启动：http://127.0.0.1:8000`。启动时会执行离线采集/DQ1/富化并建立索引；此窗口保持打开。

**窗口 B：启动前端**

```powershell
npm run dev --prefix web
```

打开 <http://127.0.0.1:5173/>。Vite 的 `/api` 代理指向窗口 A 的 8000 端口；两个窗口都不要关。顶部导航新增“采集诊断”页：它读取 `var/safetrace.sqlite` 最近一次持久化 trace，与 demo 启动时的内存 fixture 数据分开；没有数据库/静态演示模式时会明确提示。

## 建议手测

1. **态势大屏**：看 4 条原始 fixture、去重后情报、富化覆盖和 4/4 回放状态。采集趋势从 fixture 的 `published_at` 聚合，模型费用显示“— / 未接费用计量”。延迟与 SLA 未实测，显示“—”。
2. **情报列表 → CVE-2021-44228 详情**：搜索并打开该 CVE；来源数、发布时间、CVSS 来自实际运行的 ingest/enrich fixture。详情页证据链接应能打开来源 URL。
3. **情报问答**：问“Log4Shell 影响哪些版本？怎么修复？”——答案来自本机 Q1→Q2→Q4，显示 citation 和来源链接。
4. 再问“CVE-2099-4321 影响哪些版本？”——索引没有此 CVE，必须明确拒答且不生成 citation。
5. 输入“嗯”——Q1 低置信应走澄清/拒答路径。

也可在第三个窗口直接验证：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
Invoke-RestMethod 'http://127.0.0.1:5173/api/v1/vulns?page=1&page_size=10'
```

## 本地门禁

```powershell
npm run check
npm run smoke
```

若本机的 Windows TEMP 目录导致 esbuild 报 `Access is denied`，先设可写 TEMP 再构建：

```powershell
New-Item -ItemType Directory -Force .tmp | Out-Null
$env:TEMP = (Resolve-Path .tmp).Path
$env:TMP = $env:TEMP
npm run check
```

关闭时在两个窗口分别按 Ctrl+C。服务只监听本机回环地址。没有 StepPlan key 时模板模式仍可用；配置 StepPlan 后问答需要外网，并会使用云端 API。

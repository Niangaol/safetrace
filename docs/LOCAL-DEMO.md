# 本机可操作演示（fixture 实链）

此模式的采集、列表和 Q2 检索证据仍来自仓库 fixture，不是联网采集、实时威胁情报或真实企业资产。Q1 规则低置信时 StepPlan 可辅助分类/澄清；Q2 无命中或多跳证据偏少时可改写查询并重检；Q4 用 StepPlan 生成结论，未配置、失败或证据不足就保留原规则/模板。Q1/Q2 云端只接收问题与查询词，Q4 会发送公开 fixture 证据；不要输入敏感信息。费用暂未计量，显示“—”；页面横幅会保留 fixture 边界。

## LLM 调用边界

本机 `.env.local` 选择 `config/models.tokendance.yml` 时，`planner`/`answerer` 才会走 StepPlan；默认 `config/models.yml` 仍离线。每层最多发起一次 StepPlan 请求，不自动重试；费用未接计量。

- **Q1 意图层**：规则先跑；只有需要澄清或启发式置信度低于 0.55、且问题不是极短输入时才调用。StepPlan 只能返回受限 intent/澄清 JSON；若规则已有候选，模型只能从候选中选择；若模型给自评置信度且低于阈值，就继续澄清。CVE/产品/版本槽位始终由规则抽取；输出不合格就保留原规则并显示降级。
- **Q2 检索层**：只在无命中、分数低于阈值，或多跳/时间线/攻击链的证据少于两条时改写查询。发送问题、计划和命中统计，不发送检索原文；新增 CVE 会被拒绝。改写后的查询必须重新检索，且只有结果变好才替换原结果，否则保留原检索。
- **Q4 答案层**：证据门禁通过后才调用；StepPlan 只生成结论，citation 与证据原文仍来自 Q2。证据不足先拒答，不调用模型。
- **采集解析/富化**：仍走本地规则/API；A-04 注入筛查完成前，不把不可信来源原文发给 StepFun。

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

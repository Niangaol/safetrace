# 本机可操作演示（fixture 实链）

此模式为方便验收的本机可操作版本：后端启动时实际执行 **采集→去重→DQ1→富化**，页面列表/详情读取这次执行结果；每次问答实际执行 **Q1→Q2→Q4**。注意：Q2 当前检索仓库内单独构建的 evidence fixture 索引，尚未接入本次采集结果。它不是联网采集、实时威胁情报、真实企业资产或 LLM 演示。页面顶部一直显示 fixture 边界；没有测到的延迟/时效指标显示为“—”。

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

打开 <http://127.0.0.1:5173/>。Vite 的 `/api` 代理指向窗口 A 的 8000 端口；两个窗口都不要关。

## 建议手测

1. **态势大屏**：看 4 条原始 fixture、去重后情报、富化覆盖和 4/4 回放状态。采集趋势从 fixture 的 `published_at` 聚合，模型费用显示“— / 本链路未调用 LLM”。延迟与 SLA 未实测，显示“—”。
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

关闭时在两个窗口分别按 Ctrl+C。服务只监听本机回环地址；无需 Docker、API key 或外网。

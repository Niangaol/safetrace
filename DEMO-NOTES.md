# SafeTrace 演示版（`-demo-v1`）

> 这是**演示/答辩用的可跑版本**，基于 `E:\code\ai-threat-intel` 的 Python 后端 + 重做后的前端，
> 并合并了 `E:\code\ai-threat-intel-demo` 里独有的着陆页与可视化组件。
> 分工口径见 upstream 的 `docs/TEAM-PLAN.md`；本文件只记录**这一份实现了什么**。

---

## 1. 快速开始

```bat
:: 前端（自动清理占用 5180 的旧实例，并进入本目录）
start-demo.bat
:: 或
启动演示.bat
```

打开 <http://localhost:5180/>。**后端没起时**页面顶部会显示「预置数据」横幅（诚实降级）；
想要真实数据，另开一个窗口起后端：

```powershell
cd E:\code\ai-threat-intel-demo-v1
$env:PYTHONPATH="$PWD\src"
$env:APP_ENV='dev'; $env:API_TOKEN=''
$env:POSTGRES_DSN="sqlite:///$($PWD.Path.Replace('\','/'))/data/demo.db"
$env:REDIS_URL=''; $env:DEMO_MODE='true'; $env:LLM_LOCAL_ENABLED='false'
C:\Python314\python.exe -m uvicorn aiintel.api.main:app --host 127.0.0.1 --port 8000
```

页面刷新后导航栏从「预置数据」变为「**实时数据**」，四个页面的数字全部来自 `/api/v1/*`。

---

## 2. 这一份实现了什么

### 2.1 前端真实接线（原来"界面从不请求后端"）

| 项 | 改动前 | 改动后 |
| --- | --- | --- |
| 数据来源 | `api.ts:4` 硬编码 `const USE_MOCK = true` | 读 `VITE_USE_MOCK`：默认 `auto` = **先请求真实后端**，仅"不可达/未实现(404/5xx)"才回退并标注来源 |
| 业务错误 | 被假数据掩盖 | 401/422 **如实抛错、不回退**（否则把"鉴权失败"伪装成"数据正常"） |
| 来源标识 | 无 | 全站横幅 + 导航栏「实时数据 / 预置数据」，并写明回退原因 |
| 大屏趋势图 | `genTrendData()` 用 `Math.random()` + 写死日期**伪造** | 删除；改为真实的「采集源入库分布」（各源水位线） |
| 首页四个数字 | 写死 `'1,284' / '5,230' / '96%'` | 改为 `/metrics/overview` + `/collect/status` 真实值 |
| 大屏 echarts | `import * as echarts`（整库入主包） | 按需引入 → 主包 1184 kB → **650 kB（gzip 222 kB）** |
| SSE 解析 | 每帧只取第一行，多行帧**静默丢事件** | 逐行匹配 `data:`；并**接住原先被丢掉的 `reasoning` 事件** |

### 2.2 「一次完整问答」演示页（TEAM-PLAN §3.4 的答辩核心）

`/qa` 重做为一屏看完的形态，并支持深链 `/qa?q=<问题>` 直接跑：

```
提问 → 检索证据 → 推理链（可展开） → 带引用答案 → 本次运行元信息
```

页面**如实标注**三件事（都是真实值，没涂改）：

- 后端无 LLM 凭据时答案为 `【演示模式】…` 占位 → 页面顶部明示"不是模型分析结果"；
- 检索得分 `score = 0.0000` → 注明"词法兜底排序，语义排序需向量模型"；
- `cost_cny = 0` → 注明"cache 占位，未真实调用"。

实测一次问答（`/qa?q=CVE-2026-31001 怎么修复？`）：**检索 3 轮、命中 1 条证据、
2 步推理（自检"证据支持"）、耗时 5ms、模型 deepseek-v4-pro、成本 ¥0**。

### 2.3 补齐被数据模型"藏着"的排序依据

动态优先级（`src/aiintel/services/triage.py`）按 **KEV + EPSS + CVSS** 加权，但
`epss` / `kev` / `kev_due_date` **只落库、不外发**，前端因此看不到"为什么这条排前面"。

- 后端 `api/routers/vulns.py`：`_serialize()` 补发三个字段；`sort` 增加 `epss` / `kev`；
  EPSS 用 `coalesce(epss, -1.0)` 降序，保证"无值"排在最后（SQLite 与 PG 的 NULL 位置不同）。
- 前端情报列表：新增 **EPSS 列（按风险配色）** 与 **「在野利用」徽标**，并加两个排序项。

实测：13 条真实数据里 2 条 KEV；`sort=epss` 与 `sort=cvss_score` 的**首条不同**，
即"CVSS 单因子"与"被利用概率优先"确实会给出不同结论——这正是动态优先级的证据。

### 2.4 修掉 3 个"演示打不开"的真 bug

| # | 故障 | 根因 | 处置 |
| --- | --- | --- | --- |
| 1 | `GET /api/v1/vulns` **500** | 模型有 `vuln.kev_due_date`，但 `data/demo.db` 建在此列之前 → schema 漂移 | 新增 `scripts/sync_demo_schema.py`：只 `ALTER TABLE ADD COLUMN` 补缺列，不动数据，服务在跑也能执行 |
| 2 | QA 永远返回"知识库中暂无可支撑该问题的证据"，`citations: 0` | `chunk` 表为 0 行（修 #1 时被 DROP 重建却未回填）→ **RAG 检索必然空转，且接口不报错** | 新增 `scripts/reseed_knowledge.py`：从 `demo_seed.CHUNKS` 幂等恢复 12 条切片 |
| 3 | `start-demo.bat` / `启动演示.bat` 指向旧目录 `ai-threat-intel-demo` | 复制目录后未更新 | 改为本目录；并加**端口占用清理**（否则打开的是上一个目录起的服务，误以为改动没生效） |

### 2.5 测试与验证

```powershell
# 后端（CI 同口径：.github/workflows/ci.yml）
python -m ruff check .            # All checks passed
python -m ruff format --check .   # 126 files already formatted
python -m mypy src                # Success, 65 files
python -m pytest -q --no-cov      # 469 passed / 8 skipped / 0 failed

# 前端
cd web
npm run build                     # vue-tsc + vite build，exit 0
npm run smoke:data-source         # 6/6：先真后假 / 显式标注 / 业务错误不掩盖
npm run probe:live-wiring         # 驱动真实 api.ts 打真后端 → 判定 dataSource=live
```

新增测试：`tests/test_api_smoke.py` 中 3 条（triage 信号外发、新 sort 可用、EPSS NULL 排序），
配套抽出 `api_sessionmaker` fixture 以便用例能往同一测试库写数据。

---

## 3. 已知限制（**必须同步进报告「已知限制」，不要当成已完成**）

1. **答案文字是占位**：无 `LLM_API_KEY`，走 cache provider；检索/引用/推理链是真的，
   最终文字不是模型分析结果，`cost_cny` 恒为 0。
2. **检索排序弱**：当前 `score` 为 0（词法兜底），语义排序需接入向量模型。
3. **前端与 upstream 的 TS 单体仓不是同一套后端**：本目录用 Python 后端；
   upstream `src/gateway|qa` 是 TS 服务，二者接口未打通。
4. **`F2` 资产维度为 Mock**：合规红线不允许主动扫描，故"业务暴露面"维度不存在，
   不得声称能算"对我们最危险"。
5. **采集未联网**：`sync_watermark` 里的条数是预置水位线，不是真实联网抓取结果。

---

## 4. 目录说明（本次新增/改动）

```
scripts/sync_demo_schema.py     新增：补演示库缺列（幂等、不断服务）
scripts/reseed_knowledge.py     新增：恢复知识库切片（幂等）
src/aiintel/api/routers/vulns.py  改：外发 epss/kev/kev_due_date + 新增 sort
tests/test_api_smoke.py         改：+3 条断言、抽出 api_sessionmaker fixture
web/src/api.ts                  改：env 驱动 + 先真后假 + 修 SSE 多行帧
web/src/App.vue                 改：挂载 DataSourceBanner
web/src/components/TopNav.vue   改：状态反映真实来源 + 加「总览」入口
web/src/components/DataSourceBanner.vue  新增
web/src/views/DashboardView.vue 改：删伪趋势、改真实分布、按需引入 echarts
web/src/views/HomeView.vue      改：四个数字接真实接口
web/src/views/IntelView.vue     改：EPSS 列 + 在野利用徽标 + 两个排序
web/src/views/QaView.vue        重做：一次完整问答演示页
web/src/stores/qa.ts            改：接住 reasoning 事件 + 运行元信息
web/src/router.ts               改：/ 指向着陆页
web/src/types.ts                改：VulnItem 补 epss/kev/kev_due_date
web/scripts/smoke-data-source.mjs  新增：数据来源逻辑烟测（6 条）
web/scripts/probe-live-wiring.mjs  新增：真连探针
start-demo.bat / 启动演示.bat     改：指向本目录 + 清理端口占用
```

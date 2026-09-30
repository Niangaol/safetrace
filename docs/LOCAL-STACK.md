# 本地推理栈（无 Docker）

SafeTrace 的 embedding / 问答 / 决策链路可以在本机纯离线跑通，不依赖 Docker、不依赖任何云端 API。
本文说明怎么起、怎么配、哪些是真的验过、哪些没有。

## 一键起停

```powershell
# 起全部服务（Qdrant :6333 / embedding :8081 / chat :8080）
# 首次运行会自动下载缺失的模型（约 5GB，国内镜像源，见下）
npm run local:up

# 全停
npm run local:down
```

`local:up` 内部依次做三件事：**就绪模型 → 起 Qdrant → 起 llama-server**。
模型不需要单独跑 bootstrap，缺了会自动下（幂等，已存在且 sha256 匹配就跳过）。

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SAFETRACE_MODELS_DIR` | `D:\AgentPrograms\safetrace-models` | 模型存放目录（仓库外，避免大文件污染仓库） |
| `SAFETRACE_SKIP_MODEL_DOWNLOAD` | 未设 | 设 `true` = 拒绝下载，直接转云端（见下） |
| `SAFETRACE_MODEL_ONLY` | 未设 | 只就绪名字含该子串的模型，调试用 |
| `LOCAL_EMBED_BASE_URL` | `http://127.0.0.1:8081/v1` | embedding 实例 |
| `LOCAL_LLM_BASE_URL` | `http://127.0.0.1:8080/v1` | chat 实例 |
| `QDRANT_URL` | `http://127.0.0.1:6333` | 向量库 |
| `QDRANT_COLLECTION` | `safetrace_sources` | 集合名 |

## 内置模型清单（自动下载）

模型**不进 git**——GitHub 单文件硬上限 100MB，而这两个是 634MB / 4.36GB。
改成内置下载链接，源按「国内镜像 → 官方」顺序自动探测，谁通用谁：

| 模型 | 用途 | 体积 | 下载源（按序） | sha256 |
| --- | --- | --- | --- | --- |
| `bge-m3-Q8_0.gguf` | embedding（实测 1024 维） | 605 MB | hf-mirror.com → huggingface.co | `950f4a8e…11167` |
| `Qwen2.5-7B-Instruct-Q4_K_M.gguf` | chat / Jev 打分底座 | 4.36 GB | hf-mirror.com → huggingface.co | `3e357ab3…40c6` |

完整清单和校验和写在 [scripts/ensure-models.mjs](../scripts/ensure-models.mjs) 里，加模型只改那一处。
新增模型的三件套（文件名、体积、sha256）必须齐全，缺一样就不给合入——
没有 sha256 就无法证明下载到的是不是被篡改/截断的文件。

下载用 curl 而不是 Node fetch：本机环境下 fetch 拉大文件会在中途被 terminate
（实测 634MB 只下到 162MB 就断），curl 实测 4.6GB / 86MB-s 稳定。

## 拒绝下载 / 下载失败怎么办：转云端

如果你不想下这 5GB，或者下载失败（断网、源挂了），**不需要手动改任何配置**：

```powershell
# 明确拒绝下载
$env:SAFETRACE_SKIP_MODEL_DOWNLOAD = "true"
npm run local:up     # 会跳过 llama-server，只起 Qdrant
```

此时 embedder 走 `config/models.tokendance.yml` 里的降级链
`fallback_chain: [tokendance, cache]`：本地 → 云端 Tokendance → cache。
全程显式留痕（`degraded_to` + FallbackEvent + lineage），**不是静默兜底**。
实测链路：`failed/local_embed → degraded/tokendance`，返回 1024 维真实云端向量。

> **这里踩过一个真 bug（2026-09-30 修复）**：MG1 给降级 provider 的模型名原本硬编码成
> `<provider>-fallback`（即 `tokendance-fallback`），云端没这个模型，直接 HTTP 400，
> 于是"转云端"形同虚设、实际退到了 cache。现在通过 role 的
> `fallback_model_ids: { tokendance: qwen3.7-text-embedding }` 显式声明真实模型名。
> 回归测试见 `src/gateway/test/fallback-model-ids.test.ts`。

## 转云端必须过人工关卡（不允许静默出网）

出网 = 花钱 + 数据离开本机，所以**不允许程序自己决定**。MG1 在降级到 cloud provider
之前会先问人，拿不到明确同意就不出网：

| 渠道 | 行为 |
| --- | --- |
| 未注入确认钩子 | **一律拒绝**（fail closed），退到 cache，relineage 记 `cloud fallback denied by human gate` |
| CLI（交互式 TTY） | 打印醒目卡片（角色/原因/出网到哪/什么模型/trace_id），等 y/n，**30 秒不答算拒绝** |
| 非交互（CI、管道、服务长跑） | 没有 TTY 取不到人工意见 → **直接拒绝**，不出网 |
| 钩子抛异常 | 按拒绝处理，绝不当作同意 |

环境变量安全阀 `SAFETRACE_CLOUD_FALLBACK`：

| 值 | 行为 |
| --- | --- |
| `never`（**默认**） | 连问都不问，一律拒绝 |
| `ask` | CLI 交互询问 |
| `always` | 不再询问直接放行（仅建议在明确知情的批量场景用） |

被拒绝时会产生 `user_visible` 的 FallbackEvent（`degradedOf: isolation:cloud-needs-human`），
用户在界面上看得到"刚才没让它出网"，而不是静悄悄换了个便宜答案。

要彻底禁云（只许本地 + cache，不许出网）：把 `fallback_chain` 改成 `[cache]`。

## 下载源为什么放国内

本机访问 huggingface.co 直连时，release/资源下载的 302 重定向目标连不通（拿到 0 字节）。
`hf-mirror.com` 是国内镜像，实测 206 可断点续传；魔搭 `modelscope.cn` 也可达（备用）。
**探测本机服务时才用 `curl --noproxy`，下载外网文件不要加**，否则又变成 0 字节。

## 用到的模型

| 用途 | 模型 | 量化 | 体积 | 实测维度 |
| --- | --- | --- | --- | --- |
| embedding | `bge-m3`（gpustack/bge-m3-GGUF） | Q8_0 | 634 MB | **1024**（实测，非声明） |
| chat / Jev 打分底座 | `Qwen2.5-7B-Instruct`（lmstudio-community） | Q4_K_M | 4.68 GB | - |

选 bge-m3 的原因：它的 1024 维与原先 Tokendance 的 `qwen3.7-text-embedding` 一致，
所以 `safetrace_sources` 集合的向量元数据不用重建就能切换。

llama.cpp 用 winget 的 `ggml.llamacpp`（Vulkan 后端，NVIDIA 卡可用）。
启动脚本通过 `Get-Command` 动态解析路径，升级 winget 包后无需改脚本。

## 配置怎么切

模型配置在 `config/models.tokendance.yml`（由 `.env.local` 的 `MODELS_CONFIG_PATH` 指定），
本地 provider 已定义好：

```yaml
local_embed:
  type: openai_compat
  base_url_default: http://127.0.0.1:8081/v1
  trust_boundary: local        # 关键：A-03 隔离闸门放行本地，不过出网扫描
  capability_flags: { rerank: false }

local_llm:
  type: openai_compat
  base_url_default: http://127.0.0.1:8080/v1
  trust_boundary: local
  capability_flags: { rerank: false }
```

**`trust_boundary: local` 不能漏**：`openai-compat.ts` 里 A-03 隔离闸门是非 local 边界就扫私域标记，
不标 local 会把本机请求当出云请求拦掉。

embedder 角色当前指向 `local_embed`。要切回云端 Tokendance，
把 provider 改 `tokendance`、model_id 改 `qwen3.7-text-embedding`、model_version 改 `unversioned-api` 即可
（该行不留 revision，因为 API 不提供，换版须重建集合）。

## 验收状态（如实标注）

`npm run pilot:doctor` 四项（embedder_config / qdrant / collection / embedding_service）已全绿，
`prerequisites_ready: true`。但请注意它自己的两个字段：

- `embedding_inference_verified: false` —— doctor 只做 GET 探测，**不证明推理能力**
- `vector_persistence_verified: false` —— **不证明向量真的写进了 Qdrant**

以上两项是分开验的，别拿 doctor 的绿当成向量链路已验收：

- 真实 embedding 推理：单独验过 HTTP 200，返回 **1024 维、全部有限、非零**向量，计量 25 tokens
- Qdrant 真实写入与召回：`npm run vector:verify` 已验收（写入 + 语义召回 + 跑完自动清场）

## 模块运转现状（2026-09-30 实测）

口径：**只认实测证据**，不把 mock 演示和只读诊断算作验收。测试基线 276 项 / 275 过 / 0 败 / 1 跳
（跳过的是没配 `TOKENDANCE_API_KEY` 时 cloud-gate 的云端一跳，配了就跑）。

| 模块 | 状态 | 实测证据 |
| --- | --- | --- |
| `src/shared` | ✅ 真实可用 | 28 测试全过：事件总线、幂等/死信、SQLite 持久化与重启、lineage 哈希、时间归一化 |
| `src/gateway` | ✅ 真实可用 | 31/32 过（1 跳）：MG1 路由/限流/熔断/计量、A-03 隔离闸门、云端人工关卡四路径 |
| `src/ingest` | ✅ 离线全链路 | 85 测试全过；`ingest:once` 实测 5 源→7 解析→1 合并→1 放行→7 chunks→30 条 lineage |
| `src/enrich` | ✅ 离线可用 | 59 测试全过；`assets:demo` 20 个资产按「受影响/不受影响/待核实」三档正确分级 |
| `src/qa` | ✅ 离线全链路 | smoke 8 段全 PASS，引用完整率 100%；langgraph 4 个永久 skip 已随其后端删除一并消除 |
| 编排层 | ✅ 单后端 | 2026-09-30 删掉 langgraph 只留 native（依赖从未安装、用例永久 skip，属死代码）；4 条核心断言一条未少 |
| 真实向量链路 | ✅ 已验收 | `vector:verify`：bge-m3 真实推理 + Qdrant 写入 + 语义召回排序正确，跑完清理剩 0 点 |
| 本地推理服务 | ✅ 真实可用 | llama-server 8081/8080 由 `up.ps1` 拉起；模型缺了自动从国内源下载并校验 sha256 |
| 云端降级 | ⚠️ 有人工关卡 | 默认 `never` 一律拒绝；`ask` 需 TTY 人工点头；`always` 才会真的出网（会花钱） |
| 真实网页抓取 | ❌ 未验收 | `page:demo` 输出 `mock: true`、0 网络请求，只验证规则→DQ1→SQLite→证据块→BM25 协议 |
| langgraph 编排 | 🗑️ 已移除 | 2026-09-30 删除，原因写在 `compile.ts` 顶部注释 |

仍待办：QA/gateway 的 HTTP 服务入口、队友的 E-07 周期调度器与 E-09 时效看板尚未做端到端实测
（目前只有单测覆盖）。

## 向量入库是默认关闭的

源码里 `SAFETRACE_INDEX_QDRANT` 默认 `false`，只有**非离线、无 fixture 降级、且真实 embedder 配置有效**时才允许写。
这是红线设计，别为了跑通硬开。

跑法（会真实消耗本机推理，不花钱）：

```bash
SAFETRACE_INDEX_QDRANT=true SAFETRACE_INGEST_OFFLINE=false npm run ingest:once
```

集合不存在时 doctor 视为 `ok`，入库时自动创建。

## 已知问题 / 坑

1. **在 gitbash 里用 `cmd & ...` 起的进程会被父 shell 退出时带走**，
   Qdrant 会莫名消失。所以一律用 `up.ps1`（PowerShell `Start-Process`）起，别在 bash 里后台起。
2. **下载外网文件不要加 `curl --noproxy`**：本机走本地代理（`127.0.0.1:7897`）。
   `--noproxy` 会让 GitHub release 的 302 重定向目标连不通，拿到 0 字节。
   只有探测本机服务时才用 `--noproxy`。
3. **doctor 曾经对 llama-server 误报 missing**：它要求模型 id 精确相等，而 llama.cpp 的 id 是
   GGUF 文件名（`bge-m3-Q8_0.gguf`）、配置里写短名（`bge-m3`）。已改为允许前缀匹配，
   只放宽命名形式，没放宽服务语义。
4. **`pilot:doctor` 这个 npm script 没带 `--env-file`**，所以它读的是默认 `config/models.yml`
   （占位 cache 配置），不是你的真实配置。要验真实环境必须手跑：
   `node --env-file=.env.local --import tsx scripts/pilot-doctor.ts`
5. **web 构建的 esbuild 会删系统 Temp 报 Access is denied**：跑 `check:web` / pre-push 前把
   `TEMP`/`TMP` 指到仓库内的 `.tmp/web-build`。

## 目录里有什么

```
scripts/local/up.ps1          起服务（幂等，已在跑就跳过）
scripts/local/down.ps1        按端口停服务
scripts/local/bootstrap.ps1   下载二进制 + 模型（幂等，可 -Force 重下）
config/models.local.yml       纯本地栈配置模板（embedder/chat 全本地）
config/models.tokendance.yml  现役配置：embedder 已切本地，云端参数留注释备回退
third_party/                  qdrant.exe 等二进制（gitignore）
docs/LOCAL-STACK.md           本文
```

# 本地推理栈（无 Docker）

SafeTrace 的 embedding / 问答 / 决策链路可以在本机纯离线跑通，不依赖 Docker、不依赖任何云端 API。
本文说明怎么起、怎么配、哪些是真的验过、哪些没有。

## 一键起停

```powershell
# 首次：下载 llamacpp（winget 自动装）、Qdrant 二进制、两个模型，共约 5.4GB
pwsh scripts/local/bootstrap.ps1

# 起全部服务（Qdrant :6333 / embedding :8081 / chat :8080）
pwsh scripts/local/up.ps1

# 全停
pwsh scripts/local/down.ps1
```

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SAFETRACE_MODELS_DIR` | `D:\AgentPrograms\safetrace-models` | 模型存放目录（仓库外，避免大文件污染仓库） |
| `LOCAL_EMBED_BASE_URL` | `http://127.0.0.1:8081/v1` | embedding 实例 |
| `LOCAL_LLM_BASE_URL` | `http://127.0.0.1:8080/v1` | chat 实例 |
| `QDRANT_URL` | `http://127.0.0.1:6333` | 向量库 |
| `QDRANT_COLLECTION` | `safetrace_sources` | 集合名 |

模型文件**不进 git**（见 `.gitignore` 的 `third_party/` 与 `*.gguf`），由 bootstrap 脚本按需拉取。

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
- Qdrant 真实写入与召回：需要显式 opt-in，见下

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

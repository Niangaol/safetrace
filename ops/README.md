# SafeTrace 运维手册（ops/）

P0 基础设施全部收口在 `ops/`：`docker-compose.yml` 一条命令拉起向量库（Qdrant）、关系库（Postgres）和可观测全家桶（Langfuse v3：server + worker + ClickHouse + Redis + MinIO），`scripts/wait-healthy.sh` 等全部 healthy，`scripts/smoke.sh` 就绪后自动跑 `npm run smoke`。没装 Docker 的机器不用强跑容器：Qdrant 有单文件二进制、存储有 SQLite 兜底，冒烟脚本本身零容器依赖，照样能验证 P0 骨架。

## 快速开始

```bash
# 1. 拉起全部容器（在仓库根目录）
docker compose -f ops/docker-compose.yml up -d

# 2. 等待全部 healthy（超时默认 120s，WAIT_TIMEOUT=300 可调大）
bash ops/scripts/wait-healthy.sh

# 3. 冒烟（docker 可用时自动先等健康，再 npm run smoke）
bash ops/scripts/smoke.sh

# 停止（数据保留在 ops/data/，已进 .gitignore）
docker compose -f ops/docker-compose.yml down
```

Postgres 默认凭据 `safetrace/safetrace/safetrace`，可在 `ops/.env` 或 shell 环境变量里用
`POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` 覆盖（compose 解析时求值，Langfuse 的
`DATABASE_URL` 自动跟随）；Langfuse 的 `NEXTAUTH_SECRET` / `SALT` 仅为本地开发占位，生产必须更换。

## 端口表

| 端口  | 服务              | 说明                                   |
| ----- | ----------------- | -------------------------------------- |
| 6333  | qdrant            | 向量库 HTTP API（/readyz、/healthz）   |
| 5432  | postgres          | 关系库（SafeTrace + Langfuse 共用一个）|
| 3000  | langfuse-server   | Langfuse Web UI 与 API                 |
| 8123  | clickhouse        | ClickHouse HTTP 接口                   |
| 9000  | clickhouse/minio  | ClickHouse 原生协议 / MinIO S3 API     |
| 9001  | minio             | MinIO 控制台                           |
| 6379  | redis             | Langfuse 缓存/队列                     |

对应连接串：Qdrant <http://127.0.0.1:6333>、Postgres `postgres://safetrace:safetrace@127.0.0.1:5432/safetrace`、
Langfuse <http://127.0.0.1:3000>（与 `.env.example` 里的默认值一致）。

## 无 Docker 备选路径

本机没装 Docker（或暂时不想拉镜像）时，按下面顺序替代：

1. **向量库**：下载 Qdrant 官方 releases 的单文件二进制（无需安装），直接运行即监听 6333，
   数据落在本地目录；`QDRANT_URL=http://127.0.0.1:6333` 不用改。
2. **关系库**：用 SQLite——`.env` 里设 `SQLITE_PATH=./var/safetrace.sqlite`，store 层自动使用，
   无需任何服务进程。
3. **可观测**：Langfuse 整体跳过（可选功能，P0 不阻塞主线）。
4. **验证**：`bash ops/scripts/smoke.sh`——检测到无 Docker 会跳过 wait-healthy，直接跑
   `npm run smoke`（冒烟零容器依赖，离线读 `fixtures/`）。

## 常见故障

- **端口占用**：`up -d` 报 `port is already allocated`。先查占用再处理：
  `netstat -ano | findstr :6333`（PowerShell）或 `lsof -i :6333`（bash），停掉旧容器/进程；
  也可以改 compose 左侧宿主端口（如 `"16333:6333"`），同步改 `.env` 的 `QDRANT_URL`。
- **镜像拉取慢/超时**：ClickHouse、Langfuse 镜像较大，国内网络建议配置 Docker 镜像加速器，
  或先 `docker compose -f ops/docker-compose.yml pull` 预拉；失败后重试 `up -d` 即可（镜像层可续传）。
- **Langfuse 内存吃紧**：全家桶（ClickHouse + MinIO + 双 Langfuse 进程）内存占用较高，
  开发机上可以只起核心存储单起调试：
  `docker compose -f ops/docker-compose.yml up -d qdrant postgres`，
  需要看追踪面板时再补 `up -d langfuse-server langfuse-worker clickhouse redis minio`。
- **healthy 等待超时**：`wait-healthy.sh` 超时退出码 1。用
  `docker compose -f ops/docker-compose.yml ps` 看各容器状态，`logs <服务名>` 看日志；
  首次拉镜像 + 建库可能超过 120s，可 `WAIT_TIMEOUT=300 bash ops/scripts/wait-healthy.sh`。
- **Postgres 凭据不一致**：改了 `POSTGRES_*` 但数据卷 `ops/data/postgres` 已按旧凭据初始化，
  需要 `docker compose -f ops/docker-compose.yml down` 后删掉该目录再起，或用旧凭据连接。
- **`npm run smoke` 不存在**：说明 `scripts/smoke.ts` 还没接线，`smoke.sh` 会提示先等 Lead
  完成骨架；接好线后无需改任何 ops 文件。

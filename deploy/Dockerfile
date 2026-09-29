FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# pyproject 与 src 必须一起 COPY：hatchling 要靠 packages 配置定位源码，
# 只拷 pyproject 无法构建 wheel
COPY pyproject.toml ./
COPY src ./src

# ── 嵌入依赖（sentence-transformers + torch）默认**不装** ──────────────
# 理由（都是实测）：
#   1. 它把镜像从 ~1GB 拉到 ~10GB（torch + nvidia 轮子约 2.5GB），
#      构建期间 `pip install` 连接中断的概率也随之升高（本机已失败过一次）；
#   2. **装了也用不上**：本机网络下 huggingface.co 不可达（实测容器连它、
#      ollama registry、hf-mirror 全部失败），拿不到 bge-m3 权重，
#      检索照样走关键词；Embedder 会按失败熔断快速降级。
# 需要语义检索的环境：`docker compose build --build-arg INSTALL_EMBED=1 api`，
# 并确保该环境能访问 huggingface.co（或预先把模型放进 hfcache 卷）。
ARG INSTALL_EMBED=""
RUN pip install --upgrade pip \
 && if [ "$INSTALL_EMBED" = "1" ]; then \
      echo ">>> 安装嵌入依赖（体积大）"; pip install ".[embed]"; \
    else \
      echo ">>> 跳过嵌入依赖（默认；容器内检索走关键词模式）"; pip install "."; \
    fi

COPY alembic.ini ./
COPY deploy/alembic ./deploy/alembic

# 运维/演示脚本也拷进去，容器内可直接执行（seed_from_demo / smoke_runtime）。
# 注意：`accept.py` 是**开发门禁**（要 ruff/mypy/pytest 等 dev 依赖），
# 生产镜像没有这些工具 —— 运行期检查请用 `smoke_runtime.py`。
COPY scripts ./scripts
COPY eval ./eval

EXPOSE 8000
CMD ["uvicorn", "aiintel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

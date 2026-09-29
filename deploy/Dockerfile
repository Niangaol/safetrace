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
RUN pip install --upgrade pip && pip install ".[embed]"

COPY alembic.ini ./
COPY deploy/alembic ./deploy/alembic

EXPOSE 8000
CMD ["uvicorn", "aiintel.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

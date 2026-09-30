"""回填向量脚本的守卫逻辑（SQLite 环境可测的部分）。

真实回填需要 PG + ONNX 模型，CI/SQLite 测不了；这里钉住的是**守卫语义**：

- 非 PG / 缺向量列 → 体面跳过（fatal=False），不误报；
- 列宽与配置维度不一致 / 嵌入器不可用 / 批量编码出零向量 → fatal=True 明确喊停，
  而不是把错维向量或零向量写进库（红线：不静默写坏数据）。
"""

import asyncio

from scripts.backfill_embeddings import (
    _is_zero_vector,
    check_prerequisites,
    run_backfill,
)


class _PgSession:
    """最小 PG 会话替身：只为 `check_prerequisites` 提供方言。"""

    def get_bind(self):
        return type(
            "Bind",
            (),
            {"dialect": type("Dialect", (), {"name": "postgresql"})()},
        )()


def test_check_prerequisites_sqlite_noop(sqlite_sessionmaker, db_session):
    fatal, msg = check_prerequisites(db_session)
    assert fatal is False
    assert "不是 PostgreSQL" in msg


def test_check_prerequisites_dim_mismatch_fatal(monkeypatch):
    monkeypatch.setattr(
        "scripts.backfill_embeddings._pg_embedding_col_type", lambda s: "vector(1024)"
    )
    fatal, msg = check_prerequisites(_PgSession())
    assert fatal is True
    assert "alembic upgrade head" in msg


def test_check_prerequisites_missing_column_not_fatal(monkeypatch):
    monkeypatch.setattr("scripts.backfill_embeddings._pg_embedding_col_type", lambda s: None)
    fatal, msg = check_prerequisites(_PgSession())
    assert fatal is False
    assert "缺 embedding 列" in msg


def test_run_backfill_sqlite_skips(sqlite_sessionmaker, db_session):
    class _Embedder:
        failure_reason = ""

        async def embed(self, text):
            return [0.5] * 384

    result = asyncio.run(run_backfill(db_session, _Embedder()))
    assert result["ran"] is False
    assert result["fatal"] is False
    assert result["backfilled"] == 0


def test_run_backfill_embedder_unavailable_fatal(sqlite_sessionmaker, db_session, monkeypatch):
    # 前置检查直接放行，让"嵌入器不可用"成为唯一判据
    monkeypatch.setattr("scripts.backfill_embeddings.check_prerequisites", lambda s: (False, ""))

    class _Dead:
        failure_reason = "模型缺失"

        async def embed(self, text):
            return None

    result = asyncio.run(run_backfill(db_session, _Dead()))
    assert result["fatal"] is True
    assert "不可用" in result["reason"]


def test_is_zero_vector_variants():
    assert _is_zero_vector([]) is True
    assert _is_zero_vector([0.0, -0.0]) is True
    assert _is_zero_vector([0.1, 0.0]) is False

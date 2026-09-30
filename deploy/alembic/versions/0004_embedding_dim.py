"""对齐 `chunk.embedding` 列宽到当前 `settings.embedding_dim`（幂等）。

背景：`chunk.embedding` 的宽度由**迁移执行那一刻**的 `EMBED_DIM` 决定
（`db/models.py` 里 `EMBED_DIM = get_settings().embedding_dim` 是导入时求值）。
早期镜像/库可能以 `vector(1024)` 建了列，而默认 ONNX 模型
（`paraphrase-multilingual-MiniLM-L12-v2`，384 维）只产生 384 维向量：
写入会报 `expected 384 dimensions, not 1024` 之类的错，导致 `persist_vuln`
里整段分块索引被跳过、向量列永远为空（检索静默退化为内存余弦/关键词）。

本迁移把列改宽成 `vector(<当前 settings.embedding_dim>)`：

- 只对**有向量列且列宽不一致**的库生效；本就一致的库 no-op；
- 缺列（未装 pgvector 的降级库）no-op，检索层早已支持无向量列降级；
- 改列前先丢 HNSW 索引，改完按新宽度重建（幂等）。
"""

import logging

from sqlalchemy import text

log = logging.getLogger("alembic.runtime.migration")

revision = "0004_embedding_dim"
down_revision = "0003_simhash_bigint"
branch_labels = None
depends_on = None


def _column_type(conn) -> str | None:
    """`chunk.embedding` 的类型字符串（`vector(384)`）；缺列返回 None。"""

    return conn.execute(
        text(
            "SELECT format_type(a.atttypid, a.atttypmod) "
            "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
            "WHERE c.relname = 'chunk' AND a.attname = 'embedding'"
        )
    ).scalar()


def upgrade() -> None:
    from alembic import op

    from aiintel.config import get_settings

    conn = op.get_bind()
    if conn.dialect.name != "postgresql":
        return
    want = f"vector({get_settings().embedding_dim})"
    typ = _column_type(conn)
    if typ is None or typ == want:
        return

    log.info("chunk.embedding 类型 %s → %s（重建 HNSW 索引）", typ, want)
    conn.execute(text("DROP INDEX IF EXISTS ix_chunk_embedding"))
    conn.execute(text(f"ALTER TABLE chunk ALTER COLUMN embedding TYPE {want}"))
    conn.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_chunk_embedding ON chunk "
            "USING hnsw (embedding vector_cosine_ops)"
        )
    )


def downgrade() -> None:
    # 列宽由"当前模型维度"驱动，没有一个固定的"旧值"可回滚；本迁移记录在案即可。
    log.info("0004 只等比列宽，无需回滚（列宽由 settings.embedding_dim 决定）")

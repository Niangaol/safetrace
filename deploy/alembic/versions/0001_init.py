"""初始化 schema。

pgvector 缺失时的降级契约（重要，别当成 bug 修掉）：

`pgvector.sqlalchemy.Vector` 编译出的列类型是 PG 的 `vector(N)`，**扩展没装时
`create_all` 直接报 `type "vector" does not exist`，整个迁移失败**。但检索层的
降级路径本来就是设计好的：

- `services/knowledge/indexer.py::index_owner` 探测 `"embedding" in columns`，
  缺列就跳过向量化；
- `services/knowledge/retrieval.py` 退回 ILIKE / 关键词；
- `services/knowledge/embedder.py` 在没装 sentence-transformers 时返回 None。

所以这里在建表前先探测扩展：**有就建完整 schema，没有就建一个缺 `embedding`
列的 `chunk` 表**，让"没装 pgvector"从"迁移跑不起来"变成"检索质量降级"——
与项目其它地方一致。后者比前者更符合"降级必须显式"的红线。

装上 pgvector 后重跑本迁移会补回 embedding 列吗？**不会。** Alembic 只跑一次，
需要手工执行：

    ALTER TABLE chunk ADD COLUMN embedding vector(1024);
    CREATE INDEX IF NOT EXISTS ix_chunk_embedding ON chunk
        USING hnsw (embedding vector_cosine_ops);
"""

import logging
from collections.abc import Sequence

from sqlalchemy import text

import aiintel.db.models  # noqa: F401  确保模型注册到 metadata
from aiintel.db.base import Base
from aiintel.db.models import Chunk

#: alembic 会配置并显示这个 logger，降级提示才能被 `alembic upgrade` 看到
#: （scripts/* 有 T201 豁免，但 deploy/ 没有，用 print 会被 ruff 拦下）。
log = logging.getLogger("alembic.runtime.migration")

revision = "0001_init"
down_revision = None
branch_labels = None
depends_on: Sequence[str] | None = None

#: 无 pgvector 时的 `chunk` 建表语句。列与 `models.Chunk` 一致，**只少 embedding**。
#: 手写而不是自动裁剪 metadata：自动裁剪要动 Column/Index 的绑定关系，
#: 反而更容易和模型漂移；这里用单测锁住两者一致（tests/test_alembic_init.py）。
CHUNK_WITHOUT_EMBEDDING = """
CREATE TABLE IF NOT EXISTS chunk (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    owner_type VARCHAR(16) NOT NULL,
    owner_id VARCHAR(32) NOT NULL,
    chunk_no INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    tsv TSVECTOR,
    created_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_chunk_owner_no UNIQUE (owner_type, owner_id, chunk_no)
)
"""


def upgrade() -> None:
    engine = _engine()
    has_vector = _enable_vector_extension(engine)

    if has_vector:
        Base.metadata.create_all(bind=engine)
    else:
        Base.metadata.create_all(
            bind=engine,
            tables=[t for name, t in Base.metadata.tables.items() if name != "chunk"],
        )
        with engine.begin() as conn:
            conn.execute(text(CHUNK_WITHOUT_EMBEDDING))

    with engine.begin() as conn:
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_chunk_tsv ON chunk USING gin (tsv)"))
        if has_vector:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_chunk_embedding ON chunk "
                    "USING hnsw (embedding vector_cosine_ops)"
                )
            )


def downgrade() -> None:
    Base.metadata.drop_all(bind=_engine())


def _enable_vector_extension(engine) -> bool:
    """尝试启用 pgvector；不可用时返回 False 并说明原因（不抛异常）。"""

    with engine.begin() as conn:
        available = conn.execute(
            text("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'")
        ).scalar()
        if not available:
            log.warning(
                "pgvector 未安装：chunk 表将缺 embedding 列，检索退化为关键词模式。"
                "检索层已支持该降级（见 indexer.has_embedding）。"
            )
            return False
        try:
            # pgvector 扩展文件在服务器上，但 CREATE EXTENSION 需要超级用户。
            # 权限不足时同样降级，不要让整个迁移失败。
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("pgvector 启用失败（%s）：chunk 表将缺 embedding 列。", type(exc).__name__)
            return False


def chunk_columns() -> list[str]:
    return [c.name for c in Chunk.__table__.columns]


def _engine():
    from aiintel.db.base import get_engine

    return get_engine()

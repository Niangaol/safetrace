"""KEV 强制修复截止日列。

背景：接入 CISA KEV 官方目录（`src/aiintel/services/collectors/kev.py`）后，
`vuln.kev_due_date` 有了权威来源——CISA 对每个在野利用条目给出联邦机构的
强制修复截止日。

注意 0001 用的是 `create_all`，**它不会给已存在的表补列**，所以这一版必须
显式 ALTER。SQLite 不支持 `ADD COLUMN IF NOT EXISTS`，因此用 Alembic 的
`batch_alter_table`（内部走"建新表 + 拷贝 + 改名"），两种方言都能跑。
"""

from collections.abc import Sequence

from sqlalchemy import Column, String, inspect

from aiintel.db.base import get_engine

revision = "0002_kev_due_date"
down_revision = "0001_init"
branch_labels = None
depends_on: Sequence[str] | None = None


def _has_column(conn) -> bool:
    return any(c["name"] == "kev_due_date" for c in inspect(conn).get_columns("vuln"))


def upgrade() -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = get_engine()
    # SQLAlchemy 2.0 下 connect() 会隐式开事务，DDL 必须显式 commit。
    with engine.begin() as conn:
        if _has_column(conn):
            return
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)
        with op.batch_alter_table("vuln") as batch:
            batch.add_column(Column("kev_due_date", String(length=10)))


def downgrade() -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = get_engine()
    # SQLAlchemy 2.0 下 connect() 会隐式开事务，DDL 必须显式 commit，
    # 否则连接回滚时 ALTER 一起被撤销（downgrade 表现为"列还在"）。
    with engine.begin() as conn:
        if not _has_column(conn):
            return
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)
        # 同样走 batch：裸 `ALTER TABLE ... DROP COLUMN IF EXISTS` 是 PG 语法，
        # SQLite 直接报 syntax error。
        with op.batch_alter_table("vuln") as batch:
            batch.drop_column("kev_due_date")

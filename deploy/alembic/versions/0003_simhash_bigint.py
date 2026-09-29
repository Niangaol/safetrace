"""把 `raw_item.simhash` 从 int4 拓宽为 int8（BigInteger）。

## 背景：一个只在 PostgreSQL 上暴露的真 bug

`simhash` 是**64 位**指纹（实测取值最大 8 990 225 398 902 710 575，约 8.99e18），
但模型原先声明为 `Integer` —— 在 PostgreSQL 上编译成 **int4**，上限 2 147 483 647。
于是往 PG 灌数据时 **22/22 行全部** `psycopg.errors.NumericValueOutOfRange`。

之所以长期没被发现：演示库一直是 **SQLite**，而 SQLite 不校验整型宽度，
`INTEGER` 可存 8 字节。这个迁移把模型与真实库对齐。

`down_revision` 指向 0002，链条：0001_init → 0002_kev_due_date → 0003_simhash_bigint。
"""

from collections.abc import Sequence

from sqlalchemy import BigInteger, inspect

from aiintel.db.base import get_engine

revision = "0003_simhash_bigint"
down_revision = "0002_kev_due_date"
branch_labels = None
depends_on: Sequence[str] | None = None


def _current_type(conn) -> str | None:
    for col in inspect(conn).get_columns("raw_item"):
        if col["name"] == "simhash":
            return str(col["type"]).upper()
    return None


def upgrade() -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = get_engine()
    with engine.begin() as conn:
        current = _current_type(conn)
        if current is None:
            return  # 表/列不存在，交给 create_all
        if "BIGINT" in current:
            return  # 已经是 int8，幂等
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)
        # 用 batch：SQLite 不支持 `ALTER COLUMN ... TYPE`（PG 语法），
        # batch 会走"建新表 + 拷贝 + 改名"，两种方言都能跑。
        # `existing_type` 必须给，否则 Alembic 在 SQLite 分支上无法生成 DDL。
        with op.batch_alter_table("raw_item") as batch:
            batch.alter_column(
                "simhash",
                existing_type=BigInteger,
                type_=BigInteger,
                existing_nullable=True,
            )


def downgrade() -> None:
    """回退会把超范围的值截断，因此**只在确认无超范围数据时**才应执行。"""

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import Integer, text

    engine = get_engine()
    with engine.begin() as conn:
        current = _current_type(conn)
        if current is None or "BIGINT" not in current:
            return
        over = conn.execute(
            text("select count(*) from raw_item where simhash > 2147483647")
        ).scalar()
        if over:
            raise RuntimeError(f"有 {over} 行 simhash 超出 int4 范围，回退会损坏数据；已阻止。")
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)
        with op.batch_alter_table("raw_item") as batch:
            batch.alter_column(
                "simhash",
                existing_type=BigInteger,
                type_=Integer(),
                existing_nullable=True,
            )

"""alembic 环境配置。"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

import aiintel.db.models  # noqa: F401
from aiintel.db.base import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    from aiintel.config import get_settings

    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = get_settings().postgres_dsn
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

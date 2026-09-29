"""Alembic 0002（KEV dueDate 列）迁移自检：加列、幂等、回滚。

不依赖 alembic CLI（那需要 PG），直接按 env.py 的方式装配 Operations。
临时库建在系统 temp 目录，跑完即删。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import sqlalchemy
from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION = (
    Path(__file__).resolve().parents[1] / "deploy" / "alembic" / "versions" / "0002_kev_due_date.py"
)


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    # DSN 的 env 名是 POSTGRES_DSN（config.py:20），不是 AIINTEL_ 前缀。
    # conftest 13-17 用 setdefault 把它设成了 PG，所以这里必须显式覆盖。
    monkeypatch.setenv("POSTGRES_DSN", f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
    import aiintel.db.models  # noqa: F401  触发模型注册
    from aiintel.config import get_settings
    from aiintel.db.base import Base, get_engine, get_sessionmaker

    # get_settings / get_engine 都带 lru_cache，不清掉会复用 conftest 已建的
    # PG engine，然后这些用例就会去连真库（本机没有 PG，报 psycopg 连接失败）。
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()

    eng = get_engine()
    Base.metadata.create_all(
        eng, tables=[t for name, t in Base.metadata.tables.items() if name != "chunk"]
    )
    yield eng
    eng.dispose()


def _load():
    spec = importlib.util.spec_from_file_location("m0002", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cols(engine) -> list[str]:
    return [c["name"] for c in sqlalchemy.inspect(engine).get_columns("vuln")]


def test_add_column_on_existing_table(engine):
    """真实痛点：0001 的 create_all 不会给已存在的表补列。"""

    with engine.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE vuln DROP COLUMN kev_due_date")
    assert "kev_due_date" not in _cols(engine)

    _load().upgrade()
    assert "kev_due_date" in _cols(engine)


def test_upgrade_is_idempotent(engine):
    module = _load()
    with engine.begin() as conn:
        conn.exec_driver_sql("ALTER TABLE vuln DROP COLUMN kev_due_date")

    module.upgrade()
    module.upgrade()  # 重复执行不应报错（create_all 之后已存在的库也要能跑）
    assert "kev_due_date" in _cols(engine)


def test_upgrade_is_noop_when_column_present(engine):
    _load().upgrade()
    _load().upgrade()
    assert "kev_due_date" in _cols(engine)


def test_downgrade_removes_column(engine):
    _load().upgrade()
    _load().downgrade()
    assert "kev_due_date" not in _cols(engine)


def test_column_type_is_iso_string(engine):
    _load().upgrade()
    col = next(
        c for c in sqlalchemy.inspect(engine).get_columns("vuln") if c["name"] == "kev_due_date"
    )
    assert col["type"].python_type is str
    assert col["type"].length == 10


def test_data_survives_batch_alter(engine):
    """batch_alter_table 在 SQLite 上是"建新表+拷贝"，不能把已有数据弄丢。"""

    from sqlalchemy.orm import sessionmaker

    from aiintel.db.models import Vuln

    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with factory() as s:
        s.add(Vuln(id="v1", cve_id="CVE-2026-88772", title="保留我", kev=True))
        s.commit()

    _load().upgrade()

    with factory() as s:
        row = s.get(Vuln, "v1")
        assert row is not None
        assert row.title == "保留我"
        assert row.kev is True


def test_operations_are_usable_on_this_engine(engine):
    """守住 env.py 的装配方式可用（Operations + MigrationContext）。"""

    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)
        assert op is not None

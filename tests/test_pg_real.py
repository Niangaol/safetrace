"""真实 PostgreSQL 下的 schema 契约测试。

默认 CI 只有 SQLite，这里全部 skip；`POSTGRES_DSN` 指向的库真的能连上才会真跑。
存在的理由：SQLite 测不出的问题在 PG 上才会暴露，已经踩到两个——
  1. `chunk.tsv` 声明成 `text` 时，`CREATE INDEX ... USING gin (tsv)` 在 PG 上
     直接报 "access method gin does not support data type text"；而检索侧
     `retrieval.py` 用的是 `tsv @@ plainto_tsquery(...)`，text 列同样跑不了。
     正确类型是 `tsvector`。
  2. `psycopg.connect()` 收不了 `postgresql+psycopg://` 这种 SQLAlchemy DSN，
     会让"数据库是否可用"的探测假阴性（accept.py 曾因此永远 SKIP）。

所以这些断言只能钉在 PG 上验证。

**不要用 `aiintel.db.base.get_engine()`**：conftest 会把它换成内存 SQLite，
那样这些测试会安静地对着 SQLite 断言、全部假失败。这里从 DSN 单独建 engine。

判定条件是"**连得上**"而不是"环境变量有值"——conftest.py 会 setdefault 一个
默认 DSN，光看变量是否存在会让没装 PG 的机器也以为该跑，然后集体假失败。
"""

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

from aiintel.config import get_settings

_ROOT = Path(__file__).resolve().parent.parent


def _script_heads() -> set[str]:
    """从迁移脚本目录解析当前 head，不写死任何 revision 号。"""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    ini = _ROOT / "alembic.ini"
    if not ini.is_file():  # pragma: no cover
        pytest.skip("找不到 alembic.ini，无法判断 head")
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(_ROOT / "deploy" / "alembic"))
    return set(ScriptDirectory.from_config(cfg).get_heads())


@pytest.fixture(scope="module")
def pg():
    # 必须先 cache_clear()：`get_settings()` 带 lru_cache，而本仓库有若干用例
    # 会 monkeypatch 环境变量后调 `get_settings.cache_clear()`（见
    # test_enrich_consistency / test_kev_migration）。缓存里可能残留着某个
    # 临时 SQLite DSN，于是**全量跑时这 8 条永远 skip**，真实 PG 的断言
    # 形同虚设——而这正是本文件唯一存在的理由。
    get_settings.cache_clear()
    dsn = get_settings().postgres_dsn
    try:
        engine = create_engine(dsn, pool_pre_ping=True, connect_args={"connect_timeout": 3})
        if engine.dialect.name != "postgresql":  # pragma: no cover
            pytest.skip(f"POSTGRES_DSN 指向的不是 PostgreSQL（当前={dsn}）")
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError) as exc:  # pragma: no cover
        pytest.skip(f"连不上 POSTGRES_DSN 指向的库，跳过真实 PG 测试: {exc}")
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def conn(pg):
    with pg.connect() as c:
        yield c


def test_alembic_at_head(conn):
    """迁移必须已推到 head，否则下面所有 schema 断言都不可信。

    head **不能写死**成某个 revision：写死过一次（`0002_kev_due_date`），
    结果 `0003_simhash_bigint` 加进来之后，这个测试在任何正确迁移过的库上
    都必然失败——它测的不是"迁移到位"，而是"迁移停在我写那行字的时候"。
    改为从 `deploy/alembic/versions` 现场解析 head。
    """
    row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
    assert row is not None, "alembic_version 为空：没跑过 alembic upgrade head"
    heads = _script_heads()
    assert row[0] in heads, (
        f"库里的版本是 {row[0]!r}，但迁移链的 head 是 {sorted(heads)}；"
        "跑 `alembic upgrade head`（多 head 时需 --heads 指定分支）"
    )


def test_chunk_tsv_is_tsvector(conn):
    """GIN 索引和 `@@` 运算符都要求 tsv 是 tsvector，不是 text。"""
    got = conn.execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name='chunk' AND column_name='tsv'"
        )
    ).scalar()
    assert got == "tsvector", f"chunk.tsv 应为 tsvector，实际 {got!r}"


def test_chunk_tsv_gin_index_exists(conn):
    """tsv 上的 GIN 索引建不出来 = 迁移在 PG 上是失败的。"""
    names = {
        r[0]
        for r in conn.execute(
            text("SELECT indexname FROM pg_indexes WHERE tablename='chunk'")
        ).fetchall()
    }
    assert "ix_chunk_tsv" in names, f"chunk 索引缺失: {sorted(names)}"


def test_kev_due_date_column_type(conn):
    """dueDate 是 YYYY-MM-DD，用 String(10)；不能是 date/timestamp。"""
    dtype, length = conn.execute(
        text(
            "SELECT data_type, character_maximum_length FROM information_schema.columns "
            "WHERE table_name='vuln' AND column_name='kev_due_date'"
        )
    ).fetchone()
    assert dtype == "character varying"
    assert length == 10


def test_vuln_kev_columns_present(conn):
    cols = {
        r[0]
        for r in conn.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name='vuln'")
        ).fetchall()
    }
    assert {"kev", "kev_due_date", "epss", "quality_score"} <= cols


def test_chunk_embedding_matches_pgvector_presence(conn):
    """没装 pgvector 时 embedding 列应当缺失，检索走关键词降级。

    装了 pgvector 时列应存在——两种情况都算通过，这里只断言**一致性**：
    列的存在与否必须和扩展存在与否对得上，不能是迁移中途失败留下的半截表。
    """
    has_ext = bool(conn.execute(text("SELECT 1 FROM pg_extension WHERE extname='vector'")).scalar())
    cols = {
        r[0]
        for r in conn.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name='chunk'")
        ).fetchall()
    }
    assert has_ext == ("embedding" in cols), (
        f"pgvector 存在={has_ext}，但 embedding 列存在={'embedding' in cols}；"
        "schema 与扩展状态不一致"
    )


def test_tables_created(pg):
    """0001 覆盖的业务表不能少。"""
    expected = {
        "vuln",
        "vuln_source",
        "raw_item",
        "enrichment",
        "chunk",
        "graph_edge",
        "ttp_mapping",
        "alert",
        "source_config",
        "sync_watermark",
        "agent_run",
        "agent_step",
        "eval_case",
        "eval_result",
        "paper",
        "vuln_paper",
        "poc",
        "policy_standard",
    }
    actual = set(inspect(pg).get_table_names())
    assert expected <= actual, f"缺表: {sorted(expected - actual)}"


def test_kev_due_date_survives_normal_write(pg):
    """ORM 写入路径能把 kev_due_date 真实落库（不只是 DDL 有列）。"""
    from sqlalchemy.orm import sessionmaker

    from aiintel.db.models import Vuln

    Session = sessionmaker(bind=pg, expire_on_commit=False)
    marker = "CVE-2099-TESTONLY"
    with Session() as s:
        s.query(Vuln).filter_by(cve_id=marker).delete()
        s.add(
            Vuln(
                cve_id=marker,
                title="pg round-trip test",
                kev=True,
                kev_due_date="2026-12-31",
            )
        )
        s.commit()

    try:
        with Session() as s:
            got = s.query(Vuln).filter_by(cve_id=marker).one()
            assert got.kev is True
            assert got.kev_due_date == "2026-12-31"
    finally:
        with Session() as s:
            s.query(Vuln).filter_by(cve_id=marker).delete()
            s.commit()

"""KEV 截止日端到端接线：`raw` → 归一 → 去重合并 → 落库。

重点验证三处语义，都是"看起来能跑但会悄悄出错"的地方：

1. **累积型**：`kev` 只能 False→True，`epss` 只增不减，`kev_due_date` 取最早。
   源顺序不该影响风险判断（与 `services/ingest/dedup.py` 的理由一致）。
2. **未知不是零**：`kev_due_date` 取不到必须是 `None`，不能糊成宽松值 ——
   否则 triage 会把"没期限"当成"不急"。
3. **落库不回退**：已有 True/更大的 epss/更早的 dueDate 不能被后来的空值覆盖。
"""

from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from aiintel.db.base import Base
from aiintel.services.ingest.dedup import _merge_fields
from aiintel.services.ingest.pipeline import normalize_item


@pytest.fixture()
def session():
    import aiintel.db.models  # noqa: F401  触发模型注册

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # _upsert_vuln 的 flush 会连带查询外键关联表，缺一张表就会 OperationalError。
    # 排除 chunk（同 conftest 的做法：它的 embedding 列是 PG 的 vector 类型，SQLite 建不出来）。
    Base.metadata.create_all(
        engine,
        tables=[t for name, t in Base.metadata.tables.items() if name != "chunk"],
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with factory() as s:
        yield s
    engine.dispose()


def _kev_item(cve: str, due: str, *, added: str = "2026-09-20") -> dict:
    return {
        "source": "kev",
        "external_id": cve,
        "title": f"{cve} 标题",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "content_text": "正文",
        "published_at": f"{added}T00:00:00+00:00",
        "raw": {
            "cve_id": cve,
            "kev_due_date": due,
            "kev_ransomware": "known",
        },
    }


async def test_normalize_extracts_due_date_from_kev_raw():
    item = await normalize_item(_kev_item("CVE-2026-88772", "2026-09-30"))
    assert item["kev"] is True
    assert item["kev_due_date"] == "2026-09-30"


async def test_missing_due_date_yields_none_not_placeholder():
    payload = _kev_item("CVE-2026-50000", "2026-09-30")
    payload["raw"].pop("kev_due_date")
    item = await normalize_item(payload)
    assert item["kev"] is True  # 已确认在野利用
    assert item["kev_due_date"] is None  # 但期限未知


async def test_nvd_item_without_kev_leaves_due_date_none():
    """NVD 侧没有 dueDate 字段 —— 不能被 KEV 的值反向污染。"""

    nvd_item = {
        "source": "nvd",
        "external_id": "CVE-2026-60000",
        "title": "普通 NVD 条目",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-60000",
        "content_text": "描述",
        "raw": {"severity": "HIGH"},
    }
    item = await normalize_item(nvd_item)
    assert item["kev"] is False
    assert item["kev_due_date"] is None


def test_merge_keeps_earliest_due_date():
    """两个源给不同期限时，最紧的那个才是约束。"""

    primary = {"cve_id": "CVE-A", "kev": True, "kev_due_date": "2026-12-01"}
    other = {"cve_id": "CVE-A", "kev": True, "kev_due_date": "2026-09-30"}
    _merge_fields(primary, other)
    assert primary["kev_due_date"] == "2026-09-30"


def test_merge_does_not_relax_due_date():
    primary = {"cve_id": "CVE-A", "kev": True, "kev_due_date": "2026-09-30"}
    other = {"cve_id": "CVE-A", "kev": True, "kev_due_date": "2027-01-01"}
    _merge_fields(primary, other)
    assert primary["kev_due_date"] == "2026-09-30"


def test_merge_kev_is_union_not_override():
    primary = {"cve_id": "CVE-A", "kev": False}
    other = {"cve_id": "CVE-A", "kev": True}
    _merge_fields(primary, other)
    assert primary["kev"] is True


def test_merge_keeps_higher_epss():
    primary = {"cve_id": "CVE-A", "epss": 0.9}
    other = {"cve_id": "CVE-A", "epss": 0.2}
    _merge_fields(primary, other)
    assert primary["epss"] == 0.9


def test_merge_does_not_invent_due_date():
    primary = {"cve_id": "CVE-A", "kev": True}
    other = {"cve_id": "CVE-A", "raw": {"kev_due_date": "2026-10-01"}}
    _merge_fields(primary, other)
    assert primary["kev_due_date"] == "2026-10-01"


def test_persist_does_not_downgrade_existing_kev(session):
    from aiintel.db.models import Vuln
    from aiintel.services.knowledge.indexer import _upsert_vuln

    _upsert_vuln(
        session,
        {"id": "v1", "cve_id": "CVE-A", "kev": True, "epss": 0.9, "kev_due_date": "2026-09-30"},
    )
    session.commit()

    # 后到的空值不能把风险降级
    _upsert_vuln(session, {"id": "v1", "cve_id": "CVE-A", "kev": False, "epss": 0.1})
    session.commit()

    saved = session.execute(select(Vuln).filter_by(cve_id="CVE-A")).scalar_one()
    assert saved.kev is True
    assert saved.epss == 0.9
    assert saved.kev_due_date == "2026-09-30"


def test_persist_raises_epss_but_keeps_earliest_due(session):
    from aiintel.db.models import Vuln
    from aiintel.services.knowledge.indexer import _upsert_vuln

    _upsert_vuln(
        session,
        {"id": "v1", "cve_id": "CVE-A", "kev": True, "epss": 0.2, "kev_due_date": "2026-12-01"},
    )
    session.commit()
    _upsert_vuln(
        session,
        {"id": "v1", "cve_id": "CVE-A", "kev": True, "epss": 0.8, "kev_due_date": "2026-09-30"},
    )
    session.commit()

    saved = session.execute(select(Vuln).filter_by(cve_id="CVE-A")).scalar_one()
    assert saved.epss == 0.8
    assert saved.kev_due_date == "2026-09-30"


def test_persist_ignores_bool_epss(session):
    """Python 里 bool 是 int 的子类，不排除会把 True 当成 EPSS=1.0 写进去。"""

    from aiintel.db.models import Vuln
    from aiintel.services.knowledge.indexer import _upsert_vuln

    _upsert_vuln(session, {"id": "v1", "cve_id": "CVE-A", "epss": True})
    session.commit()
    saved = session.execute(select(Vuln).filter_by(cve_id="CVE-A")).scalar_one()
    assert saved.epss is None


def test_kev_column_is_string10_for_iso_date(session):
    from aiintel.db.models import Vuln

    assert Vuln.__table__.c.kev_due_date.type.length == 10
    assert Vuln.__table__.c.kev_due_date.type.python_type is str


def test_due_date_survives_round_trip(session):
    from aiintel.db.models import Vuln
    from aiintel.services.knowledge.indexer import _upsert_vuln

    _upsert_vuln(
        session,
        {"id": "v1", "cve_id": "CVE-A", "kev": True, "kev_due_date": "2026-09-30"},
    )
    session.commit()
    saved = session.execute(select(Vuln).filter_by(cve_id="CVE-A")).scalar_one()
    assert saved.kev_due_date == "2026-09-30"
    # 必须是可排序的 ISO 字符串，不是 datetime
    assert isinstance(saved.kev_due_date, str)
    assert dt.date.fromisoformat(saved.kev_due_date).year == 2026

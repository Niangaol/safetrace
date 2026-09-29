"""采集注册表：水位线落库 + 单源失败隔离。"""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest

from aiintel.db.models import SyncWatermark
from aiintel.services.collectors.base import parse_datetime
from aiintel.services.collectors.registry import CollectorRegistry


class _FakeCollector:
    """替身采集器：避免测试触网。"""

    def __init__(
        self, name: str, items: list[dict] | None = None, error: Exception | None = None
    ) -> None:
        self.name = name
        self.priority = 10
        self._items = items or []
        self._error = error
        self.modes: list[str] = []

    async def poll(self, mode: str = "incremental") -> list[dict]:
        self.modes.append(mode)
        if self._error is not None:
            raise self._error
        return self._items

    async def aclose(self) -> None:
        return None


@pytest.fixture(autouse=True)
def factory(sqlite_sessionmaker):
    """每个用例一个干净的内存库。"""

    return sqlite_sessionmaker


def _fetch(factory, source: str):
    with factory() as session:
        return session.get(SyncWatermark, source)


def test_successful_poll_writes_watermark(factory):
    items = [
        {"source": "nvd", "external_id": "CVE-1", "published_at": "2026-09-20T00:00:00+00:00"},
        {"source": "nvd", "external_id": "CVE-2", "published_at": "2026-09-25T00:00:00+00:00"},
    ]
    reg = CollectorRegistry()
    reg._collectors = {"nvd": _FakeCollector("nvd", items)}

    assert len(asyncio.run(reg.poll(None, "incremental"))) == 2

    mark = _fetch(factory, "nvd")
    assert mark is not None
    assert mark.last_sync_at is not None
    # 增量模式不能推进全量游标，否则重启后会漏掉增量窗口的数据
    assert mark.last_full_sync is None
    assert mark.items_last_run == 2
    assert mark.last_error is None
    assert mark.last_published_at is not None
    assert mark.last_published_at.replace(tzinfo=dt.UTC) == parse_datetime(
        "2026-09-25T00:00:00+00:00"
    )


def test_full_mode_advances_full_sync_watermark(factory):
    reg = CollectorRegistry()
    reg._collectors = {"nvd": _FakeCollector("nvd", [{"external_id": "CVE-1"}])}

    asyncio.run(reg.poll(None, "full"))

    mark = _fetch(factory, "nvd")
    assert mark is not None and mark.last_full_sync is not None


def test_source_failure_is_recorded_and_does_not_block_others(factory):
    reg = CollectorRegistry()
    reg._collectors = {
        "ghsa": _FakeCollector("ghsa", error=RuntimeError("token 无效")),
        "nvd": _FakeCollector("nvd", [{"external_id": "CVE-9"}]),
    }

    collected = asyncio.run(reg.poll(None))

    assert [i["external_id"] for i in collected] == ["CVE-9"]
    failed = _fetch(factory, "ghsa")
    assert failed is not None
    assert "token 无效" in (failed.last_error or "")
    assert failed.items_last_run == 0


def test_poll_passes_mode_through_to_collector():
    collector = _FakeCollector("nvd", [{"external_id": "CVE-1"}])
    reg = CollectorRegistry()
    reg._collectors = {"nvd": collector}

    asyncio.run(reg.poll(["nvd"], "full"))
    assert collector.modes == ["full"]


def test_unknown_source_names_are_ignored():
    reg = CollectorRegistry()
    reg._collectors = {"nvd": _FakeCollector("nvd", [{"external_id": "CVE-1"}])}
    assert asyncio.run(reg.poll(["not_a_source"])) == []


def test_watermark_write_failure_does_not_break_collection(monkeypatch):
    """水位线写库失败不能拖垮采集：采集结果仍要返回。"""

    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr("aiintel.db.base.get_sessionmaker", _boom)
    reg = CollectorRegistry()
    reg._collectors = {"nvd": _FakeCollector("nvd", [{"external_id": "CVE-1"}])}

    assert len(asyncio.run(reg.poll(None))) == 1


def test_watermark_last_sync_at_is_recent(factory):
    reg = CollectorRegistry()
    reg._collectors = {"arxiv": _FakeCollector("arxiv", [{"external_id": "2501.00001"}])}
    asyncio.run(reg.poll(None))

    mark = _fetch(factory, "arxiv")
    assert mark is not None and mark.last_sync_at is not None
    last_sync = mark.last_sync_at
    if last_sync.tzinfo is None:
        last_sync = last_sync.replace(tzinfo=dt.UTC)
    assert (dt.datetime.now(dt.UTC) - last_sync).total_seconds() < 120

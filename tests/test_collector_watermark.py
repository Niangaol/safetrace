"""采集水位线的时区处理（增量采集的被阻塞点）。

## 修的 bug

`BaseCollector.watermark()` 直接返回 `SyncWatermark.last_published_at`。
SQLite（以及部分驱动）读回 `DateTime(timezone=True)` 时会**丢掉 tzinfo** ——
本仓 `registry.py` 的注释里早就记过这个坑，但水位线这一处漏了。

后果不是小瑕疵：`NvdCollector._page_url()` 会做 `now - start`（`now` 是 aware），
naive 减 aware 直接抛
`TypeError: can't subtract offset-naive and offset-aware datetimes`，
**整条增量采集链路失败**。而 `fetch(mode='full')` 不走 `since`，所以正常 ——
问题只在增量模式下暴露，正是天天在跑的那条路径。

时区语义：库里存的就是 UTC（写入时是 aware UTC），所以补 `dt.UTC` 是**还原**已知事实，
不是猜一个时区。
"""

from __future__ import annotations

import datetime as dt

import pytest

from aiintel.db.models import SyncWatermark
from aiintel.services.collectors.registry import CollectorRegistry


@pytest.fixture()
def registry_with_naive_watermark(sqlite_sessionmaker, monkeypatch):
    """造一条 **naive** 水位线（模拟 SQLite 读回丢 tzinfo 的真实行为）。"""

    with sqlite_sessionmaker() as session:
        session.add(
            SyncWatermark(
                source="nvd",
                last_published_at=dt.datetime(2026, 9, 28, 11, 53, 51),  # naive
                last_sync_at=dt.datetime(2026, 9, 30, 12, 0, 0),
                items_last_run=0,
            )
        )
        session.commit()

    monkeypatch.setattr("aiintel.db.base.get_sessionmaker", lambda: sqlite_sessionmaker)
    return CollectorRegistry()


def test_naive_watermark_gets_utc(registry_with_naive_watermark) -> None:
    """naive 水位线必须补成 UTC-aware —— 否则增量采集会在算术处炸。"""

    collector = registry_with_naive_watermark.get("nvd")
    w = collector.watermark()
    assert w is not None
    assert w.tzinfo is not None, "watermark() 必须返回带时区的时间"
    assert w.tzinfo == dt.UTC
    # 补时区不能改变"时刻"
    assert w.replace(tzinfo=None) == dt.datetime(2026, 9, 28, 11, 53, 51)


def test_incremental_page_url_does_not_raise(registry_with_naive_watermark) -> None:
    """**核心回归**：增量模式的 URL 构造不得抛 naive/aware 混算。

    这一条就是修复前必然失败的那条（`_page_url` 里 `now - start`）。
    """

    collector = registry_with_naive_watermark.get("nvd")
    url = collector._page_url("ollama", collector.watermark(), 0)
    assert "lastModStartDate=" in url
    assert "keywordSearch=ollama" in url


def test_aware_watermark_is_returned_unchanged(sqlite_sessionmaker, monkeypatch) -> None:
    """已经是 aware 的水位线不得被改写（幂等）。"""

    moment = dt.datetime(2026, 9, 28, 11, 53, 51, tzinfo=dt.UTC)
    with sqlite_sessionmaker() as session:
        session.add(
            SyncWatermark(
                source="nvd",
                last_published_at=moment,
                last_sync_at=moment,
                items_last_run=0,
            )
        )
        session.commit()

    monkeypatch.setattr("aiintel.db.base.get_sessionmaker", lambda: sqlite_sessionmaker)
    w = CollectorRegistry().get("nvd").watermark()
    assert w is not None
    assert w.tzinfo is not None


def test_missing_watermark_returns_none(sqlite_sessionmaker, monkeypatch) -> None:
    """没有水位线时返回 None（首次采集走全窗），不得抛异常。"""

    monkeypatch.setattr("aiintel.db.base.get_sessionmaker", lambda: sqlite_sessionmaker)
    assert CollectorRegistry().get("nvd").watermark() is None

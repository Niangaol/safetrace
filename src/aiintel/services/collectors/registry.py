"""采集器注册表与统一轮询入口。"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from aiintel.services.collectors.arxiv import ArxivCollector
from aiintel.services.collectors.base import BaseCollector, parse_datetime
from aiintel.services.collectors.community_rss import CommunityRssCollector
from aiintel.services.collectors.ghsa import GhsaCollector
from aiintel.services.collectors.kev import KevCollector
from aiintel.services.collectors.nvd import NvdCollector

logger = logging.getLogger(__name__)

_COLLECTOR_CLASSES: tuple[type[BaseCollector], ...] = (
    KevCollector,
    NvdCollector,
    GhsaCollector,
    ArxivCollector,
    CommunityRssCollector,
)


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    """把 naive 时间当作 UTC 补上 tzinfo。

    驱动（SQLite、不带时区的驱动）读回 DateTime(timezone=True) 时会丢 tzinfo，
    拿它跟 aware 时间比较会直接抛 TypeError。
    """

    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


class CollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, BaseCollector] = {}
        for cls in _COLLECTOR_CLASSES:
            collector = cls()
            self._collectors[collector.name] = collector

    def names(self) -> list[str]:
        return sorted(self._collectors, key=lambda n: self._collectors[n].priority)

    def get(self, name: str) -> BaseCollector:
        return self._collectors[name]

    async def poll(
        self, names: list[str] | None, mode: str = "incremental"
    ) -> list[dict[str, Any]]:
        """按优先级轮询；单源失败不阻断其他源，失败信息记入 watermark。"""

        selected = [n for n in (names or self.names()) if n in self._collectors]
        collected: list[dict[str, Any]] = []
        for name in selected:
            collector = self._collectors[name]
            try:
                items = await collector.poll(mode)
            except Exception as exc:  # noqa: BLE001 - 上层 supervisor 决定是否 repair
                logger.warning("采集源 %s 失败: %s", name, exc)
                self._save_watermark(name, mode, [], error=f"{type(exc).__name__}: {exc}")
                continue
            collected.extend(items)
            self._save_watermark(name, mode, items)
        return collected

    @staticmethod
    def _save_watermark(
        source: str, mode: str, items: list[dict[str, Any]], error: str | None = None
    ) -> None:
        """落水位线。

        水位线有两个用途：增量模式跨进程续跑（重启后不重复拉全量），
        以及大屏展示各源的新鲜度。写库失败不能影响采集结果。
        """

        try:
            from aiintel.config import BEIJING_TZ
            from aiintel.db.base import get_sessionmaker
            from aiintel.db.models import SyncWatermark

            now = dt.datetime.now(BEIJING_TZ)
            latest: dt.datetime | None = None
            for item in items:
                published = _as_utc(parse_datetime(item.get("published_at")))
                if published and (latest is None or published > latest):
                    latest = published

            with get_sessionmaker()() as session:
                mark = session.get(SyncWatermark, source)
                if mark is None:
                    mark = SyncWatermark(source=source)
                    session.add(mark)
                mark.last_sync_at = now
                if mode == "full":
                    # 只有全量同步才推进全量游标：增量模式下拿它当基准会漏数据
                    mark.last_full_sync = now
                previous = _as_utc(mark.last_published_at)
                if latest is not None and (previous is None or latest > previous):
                    mark.last_published_at = latest
                mark.items_last_run = len(items)
                mark.last_error = error
                session.commit()
        except Exception:  # noqa: BLE001
            logger.debug("写水位线失败 source=%s", source, exc_info=True)

    async def aclose(self) -> None:
        for collector in self._collectors.values():
            await collector.aclose()


_registry: CollectorRegistry | None = None


def get_registry() -> CollectorRegistry:
    global _registry
    if _registry is None:
        _registry = CollectorRegistry()
    return _registry

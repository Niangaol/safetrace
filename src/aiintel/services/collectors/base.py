"""采集器基类与统一数据结构。"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from aiintel.config import BEIJING_TZ, get_settings
from aiintel.core.metrics import collect_items, collect_latency

logger = logging.getLogger(__name__)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def parse_datetime(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


_WS = re.compile(r"\s+")


def content_hash(text: str) -> str:
    return hashlib.sha256(_WS.sub(" ", text or "").strip().lower().encode()).hexdigest()


@dataclass(slots=True)
class RawItemData:
    """采集器输出。id 与 hash 在入库前计算，便于去重。"""

    source: str
    external_id: str
    title: str
    url: str | None
    content_text: str
    published_at: dt.datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return hashlib.sha256(f"{self.source}:{self.external_id}".encode()).hexdigest()[:32]

    @property
    def hash(self) -> str:
        return content_hash(self.title + self.content_text)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            id=self.id,
            content_hash=self.hash,
            published_at=self.published_at.isoformat() if self.published_at else None,
            fetched_at=utcnow().isoformat(),
        )
        return data


class BaseCollector:
    """适配器接口。新增数据源只需实现 fetch 并注册。"""

    name: str = "base"
    priority: int = 100
    rate_limit_per_min: int = 20

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self.settings = get_settings()
        headers = {"User-Agent": self.settings.collect_user_agent}
        self._client = client or httpx.AsyncClient(
            headers=headers, timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        reraise=True,
    )
    async def _get_json(self, url: str, **kwargs: Any) -> dict:
        resp = await self._client.get(url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    @retry(
        retry=retry_if_exception_type((httpx.HTTPError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        reraise=True,
    )
    async def _get_text(self, url: str) -> str:
        resp = await self._client.get(url)
        resp.raise_for_status()
        return resp.text

    def watermark(self) -> dt.datetime | None:
        """上次同步水位线。**保证返回带时区的时间**（naive 一律按 UTC 补上）。

        ⚠️ 这个补时区不是可选的：SQLite（以及部分驱动）读回
        `DateTime(timezone=True)` 列时会**丢掉 tzinfo**，于是水位线变成 naive。
        而下游 `NvdCollector._page_url()` 会做 `now - start`（`now` 是 aware），
        naive 减 aware 直接抛
        `TypeError: can't subtract offset-naive and offset-aware datetimes`
        —— 实测**增量采集整条链路因此失败**（`fetch('incremental')` 报这个错，
        `fetch('full')` 正常，所以只在增量模式下暴露）。

        时区语义：库里存的就是 UTC（写入时是 aware UTC），所以补 `dt.UTC` 是正确的，
        不是"猜一个时区"。
        """

        from aiintel.db.base import get_sessionmaker
        from aiintel.db.models import SyncWatermark

        with get_sessionmaker()() as session:
            row = session.get(SyncWatermark, self.name)
            if row is None or row.last_published_at is None:
                return None
            value = row.last_published_at
            return value if value.tzinfo else value.replace(tzinfo=dt.UTC)

    def save_watermark(
        self,
        last_published: dt.datetime | None,
        items: int,
        error: str | None = None,
        full_sync: bool = False,
    ) -> None:
        from aiintel.db.base import get_sessionmaker
        from aiintel.db.models import SyncWatermark

        with get_sessionmaker()() as session:
            row = session.get(SyncWatermark, self.name)
            if row is None:
                row = SyncWatermark(source=self.name)
                session.add(row)
            if last_published and (
                row.last_published_at is None or last_published > row.last_published_at
            ):
                row.last_published_at = last_published
            row.items_last_run = items
            row.last_error = error
            if full_sync:
                # 只有全量同步才刷新"最近全量"时间，增量轮询不算
                row.last_full_sync = utcnow()
            session.commit()

    async def fetch(
        self, mode: str = "incremental"
    ) -> list[RawItemData]:  # pragma: no cover - 抽象
        raise NotImplementedError

    async def poll(self, mode: str = "incremental") -> list[dict[str, Any]]:
        """带指标埋点的包装。异常记录到 watermark 后抛出，由 supervisor 处理。"""

        try:
            items = await self.fetch(mode)
        except Exception as exc:  # noqa: BLE001
            self.save_watermark(None, 0, error=str(exc)[:500])
            collect_items.labels(source=self.name, stage="failed").inc()
            raise
        self.save_watermark(
            max((i.published_at for i in items if i.published_at), default=None),
            len(items),
            full_sync=(mode == "full"),
        )
        collect_items.labels(source=self.name, stage="fetched").inc(len(items))
        for item in items:
            if item.published_at:
                delay = (utcnow() - item.published_at).total_seconds()
                if delay >= 0:
                    collect_latency.labels(source=self.name).observe(delay)
        return [i.to_dict() for i in items]


def now_bj() -> dt.datetime:
    return dt.datetime.now(BEIJING_TZ)

"""安全社区 / 技术博客 RSS 采集器。"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

from aiintel.services.collectors.base import BaseCollector, RawItemData, parse_datetime
from aiintel.services.collectors.nvd import AI_KEYWORDS
from aiintel.services.ingest.text import extract_main_text

logger = logging.getLogger(__name__)

# 均为公开 RSS，遵守站点 robots 与速率限制
FEEDS = (
    ("https://www.freebuf.com/feed", "FreeBuf"),
    ("https://www.secrss.com/rss", "安全客"),
    ("https://github.blog/feed/", "GitHub Blog"),
)

# 中文站点的 AI 安全关键词：只靠英文 AI_KEYWORDS 会把 FreeBuf/安全客 的内容全部过滤掉
AI_KEYWORDS_ZH = (
    "大模型",
    "大语言模型",
    "人工智能",
    "生成式",
    "提示注入",
    "提示词",
    "越狱",
    "投毒",
    "智能体",
    "aiagent",
    "agent",
    "llm",
    "aigc",
    "模型安全",
    "rag",
    "深度学习",
    "机器学习",
    "神经网络",
)


class CommunityRssCollector(BaseCollector):
    name = "community_rss"
    priority = 40
    rate_limit_per_min = 20

    def __init__(
        self, client: Any | None = None, feeds: tuple[tuple[str, str], ...] = FEEDS
    ) -> None:
        super().__init__(client)
        self.feeds = feeds

    async def fetch(self, mode: str = "incremental") -> list[RawItemData]:
        since = None if mode == "full" else self.watermark()
        items: list[RawItemData] = []
        for url, site in self.feeds:
            try:
                entries = await self._fetch_feed(url)
            except Exception as exc:  # noqa: BLE001 - 单站失败不影响整体
                logger.warning("RSS %s 抓取失败: %s", site, exc)
                continue
            for entry in entries:
                published = parse_datetime(entry.get("published"))
                if mode == "incremental" and since and published and published <= since:
                    continue
                item = self._to_item(entry, site, url)
                if item is not None:
                    items.append(item)
        return items

    async def _fetch_feed(self, url: str) -> list[dict]:
        import feedparser

        raw = await self._get_text(url)
        feed = feedparser.parse(raw)
        return [dict(e) for e in feed.entries]

    @staticmethod
    def _to_item(entry: dict, site: str, feed_url: str) -> RawItemData | None:
        title = entry.get("title", "")
        summary = entry.get("summary", "")
        haystack = f"{title} {summary}".lower()
        keywords = AI_KEYWORDS + AI_KEYWORDS_ZH
        if not any(k in haystack for k in keywords):
            return None
        link = entry.get("link", "")
        return RawItemData(
            source="community_rss",
            external_id=entry.get("id") or link,
            title=title,
            url=urljoin(feed_url, link) if link else None,
            content_text=_strip_html(summary),
            published_at=parse_datetime(entry.get("published") or entry.get("updated")),
            raw={"site": site, "author": entry.get("author", "")},
        )


def _strip_html(text: str) -> str:
    from bs4 import BeautifulSoup

    return BeautifulSoup(text or "", "html.parser").get_text(" ", strip=True)[:20000]


async def fetch_article_text(url: str) -> str:
    """抓取博客正文（富化与知识库入库用）。"""

    collector = CommunityRssCollector()
    try:
        html = await collector._get_text(url)
        return extract_main_text(html)[:20000]
    finally:
        await collector.aclose()

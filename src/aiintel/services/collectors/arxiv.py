"""arXiv 论文采集器：AI 安全方向的学术动态，支撑"论文关联"富化与知识底座。"""

from __future__ import annotations

import logging
from urllib.parse import quote

from aiintel.services.collectors.base import BaseCollector, RawItemData, parse_datetime
from aiintel.services.ingest.text import extract_main_text

logger = logging.getLogger(__name__)

API = "https://export.arxiv.org/api/query"
KEYWORDS = (
    'all:"prompt injection"',
    'all:"AI agent" AND all:"security"',
    'all:"LLM" AND all:"vulnerability"',
    'all:"large language model" AND all:"red teaming"',
    'all:"AI supply chain"',
)


class ArxivCollector(BaseCollector):
    name = "arxiv"
    priority = 30
    rate_limit_per_min = 10

    async def fetch(self, mode: str = "incremental") -> list[RawItemData]:
        since = None if mode == "full" else self.watermark()
        query = " OR ".join(KEYWORDS)
        url = (
            f"{API}?search_query={quote(query)}&sortBy=submittedDate&sortOrder=descending"
            "&start=0&max_results=200"
        )
        payload = await self._get_text(url)
        entries = _parse_atom(payload)
        items: list[RawItemData] = []
        for entry in entries:
            published = parse_datetime(entry.get("published"))
            if mode == "incremental" and since and published and published <= since:
                continue
            items.append(self._to_item(entry))
        return items

    @staticmethod
    def _to_item(entry: dict) -> RawItemData:
        summary = entry.get("summary", "")
        url = entry.get("id", "")
        return RawItemData(
            source="arxiv",
            # external_id 只放 arXiv 编号（如 2401.00001）：它会进 chunk_key 与关系边表，
            # 放整条 URL 会把分隔符语义搞乱
            external_id=_arxiv_id(url),
            title=_clean(entry.get("title", "")),
            url=url,
            content_text=_clean(summary),
            published_at=parse_datetime(entry.get("published")),
            raw={
                "authors": entry.get("authors", [])[:10],
                "categories": entry.get("categories", ""),
                "abs_url": url,
            },
        )


def _arxiv_id(url: str) -> str:
    """从 http://arxiv.org/abs/2401.00001v2 提取 2401.00001。"""

    tail = (url or "").rstrip("/").rsplit("/", 1)[-1]
    return tail.split("v")[0] if tail[:1].isdigit() else tail or (url or "")


def _clean(text: str) -> str:
    return " ".join(text.split())


def _parse_atom(xml_text: str) -> list[dict]:
    import re

    def tag(block: str, name: str) -> str:
        match = re.search(rf"<{name}>(.*?)</{name}>", block, re.S)
        return _clean(match.group(1)) if match else ""

    entries: list[dict] = []
    for block in re.findall(r"<entry>(.*?)</entry>", xml_text, re.S):
        entries.append(
            {
                "id": tag(block, "id"),
                "title": tag(block, "title"),
                "summary": tag(block, "summary"),
                "published": tag(block, "published"),
                "updated": tag(block, "updated"),
                "categories": " ".join(re.findall(r'term="([^"]+)"', block)),
                "authors": [_clean(a) for a in re.findall(r"<name>(.*?)</name>", block, re.S)],
            }
        )
    return entries


async def fetch_paper_abstract(url: str) -> str:
    """按 URL 补全论文正文/摘要（论文关联富化用）。"""

    collector = ArxivCollector()
    try:
        return extract_main_text(await collector._get_text(url))[:8000]
    finally:
        await collector.aclose()

"""NVD CVE API 采集器（CVE 5.1）。

按 AI 安全关键词过滤：ollama / vllm / triton / langchain / llm / ai agent 等。
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import urllib.parse
from typing import Any

from aiintel.services.collectors.base import BaseCollector, RawItemData, parse_datetime

logger = logging.getLogger(__name__)

AI_KEYWORDS = (
    "ollama",
    "vllm",
    "triton",
    "langchain",
    "llamaindex",
    "llama",
    "large language model",
    "llm",
    "ai agent",
    "ai-agent",
    "agentic",
    "rag",
    "embedding model",
    "huggingface",
    "openai",
    "pytorch",
    "tensorflow",
)

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# NVD 单次时间窗上限 120 天
MAX_WINDOW = dt.timedelta(days=119)
# 单轮最多取多少条，防止全量模式把 token/时间打爆（成本治理）
MAX_RESULTS = 20_000


def _nvd_datetime(value: dt.datetime) -> str:
    """NVD 参数日期必须用 ISO8601（URL 编码 +00:00）。

    本环境实测：`lastModStartDate` 用 epoch 毫秒会被 NVD 边缘以 HTTP 404（空
    响应）拒绝；同一窗口换成 `%2B00:00` ISO 形式则正常返回。不要回到 ms 格式。
    """
    return value.isoformat(timespec="milliseconds").replace("+00:00", "%2B00:00")


class NvdCollector(BaseCollector):
    name = "nvd"
    priority = 10
    # 匿名限速实测约 5 req/30s（再快会 429）；留边际余量取 8/min
    rate_limit_per_min = 8

    def _page_url(self, keyword: str, since: dt.datetime | None, start_index: int) -> str:
        """keywordSearch 服务端精筛 + lastMod 时间窗。

        keywordSearch：NVD 直接按关键词过滤（实测 ollama→41、llm→319 条），
        免去"119 天全窗 38 万条逐页客户端过滤"（实测 0 命中且要约 30 分钟）。
        每个关键词单独发请求（NVD 多词并集语义不可靠，实测并集返回 0 条）。
        """
        now = dt.datetime.now(dt.UTC)
        start = since or (now - MAX_WINDOW)
        if now - start > MAX_WINDOW:
            logger.warning("NVD 时间窗超过 119 天，收窄为最近 119 天")
            start = now - MAX_WINDOW
        return (
            f"{API}?keywordSearch={urllib.parse.quote(keyword)}"
            f"&lastModStartDate={_nvd_datetime(start)}"
            f"&lastModEndDate={_nvd_datetime(now)}"
            f"&resultsPerPage={PAGE_SIZE}&startIndex={start_index}"
        )

    @staticmethod
    def _is_ai_related(vuln: dict) -> bool:
        cve = vuln.get("cve") or vuln  # NVD 列表元素是 {"cve": {...}} 包装层
        haystack = " ".join(
            [
                cve.get("id", ""),
                _english(cve.get("descriptions", [])),
                " ".join(cve.get("cwe", []) and [c["value"] for c in cve["cwe"]] or []),
            ]
        ).lower()
        return any(k in haystack for k in AI_KEYWORDS)

    async def fetch(self, mode: str = "incremental") -> list[RawItemData]:
        since = None if mode == "full" else self.watermark()
        logger.info("NVD 查询: mode=%s since=%s", mode, since)

        items: list[RawItemData] = []
        seen: set[str] = set()
        for keyword in AI_KEYWORDS:
            start_index = 0
            while True:
                # 每个请求前都按 rate_limit 限速（关键词之间、分页之间都要）
                await asyncio.sleep(60 / self.rate_limit_per_min)
                url = self._page_url(keyword, since, start_index)
                payload: dict[str, Any] = await self._get_json(url)
                vulns = payload.get("vulnerabilities") or []
                for cve in vulns:
                    if not self._is_ai_related(cve):
                        continue
                    item = self._to_item(cve)
                    if item.external_id in seen:
                        continue
                    seen.add(item.external_id)
                    items.append(item)
                    if len(items) >= MAX_RESULTS:
                        logger.info("NVD 命中达 MAX_RESULTS=%d，提前停止", MAX_RESULTS)
                        return items
                total = int(payload.get("totalResults") or 0)
                start_index += len(vulns)
                if not vulns or start_index >= total:
                    break
        logger.info("NVD 命中 AI 相关 %d 条", len(items))
        return items

    @staticmethod
    def _to_item(cve: dict) -> RawItemData:
        cna = cve.get("cve", {})
        description = _english(cna.get("descriptions", []))
        metrics = cna.get("metrics", {})
        cvss = _pick_cvss(metrics)
        return RawItemData(
            source="nvd",
            external_id=cna.get("id", ""),
            title=description[:200] or cna.get("id", ""),
            url=f"https://nvd.nist.gov/vuln/detail/{cna.get('id')}",
            content_text=description,
            published_at=parse_datetime(cna.get("published")),
            raw={
                "cvss_vector": cvss.get("vector"),
                "cvss_score": cvss.get("score"),
                "severity": cvss.get("severity"),
                "cwe": [
                    c["value"] for c in cna.get("weaknesses", []) for c in c.get("description", [])
                ],
                "cpe": _cpe_list(cna.get("configurations", [])),
                "references": [r.get("url") for r in cna.get("references", [])][:20],
                "modified_at": cna.get("lastModified"),
            },
        )


def _english(descriptions: list[dict]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _pick_cvss(metrics: dict) -> dict:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {})
        return {
            "vector": data.get("vectorString"),
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or primary.get("baseSeverity"),
        }
    return {}


def _cpe_list(configurations: list[dict]) -> list[str]:
    out: list[str] = []
    for conf in configurations:
        for node in conf.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable") and cpe.get("criteria"):
                    out.append(cpe["criteria"])
    return out[:50]

"""NVD CVE API 采集器（CVE 5.1）。

按 AI 安全关键词过滤：ollama / vllm / triton / langchain / llm / ai agent 等。
"""

from __future__ import annotations

import datetime as dt
import logging
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


class NvdCollector(BaseCollector):
    name = "nvd"
    priority = 10
    rate_limit_per_min = 10

    def _search_url(self, since: dt.datetime | None) -> str:
        """构造 lastMod 时间窗查询。

        注意：不能用 hasKev 兜底——KEV 只有约 1% 的漏洞，会漏掉绝大多数 AI 组件漏洞。
        漏采在这里不可接受，改为"最近 119 天全量 + 客户端 AI 关键词过滤"。
        """

        now = dt.datetime.now(dt.UTC)
        start = since or (now - MAX_WINDOW)
        if now - start > MAX_WINDOW:
            logger.warning("NVD 时间窗超过 119 天，收窄为最近 119 天")
            start = now - MAX_WINDOW
        return (
            f"{API}?lastModStartDate={int(start.timestamp() * 1000)}"
            f"&lastModEndDate={int(now.timestamp() * 1000)}"
            f"&resultsPerPage={PAGE_SIZE}"
        )

    @staticmethod
    def _is_ai_related(cve: dict) -> bool:
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
        base_url = self._search_url(since)
        logger.info("NVD 查询: mode=%s since=%s", mode, since)

        items: list[RawItemData] = []
        start_index = 0
        while True:
            payload: dict[str, Any] = await self._get_json(f"{base_url}&startIndex={start_index}")
            vulns = payload.get("vulnerabilities") or []
            items.extend(self._to_item(cve) for cve in vulns if self._is_ai_related(cve))
            total = int(payload.get("totalResults") or 0)
            start_index += len(vulns)
            if not vulns or start_index >= total or len(items) >= MAX_RESULTS:
                break
        logger.info("NVD 命中 AI 相关 %d 条（扫描 %d 条）", len(items), min(start_index, total))
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

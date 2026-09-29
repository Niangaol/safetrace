"""GitHub Security Advisory (GHSA) 采集器 + 实时 webhook 接收。"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging
from typing import Any

from aiintel.config import get_settings
from aiintel.services.collectors.base import BaseCollector, RawItemData, parse_datetime, utcnow
from aiintel.services.collectors.nvd import AI_KEYWORDS

logger = logging.getLogger(__name__)

API = "https://api.github.com/graphql"
WEBHOOK_SECRET_HEADER = "X-Hub-Signature-256"


class GhsaCollector(BaseCollector):
    """GitHub GraphQL 查询 security advisories。

    注意：GraphQL 端点必须鉴权（无 token 一律 401），token 缺失时直接抛错，
    由上层按"单源失败不阻断"降级处理。
    """

    name = "ghsa"
    priority = 20
    rate_limit_per_min = 30

    QUERY = """
    query($cursor: String) {
      securityAdvisories(first: 100, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
        pageInfo { hasNextPage endCursor }
        nodes {
          ghsaId cveId summary severity publishedAt updatedAt
          description
          references { url }
          vulnerabilities(first: 5) { nodes { package { name ecosystem } } }
        }
      }
    }
    """

    def __init__(self, client: Any | None = None, token: str | None = None) -> None:
        super().__init__(client)
        self.token = token if token is not None else get_settings().github_token

    async def fetch(self, mode: str = "incremental") -> list[RawItemData]:
        if not self.token:
            raise RuntimeError("未配置 GITHUB_TOKEN：GitHub GraphQL 需要鉴权，GHSA 源已跳过")
        headers = {
            "Authorization": f"bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        since = None if mode == "full" else self.watermark()
        cursor: str | None = None
        items: list[RawItemData] = []
        for _ in range(10):  # 最多翻 10 页
            resp = await self._client.post(
                API,
                json={"query": self.QUERY, "variables": {"cursor": cursor}},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("securityAdvisories", {})
            for node in data.get("nodes", []):
                item = self._to_item(node)
                if item is None:
                    continue
                if since and item.published_at and item.published_at <= since:
                    logger.info("到达增量水位线，停止翻页")
                    return items
                items.append(item)
            page = data.get("pageInfo", {})
            if not page.get("hasNextPage"):
                break
            cursor = page.get("endCursor")
        return items

    @staticmethod
    def _to_item(node: dict) -> RawItemData | None:
        text = " ".join(
            filter(None, [node.get("summary", ""), node.get("description") or ""])
        ).lower()
        if not any(k in text for k in AI_KEYWORDS):
            return None
        ghsa_id = node.get("ghsaId", "")
        return RawItemData(
            source="ghsa",
            external_id=ghsa_id,
            title=node.get("summary", ""),
            url=f"https://github.com/advisories/{ghsa_id}",
            content_text=node.get("description") or node.get("summary", ""),
            published_at=parse_datetime(node.get("publishedAt")),
            raw={
                "cve_id": _clean_cve(node.get("cveId")),
                "severity": (node.get("severity") or "").lower(),
                "references": [r.get("url") for r in node.get("references", [])][:20],
                "packages": [
                    f"{v['package']['ecosystem']}:{v['package']['name']}"
                    for v in node.get("vulnerabilities", {}).get("nodes", [])
                ],
                "updated_at": node.get("updatedAt"),
            },
        )


def _clean_cve(identifier: str | None) -> str | None:
    return identifier if (identifier or "").startswith("CVE-") else None


def _cve_from_identifier(identifier: str) -> str | None:
    return _clean_cve(identifier)


def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """校验 GitHub webhook 签名，防止伪造事件注入情报。"""

    if not signature.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature[7:])


def parse_webhook_event(event: str, payload: dict) -> list[RawItemData]:
    """把 webhook 事件转成 RawItem 列表；security_advisory 为主要来源。"""

    if event == "security_advisory":
        node = payload.get("security_advisory", {})
        ghsa_id = node.get("ghsa_id", "")
        return [
            RawItemData(
                source="ghsa",
                external_id=ghsa_id,
                title=node.get("summary", ""),
                url=node.get("html_url"),
                content_text=node.get("description", ""),
                published_at=parse_datetime(node.get("published_at")),
                raw={
                    "cve_id": node.get("cve_id"),
                    "severity": (node.get("severity") or "").lower(),
                },
            )
        ]
    return []


def webhook_received_at() -> dt.datetime:
    return utcnow()

"""CISA KEV 官方目录采集器（已知在野利用漏洞）。

为什么必须单独接这个源，而不是继续从 NVD 的二次加工字段里刨 `kev`
（见 `collectors/nvd.py` 的 `_search_url` 警告）：

1. **覆盖**：NVD 侧 `cisaExploitAdd` 只在部分条目上出现，无法当作"是否在野利用"
   的权威判据。KEV 官方 JSON 是唯一权威来源。
2. **新鲜度**：KEV 每日更新，NVD 侧的镜像字段滞后数天。
3. **白送 `dueDate`**：CISA 对每个 KEV 条目给出联邦机构的强制修复截止日。
   这是"先修哪个"最硬的依据——比 CVSS 分、比 EPSS 概率都硬，因为它是期限而非估计。

本采集器只读公开 JSON 目录，不发送任何探测流量，符合"不做漏洞动态验证"的合规红线。
"""

from __future__ import annotations

import logging
from typing import Any

from aiintel.services.collectors.base import BaseCollector, RawItemData, parse_datetime

logger = logging.getLogger(__name__)

# CISA 公开的 KEV 目录（静态 JSON，无鉴权、无配额）
FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# 目录里的 ransomware 字段有三种取值：Known / Unknown / 留空
RANSOMWARE_KNOWN = "known"


class KevCollector(BaseCollector):
    name = "kev"
    priority = 5
    rate_limit_per_min = 5

    async def fetch(self, mode: str = "incremental") -> list[RawItemData]:
        # KEV 是全量快照（每次都是完整目录），没有"增量"语义。
        # mode 参数保留是为了满足 BaseCollector 接口；水位的 last_published_at
        # 仍然有意义（它反映本仓最后一次见到该 CVE 被加入 KEV 的时间）。
        since = None if mode == "full" else self.watermark()

        payload: dict[str, Any] = await self._get_json(FEED)
        catalog_version = payload.get("catalogVersion", "")
        entries = payload.get("vulnerabilities") or []
        logger.info(
            "KEV 目录 %s 共 %s 条（声明 count=%s）",
            catalog_version,
            len(entries),
            payload.get("count"),
        )

        items: list[RawItemData] = []
        for entry in entries:
            item = self._to_item(entry, catalog_version)
            if item is None:
                continue
            # 增量模式只取"新入 KEV"的条目。全量目录每次都返回，
            # 不做水位过滤会让 NVD 那边 1728 条重复进管道。
            if since and item.published_at and item.published_at <= since:
                continue
            items.append(item)
        return items

    @staticmethod
    def _to_item(entry: dict[str, Any], catalog_version: str) -> RawItemData | None:
        cve_id = str(entry.get("cveID") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            return None

        name = str(entry.get("vulnerabilityName") or "").strip()
        vendor = str(entry.get("vendorProject") or "").strip()
        product = str(entry.get("product") or "").strip()
        description = str(entry.get("shortDescription") or "").strip()
        required_action = str(entry.get("requiredAction") or "").strip()
        notes = str(entry.get("notes") or "").strip()

        # 正文拼成一段可检索文本：进 F3/F5 与知识库时，requiredAction 往往是
        # 唯一含"具体怎么做"的信息，不能丢。
        body_parts = [p for p in (name, description, required_action, notes) if p]
        content_text = "\n".join(body_parts)[:20000]

        # external_id 用 cveID，这样 KEV 与 NVD/GHSA 对同一 CVE 归一到同一条 Vuln
        return RawItemData(
            source="kev",
            external_id=cve_id,
            title=name or cve_id,
            url=(
                f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else None
            ),
            content_text=content_text,
            published_at=parse_datetime(entry.get("dateAdded")),
            raw={
                "cve_id": cve_id,
                "vendor_project": vendor,
                "product": product,
                "kev_due_date": entry.get("dueDate") or None,
                "kev_date_added": entry.get("dateAdded") or None,
                "kev_required_action": required_action or None,
                "kev_notes": notes or None,
                "kev_ransomware": _ransomware(entry),
                "kev_forensic_triage": entry.get("forensicTriage") or None,
                "kev_cwes": _cwes(entry),
                "kev_catalog_version": catalog_version or None,
            },
        )


def _ransomware(entry: dict[str, Any]) -> str | None:
    """CISA 用 Known / Unknown 两种取值；只在确认为 Known 时返回 'known'，否则 None。"""

    value = str(entry.get("knownRansomwareCampaignUse") or "").strip().lower()
    return RANSOMWARE_KNOWN if value == RANSOMWARE_KNOWN else None


def _cwes(entry: dict[str, Any]) -> list[str]:
    raw = entry.get("cwes")
    if not isinstance(raw, list):
        return []
    return [str(c).strip() for c in raw if str(c).strip()][:20]

"""F2 受影响资产（`asset`）：CPE/版本区间解析为**真跑**，组织资产画像为 **Mock**。

合规红线（计划原文：F2 初版 Mock，决赛再真跑）：

- **不主动扫描、不探测、不爆破**。`ASSET_SCAN_ENABLED` 默认 `false`；
- 资产清单只能来自"用户导入的清单文件"（`ASSET_INVENTORY_PATH`），没有文件就 `exposed_assets=[]`；
- 任何来自预置数据的结果都带 `mock=true` 与 `degraded_to="mock"`，前端显示「预置数据」徽标。

真跑的部分：CPE 解析、厂商/产品归一、版本区间判定 —— 这些完全确定性，可单测。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from aiintel.config import get_settings
from aiintel.services.enrich.evidence import EvidenceBuilder, build_result

logger = logging.getLogger(__name__)

_WILDCARD = {"*", "-", ""}


def parse_cpe(cpe: str) -> dict[str, Any]:
    """解析 CPE 2.3（`cpe:2.3:a:vendor:product:version:...`）与 2.2 URI 形态。"""

    text = (cpe or "").strip()
    if not text.startswith("cpe:"):
        return {}
    parts = text.split(":")
    if len(parts) >= 6 and parts[1] == "2.3":
        vendor, product, version = parts[3], parts[4], parts[5]
    elif len(parts) >= 5:  # cpe:/a:vendor:product:version
        vendor, product, version = parts[2], parts[3], parts[4]
    else:
        return {}

    def clean(value: str) -> str | None:
        return None if value in _WILDCARD else value

    return {
        "vendor": clean(vendor),
        "product": clean(product),
        "version": clean(version),
        "raw": text,
    }


def parse_version_range(entry: dict[str, Any]) -> dict[str, Any]:
    """把 `{introduced, fixed}` 转成人类可读区间字符串（缺失则说明缺失）。"""

    introduced = entry.get("introduced")
    fixed = entry.get("fixed")
    if introduced and fixed:
        affected = f">={introduced},<{fixed}"
    elif fixed:
        affected = f"<{fixed}"
    elif introduced:
        affected = f">={introduced}"
    else:
        affected = "unknown"
    return {
        "product": entry.get("product"),
        "vendor": entry.get("vendor"),
        "affected_versions": affected,
        "introduced": introduced,
        "fixed": fixed,
        "range_source": entry.get("source") or ("nvd" if introduced or fixed else "unknown"),
        "url": entry.get("url"),
    }


def load_inventory(path: str) -> list[dict[str, Any]]:
    """读取资产清单（用户导入）。文件不存在或非法都返回空列表，不抛异常。"""

    if not path:
        return []
    file = Path(path)
    if not file.exists():
        return []
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("资产清单读取失败 %s: %s", path, exc)
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        assets = payload.get("assets")
        return (
            [item for item in assets if isinstance(item, dict)] if isinstance(assets, list) else []
        )
    return []


def _match_inventory(
    products: list[dict[str, Any]], inventory: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """把清单条目与受影响产品做名称匹配（确定性，不做指纹识别）。"""

    wanted: set[str] = set()
    for product in products:
        for key in ("product", "vendor"):
            value = (product.get(key) or "").lower()
            if value:
                wanted.add(value)

    hits: list[dict[str, Any]] = []
    for asset in inventory:
        haystack = " ".join(
            str(asset.get(k) or "") for k in ("product", "vendor", "name", "cpe")
        ).lower()
        for needle in wanted:
            if needle and needle in haystack:
                hits.append(
                    {
                        "name": asset.get("name") or asset.get("host") or "未命名资产",
                        "product": asset.get("product"),
                        "version": asset.get("version"),
                        "exposure": asset.get("exposure") or "unknown",
                        "matched_by": needle,
                    }
                )
                break
    return hits


async def asset_impact(vuln: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    """F2 入口。"""

    settings = get_settings()
    evidence = EvidenceBuilder()
    products: list[dict[str, Any]] = []

    # CPE 解析（真跑）
    for cpe in vuln.get("cpe") or []:
        parsed = parse_cpe(str(cpe))
        if not parsed:
            continue
        product = {
            "vendor": parsed["vendor"],
            "product": parsed["product"],
            "cpe": parsed["raw"],
            "affected_versions": (f"={parsed['version']}" if parsed["version"] else "unknown"),
            "range_source": "nvd",
            "url": None,
        }
        products.append(product)

    # 版本区间（Y 线提供则用，精确；否则标注 unknown）
    ranges = list(vuln.get("version_ranges") or [])
    for entry in ranges:
        normalized = parse_version_range(entry)
        if normalized["product"]:
            products.append({**normalized, "cpe": None})

    # 没有 CPE 也没有区间时，退化为 affected_products 文本匹配
    degraded_to: str | None = None
    degraded_reason = ""
    if not products:
        for name in vuln.get("affected_products") or []:
            products.append(
                {
                    "vendor": None,
                    "product": str(name),
                    "cpe": None,
                    "affected_versions": "unknown",
                    "range_source": "unknown",
                    "url": None,
                }
            )
        if products:
            degraded_to = "rule"
            degraded_reason = "缺少 CPE 与版本区间，仅按受影响产品名做文本匹配"

    for product in products[:5]:
        # CPE 解析是本地确定性变换 → 证据来源标 rule；只有带 URL 的才是外部来源，
        # 否则会出现"来源写着 nvd 但没有可点的 URL"这种不可核对的证据。
        if product.get("url"):
            source = "nvd" if product.get("cpe") else str(product.get("range_source") or "vendor")
        else:
            source = "rule"
        evidence.add(
            source,
            product.get("url"),
            f"{product.get('vendor') or '-'}:{product.get('product') or '-'} 受影响版本 {product['affected_versions']}",
        )

    if ranges and (vuln.get("sources") or []):
        for entry in vuln.get("sources") or []:
            if entry.get("url"):
                evidence.add(
                    str(entry.get("source") or "vendor"), entry["url"], "受影响版本区间来源"
                )

    # 组织资产画像（Mock / 或用户导入清单）
    inventory = load_inventory(settings.asset_inventory_path)
    exposed = _match_inventory(products, inventory) if settings.asset_scan_enabled else []
    mock = bool(exposed) or (settings.asset_scan_enabled is False)

    if exposed:
        assets_source = "mock" if not settings.asset_scan_enabled else "inventory"
        evidence.add(
            assets_source,
            None,
            f"资产清单匹配 {len(exposed)} 条（清单来源：{settings.asset_inventory_path}）",
        )

    if not settings.asset_scan_enabled and degraded_to is None:
        degraded_to = "mock"
        degraded_reason = "主动资产测绘默认关闭（合规红线），资产暴露面为空；如需匹配请开启 ASSET_SCAN_ENABLED 并导入清单"

    exposure_level = "unknown"
    if exposed:
        levels = {str(item.get("exposure") or "unknown") for item in exposed}
        exposure_level = "high" if "high" in levels else ("medium" if "medium" in levels else "low")
    elif settings.asset_scan_enabled and not inventory:
        exposure_level = "none"

    value = {
        "products": products[:10],
        "exposed_assets": exposed[:20],
        "exposure_level": exposure_level,
        "inventory_loaded": bool(inventory),
        "asset_scan_enabled": settings.asset_scan_enabled,
        "mock": mock,
    }

    if not products and not exposed:
        evidence.add("rule", None, "未取得 CPE、版本区间与受影响产品，资产维度无可用结论")

    confidence = 0.55 if ranges else (0.4 if products else 0.2)
    if degraded_to:
        confidence = min(confidence, 0.6)

    return build_result(
        "asset",
        value,
        evidence,
        confidence,
        source=["nvd", "rule"] if products else ["rule"],
        model="rule-based",
        trace_id=trace_id,
        mock=mock,
        degraded_to=degraded_to,
        degraded_reason=degraded_reason,
        note="资产画像为预置/导入数据，非主动测绘" if mock else "",
    )

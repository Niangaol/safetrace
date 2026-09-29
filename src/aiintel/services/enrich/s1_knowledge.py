"""S1 · 知识底座客户端桩（F 线出库的**唯一**通道）。

计划红线：F 线**不直接写向量库**（本项目向量库是 PostgreSQL+pgvector，计划里写的是 Qdrant），
出库语义统一走 S1 客户端。默认桩模式（`S1_STUB_MODE=true`）只做契约校验与事件广播，
不触库——这样 F 线可以在没有 PostgreSQL 的机器上完整自测。

置 `S1_STUB_MODE=false` 时按 `services/knowledge/indexer.py` 真实落库（结构化 + 富化 + 向量 + 边表）。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from aiintel.config import get_settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class S1Result:
    """出库结果。stub=True 表示只做了契约校验，没写任何存储。"""

    vuln_id: str
    stored: bool = False
    stub: bool = True
    dimensions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def s1_stub_mode() -> bool:
    return get_settings().s1_stub_mode


async def store_enrichment(vuln: dict[str, Any], enrichments: list[dict[str, Any]]) -> S1Result:
    """把一次富化结果交给 S1。**永不抛异常**，问题进 `errors` 列表。

    这里不做任何"编造成功"的事：桩模式明确返回 `stored=False, stub=True`。
    """

    vuln_id = str(vuln.get("id") or vuln.get("vuln_id") or "")
    dims = [str(e.get("dimension")) for e in enrichments if e.get("dimension")]

    if s1_stub_mode():
        logger.info("S1 桩模式：跳过落库 vuln=%s dimensions=%s", vuln_id, dims)
        return S1Result(vuln_id=vuln_id, stored=False, stub=True, dimensions=dims, errors=[])

    from aiintel.services.knowledge.indexer import persist_vuln

    try:
        await persist_vuln(vuln, enrichments)
    except Exception as exc:  # noqa: BLE001 - 落库失败不该炸掉富化链路
        logger.warning("S1 落库失败 vuln=%s: %s", vuln_id, exc)
        return S1Result(
            vuln_id=vuln_id, stored=False, stub=False, dimensions=dims, errors=[str(exc)[:200]]
        )
    return S1Result(vuln_id=vuln_id, stored=True, stub=False, dimensions=dims, errors=[])

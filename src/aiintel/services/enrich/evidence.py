"""证据链基础设施：F 线所有维度共用。

三条不变量（契约强制，见 `contracts/schemas/EnrichmentResult.json`）：

1. `evidence` 非空才能落库（`indexer._persist_enrichments` 强制）；
2. `degraded_to != null` 时 `confidence <= 0.6` 且 `degraded_reason` 非空；
3. `source` 非空 —— 赛题硬要求"每条富化带 source"。

`build_result()` 是唯一的结果构造出口，维度实现禁止自己拼 dict。
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from aiintel.services.collectors.base import utcnow

MAX_SNIPPET = 600

# 证据来源白名单：出现新来源要同步 contracts/schemas/EnrichmentResult.json 的 source 描述
KNOWN_SOURCES = frozenset(
    {
        "arxiv",
        "openalex",
        "nvd",
        "ghsa",
        "osv",
        "vendor",
        "github",
        "nuclei",
        "exploitdb",
        "community_rss",
        "computed",
        "rule",
        "mock",
        "cache",
    }
)

# 降级层级（FB1）：非 null 即视为"降级产物"，必须对用户可见
DEGRADED_VALUES = ("cache", "fixture", "rule", "mock", "local")


@dataclass(slots=True)
class EvidenceBuilder:
    """按维度累积证据，自动分配 ev-1 / ev-2 … 编号。"""

    items: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self,
        source: str,
        url: str | None,
        snippet: str,
        *,
        raw_item_id: str | None = None,
        fetched_at: str | None = None,
        evidence_id: str | None = None,
    ) -> str:
        """追加一条证据，返回其 `evidence_id`（供 value 里的 evidence_ref 回指）。

        同一 URL 只保留一条：否则"多个 claim 指向同一公告"会让证据链出现重复噪声。
        """

        if url:
            for existing in self.items:
                if existing.get("url") == url:
                    return str(existing["evidence_id"])

        eid = evidence_id or f"ev-{len(self.items) + 1}"
        self.items.append(
            {
                "evidence_id": eid,
                "source": source,
                "url": url,
                "snippet": (snippet or "")[:MAX_SNIPPET],
                "fetched_at": fetched_at or utcnow().isoformat(),
                "raw_item_id": raw_item_id,
            }
        )
        return eid

    def add_many(
        self, source: str, refs: list[dict[str, Any]], *, snippet_key: str = "title"
    ) -> list[str]:
        """批量追加（如 IntelItem.references / sources）。返回编号列表。"""

        ids: list[str] = []
        for ref in refs or []:
            url = ref.get("url")
            if not url:
                continue
            ids.append(
                self.add(
                    ref.get("source") or source,
                    url,
                    str(ref.get(snippet_key) or ref.get("kind") or url),
                    raw_item_id=ref.get("raw_item_id"),
                    fetched_at=ref.get("fetched_at"),
                )
            )
        return ids

    @property
    def sources(self) -> list[str]:
        """证据里出现的来源（去重、保持出现顺序）。"""

        seen: list[str] = []
        for item in self.items:
            src = item.get("source")
            if src and src not in seen:
                seen.append(src)
        return seen

    def __bool__(self) -> bool:
        return bool(self.items)

    def __len__(self) -> int:
        return len(self.items)


def build_result(
    dimension: str,
    value: dict[str, Any],
    evidence: EvidenceBuilder | list[dict[str, Any]],
    confidence: float,
    *,
    source: list[str] | None = None,
    model: str = "rule-based",
    agent: str = "EnrichAgent",
    version: int = 1,
    trace_id: str | None = None,
    mock: bool = False,
    degraded_to: str | None = None,
    degraded_reason: str = "",
    quality_score: float | None = None,
    note: str = "",
) -> dict[str, Any]:
    """构造 EnrichmentResult（唯一出口，内部强制三条不变量）。"""

    ev = evidence.items if isinstance(evidence, EvidenceBuilder) else list(evidence or [])
    srcs = (
        list(source)
        if source
        else (evidence.sources if isinstance(evidence, EvidenceBuilder) else [])
    )

    if degraded_to is not None:
        if degraded_to not in DEGRADED_VALUES:
            raise ValueError(f"degraded_to 取值非法: {degraded_to!r}，允许 {DEGRADED_VALUES}")
        # 不变量 2：降级结论不许包装成高置信
        confidence = min(float(confidence), 0.6)
        if not degraded_reason:
            raise ValueError(
                f"dimension={dimension} 标记了 degraded_to={degraded_to} 但没写 degraded_reason"
            )
        # 统一降级出口（FB1）：权威三件套由 `core/degrade.py` 产出，这里只挂上去。
        # 内部细名保留在 `degraded_to`，权威枚举在 `degradation.degraded_to`。
        # 惰性导入：`core.degrade` 依赖 `core.contracts`，模块级导入会和本模块成环。
        from aiintel.core.degrade import degrade

        marker = degrade(degraded_to, detail=degraded_reason, trace_id=trace_id)
        degradation = marker.to_contract()
        degradation["degraded_detail"] = degraded_to
    else:
        marker = None
        degradation = None

    # 不变量 3：source 非空
    if not srcs:
        srcs = ["rule"]
    unknown = [s for s in srcs if s not in KNOWN_SOURCES]
    if unknown:
        # 不阻断（真实世界会出现新来源），但要留痕便于补白名单
        note = f"{note} | 未登记来源: {','.join(unknown)}".strip(" |")

    return {
        "dimension": dimension,
        "value": value,
        "source": srcs,
        "evidence": ev,
        "confidence": round(float(confidence), 3),
        "model": model,
        "agent": agent,
        "version": version,
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "trace_id": trace_id,
        "mock": bool(mock),
        "degraded_to": degraded_to,
        "degraded_reason": degraded_reason,
        "degradation": degradation,
        "quality_score": quality_score,
        "note": note,
    }


def check_invariants(result: dict[str, Any]) -> list[str]:
    """返回违反不变量的描述列表；空列表 = 通过。测试与 verify 节点都用它。"""

    problems: list[str] = []
    dim = result.get("dimension", "?")
    if not result.get("evidence"):
        problems.append(f"{dim}: evidence 为空（不变量 1）")
    if not result.get("source"):
        problems.append(f"{dim}: source 为空（不变量 3）")
    if result.get("degraded_to") is not None:
        if float(result.get("confidence") or 0) > 0.6:
            problems.append(
                f"{dim}: degraded_to={result['degraded_to']} 但 confidence>0.6（不变量 2）"
            )
        if not result.get("degraded_reason"):
            problems.append(f"{dim}: degraded_to 非空但 degraded_reason 为空（不变量 2）")
    return problems

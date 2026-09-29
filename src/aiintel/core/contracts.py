"""契约投影层：内部富对象 → SafeTrace 冻结契约。

**为什么需要这一层**：本仓的 `evidence.build_result()` 产出的是「胖」内部对象
（`value`/`evidence[]`/`model`/`agent`/`note` …），而 SafeTrace 的
`EnrichmentResult.json` 是 `additionalProperties: false` 的「瘦」交接口，
且 `artifacts` 只允许 `papers` 与 `score_assessment` 两类明细。
直接改 `build_result()` 去迎合瘦契约会丢掉证据链，因此这里做**单向投影**：

- `build_result()` 保持不变，继续强制三条内部不变量（证据非空 / 降级压置信 / source 非空）；
- `to_dimension_evidence()` 投影到本仓扩展契约 `DimensionEvidence.json`（承载 7 维明细）；
- `to_enrichment_result()` 投影到权威契约 `EnrichmentResult.json`（跨线交接口）。

权威契约映射（`docs/契约对齐-SafeTrace.md` §5）：
`fix → remediation`、`consistency → triage`；`ai_risk` 是赛题九 AI 安全专项第 7 维，
因权威契约 `additionalProperties: false` 不可入内，只走扩展契约。
"""

from __future__ import annotations

import datetime as dt
from typing import Any

SCHEMA_VERSION = "1.0"

# 内部维度 → 权威契约维度主键
DIMENSION_TO_CONTRACT: dict[str, str] = {
    "paper": "paper",
    "asset": "asset",
    "poc": "poc",
    "cvss": "cvss",
    "fix": "remediation",
    "consistency": "triage",
    "ai_risk": "ai_risk",
}

CONTRACT_TO_DIMENSION: dict[str, str] = {v: k for k, v in DIMENSION_TO_CONTRACT.items()}

#: 权威 `EnrichmentResult.dimensions_*` 允许的 6 值
CONTRACT_DIMENSIONS: frozenset[str] = frozenset(
    {"paper", "asset", "poc", "cvss", "remediation", "triage"}
)

#: 仅扩展契约 `DimensionEvidence` 承载的维度
EXTENSION_DIMENSIONS: frozenset[str] = frozenset(DIMENSION_TO_CONTRACT) - CONTRACT_DIMENSIONS

#: 内部 `degraded_to` → 权威 6 值枚举（events.md §降级标记）
#: 权威枚举无 `rule`（确定性规则通道），映射为语义最近的 `template`；原始细名保留在
#: `DimensionEvidence.degraded_detail`，不丢精度。
DEGRADE_TO_CONTRACT: dict[str, str] = {
    "cache": "cache",
    "fixture": "fixture",
    "mock": "fixture",
    "rule": "template",
    "local": "provider_switch",
    "memory_index": "memory_index",
    "source_switch": "source_switch",
    "provider_switch": "provider_switch",
}

#: 权威 `source_of_score` 六枚举
SCORE_SOURCE_MAP: dict[str, str] = {
    "nvd": "nvd",
    "cna": "cna",
    "ghsa": "ghsa",
    "adp": "adp",
    "computed": "system_derived",
    "system_derived": "system_derived",
}

DEGRADE_LABELS: dict[str, str] = {
    "cache": "已切换到缓存结果",
    "fixture": "当前展示为预置样本数据，非实时采集",
    "mock": "当前展示为预置样本数据，非实时采集",
    "rule": "已降级为规则匹配，语义理解能力受限",
    "local": "云端模型不可用，已切换到本地模型",
    "memory_index": "向量检索不可用，已降级为内存索引",
    "source_switch": "主采集源不可用，已切换备用源",
    "provider_switch": "云端模型不可用，已切换到本地模型",
}

RECOVERY_HINTS: dict[str, str] = {
    "cache": "等待上游恢复后重试以获得最新结果",
    "fixture": "接入实时采集源后重跑富化可消除预置数据",
    "mock": "接入实时采集源后重跑富化可消除预置数据",
    "rule": "配置 DEEPSEEK_API_KEY 后重跑富化可恢复语义能力",
    "local": "配置 DEEPSEEK_API_KEY 后重跑富化可恢复云端能力",
    "memory_index": "启动向量服务后重试",
    "source_switch": "主采集源恢复后自动切回",
    "provider_switch": "云端模型恢复后自动切回",
}

COMPUTED_EVIDENCE_URN = "urn:aiintel:evidence:{eid}"

#: 内部采集源名 → 权威 `RawDoc.source_type` 11 枚举。
#: 关键词命中在 `source_type_of()` 里做，这里只登记已知源。
SOURCE_TYPE_MAP: dict[str, str] = {
    "nvd": "nvd_cve",
    "cve_org": "cve_org",
    "ghsa": "ghsa",
    "osv": "osv",
    "vendor": "vendor_advisory",
    "vendor_advisory": "vendor_advisory",
    "exploitdb": "poec_source",
    "nuclei": "poec_source",
    "poec": "poec_source",
    "kev": "kev",
    "cisa": "kev",
    "arxiv": "paper",
    "paper": "paper",
    "openalex": "paper",
    "policy": "standard_policy",
    "standard": "standard_policy",
    "community_rss": "security_community",
    "security_community": "security_community",
    "rss": "security_community",
    "blog": "security_blog",
    "security_blog": "security_blog",
}

#: 内部采集源名 → 权威 `RawDoc.content_type` 5 枚举
SOURCE_CONTENT_TYPE: dict[str, str] = {
    "nvd": "json",
    "ghsa": "json",
    "osv": "json",
    "kev": "json",
    "cisa": "json",
    "arxiv": "xml",
    "openalex": "json",
    "community_rss": "xml",
    "rss": "xml",
    "vendor": "html",
    "vendor_advisory": "html",
    "blog": "html",
    "security_blog": "html",
    "exploitdb": "html",
    "nuclei": "json",
    "policy": "html",
    "standard": "html",
}


def source_type_of(source: str) -> str:
    """内部源名 → 权威 `source_type`。未知源按采集形态兜底，绝不臆造枚举外的值。"""

    key = (source or "").strip().lower()
    if key in SOURCE_TYPE_MAP:
        return SOURCE_TYPE_MAP[key]
    if "advisor" in key or "vendor" in key:
        return "vendor_advisory"
    if "community" in key or "forum" in key:
        return "security_community"
    if "blog" in key:
        return "security_blog"
    if "paper" in key or "arxiv" in key or "scholar" in key:
        return "paper"
    # 兜底：社区渠道（枚举内最宽松的一档），不抛错也不越界
    return "security_community"


def content_type_of(source: str) -> str:
    """内部源名 → 权威 `content_type` 5 枚举。未知源按 API 形态兜底为 json。"""

    key = (source or "").strip().lower()
    if key in SOURCE_CONTENT_TYPE:
        return SOURCE_CONTENT_TYPE[key]
    if "rss" in key or "feed" in key:
        return "xml"
    if "blog" in key or "vendor" in key or "advisor" in key:
        return "html"
    return "json"


def source_ids_of(sources: Any) -> list[str]:
    """把内部 `sources` 归一到权威 `source_ids[]`（**字符串列表**）。

    内部存在两种形状，历史上它们被混填过（`AttributeError: 'str' object has no
    attribute 'get'` 就是这么来的），这里统一处理：

    - 字典列表（`vuln.sources` / `references`，带 url/source）：取 `source` 键；
    - 字符串列表（权威形状本身）：原样保留。

    保序去重，空值丢弃；结果为空时返回 `["unknown"]`（权威要求 `minItems: 1`）。
    """

    ids: list[str] = []
    if isinstance(sources, (list, tuple)):
        for entry in sources:
            value: Any = None
            if isinstance(entry, dict):
                value = entry.get("source") or entry.get("source_id")
            elif isinstance(entry, str):
                value = entry
            if not value:
                continue
            text = str(value).strip()
            if text and text not in ids:
                ids.append(text)
    elif isinstance(sources, str) and sources.strip():
        ids.append(sources.strip())
    return ids or ["unknown"]


#: 权威 `IntelItem.entities` → 内部富化视图的键映射
_ENTITY_MAP: tuple[tuple[str, str, bool], ...] = (
    # (权威键, 内部键, 是否 list)
    ("version_range", "version_ranges", True),
    ("cwe", "cwe", True),
    ("cpes", "cpe", True),
    ("product", "product", False),
    ("vendor", "vendor", False),
)


class ContractProjectionError(ValueError):
    """内部对象无法投影为权威契约时抛出。"""


def to_enrich_input(
    intel_item: dict[str, Any],
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """权威 `IntelItem` → 内部富化视图（F 线引擎的输入形状）。

    权威 `IntelItem` 是刻意精简的不可变对象（`additionalProperties: false`），
    **不带** `references` / `epss` / `kev` / `cvss_vector` / `severity` / `description`
    —— 这些细节由 `raw_refs` 指向的原始 payload 承载，对标 SafeTrace
    `f4-cvss.ts::loadScoreSourcesFromRawRefs`。

    因此本函数做两件事：
    1. 把 `entities` 五件套摊平成维度引擎习惯的顶层键；
    2. 把传入的 `raw`（由 `raw_refs` 回读得到的原始响应）合并进来。

    `raw` 缺失时**不编造**任何字段：对应维度会因此拿不到输入而显式降级，
    这正是契约想要的"缺证据即降级"，而不是把 None 当 0 用。

    本函数幂等：已是内部形状时原样返回（只做补全），因此 Y 线旧调用方无需改造。
    """

    if raw is None:
        merged: dict[str, Any] = dict(intel_item)
    else:
        merged = {**intel_item, **raw}

    # 已经是内部形状（vuln_id + description）就不再摊平 entities
    if "entities" in intel_item and "vuln_id" not in merged:
        merged["vuln_id"] = intel_item.get("intel_id", "")
        merged["id"] = merged["vuln_id"]
        cve_ids = intel_item.get("cve_ids") or []
        if cve_ids:
            merged.setdefault("cve_id", cve_ids[0])
        if not merged.get("description"):
            summary = intel_item.get("summary")
            merged["description"] = summary or intel_item.get("title") or ""
        if not merged.get("title"):
            merged["title"] = intel_item.get("title") or ""
        source_ids = intel_item.get("source_ids")
        if source_ids and not merged.get("source_ids"):
            merged["source_ids"] = list(source_ids)
        # 注意：权威 `source_ids` 是**源名字符串列表**，而内部 `sources` / `references`
        # 是**引用字典列表**（asset.py / consistency.py 读 `entry["url"]`、`entry["source"]`）。
        # 两者语义不同，不可直接互填；引用字典只能来自 `raw_refs` 回读。
        refs = merged.get("references")
        if not merged.get("sources") and isinstance(refs, list):
            merged["sources"] = list(refs)
        entities = intel_item.get("entities")
        if isinstance(entities, dict):
            for src_key, dst_key, is_list in _ENTITY_MAP:
                if dst_key in merged:
                    continue
                val = entities.get(src_key)
                if is_list:
                    merged[dst_key] = list(val or [])
                elif val is not None:
                    merged[dst_key] = val
            if entities.get("product") and not merged.get("affected_products"):
                merged["affected_products"] = [entities["product"]]
        if intel_item.get("published_at") and not merged.get("published_at"):
            merged["published_at"] = intel_item["published_at"]

    return merged


def to_intel_item(
    internal: dict[str, Any],
    *,
    intel_id: str | None = None,
) -> dict[str, Any]:
    """内部视图 → 权威 `IntelItem`（Y3 → F 线交接口）。"""

    cve_id = internal.get("cve_id") or ""
    resolved_id = intel_id or internal.get("intel_id")
    if not resolved_id:
        resolved_id = f"intel_{cve_id or internal.get('vuln_id') or 'unknown'}".replace("-", "_")

    cpes = internal.get("cpe")
    if isinstance(cpes, str):
        cpes = [cpes]
    version_ranges = internal.get("version_ranges")
    if isinstance(version_ranges, str):
        version_ranges = [version_ranges]
    # 权威 `entities.version_range` 是**字符串**区间（如 "<=0.6.1"），而内部
    # `version_ranges` 是**字典**（含 introduced/fixed/source/url）。投影时必须
    # 压成区间字符串，不能把字典塞进 string 数组。
    version_range_strs: list[str] = []
    for entry in version_ranges or []:
        if isinstance(entry, str):
            version_range_strs.append(entry)
            continue
        introduced, fixed = entry.get("introduced"), entry.get("fixed")
        if fixed:
            version_range_strs.append(f"<={fixed}")
        elif introduced:
            version_range_strs.append(f">={introduced}")
        else:
            continue
    cwe = internal.get("cwe")
    if isinstance(cwe, str):
        cwe = [cwe]
    affected = internal.get("affected_products") or []
    product = affected[0] if affected else internal.get("product")
    if isinstance(product, list):
        product = product[0] if product else None

    # `raw_refs` 遵循权威 `payload://` 约定（可回溯原始响应），不塞 web 公告 URL
    # 注意：`sources` 可能是字典列表（引用），必须经 `source_ids_of` 归一成字符串，
    # 否则会产出 `source_ids: [{...}]` 直接违约（本条曾有真实 bug）。
    source_ids = source_ids_of(internal.get("sources") or internal.get("source_ids"))
    raw_refs = (
        internal.get("raw_refs")
        or [f"payload://{src}/{cve_id}" for src in source_ids if cve_id]
        or ["payload://unknown"]
    )

    out: dict[str, Any] = {
        "intel_id": str(resolved_id),
        "cve_ids": [cve_id] if cve_id else [],
        "ghsa_ids": list(internal.get("ghsa_ids") or []),
        "osv_ids": list(internal.get("osv_ids") or []),
        "source_ids": source_ids,
        "title": str(internal.get("title") or internal.get("description") or cve_id or "untitled"),
        "published_at": str(
            internal.get("published_at") or internal.get("created_at") or _utcnow()
        ),
        "first_seen_at": str(internal.get("first_seen_at") or _utcnow()),
        "entities": {
            "product": str(product) if product else None,
            "vendor": internal.get("vendor"),
            "version_range": version_range_strs,
            "cwe": list(cwe or []),
            "cpes": list(cpes or []),
        },
        "raw_refs": list(raw_refs),
        "source_reliability": float(internal.get("source_reliability") or 0.5),
        "schema_version": SCHEMA_VERSION,
    }
    description = internal.get("description")
    if isinstance(description, str) and description.strip():
        out["summary"] = description.strip()
    aliases = internal.get("aliases")
    if aliases:
        out["aliases"] = [str(a) for a in aliases]
    return out


def to_raw_doc(
    internal: dict[str, Any],
    *,
    source_id: str,
    source_type: str,
    external_id: str,
    url: str,
    payload_ref: str,
) -> dict[str, Any]:
    """内部抓取记录 → 权威 `RawDoc`（Y1/Y2 → Y3 交接口）。"""

    allowed = {
        "nvd_cve",
        "cve_org",
        "ghsa",
        "osv",
        "vendor_advisory",
        "security_community",
        "security_blog",
        "poec_source",
        "kev",
        "standard_policy",
        "paper",
    }
    if source_type not in allowed:
        raise ContractProjectionError(f"source_type {source_type!r} 不在权威 11 枚举内")
    out: dict[str, Any] = {
        "source_id": source_id,
        "source_type": source_type,
        "external_id": external_id,
        "url": url,
        "fetched_at": str(internal.get("fetched_at") or _utcnow()),
        "content_type": str(internal.get("content_type") or content_type_of(source_id)),
        "payload_ref": payload_ref,
    }
    if internal.get("http_etag"):
        out["http_etag"] = str(internal["http_etag"])
    warnings = internal.get("parse_warnings")
    if warnings:
        out["parse_warnings"] = [str(w) for w in warnings]
    return out


def _utcnow() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def to_contract_dimension(dimension: str) -> str:
    """内部维度名 → 权威契约维度主键。未知维度直接报错，禁止静默透传。"""

    try:
        return DIMENSION_TO_CONTRACT[dimension]
    except KeyError:
        raise ContractProjectionError(
            f"未知维度 {dimension!r}，允许 {sorted(DIMENSION_TO_CONTRACT)}"
        ) from None


def to_contract_degrade(degraded_to: str | None) -> str | None:
    """内部降级通道 → 权威 6 值枚举。`None` 表示未降级。"""

    if degraded_to is None:
        return None
    try:
        return DEGRADE_TO_CONTRACT[degraded_to]
    except KeyError:
        raise ContractProjectionError(
            f"未登记的降级通道 {degraded_to!r}，允许 {sorted(DEGRADE_TO_CONTRACT)}"
        ) from None


def degrade_state(degraded_to: str, trace_id: str | None) -> dict[str, str]:
    """权威 `degraded_state` 固定形状 `{label, since, detail_ref}`。"""

    return {
        "label": DEGRADE_LABELS.get(degraded_to, f"已降级：{degraded_to}"),
        "since": dt.datetime.now(dt.UTC).isoformat(),
        "detail_ref": trace_id or "trace_unavailable",
    }


def _project_evidence(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """内部证据 → `DimensionEvidence.evidence[]`。

    权威契约要求 `url` 为 `format: uri` 且 `additionalProperties: false`，
    而本地计算类证据（CVSS 本地计分等）天然没有网页 URL —— 用 `urn:aiintel:evidence:<id>`
    如实表达"这是计算产物而非网页快照"，不伪造链接。
    """

    out: list[dict[str, Any]] = []
    for item in items:
        eid = str(item.get("evidence_id") or f"ev-{len(out) + 1}")
        url = item.get("url") or COMPUTED_EVIDENCE_URN.format(eid=eid)
        projected: dict[str, Any] = {
            "url": url,
            "snippet": str(item.get("snippet") or ""),
            "fetched_at": str(item.get("fetched_at") or dt.datetime.now(dt.UTC).isoformat()),
        }
        sha = item.get("sha256")
        if sha:
            projected["sha256"] = str(sha)
        out.append(projected)
    return out


def _default_summary(result: dict[str, Any]) -> str:
    """`DimensionEvidence.summary` 必填且 minLength=1；无显式摘要时用维度+置信度兜底。"""

    dimension = str(result.get("dimension", "?"))
    value = result.get("value")
    if isinstance(value, dict):
        for key in ("summary", "label", "category_label", "impact_summary"):
            text = value.get(key)
            if isinstance(text, str) and text.strip():
                return text.strip()
    if result.get("degraded_to"):
        return f"{dimension} 维度结果（经 {result['degraded_to']} 通道降级，详见证据链）"
    return f"{dimension} 维度富化结果，详见证据链"


def to_dimension_evidence(
    result: dict[str, Any],
    *,
    intel_id: str,
    cve_id: str | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    """`evidence.build_result()` 输出 → `DimensionEvidence.json` 载荷。

    权威 `EnrichmentResult` 因 `additionalProperties: false` 无法承载 7 维明细，
    明细一律走本扩展契约，与权威契约用 `intel_id` 关联（见 docs/契约对齐-SafeTrace.md §5）。
    """

    dimension = to_contract_dimension(str(result.get("dimension", "")))
    trace_id = result.get("trace_id")
    # 降级口径**只有一处**：`core/degrade.py::degrade()`。
    # 这里不再自带一份映射表（两份表就是"降级口径有两处定义"的老毛病）。
    # 惰性导入：`core.degrade` 反向依赖本模块的映射表，模块级导入会成环。
    from aiintel.core.degrade import degrade

    internal_channel = result.get("degraded_to")
    marker = (
        degrade(
            str(internal_channel),
            detail=str(result.get("degraded_reason") or ""),
            trace_id=trace_id,
        )
        if internal_channel
        else None
    )

    payload: dict[str, Any] = {
        "intel_id": intel_id,
        "dimension": dimension,
        "summary": summary or _default_summary(result),
        "confidence": float(result.get("confidence") or 0.0),
        "sources": list(result.get("source") or ["rule"]),
        "evidence": _project_evidence(list(result.get("evidence") or [])),
        "mock": bool(result.get("mock")),
        "completed_at": str(result.get("created_at") or dt.datetime.now(dt.UTC).isoformat()),
        "schema_version": SCHEMA_VERSION,
    }
    if cve_id:
        payload["cve_id"] = cve_id
    if marker is not None:
        payload["degraded_to"] = marker.contract_value
        payload["degraded_state"] = marker.state()
        # 本仓内部细名（rule / mock / local…）比权威 6 值更精确，保留给前端与审计
        payload["degraded_detail"] = str(internal_channel)
        if marker.recovery_hint:
            payload["recovery_hint"] = marker.recovery_hint
        if result.get("degraded_reason"):
            payload["degraded_reason"] = str(result["degraded_reason"])
    if result.get("quality_score") is not None:
        payload["quality_score"] = float(result["quality_score"])
    if isinstance(result.get("value"), dict):
        payload["value"] = result["value"]
    return payload


def to_score_assessment(result: dict[str, Any]) -> dict[str, Any] | None:
    """内部 cvss 维度结果 → 权威 `artifacts.score_assessment`。"""

    if str(result.get("dimension")) != "cvss":
        return None
    value = result.get("value")
    if not isinstance(value, dict):
        return None

    vector = value.get("vector") or value.get("cvss_v3_vector")
    base = value.get("base_score", value.get("cvss_v3_base"))
    if not vector or base is None:
        return None

    raw_source = str(value.get("score_source") or value.get("source_of_score") or "computed")
    source_of_score = SCORE_SOURCE_MAP.get(raw_source)
    if source_of_score is None:
        raise ContractProjectionError(
            f"score_source {raw_source!r} 不在权威六枚举映射内，允许 {sorted(SCORE_SOURCE_MAP)}"
        )

    out: dict[str, Any] = {
        "cvss_v3_vector": str(vector),
        "cvss_v3_base": float(base),
        "source_of_score": source_of_score,
        "confidence": float(result.get("confidence") or 0.0),
    }
    # system_derived 必须附理由（权威 schema description 硬要求）
    if source_of_score == "system_derived":
        out["derived_reason"] = str(
            value.get("derived_reason")
            or "按 CVSS v3.1 规范本地计算（ISS→Impact→Exploitability→Roundup），可复核"
        )
    epss = value.get("epss")
    if isinstance(epss, (int, float)):
        out["epss_score"] = float(epss)
    if isinstance(value.get("kev"), bool):
        out["kev_flag"] = value["kev"]
    for src, dst in (
        ("technical_impact", "impact_summary"),
        ("exploit_maturity", "exploit_maturity"),
        ("severity", "exploit_maturity"),
    ):
        text = value.get(src)
        if isinstance(text, str) and text.strip() and dst not in out:
            out[dst] = text.strip()
    return out


def to_papers(result: dict[str, Any]) -> list[dict[str, Any]] | None:
    """内部 paper 维度结果 → 权威 `artifacts.papers[]`。"""

    if str(result.get("dimension")) != "paper":
        return None
    value = result.get("value")
    papers = value.get("papers") if isinstance(value, dict) else None
    if not isinstance(papers, list):
        return None

    out: list[dict[str, Any]] = []
    for item in papers:
        if not isinstance(item, dict):
            continue
        paper_id = item.get("paper_id") or item.get("id")
        title = item.get("title")
        if not paper_id or not title:
            continue
        source = str(item.get("source") or "arxiv")
        if source not in ("arxiv", "s2"):
            source = "arxiv"  # openalex 等归一到权威二值枚举
        entry: dict[str, Any] = {
            "paper_id": str(paper_id),
            "source": source,
            "title": str(title),
            "relevance_score": float(item.get("relevance_score") or 0.0),
            "confidence": float(item.get("confidence") or result.get("confidence") or 0.0),
        }
        if isinstance(item.get("year"), int):
            entry["year"] = item["year"]
        if isinstance(item.get("venue"), str):
            entry["venue"] = item["venue"]
        terms = item.get("evidence_terms") or item.get("matched_terms")
        if isinstance(terms, list) and terms:
            entry["evidence_terms"] = [str(t) for t in terms]
        out.append(entry)
    return out or None


def to_enrichment_result(
    intel_id: str,
    results: list[dict[str, Any]],
    *,
    failed: list[dict[str, Any]] | None = None,
    enrichment_score: float | None = None,
) -> dict[str, Any]:
    """一组内部维度结果 → 权威 `EnrichmentResult.json` 载荷。

    `artifacts` 只允许 `papers` 与 `score_assessment`；其余维度仅进
    `dimensions_completed/failed`，明细走 `DimensionEvidence`。
    """

    completed: list[str] = []
    artifacts: dict[str, Any] = {}
    for item in results:
        name = to_contract_dimension(str(item.get("dimension", "")))
        if name in CONTRACT_DIMENSIONS:
            completed.append(name)
        papers = to_papers(item)
        if papers:
            artifacts["papers"] = papers
        assessment = to_score_assessment(item)
        if assessment:
            artifacts["score_assessment"] = assessment

    failed_dims = [to_contract_dimension(str(item.get("dimension", ""))) for item in (failed or [])]
    score = enrichment_score
    if score is None:
        scores = [float(r["quality_score"]) for r in results if r.get("quality_score") is not None]
        score = sum(scores) / len(scores) if scores else round(len(completed) / 7, 3)

    return {
        "intel_id": intel_id,
        "dimensions_completed": completed,
        "dimensions_failed": [d for d in failed_dims if d in CONTRACT_DIMENSIONS],
        "artifacts": artifacts,
        "enrichment_score": round(min(max(float(score), 0.0), 1.0), 3),
        "completed_at": dt.datetime.now(dt.UTC).isoformat(),
        "schema_version": SCHEMA_VERSION,
    }

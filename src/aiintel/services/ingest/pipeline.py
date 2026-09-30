"""解析标准化管线：LLM 字段抽取 → CVE Schema 归一 → 落库。

LLM 只负责"从非结构化文本里抽字段"，CVSS 分数一律本地计算，不让模型编数字。
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import uuid
from typing import Any

from aiintel.core.llm import get_llm
from aiintel.services.collectors.base import parse_datetime
from aiintel.services.enrich.cvss import score_vector_31
from aiintel.services.enrich.nvd import cve_body, parse_nvd
from aiintel.services.ingest.text import truncate

logger = logging.getLogger(__name__)

#: CVE 编号的**完整匹配**用（不是搜索）。用于判断 `external_id` 能否当 CVE 用 ——
#: 只做 `fullmatch`，避免把 "CVE-2024-1234-extra" 这类当合法编号。
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

EXTRACT_SYSTEM_PROMPT = (
    "你是漏洞情报结构化助手。从给定的安全公告/漏洞描述中抽取结构化字段，"
    "只输出 JSON，字段缺失用 null，不要编造。"
)

EXTRACT_SCHEMA_HINT = {
    "cve_id": "CVE 编号，无则 null",
    "severity": "critical/high/medium/low/unknown",
    "cvss_vector": "CVSS 3.1 向量字符串，无则 null",
    "cwe": "CWE 编号列表",
    "affected_products": "受影响产品/框架名列表（如 vLLM、Ollama、Transformers）",
    "attack_prerequisites": "利用所需前置条件",
    "impact": "一句话描述影响",
    "fix": "修复建议",
}

LLM_EXTRACT_THRESHOLD = 200  # 短文本（如 GHSA 摘要）不消耗 LLM


async def _llm_extract(item: dict) -> dict:
    text = truncate(f"{item.get('title', '')}\n{item.get('content_text', '')}", 6000)
    prompt = "\n".join(f"- {k}: {v}" for k, v in EXTRACT_SCHEMA_HINT.items())
    result = await get_llm().complete(
        [
            {"role": "system", "content": EXTRACT_SYSTEM_PROMPT},
            {"role": "user", "content": f"字段定义：\n{prompt}\n\n原文：\n{text}"},
        ],
        task="extract",
        max_tokens=800,
        node="normalize",
        agent="IngestAgent",
    )
    try:
        return result.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM 抽取失败，回退规则解析: %s", exc)
        return {}


def _rule_extract(item: dict) -> dict:
    """规则抽取（LLM 不可用/输出被截断时的兜底）。

    ⚠️ `cve_id` 必须能从 **`external_id`** 兜底取到 —— 这是实测踩出来的：
    `NvdCollector._to_item()` 把 CVE 编号放在 `external_id`
    （`raw` 里**没有** `cve_id` 字段），而这里原先只读 `raw.cve_id` / `item.cve_id`
    → NVD 来源的条目 `cve_id` **恒为 None**。

    为什么以前没暴露：正常路径走 LLM 抽取，LLM 会自己认出来；
    只有当 LLM 不可用或输出被 `max_tokens` 截断时才会落到这条规则路径 ——
    而本机实测 LLM 抽取正好一直被截断（思维 token 占满 800），
    于是**所有真实 NVD 条目都丢了 CVE 编号**。

    `external_id` 只在**形如 CVE 编号**时才采用：其它源（RSS、arXiv）的
    external_id 是普通标识，当成 CVE 会把脏数据写进底座。
    """

    raw = item.get("raw") or {}
    cve_id = raw.get("cve_id") or item.get("cve_id")
    if not cve_id:
        candidate = str(item.get("external_id") or "").strip()
        if _CVE_ID_RE.fullmatch(candidate):
            cve_id = candidate
    return {
        "cve_id": cve_id,
        "severity": (raw.get("severity") or item.get("severity") or "unknown").lower(),
        "cvss_vector": item.get("cvss_vector") or raw.get("cvss_vector"),
        "cwe": item.get("cwe") or raw.get("cwe") or [],
        "affected_products": _guess_products(item),
        "impact": item.get("title", ""),
        "fix": "",
    }


_PRODUCT_HINTS = (
    "vllm",
    "ollama",
    "triton",
    "langchain",
    "llamaindex",
    "huggingface",
    "transformers",
    "pytorch",
    "tensorflow",
)


def _guess_products(item: dict) -> list[str]:
    haystack = f"{item.get('title', '')} {item.get('content_text', '')}".lower()
    for cpe in item.get("cpe") or (item.get("raw") or {}).get("cpe") or []:
        if cpe.count(":") >= 4:
            parts = cpe.split(":")
            if parts[3] not in {"*", "-"}:
                return [parts[3]]
    return [name for name in _PRODUCT_HINTS if name in haystack]


def extract_kev(payload: Any) -> bool:
    """从原始载荷里判断是否**已列入 CISA KEV**（在野利用）。

    只用"实际被列入"的证据：`cisaExploitAdd`（NVD 2.0 的字段）或显式 `kev=true`。
    **不用 `hasKev` 查询参数兜底** —— 那是采集侧的查询开关，不是本条情报的属性
    （`services/collectors/nvd.py:52` 有专门警告：KEV 只覆盖约 1%）。
    """

    body = cve_body(payload)
    if body.get("cisaExploitAdd") or body.get("kev"):
        return True
    # KEV 官方目录的条目本身就是"已列入 KEV"的一手证据，且不保证每个条目都带
    # dueDate（见 services/collectors/kev.py），所以靠 **kev_* 专有字段存在** 判断，
    # 不能只认 dueDate —— 否则缺期限的条目会被误判成"不在 KEV"。
    return any(key.startswith("kev_") for key in body)


def extract_epss(payload: Any) -> float | None:
    """抽取 EPSS 被利用概率。支持三种已知形态，取不到返回 None（不猜）。"""

    body = cve_body(payload)
    value: Any = body.get("epss")
    if value is None:
        return None
    # NVD 2.0 里可能是 [{"epss": 0.87, ...}]
    if isinstance(value, list):
        if not value:
            return None
        first = value[0]
        value = first.get("epss") if isinstance(first, dict) else first
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _extract_kev_due_date(raw: dict[str, Any], item: dict[str, Any]) -> str | None:
    """抽取 CISA KEV 的强制修复截止日（ISO `YYYY-MM-DD`）。

    取不到返回 None。**不要用"没有 dueDate"推断"不紧急"**——CISA 目录里
    `dueDate` 可能缺失或格式异常，此时只能诚实地说"未知"，让 triage 走别的信号。
    """

    for candidate in (item.get("kev_due_date"), raw.get("kev_due_date")):
        parsed = _normalize_due_date(candidate)
        if parsed:
            return parsed
    return None


def _normalize_due_date(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text_value = value.strip()
    if not text_value:
        return None
    # `parse_datetime` 对无法识别的输入返回 None（不抛异常），所以这里必须判空
    parsed = parse_datetime(text_value)
    if parsed is None:
        return None
    return parsed.strftime("%Y-%m-%d")


async def normalize_item(item: dict) -> dict:
    """单个条目归一。规则能搞定就不用 LLM（成本治理）。"""

    extracted: dict[str, Any]
    if len(item.get("content_text", "")) >= LLM_EXTRACT_THRESHOLD:
        extracted = await _llm_extract(item)
        if not extracted:
            extracted = _rule_extract(item)
    else:
        extracted = _rule_extract(item)

    raw = item.get("raw") or {}
    vector = extracted.get("cvss_vector") or item.get("cvss_vector") or raw.get("cvss_vector")
    score = item.get("cvss_score") or raw.get("cvss_score")

    # NVD 的 CVSS 藏在 `raw["cve"]["metrics"]` 里，而上面只读了 `item/raw` 顶层的
    # `cvss_vector`。结果是**NVD 来源的条目一直拿不到 CVSS 分数**（severity 掉成 unknown），
    # 而 triage 的旧排序恰好只看 cvss_score —— 等于 NVD 情报被系统性排在后面。
    # 复用富化线那份经过验证的解析器，不在这里重写一套。
    parsed = parse_nvd({**item, "raw_json": raw})
    vector = vector or parsed.get("cvss_vector")
    if score is None:
        score = parsed.get("official_score")
    if score is None and vector:
        score = score_vector_31(vector)

    # CISA KEV 官方目录给的强制修复截止日。这是"在野利用"唯一带**期限**的证据，
    # 比 CVSS 分、比 EPSS 概率都硬（是截止日，不是估计）。只有 KEV 源提供它，
    # NVD 二次加工的镜像字段没有这个值。
    kev_due_date = _extract_kev_due_date(raw, item)

    # EPSS / KEV 在**归一阶段**就抽出来写进条目：`node_triage` 排优先级要用它们，
    # 而 triage 跑在富化之前（F4 的解析结果那时还不存在）。
    # 权威 IntelItem 刻意不含这两个字段（见 docs/路线评估-优先级与RAG.md §1），
    # 所以它们只活在内部条目与 DB 列上，不进事件载荷。
    epss = item.get("epss") if item.get("epss") is not None else extract_epss(raw)
    kev = bool(item.get("kev")) or extract_kev(raw)

    severity = (
        item.get("severity") or raw.get("severity") or extracted.get("severity") or "unknown"
    ).lower()
    if score is not None:
        severity = _severity_from_score(float(score)) or severity

    return {
        **item,
        "cve_id": extracted.get("cve_id") or raw.get("cve_id") or item.get("cve_id"),
        "ghsa_id": item.get("ghsa_id") or raw.get("ghsa_id"),
        "title": item.get("title") or extracted.get("impact", ""),
        "description": item.get("content_text", ""),
        "summary": extracted.get("impact", "")[:500],
        "severity": severity,
        "cvss_vector": vector,
        "cvss_score": score,
        "epss": epss,
        "kev": kev,
        "kev_due_date": kev_due_date,
        "cwe": extracted.get("cwe") or item.get("cwe") or raw.get("cwe") or [],
        "cpe": item.get("cpe") or raw.get("cpe") or [],
        "affected_products": extracted.get("affected_products", []),
        "attack_prerequisites": extracted.get("attack_prerequisites", ""),
        "fix": extracted.get("fix", ""),
        "references": raw.get("references", []),
    }


def _severity_from_score(score: float) -> str | None:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


async def normalize_items(items: list[dict]) -> list[dict]:
    result: list[dict] = []
    for item in items:
        try:
            result.append(await normalize_item(item))
        except Exception as exc:  # noqa: BLE001
            logger.warning("归一化失败 item=%s: %s", item.get("id"), exc)
    return result


async def poll_sources(sources: list[str] | None, mode: str = "incremental") -> list[dict]:
    from aiintel.services.collectors.registry import get_registry

    return await get_registry().poll(sources, mode)


def _iso_utc(value: object) -> str | None:
    """DB 日期时间 → 带时区的 ISO 字符串。

    **为什么必须补时区**：SQLite 的 `DateTime(timezone=True)` 列**不保留 tzinfo**，
    `row.published_at` 取出来是 naive 的。若原样 `isoformat()`，产出的字符串就没有时区，
    DQ1 会如实判它 `ts_no_tz`（"时间戳无法定时区"）→ 整库条目被隔离。
    那其实是**存储介质的假象**，不是数据脏：本库所有时间戳都以 UTC 写入，
    所以 naive 一律按 UTC 补全；PG 本来就返回 aware，这个函数对它无副作用。
    """

    if value is None:
        return None
    if isinstance(value, dt.datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=dt.UTC)
        return moment.isoformat()
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)).isoformat()


def load_intel_item(vuln_id: str) -> dict:
    """把 DB 里的漏洞装配成 **IntelItem**（Y 线 → F 线的正式接口）。

    契约见 `contracts/schemas/IntelItem.json`。要点：

    - 从 `vuln_source` + `raw_item` 联查出 `sources[]`（含 url / external_id / 时间戳），
      这是 F 线产出"每条结论带 source 与 evidence"的唯一依据；
    - `references` 优先取 `vuln.references`（Y 线已入库），缺失时从关联 `raw_item.raw_json`
      里兜底提取，避免 F5 修复建议因为 Y 线还没补列而完全失效；
    - 时间戳一律经 `_iso_utc()` 补时区（见该函数说明）；
    - 找不到漏洞返回 `{}`，由调用方决定跳过（不抛异常）。
    """

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import RawItem, Vuln, VulnSource

    with get_sessionmaker()() as session:
        row = (
            session.get(Vuln, vuln_id)
            or session.query(Vuln).filter_by(cve_id=vuln_id).one_or_none()
        )
        if row is None:
            return {}

        links = session.query(VulnSource).filter_by(vuln_id=row.id).all()
        raw_ids = [link.raw_item_id for link in links if link.raw_item_id]
        raws = session.query(RawItem).filter(RawItem.id.in_(raw_ids)).all() if raw_ids else []
        raw_by_id = {item.id: item for item in raws}

        sources: list[dict] = []
        for link in links:
            raw = raw_by_id.get(link.raw_item_id or "")
            sources.append(
                {
                    "source": link.source,
                    "url": raw.url if raw else None,
                    "external_id": raw.external_id if raw else None,
                    "raw_item_id": link.raw_item_id,
                    "published_at": _iso_utc(raw.published_at) if raw else None,
                    "fetched_at": _iso_utc(raw.fetched_at) if raw else None,
                }
            )

        references = list(row.references or [])
        if not references:
            references = _references_from_raw(raws)

        return {
            "id": row.id,
            "vuln_id": row.id,
            "cve_id": row.cve_id,
            "ghsa_id": row.ghsa_id,
            "aliases": [x for x in (row.cve_id, row.ghsa_id) if x],
            "title": row.title or "",
            "description": row.description or "",
            "summary": row.summary or "",
            "severity": row.severity,
            "cvss_vector": row.cvss_vector,
            "cvss_score": row.cvss_score,
            "cwe": list(row.cwe or []),
            "cpe": list(row.cpe or []),
            "affected_products": list(row.affected_products or []),
            "version_ranges": list(row.version_ranges or []),
            "references": references,
            "epss": row.epss,
            "kev": row.kev,
            "published_at": _iso_utc(row.published_at),
            "modified_at": _iso_utc(row.modified_at),
            "fetched_at": _iso_utc(row.fetched_at),
            "quality_score": row.quality_score,
            "sources": sources,
        }


def _references_from_raw(raws: list[Any]) -> list[dict]:
    """从 raw_item.raw_json 里兜底提取 references（NVD 2.0 / GHSA 两种形态）。"""

    out: list[dict] = []
    seen: set[str] = set()
    for raw in raws:
        payload = raw.raw_json or {}
        cve = payload.get("cve") if isinstance(payload, dict) else None
        # raw_json 是自由 JSON，取出来先是 Any，后面再逐条窄化
        raw_refs: Any = None
        if isinstance(cve, dict):
            raw_refs = cve.get("references")
        elif isinstance(payload, dict):
            raw_refs = payload.get("references")
        if not isinstance(raw_refs, list):
            continue
        for ref in raw_refs:
            if isinstance(ref, dict):
                url = ref.get("url")
                tags = ref.get("tags") or []
                provider = ref.get("source")
            else:
                url, tags, provider = str(ref), [], None
            if not url or url in seen:
                continue
            seen.add(url)
            out.append({"url": url, "kind": None, "provider": provider, "tags": tags})
    return out


async def persist_raw_items(items: list[dict]) -> int:
    """原始条目落库，幂等：source + external_id 唯一，命中则只更新 etag。"""

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import RawItem
    from aiintel.services.collectors.base import parse_datetime

    written = 0
    with get_sessionmaker()() as session:
        for item in items:
            existing = (
                session.query(RawItem)
                .filter_by(source=item["source"], external_id=item["external_id"])
                .one_or_none()
            )
            if existing is not None:
                continue
            session.add(
                RawItem(
                    id=item.get("id") or uuid.uuid4().hex,
                    source=item["source"],
                    external_id=item["external_id"],
                    url=item.get("url"),
                    title=item.get("title", ""),
                    content_text=item.get("content_text", ""),
                    published_at=parse_datetime(item.get("published_at")),
                    content_hash=item.get("content_hash", ""),
                    simhash=item.get("simhash"),
                    raw_json=item.get("raw", {}),
                )
            )
            written += 1
        session.commit()
    return written

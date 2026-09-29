"""F1 论文关联（`paper`）：arXiv 为主源 + OpenAlex 为第二源。

设计取舍（与计划一致、与"每条结论可溯源"一致）：

- **不抓全文**：只取元数据（标题/摘要/年份）作为证据片段，OpenAlex 取 abstract 时若为
  inverted index 则还原为文本。抓全文属于 S1 知识底座的活，F 线不重复做。
- **双源真实可换**：arXiv 是真跑主源；OpenAlex 是真跑第二源（失败只记降级，不阻断）。
  `enrich_paper_sources` 可配置，离线环境自动退化为单源。
- **判定失败不许装成功**：LLM 不可用时退化为"关键词重叠"规则，结果标
  `degraded_to="rule"`，置信度 ≤0.6，前端会显示降级徽标。
- **命名诚实**：只做"论文 ↔ 漏洞"关联判定，**不产出"章节级证据"**（那需要全文解析，
  本轮未做）。这一点写进报告「已知限制」。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from aiintel.config import get_settings
from aiintel.services.enrich import mg1
from aiintel.services.enrich.evidence import EvidenceBuilder, build_result
from aiintel.services.ingest.text import truncate

logger = logging.getLogger(__name__)

ARXIV_API = "https://export.arxiv.org/api/query"
OPENALEX_API = "https://api.openalex.org/works"

MAX_CANDIDATES = 5
MAX_KEPT = 3

JUDGE_SYSTEM_PROMPT = (
    "你是安全情报分析师。判断给定论文与漏洞的关联类型，只输出 JSON："
    '{"relevant": true/false, "relation_type": "same_vuln|same_attack_surface|method_for|none", '
    '"relevance": 0.0-1.0, "reason": "≤40字", "findings": ["论文给出的关键结论，≤3条"]}'
)

# 关键词重叠判定用的英文停用词（规则兜底，避免噪声词把不相关论文拉进来）
_STOP = frozenset(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "for",
        "to",
        "in",
        "on",
        "with",
        "without",
        "via",
        "using",
        "use",
        "used",
        "allows",
        "allow",
        "vulnerability",
        "vulnerable",
        "remote",
        "code",
        "execution",
        "security",
        "secure",
        "issue",
        "issues",
        "versions",
        "version",
        "through",
        "before",
        "after",
        "this",
        "that",
        "these",
        "those",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "can",
        "could",
        "may",
        "might",
        "will",
        "would",
        "should",
        "not",
        "no",
        "all",
        "any",
        "from",
        "into",
        "than",
        "then",
        "there",
        "here",
        "attack",
        "attacker",
        "attackers",
        "user",
        "users",
        "server",
        "service",
        "services",
    ]
)
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9._\-]{2,}")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")


@dataclass(slots=True)
class PaperCandidate:
    source: str
    title: str
    url: str
    arxiv_id: str | None = None
    doi: str | None = None
    year: int | None = None
    abstract: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """跨源去重键：DOI 优先，其次 arXiv ID，最后标题归一。"""

        if self.doi:
            return f"doi:{self.doi.lower()}"
        if self.arxiv_id:
            return f"arxiv:{self.arxiv_id.lower()}"
        return f"title:{re.sub(r'[^a-z0-9]', '', self.title.lower())}"

    def to_value(self) -> dict[str, Any]:
        return {
            "paper_id": self.arxiv_id or self.doi or self.url,
            "arxiv_id": self.arxiv_id,
            "doi": self.doi,
            "title": self.title,
            "year": self.year,
            "url": self.url,
            "source": self.source,
        }


def build_query(vuln: dict[str, Any]) -> str:
    """检索式：CVE 号最精确，退化到受影响产品，再退化到通用 AI 安全题面。"""

    cve = vuln.get("cve_id")
    if cve:
        return f'"{cve}"'
    products = vuln.get("affected_products") or []
    product = products[0] if products else None
    if product:
        return f'"{product}" AND all:"vulnerability"'
    return 'all:"AI" AND all:"vulnerability"'


# ---------------------------------------------------------------- 取数


async def fetch_arxiv(query: str, limit: int = MAX_CANDIDATES) -> list[PaperCandidate]:
    """arXiv Atom API。抛异常由调用方兜（单源失败隔离）。"""

    from aiintel.services.collectors.arxiv import ArxivCollector, _arxiv_id, _clean, _parse_atom

    collector = ArxivCollector()
    try:
        url = f"{ARXIV_API}?search_query={quote(query)}&max_results={limit * 2}"
        feed = await collector._get_text(url)
    finally:
        await collector.aclose()

    out: list[PaperCandidate] = []
    for entry in _parse_atom(feed)[:limit]:
        published = str(entry.get("published") or "")
        out.append(
            PaperCandidate(
                source="arxiv",
                title=_clean(entry.get("title", "")),
                url=entry.get("id", ""),
                arxiv_id=_arxiv_id(entry.get("id", "")),
                year=int(published[:4]) if published[:4].isdigit() else None,
                abstract=_clean(entry.get("summary", "")),
                extra={"categories": entry.get("categories", "")},
            )
        )
    return out


def _openalex_abstract(inverted: dict[str, Any] | None) -> str:
    """OpenAlex 的 abstract_inverted_index 还原成文本。"""

    if not inverted:
        return ""
    positions: list[tuple[int, str]] = []
    for word, idxs in inverted.items():
        for idx in idxs or []:
            positions.append((int(idx), word))
    positions.sort()
    return " ".join(word for _, word in positions)


async def fetch_openalex(query: str, limit: int = MAX_CANDIDATES) -> list[PaperCandidate]:
    """OpenAlex 第二源。网络不可用时抛异常，由调用方记为降级。"""

    import httpx

    settings = get_settings()
    clean_query = query.replace('"', "").replace("all:", "").replace("AND", " ").strip()
    params = {"search": clean_query, "per-page": str(limit), "mailto": "safetrace@example.invalid"}
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.enrich_http_timeout_seconds, connect=3.0),
        headers={"User-Agent": settings.collect_user_agent},
    ) as client:
        resp = await client.get(OPENALEX_API, params=params)
        resp.raise_for_status()
        payload = resp.json()

    out: list[PaperCandidate] = []
    for work in payload.get("results", [])[:limit]:
        doi = (work.get("doi") or "").replace("https://doi.org/", "") or None
        out.append(
            PaperCandidate(
                source="openalex",
                title=str(work.get("title") or work.get("display_name") or ""),
                url=str(work.get("doi") or work.get("id") or ""),
                doi=doi,
                year=work.get("publication_year"),
                abstract=_openalex_abstract(work.get("abstract_inverted_index")),
                extra={"cited_by": work.get("cited_by_count")},
            )
        )
    return out


async def collect_candidates(
    query: str, sources: list[str]
) -> tuple[list[PaperCandidate], list[str], list[str]]:
    """按配置的双源检索并去重。返回 (候选, 成功源, 失败源+原因)。"""

    merged: dict[str, PaperCandidate] = {}
    ok_sources: list[str] = []
    failures: list[str] = []
    fetchers = {"arxiv": fetch_arxiv, "openalex": fetch_openalex}

    for name in sources:
        fetcher = fetchers.get(name)
        if fetcher is None:
            continue
        try:
            for candidate in await fetcher(query):
                merged.setdefault(candidate.key, candidate)
            ok_sources.append(name)
        except Exception as exc:  # noqa: BLE001 - 单源失败隔离
            logger.info("论文源 %s 检索失败: %s", name, exc)
            failures.append(f"{name}:{str(exc)[:80]}")

    return list(merged.values())[: MAX_CANDIDATES * 2], ok_sources, failures


# ---------------------------------------------------------------- 判定


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "") if t.lower() not in _STOP}


def rule_judge(vuln: dict[str, Any], candidate: PaperCandidate) -> dict[str, Any]:
    """规则兜底判定：CVE 号命中，或标题/摘要与漏洞语料有足够关键词重叠。"""

    haystack = " ".join(
        [
            str(vuln.get("title") or ""),
            str(vuln.get("description") or "")[:2000],
            " ".join(vuln.get("affected_products") or []),
        ]
    )
    paper_text = f"{candidate.title} {candidate.abstract}"
    cve = _CVE_RE.search(haystack)
    if cve and cve.group(0).lower() in paper_text.lower():
        return {
            "relevant": True,
            "relation_type": "same_vuln",
            "relevance": 0.6,
            "reason": "论文文本中直接出现该 CVE 编号",
            "findings": [],
        }

    vuln_tokens, paper_tokens = _tokens(haystack), _tokens(paper_text)
    shared = {t for t in (vuln_tokens & paper_tokens) if not _CJK_RE.search(t)}
    # 用重叠**比例**而不是绝对个数：CVE 描述常常很短，绝对阈值会把真关联判成不相关。
    # 分母取较小集合，避免"论文摘要很长"反而拉低命中率。
    smaller = max(1, min(len(vuln_tokens), len(paper_tokens)))
    ratio = len(shared) / smaller
    if ratio >= 0.25 and len(shared) >= 2:
        return {
            "relevant": True,
            "relation_type": "same_attack_surface",
            "relevance": round(min(0.3 + 0.3 * ratio, 0.6), 3),
            "reason": f"关键词重叠 {len(shared)} 个（占比 {ratio:.0%}）：{','.join(sorted(shared)[:5])}",
            "findings": [],
        }
    return {
        "relevant": False,
        "relation_type": "none",
        "relevance": 0.0,
        "reason": f"关键词重叠不足（{len(shared)} 个 / 占比 {ratio:.0%}，阈值 2 个且 25%）",
        "findings": [],
    }


def _candidate_prompt(vuln: dict[str, Any], candidate: PaperCandidate) -> list[dict]:
    return [
        {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"漏洞：{vuln.get('title', '')}\n"
                f"CVE：{vuln.get('cve_id') or '未知'}\n"
                f"受影响产品：{vuln.get('affected_products') or []}\n"
                f"漏洞描述：{truncate(vuln.get('description', ''), 1200)}\n\n"
                f"论文标题：{candidate.title}\n"
                f"论文摘要：{truncate(candidate.abstract, 1200)}"
            ),
        },
    ]


# ---------------------------------------------------------------- 维度入口


async def paper_association(vuln: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    """F1 入口。契约见 `contracts/schemas/EnrichmentResult.json`。"""

    settings = get_settings()
    sources = [s.strip() for s in settings.enrich_paper_sources.split(",") if s.strip()]
    if not settings.enrich_openalex_enabled:
        sources = [s for s in sources if s != "openalex"]
    query = build_query(vuln)

    candidates, ok_sources, failures = await collect_candidates(query, sources)

    # LLM 判定（可用则用），不可用则整批退化为规则判定
    judged_pairs: list[tuple[PaperCandidate, dict[str, Any], bool]] = []
    llm_used = False
    if candidates:
        probe = await mg1.json_complete(
            _candidate_prompt(vuln, candidates[0]),
            task="classify",
            max_tokens=400,
            node="enrich.paper",
            agent="EnrichAgent",
        )
        llm_used = probe[0] is not None

    for candidate in candidates:
        if llm_used:
            payload, _ = await mg1.json_complete(
                _candidate_prompt(vuln, candidate),
                task="classify",
                max_tokens=400,
                node="enrich.paper",
                agent="EnrichAgent",
            )
            if payload is not None:
                judged_pairs.append((candidate, payload, False))
                continue
        judged_pairs.append((candidate, rule_judge(vuln, candidate), True))

    evidence = EvidenceBuilder()
    kept: list[dict[str, Any]] = []
    # 规则路径是否被真正使用过（即使一篇都没命中，也要如实说明"结论来自规则"）
    used_rule_path = any(is_rule for _, _, is_rule in judged_pairs)
    model = "rule-based"

    for candidate, judgement, is_rule in judged_pairs:
        if not judgement.get("relevant"):
            continue
        if not is_rule:
            model = "mg1/deepseek"
        eid = evidence.add(candidate.source, candidate.url, candidate.abstract or candidate.title)
        entry = candidate.to_value()
        entry.update(
            {
                "relation_type": judgement.get("relation_type") or "same_attack_surface",
                # `relevance_score` 是权威 `EnrichmentResult.artifacts.papers` 的字段名；
                # 同时保留 `relevance` 以兼容既有前端与评测脚本读取。
                "relevance_score": round(float(judgement.get("relevance") or 0.0), 3),
                "relevance": round(float(judgement.get("relevance") or 0.0), 3),
                "reason": str(judgement.get("reason") or "")[:100],
                "findings": list(judgement.get("findings") or [])[:3],
                "evidence_terms": list(judgement.get("findings") or [])[:3],
                "evidence_ref": eid,
            }
        )
        kept.append(entry)
        if len(kept) >= MAX_KEPT:
            break

    value = {
        "papers": kept,
        "query": query,
        "sources_queried": ok_sources,
        "source_failures": failures,
    }

    note = ""
    degraded_to: str | None = None
    degraded_reason = ""
    confidence = 0.3

    if not ok_sources:
        degraded_to = "rule"
        degraded_reason = f"论文源全部不可用（{';'.join(failures) or '未知原因'}）"
        note = "未检索到任何论文源，仅返回空结果"
    elif kept:
        if used_rule_path:
            degraded_to = "rule"
            degraded_reason = "MG1 不可用，改用关键词重叠规则判定相关性"
            confidence = 0.45
        else:
            confidence = 0.7
    else:
        # 有源但没命中：不是"计算降级"，但若结论来自规则路径也必须如实标注
        confidence = 0.3
        note = "已检索但未发现相关论文"
        if used_rule_path:
            degraded_to = "rule"
            degraded_reason = "MG1 不可用，改用关键词重叠规则判定（未命中）"

    # 证据不足时不能落库（不变量 1），此时补一条"检索过程"证据，明确它不是结论
    if not evidence:
        evidence.add(
            "arxiv" if "arxiv" in ok_sources else (ok_sources[0] if ok_sources else "rule"),
            f"{ARXIV_API}?search_query={quote(query)}",
            f"检索式 {query}，命中候选 {len(candidates)} 篇，判定相关 0 篇",
        )

    return build_result(
        "paper",
        value,
        evidence,
        confidence,
        source=ok_sources or ["rule"],
        model=model,
        trace_id=trace_id,
        degraded_to=degraded_to,
        degraded_reason=degraded_reason,
        note=note,
    )

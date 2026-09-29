"""F3 POC 搜集（`poc`）：多源候选 + 可信度分级。

**口径修正（重要）**：旧实现只要 LLM 判定是 POC 就写 `verified=True`，但那只是"检索到了"，
系统从未运行过任何验证代码。把"检索到"说成"已验证"是答辩上最容易被问倒的一处，
所以这里拆成三个正交概念：

| 字段 | 含义 |
| --- | --- |
| `listed` | 候选被检索到（来自哪个源） |
| `tier` | 可信度分级：`confirmed` / `likely` / `mention` |
| `runtime_verified` | **是否真的运行过**。初赛恒 `false`，UI 不得显示"已验证" |

`verified` 字段保留以兼容旧表，语义收紧为 `tier in {confirmed, likely}`。
"""

from __future__ import annotations

import logging
import re
from typing import Any

from aiintel.config import get_settings
from aiintel.services.enrich.evidence import EvidenceBuilder, build_result

logger = logging.getLogger(__name__)

TIERS = ("confirmed", "likely", "mention")
_TIER_RANK = {tier: idx for idx, tier in enumerate(TIERS)}

# 建议运行环境（不是执行计划）——真正的动态验证属 D1，按合规红线不做
POC_KIND_HINTS = {
    "exploit": "exploit",
    "poc": "exploit",
    "patch": "patch",
    "template": "template",
    "analysis": "analysis",
    "writeup": "analysis",
}

_NUCLEI_HINT = re.compile(r"nuclei|template", re.I)
_EXPLOIT_HINT = re.compile(r"exploit|poc|proof[- ]of[- ]concept|rce", re.I)


def _github_fallback(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    """网络不可用时，从 IntelItem.references 里挑出像 POC 的链接（规则，不猜内容）。"""

    out: list[dict[str, Any]] = []
    for ref in vuln.get("references") or []:
        url = str(ref.get("url") or "")
        if not url:
            continue
        title = str(ref.get("title") or "")
        kind = str(ref.get("kind") or "").lower()
        haystack = f"{url} {title} {kind}"
        if not _EXPLOIT_HINT.search(haystack) and kind != "exploit":
            continue
        tier = "mention"
        evidence_kind = "writeup"
        if _NUCLEI_HINT.search(haystack):
            tier, evidence_kind = "confirmed", "template"
        elif kind == "exploit" or _EXPLOIT_HINT.search(url):
            tier, evidence_kind = "likely", "code"
        out.append(
            {
                "repo": url,
                "url": url,
                "kind": POC_KIND_HINTS.get(kind, "exploit"),
                "language": None,
                "stars": 0,
                "tier": tier,
                "evidence_kind": evidence_kind,
                "listed": True,
                "runtime_verified": False,
                "verified": _TIER_RANK[tier] <= _TIER_RANK["likely"],
                "usage": "来源为公告 references，未运行验证；使用前请自行确认适用范围",
            }
        )
    return out


async def _github_search(vuln: dict[str, Any], limit: int = 5) -> tuple[list[dict[str, Any]], str]:
    """GitHub 仓库检索。返回 (候选, 错误信息)。"""

    cve = vuln.get("cve_id")
    if not cve:
        return [], "缺少 CVE 编号"

    from aiintel.services.collectors.ghsa import GhsaCollector

    settings = get_settings()
    client = GhsaCollector()
    headers = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    try:
        resp = await client._client.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{cve} in:name,description,readme", "sort": "stars", "per_page": limit},
            headers=headers,
            timeout=settings.enrich_http_timeout_seconds,
        )
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except Exception as exc:  # noqa: BLE001 - 单源失败隔离，走 references 兜底
        return [], f"github:{str(exc)[:80]}"
    finally:
        await client.aclose()

    out: list[dict[str, Any]] = []
    for repo in items[:limit]:
        stars = int(repo.get("stargazers_count") or 0)
        name = str(repo.get("full_name") or "")
        description = str(repo.get("description") or "")
        tier = "confirmed" if stars >= 5 else "likely" if stars >= 1 else "mention"
        out.append(
            {
                "repo": name,
                "url": repo.get("html_url"),
                "kind": "exploit",
                "language": repo.get("language"),
                "stars": stars,
                "tier": tier,
                "evidence_kind": "code",
                "listed": True,
                "runtime_verified": False,
                "verified": _TIER_RANK[tier] <= _TIER_RANK["likely"],
                "usage": f"{description[:80]}（未运行验证，tier 依据 star 数与描述命中）",
            }
        )
    return out, ""


def _reference_candidates(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ref in vuln.get("references") or []:
        url = str(ref.get("url") or "")
        if not url:
            continue
        kind = str(ref.get("kind") or "").lower()
        if kind not in {"exploit", "patch"}:
            continue
        haystack = f"{url} {ref.get('title') or ''}"
        if kind == "patch":
            out.append(
                {
                    "repo": url,
                    "url": url,
                    "kind": "patch",
                    "language": None,
                    "stars": 0,
                    "tier": "confirmed",
                    "evidence_kind": "patch",
                    "listed": True,
                    "runtime_verified": False,
                    "verified": True,
                    "usage": "官方修复提交/发布说明（不是利用代码）",
                }
            )
        elif _EXPLOIT_HINT.search(haystack):
            out.append(
                {
                    "repo": url,
                    "url": url,
                    "kind": "exploit",
                    "language": None,
                    "stars": 0,
                    "tier": "likely",
                    "evidence_kind": "writeup",
                    "listed": True,
                    "runtime_verified": False,
                    "verified": True,
                    "usage": "公告引用的利用情报，未运行验证",
                }
            )
    return out


async def poc_search(vuln: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    """F3 入口。"""

    evidence = EvidenceBuilder()
    candidates, error = await _github_search(vuln)
    sources_used = ["github"] if candidates else []
    failures = [error] if error else []

    ref_candidates = _reference_candidates(vuln)
    if ref_candidates:
        sources_used.append("references")

    if not candidates and not ref_candidates:
        candidates = _github_fallback(vuln)
        if candidates:
            sources_used.append("references")

    # 去重：URL 为准
    seen: set[str] = set()
    pocs: list[dict[str, Any]] = []
    for candidate in [*candidates, *ref_candidates]:
        url = str(candidate.get("url") or candidate.get("repo") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        pocs.append(candidate)

    # 排序：可信度高优先，其次 star
    pocs.sort(key=lambda p: (_TIER_RANK.get(str(p.get("tier")), 9), -int(p.get("stars") or 0)))

    for poc in pocs[:5]:
        evidence.add(
            "github" if "github.com" in str(poc.get("url")) else "vendor",
            poc.get("url"),
            f"{poc.get('repo')}（tier={poc.get('tier')}，未运行验证）",
        )

    degraded_to: str | None = None
    degraded_reason = ""
    mock = False

    if not pocs:
        if error:
            degraded_to = "rule"
            degraded_reason = f"GitHub 不可用（{error}），且公告 references 中没有可用候选"
            evidence.add("rule", None, f"POC 检索失败：{error}")
        else:
            evidence.add("rule", None, "GitHub 未命中，公告 references 也无候选")
    elif not candidates and ref_candidates:
        # 只有 references 命中：这是规则路径，明确标记而不是假装是检索结果
        degraded_to = "rule"
        degraded_reason = (
            f"GitHub 未命中或不可用（{error or '无命中'}），候选来自公告 references 的规则筛选"
        )
        mock = False

    value = {
        "pocs": pocs[:10],
        "poc_count": len(pocs),
        "confirmed_count": len([p for p in pocs if p.get("tier") == "confirmed"]),
        "sources_used": sources_used,
        "source_failures": failures,
        "runtime_verified_any": False,
        "verification_note": "本轮未运行任何验证代码（合规红线：不执行未授权目标上的利用）",
    }

    if not pocs:
        confidence = 0.2
    elif value["confirmed_count"]:
        confidence = 0.8
    elif any(p.get("tier") == "likely" for p in pocs):
        confidence = 0.6
    else:
        confidence = 0.35
    if degraded_to:
        confidence = min(confidence, 0.6)

    return build_result(
        "poc",
        value,
        evidence,
        confidence,
        source=sources_used or ["rule"],
        model="rule-based",
        trace_id=trace_id,
        mock=mock,
        degraded_to=degraded_to,
        degraded_reason=degraded_reason,
        note="tier 为可信度分级，不代表已运行验证",
    )

"""F6 汇总与一致性校验（`consistency`）：跨源冲突检测、仲裁、数据质量分。

为什么这一维值得单独做：赛题与判分的核心是"可信度"。多源情报必然互相打架
（NVD 9.8 / 厂商 8.1 / GHSA 7.5 是常态），**把冲突藏起来才是最大的不可信**。

设计取舍：

- **以计算为主，LLM 只写一句话**。字段比对、仲裁、质量分全是确定性代码，可复现、可测试；
  LLM 仅在检出冲突时把仲裁理由写成一句人话，失败就退回模板句（`degraded_to="rule"`）。
- **仲裁规则显式**：来源优先级 `NVD > 厂商 > GHSA > OSV > 社区`（可配），数值容差 ±0.1。
- **冲突进 badcase**：每次冲突落一条 JSONL，答辩时可以直接展示"我们知道自己哪里不一致"。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aiintel.config import get_settings
from aiintel.services.collectors.base import utcnow
from aiintel.services.enrich import mg1
from aiintel.services.enrich.evidence import EvidenceBuilder, build_result

logger = logging.getLogger(__name__)

# 参与比对的字段（按价值排序，砍范围时从后往前砍）
COMPARED_FIELDS = ("cvss_score", "severity", "affected_products", "fixed_version", "exploit_status")

DEFAULT_PRIORITY = ("nvd", "vendor", "ghsa", "osv", "community_rss")

# 已知公告域名 → 来源分类（用于把 references 归到具体来源，而不是笼统的 vendor）
_HOST_SOURCE = (
    ("nvd.nist.gov", "nvd"),
    ("github.com/advisories", "ghsa"),
    ("github.com", "github"),
    ("osv.dev", "osv"),
    ("cve.org", "cve"),
)


@dataclass(slots=True)
class Claim:
    """一条"某来源声称某字段等于某值"的记录，必须带 URL 才可信。

    `specificity` 用于**同一来源内部**的仲裁：IntelItem 里归一后的值是二手的，
    原始 JSON / 公告正文里解析出来的值更接近一手来源，所以后者优先。
    """

    field: str
    value: Any
    source: str
    url: str | None = None
    snippet: str = ""
    specificity: int = 0

    def as_json(self) -> dict[str, Any]:
        return {"value": self.value, "source": self.source, "url": self.url}


@dataclass(slots=True)
class FieldComparison:
    # 注意：字段名不能叫 `field`——那会遮蔽 dataclasses.field，mypy 会直接报错
    name: str
    claims: list[Claim] = field(default_factory=list)
    conflict: bool = False
    resolved_to: Any = None
    rule: str = ""
    note: str = ""


def _source_of_url(url: str) -> str:
    lowered = (url or "").lower()
    for needle, source in _HOST_SOURCE:
        if needle in lowered:
            return source
    return "vendor"


def source_priority() -> tuple[str, ...]:
    raw = get_settings().enrich_source_priority or ""
    ordered = tuple(s.strip() for s in raw.split(",") if s.strip())
    return ordered or DEFAULT_PRIORITY


def collect_claims(
    vuln: dict[str, Any], enrichments: list[dict[str, Any]] | None = None
) -> list[Claim]:
    """从 IntelItem + 本轮富化结果里收集可比较的字段声明。"""

    claims: list[Claim] = []

    def push(
        field_name: str,
        value: Any,
        source: str,
        url: str | None,
        snippet: str = "",
        specificity: int = 0,
    ) -> None:
        if value in (None, "", [], {}):
            return
        claims.append(
            Claim(
                field=field_name,
                value=value,
                source=source,
                url=url,
                snippet=snippet,
                specificity=specificity,
            )
        )

    # 1) IntelItem 本体（Y 线归一后的值，来源标记为 nvd 的通常是 NVD 口径）
    for entry in vuln.get("sources") or []:
        src = str(entry.get("source") or "unknown")
        url = entry.get("url")
        if src == "nvd":
            if vuln.get("cvss_score") is not None:
                push("cvss_score", float(vuln["cvss_score"]), "nvd", url)
            if vuln.get("severity"):
                push("severity", str(vuln["severity"]).lower(), "nvd", url)
            if vuln.get("affected_products"):
                push("affected_products", list(vuln["affected_products"]), "nvd", url)
        elif src in {"ghsa", "osv", "vendor"}:
            # GHSA/OSV 公告里的分数在 raw_json 里，这里至少记录"该源存在"，供覆盖率使用
            push("affected_products", list(vuln.get("affected_products") or []), src, url)

    # 2) NVD 原始 JSON（若 IntelItem 里带了）
    #    specificity=1：这是从一手 JSON 解析出来的值，比上面归一后的二手值更可信
    raw = vuln.get("raw_json") or vuln.get("raw") or {}
    cve = raw.get("cve") if isinstance(raw, dict) else None
    if isinstance(cve, dict):
        url = f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}" if cve.get("id") else None
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV40"):
            for entry in metrics.get(key) or []:
                data = entry.get("cvssData") or {}
                if data.get("baseScore") is not None:
                    push(
                        "cvss_score",
                        float(data["baseScore"]),
                        "nvd",
                        url,
                        "NVD CVSS baseScore（原始 JSON）",
                        specificity=1,
                    )
                    break

    # 3) references：厂商公告/补丁可能给出另一套分数与修复版本
    for ref in vuln.get("references") or []:
        url = ref.get("url")
        if not url:
            continue
        source = _source_of_url(url)
        title = str(ref.get("title") or "")
        if title:
            claims.append(Claim(field="reference_title", value=title, source=source, url=url))

    # 3b) 版本区间：F2/F5 的输入，也是 fixed_version 的权威声明之一
    for entry in vuln.get("version_ranges") or []:
        fixed = entry.get("fixed")
        if not fixed:
            continue
        claims.append(
            Claim(
                field="fixed_version",
                value=str(fixed),
                source=str(entry.get("source") or "vendor"),
                url=entry.get("url"),
                snippet=f"受影响版本区间 {entry.get('introduced') or '*'} → {fixed}",
            )
        )

    # 4) 本轮的富化结果（F5 给出的升级版本是最关键的比对对象）
    for item in enrichments or []:
        dim = item.get("dimension")
        value = item.get("value") or {}
        srcs = item.get("source") or ["rule"]
        url = next((e.get("url") for e in item.get("evidence") or [] if e.get("url")), None)
        if dim == "fix":
            upgrade = value.get("upgrade") or {}
            target = upgrade.get("target_version")
            if target:
                push(
                    "fixed_version",
                    str(target),
                    str(upgrade.get("source") or srcs[0]),
                    upgrade.get("url"),
                )
        elif dim == "cvss" and value.get("base_score") is not None:
            push("cvss_score", float(value["base_score"]), "computed", url)

    return claims


def _norm(value: Any) -> Any:
    if isinstance(value, str):
        return value.strip().lower()
    return value


def compare_field(
    field_name: str, claims: list[Claim], priority: tuple[str, ...], tolerance: float
) -> FieldComparison:
    """单个字段的比对 + 仲裁。"""

    result = FieldComparison(name=field_name, claims=claims)
    # 只取本字段的声明（第一版漏了这层过滤，导致 consensus/agreement 把其他字段的值也算进来）
    real = [c for c in claims if c.field == field_name and c.value not in (None, "", [], {})]
    result.claims = real
    if not real:
        return result
    if len(real) < 2:
        result.resolved_to = real[0].value
        result.rule = "single_source"
        return result

    if field_name == "cvss_score":
        values = [float(c.value) for c in real]
        result.conflict = (max(values) - min(values)) > tolerance
    elif field_name == "affected_products":
        sets = [set(map(str, c.value)) for c in real]
        result.conflict = not (set.intersection(*sets) if sets else set())
    else:
        distinct = {_norm(c.value) for c in real}
        result.conflict = len(distinct) > 1

    def rank(claim: Claim) -> tuple[int, int]:
        """仲裁排序：来源优先级在前，同一来源内再看证据的"一手程度"。"""

        src = claim.source.split(":", 1)[0]
        position = priority.index(src) if src in priority else len(priority)
        return (position, -claim.specificity)

    ordered = sorted(real, key=rank)
    winner = ordered[0]
    result.resolved_to = winner.value
    result.rule = f"source_priority:{winner.source}"
    if result.conflict:
        result.note = (
            f"{len(real)} 个来源给出不同值，按优先级取 {winner.source}"
            + ("（同一来源内取原始 JSON 值）" if winner.specificity else "")
            + "；其余值保留在 conflicts 里可见"
        )
    else:
        result.note = f"{len(real)} 个来源一致"
    return result


async def consistency_check(
    vuln: dict[str, Any],
    enrichments: list[dict[str, Any]] | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """F6 入口。"""

    settings = get_settings()
    priority = source_priority()
    tolerance = settings.enrich_cvss_tolerance

    claims = collect_claims(vuln, enrichments)
    # 注意：这里按**字段名**逐一比对，传的是整份 claims（第一版误传单条 claim，
    # 导致"2 个来源冲突"退化成单源、冲突检不出来——已有专项测试守住）
    comparisons = [compare_field(name, claims, priority, tolerance) for name in COMPARED_FIELDS]

    evidence = EvidenceBuilder()
    for claim in claims:
        if claim.url:
            evidence.add(claim.source, claim.url, claim.snippet or f"{claim.field}={claim.value}")

    # 字段完整率：有值计 1，来源声明了但值为空计 0.5，完全没声明计 0
    declared = {c.field for c in claims}
    complete = 0.0
    for name in COMPARED_FIELDS:
        cmp = next((c for c in comparisons if c.name == name), None)
        if cmp and cmp.resolved_to not in (None, "", [], {}):
            complete += 1.0
        elif name in declared:
            complete += 0.5
    field_completeness = complete / len(COMPARED_FIELDS)

    conflicted = [c for c in comparisons if c.conflict]
    agreement_ratio = 1.0 - (len(conflicted) / len(COMPARED_FIELDS))
    evidence_coverage = min(1.0, len(evidence) / max(1, len(claims))) if claims else 0.0
    coverage_sources = {c.source for c in claims}
    single_source = len(coverage_sources) < 2

    quality_score = round(
        0.4 * field_completeness + 0.3 * agreement_ratio + 0.3 * evidence_coverage, 3
    )
    if single_source:
        # 单源情况下"一致率"没有意义，质量分封顶 0.6
        quality_score = min(quality_score, 0.6)

    consensus = [
        {
            "field": c.name,
            "value": c.resolved_to,
            "source": (c.claims[0].source if c.claims else ""),
            "agreement": round(
                len([x for x in c.claims if _norm(x.value) == _norm(c.resolved_to)])
                / max(1, len(c.claims)),
                3,
            ),
            "values": [x.as_json() for x in c.claims],
        }
        for c in comparisons
        if c.resolved_to not in (None, "", [], {})
    ]

    conflicts = [
        {
            "field": c.name,
            "severity": "high" if c.name in {"cvss_score", "fixed_version"} else "medium",
            "values": [x.as_json() for x in c.claims],
            "resolved_to": c.resolved_to,
            "rule": c.rule,
            "note": c.note,
        }
        for c in conflicted
    ]

    # 时间线（D3）：披露 → 补丁 → 在野利用
    timeline = build_timeline(vuln, enrichments)

    degraded_to: str | None = None
    degraded_reason = ""
    model = "rule-based"

    if conflicts:
        first = conflicts[0]
        explanation, mg1_result = await mg1.json_complete(
            [
                {
                    "role": "system",
                    "content": "你是情报一致性仲裁员。用不超过 60 字的中文说明该冲突的处理理由，"
                    '只输出 JSON：{"explanation": "…"}',
                },
                {
                    "role": "user",
                    "content": (
                        f"字段：{first['field']}\n冲突值：{first['values']}\n"
                        f"仲裁结果：{first['resolved_to']}（规则 {first['rule']}）"
                    ),
                },
            ],
            task="reason",
            max_tokens=200,
            node="enrich.consistency",
            agent="EnrichAgent",
        )
        if explanation and explanation.get("explanation"):
            first["note"] = str(explanation["explanation"])[:120]
            model = mg1_result.model
        else:
            degraded_to = "rule"
            degraded_reason = "MG1 不可用，冲突理由改用模板句（仲裁规则本身仍是确定性计算）"
    elif single_source:
        degraded_to = "rule"
        degraded_reason = "仅单源情报，无法做跨源一致性校验，质量分封顶 0.6"

    if not evidence:
        evidence.add(
            "rule",
            None,
            f"可比较来源 {len(coverage_sources)} 个，字段完整率 {field_completeness:.2f}",
        )

    value = {
        "consensus": consensus,
        "conflicts": conflicts,
        "timeline": timeline,
        "quality_score": quality_score,
        "field_completeness": round(field_completeness, 3),
        "agreement_ratio": round(agreement_ratio, 3),
        "evidence_coverage": round(evidence_coverage, 3),
        "source_coverage": dict.fromkeys(sorted(coverage_sources), True),
        "arbitration_priority": list(priority),
        "single_source": single_source,
        "trace_refs": [e["evidence_id"] for e in evidence.items],
    }

    confidence = round(min(0.5 + 0.4 * quality_score, 0.9), 3)
    if degraded_to:
        confidence = min(confidence, 0.6)

    result = build_result(
        "consistency",
        value,
        evidence,
        confidence,
        source=sorted(coverage_sources) or ["rule"],
        model=model,
        trace_id=trace_id,
        degraded_to=degraded_to,
        degraded_reason=degraded_reason,
        quality_score=quality_score,
        note=f"检出 {len(conflicts)} 处冲突" if conflicts else "无冲突",
    )
    if conflicts:
        write_badcase(vuln, conflicts)
    return result


def build_timeline(
    vuln: dict[str, Any], enrichments: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """D3 事件脉络：披露 → 补丁 → 在野利用。时间点必须带来源。"""

    events: list[dict[str, Any]] = []
    published = vuln.get("published_at")
    if published:
        events.append(
            {
                "stage": "disclosed",
                "date": str(published)[:10],
                "source": "nvd" if vuln.get("cve_id") else "item",
                "url": (vuln.get("sources") or [{}])[0].get("url"),
            }
        )

    for item in enrichments or []:
        value = item.get("value") or {}
        if item.get("dimension") == "fix":
            upgrade = value.get("upgrade") or {}
            if upgrade.get("target_version"):
                events.append(
                    {
                        "stage": "patched",
                        "date": None,
                        "source": str(upgrade.get("source") or "vendor"),
                        "url": upgrade.get("url"),
                        "detail": f"修复版本 {upgrade['target_version']}",
                    }
                )
        if item.get("dimension") == "poc":
            pocs = value.get("pocs") or []
            if pocs:
                events.append(
                    {
                        "stage": "poc",
                        "date": None,
                        "source": "github",
                        "url": pocs[0].get("url"),
                        "detail": f"检索到 {len(pocs)} 个候选验证代码",
                    }
                )

    if vuln.get("kev"):
        events.append(
            {
                "stage": "exploited",
                "date": None,
                "source": "cisa",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "detail": "已列入 CISA KEV（在野利用）",
            }
        )
    return events


def write_badcase(vuln: dict[str, Any], conflicts: list[dict[str, Any]]) -> str | None:
    """把冲突落成 badcase JSONL（答辩素材）。写失败不影响主链路。"""

    path = Path(get_settings().enrich_badcase_dir) / "conflicts.jsonl"
    record = {
        "ts": utcnow().isoformat(),
        "vuln_id": vuln.get("id") or vuln.get("vuln_id"),
        "cve_id": vuln.get("cve_id"),
        "conflicts": conflicts,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:  # pragma: no cover - 磁盘问题不该影响富化
        logger.warning("badcase 写入失败: %s", exc)
        return None
    return str(path)

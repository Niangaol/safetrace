"""CVSS 3.1 / 4.0 向量解析与取值。

分工（刻意）：**LLM 不产出任何分数**，分数一律本地按规范算或直接取官方值。
`score_source` 明示分数从哪来，避免"看着像算的其实是编的"：

| score_source | 含义 |
| --- | --- |
| `computed` | 我们按 CVSS 3.1 规范本地计算（可复核） |
| `official` | 直接采用 NVD/厂商给的 baseScore，并记录来源 |
| `unavailable` | 向量缺失或不可解析 —— **不猜分数**，置 null |
"""

from __future__ import annotations

import math
import re
from decimal import ROUND_CEILING, Decimal
from typing import Any

# 异构权重表：除 PR 是二级嵌套外，其余均为 指标 -> 取值 -> 权重
WEIGHTS: dict[str, Any] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # scope 未改变
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

V31_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# CVSS 4.0 的基础指标集合（不做本地算分，只校验完整性）
V40_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def roundup(value: float) -> float:
    """CVSS v3.1 附录 A 的 Roundup：进位到小数点后 1 位。

    "the smallest number, specified to one decimal place, that is equal to or
    higher than its input" —— 因此 4.02 → 4.1，而 4.00 → 4.0。
    """

    if value <= 0:
        return 0.0
    scaled = Decimal(str(value)) * 10
    return float(scaled.to_integral_value(rounding=ROUND_CEILING) / 10)


# 内部别名，保持历史调用点可用
_roundup = roundup


def parse_vector(vector: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (vector or "").split("/"):
        if ":" in part:
            key, _, value = part.partition(":")
            key = key.strip()
            if key.upper().startswith("CVSS"):
                continue  # 跳过 "CVSS:3.1" 版本前缀
            out[key] = value.strip()
    return out


def vector_version(vector: str | None) -> str | None:
    """从向量字符串里取版本号（`CVSS:3.1/...` → `3.1`）。"""

    match = re.match(r"^\s*CVSS:(\d\.\d)", vector or "")
    return match.group(1) if match else None


def is_valid_vector(vector: str | None) -> bool:
    """向量是否可被本地解析（3.1 完整指标 / 4.0 基础指标）。"""

    version = vector_version(vector)
    metrics = parse_vector(vector or "")
    if version == "3.1":
        return all(k in metrics for k in V31_METRICS)
    if version == "4.0":
        return all(k in metrics for k in V40_METRICS)
    return False


def score_vector_31(vector: str) -> float | None:
    """返回 CVSS 3.1 基础分（0.0~10.0）；向量不合法返回 None。"""

    metrics = parse_vector(vector)
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(k not in metrics for k in required):
        return None
    try:
        scope_changed = metrics["S"] == "C"
        pr = WEIGHTS["PR"]["C" if scope_changed else "U"][metrics["PR"]]
        exploitability = (
            8.22
            * WEIGHTS["AV"][metrics["AV"]]
            * WEIGHTS["AC"][metrics["AC"]]
            * pr
            * WEIGHTS["UI"][metrics["UI"]]
        )
        isc_base = 1 - (1 - WEIGHTS["C"][metrics["C"]]) * (1 - WEIGHTS["I"][metrics["I"]]) * (
            1 - WEIGHTS["A"][metrics["A"]]
        )
        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base
        if impact <= 0:
            return 0.0
        if scope_changed:
            raw = min(1.08 * (impact + exploitability), 10.0)
        else:
            raw = min(impact + exploitability, 10.0)
        return _roundup(raw)
    except KeyError:
        return None


def resolve_score(
    vector: str | None, official_score: float | None = None
) -> tuple[float | None, str]:
    """决定最终分数与来源：本地算 > 官方值 > 不可用。

    优先本地计算（可复核），因为"官方分数"可能来自第三方而不是 NVD 本体；
    官方值仍会保留在 `value.official_score` 里供 F6 做一致性比对。
    """

    if vector and vector_version(vector) == "3.1":
        computed = score_vector_31(vector)
        if computed is not None:
            return computed, "computed"
    if official_score is not None:
        return float(official_score), "official"
    return None, "unavailable"


def severity_label(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def vector_from_components(
    *, av: str, ac: str, pr: str, ui: str, scope: str, c: str, i: str, a: str
) -> str:
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"


def qualitative(score: float | None) -> str:
    """CVSS 定性等级（None/Low/Medium/High/Critical）。"""

    if score is None or score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def risk_ratio(score: float | None) -> float:
    """粗略的利用风险权重，用于 triage 排序（不作为评分依据）。"""

    if not score:
        return 0.0
    return round(min(max(score / 10.0, 0.0), 1.0), 3) * (1 + 0.05 * math.log1p(score))

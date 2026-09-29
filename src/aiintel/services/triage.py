"""动态优先级：用 EPSS / KEV / CVSS 给情报排序（Y5 派单的决策点）。

为什么单独一个模块：优先级是**派单决策**，不是富化结论。放这里能让
`node_triage` 保持"薄"，也让"为什么这条排第一"可以脱离编排单独复算与测试。

三条设计约束（与 `docs/路线评估-优先级与RAG.md` §2.3 一致）：

1. **权重版本化 + 可复算**（照抄 DQ1 的 `gate_version` 做法）：
   同 `policy_version` + 同输入 ⇒ 同分数、同排名。分数里不读时钟、不调 LLM。
2. **绝对不能用 KEV 单独排序**：KEV 只覆盖约 1% 的漏洞
   （`services/collectors/nvd.py:52` 有警告），99% 的条目拿不到该信号会全部同分。
   所以 KEV 是**加权项**，主信号是 EPSS 概率 + CVSS 影响。
3. **职责切分**：triage **决定**优先级（它能看全批次，是唯一有这个视角的节点）；
   F5 **消费**优先级（排第一的给详细版本号/补丁链接，排后的给通用模板）。

诚实边界（必须写进报告）：`asset_scan_enabled=False` 时**拿不到"业务暴露面"**，
所以本模块算的是"**被利用概率优先**"，**不是"对我们最危险"**。不要假装算出了业务风险。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: 当前策略版本。改权重/阈值/分档必须同步 +1，否则历史排名不可复算。
POLICY_VERSION = "1.0.0"

#: 版本化权重（每版本一套，禁止原地改）
POLICY_WEIGHTS: dict[str, dict[str, float]] = {
    "1.0.0": {
        "cvss": 0.4,  # 影响面
        "epss": 0.45,  # 被利用概率（主信号）
        "kev": 0.15,  # 在野利用（罕见但决定性）
    },
}

#: 优先级分档线（版本化，与权重同版本）
PRIORITY_THRESHOLDS: dict[str, tuple[float, float, float]] = {
    # (urgent, high, normal)；低于 normal 即 low
    "1.0.0": (0.75, 0.55, 0.3),
}

#: 排序输出档位：`urgent` / `high` / `normal` / `low`
PRIORITIES: tuple[str, ...] = ("urgent", "high", "normal", "low")

#: 派单路由：`detail_enrich` 进 Top-N（F5 给详细建议），其余 `template_enrich`
ROUTE_DETAIL = "detail_enrich"
ROUTE_TEMPLATE = "template_enrich"

#: KEV 命中时的最低优先级 —— 在野利用的情报不能被排到队尾
KEV_FLOOR = "high"

#: 质量分权重：低质量条目整体降权（DQ1 的产物），但不至于反过来压过 KEV
QUALITY_WEIGHT = 0.1


class TriagePolicyError(ValueError):
    """策略参数非法（如未知 policy_version）。"""


@dataclass(slots=True)
class TriageCandidate:
    """一条候选的排序结果。所有字段都是可复算的确定性产物。"""

    vuln_id: str
    score: float
    priority: str
    severity: str = "unknown"
    cvss_score: float | None = None
    epss: float | None = None
    kev: bool = False
    quality_score: float | None = None
    route: str = ROUTE_TEMPLATE
    rank: int = 1
    reasons: list[str] = field(default_factory=list)
    policy_version: str = POLICY_VERSION

    def to_order_payload(self) -> dict[str, Any]:
        """→ `enrich.triage` 载荷（过 `LocalPayloads.json::TriageOrder`）。"""

        payload: dict[str, Any] = {
            "vuln_id": self.vuln_id,
            "priority": self.priority,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "epss": self.epss,
            "kev": self.kev,
            "score": round(self.score, 4),
            "rank": self.rank,
            "route": self.route,
            "reasons": self.reasons,
            "policy_version": self.policy_version,
        }
        return payload


def weights_for(policy_version: str = POLICY_VERSION) -> dict[str, float]:
    try:
        return dict(POLICY_WEIGHTS[policy_version])
    except KeyError:
        raise TriagePolicyError(
            f"未知 policy_version {policy_version!r}，允许 {sorted(POLICY_WEIGHTS)}"
            "（换权重必须换版本号，否则历史排名不可复算）"
        ) from None


def thresholds_for(policy_version: str = POLICY_VERSION) -> tuple[float, float, float]:
    try:
        return PRIORITY_THRESHOLDS[policy_version]
    except KeyError:
        raise TriagePolicyError(f"未知 policy_version {policy_version!r} 的分档线") from None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def score_item(item: dict[str, Any], *, policy_version: str = POLICY_VERSION) -> TriageCandidate:
    """给单条情报打分。确定性：同输入 + 同版本 ⇒ 同输出。

    三项信号都先**夹紧到定义域**再参与加权（CVSS 0~10、EPSS 0~1）：
    上游偶尔会给出越界值（例如 EPSS=3.0），不清洗数据，但也绝不让它把总分推过 1
    —— 那会让 `TriageOrder.score` 违反契约（`maximum: 1`）。
    """

    weights = weights_for(policy_version)

    cvss = _clamp(_as_float(item.get("cvss_score")) or 0.0, 0.0, 10.0)
    epss = _clamp(_as_float(item.get("epss")) or 0.0, 0.0, 1.0)
    kev = bool(item.get("kev"))
    quality = _as_float(item.get("quality_score"))

    # 三项加权后**归一**回 0~1：否则 max_score 会落在 0.4+0.45+0.15=1.0 之外
    weighted = (
        weights["cvss"] * (cvss / 10.0)
        + weights["epss"] * epss
        + weights["kev"] * (1.0 if kev else 0.0)
    )
    total_weight = sum(weights.values())
    if quality is not None:
        weighted *= 1.0 - QUALITY_WEIGHT * (1.0 - _clamp(quality, 0.0, 1.0))
        total_weight += 0.0  # 质量是乘性降权，不进分母
    score = _clamp(weighted / total_weight, 0.0, 1.0) if total_weight else 0.0

    reasons: list[str] = []
    if kev:
        reasons.append("已列入 CISA KEV（在野利用）")
    if epss:
        reasons.append(f"EPSS={epss:.3f}")
    if cvss:
        reasons.append(f"CVSS={cvss:.1f}")
    if quality is not None and quality < 0.7:
        reasons.append(f"数据质量偏低（{quality:.2f}）已降权")
    if not reasons:
        reasons.append("三项信号均缺失，仅按缺省参与排序")

    priority = _label(score, kev=kev, policy_version=policy_version)
    vuln_id = str(item.get("cve_id") or item.get("id") or item.get("vuln_id") or "unknown")
    return TriageCandidate(
        vuln_id=vuln_id,
        score=round(score, 4),
        priority=priority,
        severity=str(item.get("severity") or "unknown").lower(),
        cvss_score=cvss or None,
        epss=epss or None,
        kev=kev,
        quality_score=quality,
        reasons=reasons,
        policy_version=policy_version,
    )


def _label(score: float, *, kev: bool, policy_version: str) -> str:
    urgent, high, normal = thresholds_for(policy_version)
    if score >= urgent:
        label = "urgent"
    elif score >= high:
        label = "high"
    elif score >= normal:
        label = "normal"
    else:
        label = "low"

    # KEV 是"罕见但决定性"的信号：命中就不许沉到队尾
    if kev and PRIORITIES.index(label) > PRIORITIES.index(KEV_FLOOR):
        return KEV_FLOOR
    return label


def rank_items(
    items: list[dict[str, Any]],
    *,
    limit: int | None = None,
    policy_version: str = POLICY_VERSION,
) -> list[TriageCandidate]:
    """按分数降序排名，标注 `rank` 与 `route`。

    排序是**全序**（同分再按 vuln_id 字典序），因此同输入必得同排名 ——
    否则"为什么这条排第一"无法复算。

    KEV 条目有两条安全网（在野利用不能被排在队尾）：
    1. 优先级至少 `KEV_FLOOR`（见 `_label`）；
    2. **路由强制 `detail_enrich`** —— 否则它会被降级成通用模板建议，
       把"已知在野利用"当普通条目处理，这在演示与实战里都说不通。
    """

    candidates = [score_item(item, policy_version=policy_version) for item in items]
    candidates.sort(key=lambda c: (-c.score, c.vuln_id))

    detail_limit = limit if limit is not None else len(candidates)
    for index, candidate in enumerate(candidates, start=1):
        candidate.rank = index
        if index <= detail_limit or candidate.kev:
            candidate.route = ROUTE_DETAIL
        else:
            candidate.route = ROUTE_TEMPLATE
    return candidates


__all__ = [
    "KEV_FLOOR",
    "POLICY_VERSION",
    "POLICY_WEIGHTS",
    "PRIORITIES",
    "PRIORITY_THRESHOLDS",
    "ROUTE_DETAIL",
    "ROUTE_TEMPLATE",
    "TriageCandidate",
    "TriagePolicyError",
    "rank_items",
    "score_item",
    "thresholds_for",
    "weights_for",
]

"""智能体共享状态与图构建。

MonitorGraph：collect → normalize → dedup → triage → enrich → verify → persist → alert → report
Supervisor 通过条件边按"数据成熟度"路由，失败走 repair 分支（重试 → 换源 → 降级）。
"""

from __future__ import annotations

from typing import Any, TypedDict, cast

from aiintel.db.models import Vuln


class IntelState(TypedDict, total=False):
    """跨节点共享状态。budget 字段用于成本治理（累计 token/金额）。"""

    trace_id: str
    task: str
    sources: list[str]
    mode: str

    raw_items: list[dict[str, Any]]
    merged: list[dict[str, Any]]
    vuln: dict[str, Any]
    vuln_id: str
    enrichments: list[dict[str, Any]]

    #: DQ1 质量判定：`item_id -> QualityVerdict.to_payload()`（见 services/dq1.py）
    quality_verdicts: dict[str, dict[str, Any]]
    #: 逐条 `intel.items` 的 event_id：`item_key -> event_id`，供 dq1 挂因果链
    intel_causation: dict[str, str]
    #: 动态优先级排名（`services/triage.py` 的 TriageOrder 载荷列表，队首最该先修）
    triage_queue: list[dict[str, Any]]

    priority: str
    ai_risk_category: str
    severity: str

    failed_node: str
    retry_map: dict[str, int]
    errors: list[str]
    degraded: bool
    budget: dict[str, Any]
    report: str
    causality: dict[str, str]

    collected: int
    raw_persisted: int
    merged_count: int
    enriched_count: int
    alerts: int


def new_state(trace_id: str, task: str = "monitor_cycle", **extra: Any) -> IntelState:
    base: IntelState = IntelState(
        trace_id=trace_id,
        task=task,
        sources=[],
        mode="incremental",
        raw_items=[],
        merged=[],
        vuln={},
        vuln_id="",
        enrichments=[],
        quality_verdicts={},
        intel_causation={},
        triage_queue=[],
        priority="normal",
        ai_risk_category="",
        severity="",
        failed_node="",
        retry_map={},
        errors=[],
        degraded=False,
        budget={"tokens": 0, "cost_cny": 0.0},
        report="",
        # 主题 -> 最近一次发布的 event_id。用于给下游事件填 causation_id，
        # 把 raw.docs -> intel.items -> enrich.items 串成因果链（权威信封要求）。
        causality={},
        collected=0,
        raw_persisted=0,
        merged_count=0,
        enriched_count=0,
        alerts=0,
    )
    # extra 可能带来调用方自定义键（例如 test 用的 fake_llm），不属于 IntelState 声明字段
    merged: dict[str, Any] = {**base, **extra}
    return cast(IntelState, merged)


def vuln_to_dict(vuln: Vuln) -> dict[str, Any]:
    return {
        "id": vuln.id,
        "cve_id": vuln.cve_id,
        "ghsa_id": vuln.ghsa_id,
        "title": vuln.title,
        "description": vuln.description,
        "severity": vuln.severity,
        "cvss_vector": vuln.cvss_vector,
        "cvss_score": vuln.cvss_score,
        "cwe": vuln.cwe or [],
        "cpe": vuln.cpe or [],
        "ai_risk_category": vuln.ai_risk_category,
        "exploit_status": vuln.exploit_status,
        "published_at": vuln.published_at.isoformat() if vuln.published_at else None,
    }

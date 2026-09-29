"""指标、Agent 轨迹、告警、工具目录端点。"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aiintel.agents.tools import registry
from aiintel.api.deps import Auth, DBSession
from aiintel.core.cost import get_cost_guard
from aiintel.db.models import AgentRun, AgentStep, Alert, Chunk, Enrichment, RawItem, Vuln
from aiintel.services.enrich.dimensions import DIMENSIONS

router = APIRouter(tags=["ops"])


def _degraded_ratio(session: Session) -> float:
    """降级占比（FB1：降级必须可见，所以指标上也要能看到它）。"""

    total = session.execute(select(func.count()).select_from(Enrichment)).scalar_one()
    if not total:
        return 0.0
    degraded = session.execute(
        select(func.count()).select_from(Enrichment).where(Enrichment.degraded_to.isnot(None))
    ).scalar_one()
    return round(degraded / total, 3)


def _per_dimension(session: Session) -> dict[str, dict[str, float]]:
    """逐维度指标：覆盖率 / 平均置信度 / 降级率 / Mock 率。

    覆盖率的分母是"已富化的漏洞数"（而不是全部漏洞），否则维度之间不可比。
    """

    enriched_vulns = (
        session.execute(select(func.count(func.distinct(Enrichment.vuln_id)))).scalar_one() or 0
    )
    out: dict[str, dict[str, float]] = {}
    for dimension in DIMENSIONS:
        rows = (
            session.execute(select(Enrichment).where(Enrichment.dimension == dimension))
            .scalars()
            .all()
        )
        if not rows:
            out[dimension] = {
                "records": 0,
                "coverage_ratio": 0.0,
                "confidence_avg": 0.0,
                "degraded_ratio": 0.0,
                "mock_ratio": 0.0,
            }
            continue
        degraded = len([r for r in rows if r.degraded_to])
        mocked = len([r for r in rows if r.mock])
        out[dimension] = {
            "records": len(rows),
            "coverage_ratio": round(len(rows) / enriched_vulns, 3) if enriched_vulns else 0.0,
            "confidence_avg": round(sum(float(r.confidence or 0.0) for r in rows) / len(rows), 3),
            "degraded_ratio": round(degraded / len(rows), 3),
            "mock_ratio": round(mocked / len(rows), 3),
        }
    return out


@router.get("/metrics/overview", dependencies=[Auth])
def metrics_overview(session: Session = DBSession) -> dict[str, Any]:
    guard = get_cost_guard()
    raw_items = session.execute(select(func.count()).select_from(RawItem)).scalar_one()
    vulns = session.execute(select(func.count()).select_from(Vuln)).scalar_one()
    # 用 count(distinct) 而不是 DISTINCT ON：后者只在 PostgreSQL 生效且已被 SQLAlchemy 标记弃用
    enriched_vulns = session.execute(
        select(func.count(func.distinct(Enrichment.vuln_id)))
    ).scalar_one()
    chunks = session.execute(select(func.count()).select_from(Chunk)).scalar_one()

    latencies = [
        (row.fetched_at - row.published_at).total_seconds()
        for row in session.execute(
            select(RawItem).where(RawItem.published_at.isnot(None)).limit(2000)
        ).scalars()
        if row.published_at and (row.fetched_at - row.published_at).total_seconds() >= 0
    ]
    latencies.sort()

    def pct(p: float) -> float | None:
        if not latencies:
            return None
        return round(latencies[min(int(len(latencies) * p), len(latencies) - 1)], 1)

    return {
        "collect": {
            "raw_items": raw_items,
            "vulns": vulns,
            "merge_ratio": round(1 - vulns / raw_items, 3) if raw_items else 0.0,
            "sources": session.execute(
                select(func.count(func.distinct(RawItem.source)))
            ).scalar_one(),
        },
        "latency": {
            "p50_seconds": pct(0.5),
            "p95_seconds": pct(0.95),
            "sla_6h_ratio": (
                round(sum(1 for x in latencies if x <= 6 * 3600) / len(latencies), 3)
                if latencies
                else None
            ),
        },
        "enrich": {
            "coverage_ratio": round(enriched_vulns / vulns, 3) if vulns else 0.0,
            "records": session.execute(select(func.count()).select_from(Enrichment)).scalar_one(),
            "dimensions": len(DIMENSIONS),
            "degraded_ratio": _degraded_ratio(session),
            "per_dimension": _per_dimension(session),
        },
        "knowledge": {"chunks": chunks},
        "agents": {
            "runs": session.execute(select(func.count()).select_from(AgentRun)).scalar_one(),
            "failed": session.execute(
                select(func.count()).select_from(AgentRun).where(AgentRun.state == "error")
            ).scalar_one(),
        },
        "cost": {
            "total_cny": round(guard.spent_today(), 2),
            "daily_budget_cny": guard.daily_budget,
            "degraded": guard.exceeded(),
            "breakdown": {k: round(v, 4) for k, v in guard.breakdown().items()},
        },
    }


@router.get("/agents/tools", dependencies=[Auth])
def tool_catalog() -> dict[str, Any]:
    """Agent 工具白名单（答辩时展示架构与安全约束用）。"""

    return {"tools": registry.catalog()}


@router.get("/agents/runs", dependencies=[Auth])
def list_runs(session: Session = DBSession, limit: int = 20) -> dict[str, Any]:
    rows = (
        session.execute(select(AgentRun).order_by(AgentRun.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "graph": r.graph,
                "trigger": r.trigger,
                "state": r.state,
                "tokens": r.tokens,
                "cost_cny": r.cost_cny,
                "latency_ms": r.latency_ms,
                "error": r.error,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }


@router.get("/agents/runs/{run_id}", dependencies=[Auth])
def get_run(run_id: str, session: Session = DBSession) -> dict[str, Any]:
    run = session.get(AgentRun, run_id)
    if run is None:
        return {"error": "run not found"}
    steps = (
        session.execute(select(AgentStep).filter_by(run_id=run_id).order_by(AgentStep.seq))
        .scalars()
        .all()
    )
    return {
        "id": run.id,
        "state": run.state,
        "cost_cny": run.cost_cny,
        "latency_ms": run.latency_ms,
        "steps": [
            {
                "seq": s.seq,
                "node": s.node,
                "state": s.state,
                "input_summary": s.input_summary,
                "output_summary": s.output_summary,
                "cost_cny": s.cost_cny,
                "latency_ms": s.latency_ms,
                "error": s.error,
            }
            for s in steps
        ],
    }


@router.get("/alerts", dependencies=[Auth])
def list_alerts(session: Session = DBSession, limit: int = 50) -> dict[str, Any]:
    rows = (
        session.execute(select(Alert).order_by(Alert.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": a.id,
                "level": a.level,
                "title": a.title,
                "message": a.message,
                "vuln_id": a.vuln_id,
                "delivered": a.delivered,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in rows
        ]
    }


@router.post("/alerts/test", dependencies=[Auth])
async def test_alert() -> dict[str, Any]:
    from aiintel.core.alerts import AlertManager

    return await AlertManager().test()


@router.get("/reports/daily", dependencies=[Auth])
async def daily_report() -> dict[str, Any]:
    from aiintel.agents.report import build_daily_report
    from aiintel.agents.state import new_state

    return {"markdown": await build_daily_report(new_state(trace_id="api", task="report"))}

"""漏洞查询、详情、证据链、图谱端点。"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aiintel.api.deps import Auth, DBSession, spawn
from aiintel.db.models import Enrichment, GraphEdge, Vuln

logger = logging.getLogger(__name__)
router = APIRouter(tags=["vulns"])


def _serialize(row: Vuln) -> dict[str, Any]:
    return {
        "id": row.id,
        "cve_id": row.cve_id,
        "ghsa_id": row.ghsa_id,
        "title": row.title,
        "severity": row.severity,
        "cvss_score": row.cvss_score,
        "cvss_vector": row.cvss_vector,
        # 动态优先级用的两个信号（services/triage.py 的 KEV/EPSS 加权）。
        # 它们早就落库了（模型里有列、KEV/EPSS 采集器会写入），但一直没往接口外发，
        # 于是前端无法展示"为什么这条排前面"——排序依据看不见，等于白算。
        "epss": row.epss,
        "kev": bool(row.kev),
        "kev_due_date": row.kev_due_date,
        "cwe": row.cwe or [],
        "cpe": row.cpe or [],
        "affected_products": row.affected_products or [],
        "ai_risk_category": row.ai_risk_category,
        "exploit_status": row.exploit_status,
        "quality_score": row.quality_score,
        "published_at": row.published_at.isoformat() if row.published_at else None,
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
        "collect_latency_seconds": (
            (row.fetched_at - row.published_at).total_seconds()
            if row.published_at and row.fetched_at
            else None
        ),
        "source_count": len(row.sources or []),
        "enriched": bool(row.enrichments),
    }


@router.get("/vulns", dependencies=[Auth])
def list_vulns(
    session: Session = DBSession,
    q: str | None = None,
    severity: str | None = None,
    ai_risk_category: str | None = None,
    has_poc: bool | None = None,
    enriched: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    sort: str = Query("published_at", pattern="^(published_at|cvss_score|epss|kev|fetched_at)$"),
) -> dict[str, Any]:
    stmt = select(Vuln)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(Vuln.title.ilike(like), Vuln.description.ilike(like), Vuln.cve_id.ilike(like))
        )
    if severity:
        stmt = stmt.where(Vuln.severity.in_(severity.split(",")))
    if ai_risk_category:
        stmt = stmt.where(Vuln.ai_risk_category == ai_risk_category)
    if enriched is not None:
        stmt = stmt.where(Vuln.enrichments.any() if enriched else ~Vuln.enrichments.any())
    if has_poc is not None:
        # 必须在 SQL 里过滤：放在分页之后会让 total 与实际返回条数不一致
        poc_q = select(Enrichment.vuln_id).where(Enrichment.dimension == "poc")
        stmt = stmt.where(Vuln.id.in_(poc_q) if has_poc else ~Vuln.id.in_(poc_q))

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    # EPSS 允许为空（未覆盖的条目），降序时把 NULL 排在最后而不是最前
    order_expr = (
        func.coalesce(Vuln.epss, -1.0).desc() if sort == "epss" else getattr(Vuln, sort).desc()
    )
    stmt = stmt.order_by(order_expr)
    rows = session.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars().all()

    return {
        "items": [_serialize(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/vulns/{vuln_id}", dependencies=[Auth])
def get_vuln(vuln_id: str, session: Session = DBSession) -> dict[str, Any]:
    row = session.get(Vuln, vuln_id) or session.query(Vuln).filter_by(cve_id=vuln_id).one_or_none()
    if row is None:
        raise HTTPException(404, detail={"error": {"code": "VULN_NOT_FOUND", "message": vuln_id}})
    data = _serialize(row)
    data.update(
        description=row.description,
        summary=row.summary,
        version_ranges=row.version_ranges or [],
        references=[{"url": r.get("url"), "kind": r.get("kind")} for r in (row.references or [])],
        related={
            "papers": [e.value for e in row.enrichments if e.dimension == "paper"],
            "pocs": [e.value for e in row.enrichments if e.dimension == "poc"],
            "fix": [e.value for e in row.enrichments if e.dimension == "fix"],
        },
    )
    return data


@router.get("/vulns/{vuln_id}/evidence", dependencies=[Auth])
def get_evidence(vuln_id: str, session: Session = DBSession) -> dict[str, Any]:
    """证据链：富化字段 + 来源片段 + 关系子图。"""

    row = session.get(Vuln, vuln_id) or session.query(Vuln).filter_by(cve_id=vuln_id).one_or_none()
    if row is None:
        raise HTTPException(404, detail={"error": {"code": "VULN_NOT_FOUND", "message": vuln_id}})

    enrichments = (
        session.query(Enrichment)
        .filter_by(vuln_id=row.id)
        .order_by(Enrichment.dimension, Enrichment.version.desc())
        .all()
    )
    latest: dict[str, Enrichment] = {}
    for item in enrichments:
        latest.setdefault(item.dimension, item)

    edges = session.query(GraphEdge).filter_by(src_type="vuln", src_id=row.id).all()
    return {
        "enrichments": [
            {
                "dimension": e.dimension,
                "value": e.value,
                "source": e.source or [],
                "evidence": e.evidence,
                "confidence": e.confidence,
                "model": e.model,
                "agent": e.agent,
                "version": e.version,
                "mock": bool(e.mock),
                "degraded_to": e.degraded_to,
                "degraded_reason": e.degraded_reason or "",
                "quality_score": e.quality_score,
                "trace_id": e.trace_id,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in latest.values()
        ],
        "graph": {
            "nodes": [{"id": row.id, "type": "vuln", "label": row.cve_id or row.id}]
            + [{"id": e.dst_id, "type": e.dst_type, "label": e.dst_id} for e in edges],
            "edges": [
                {"src": e.src_id, "rel": e.rel, "dst": e.dst_id, "type": e.dst_type} for e in edges
            ],
        },
    }


@router.get("/graph/neighbors", dependencies=[Auth])
async def graph_neighbors(
    node_id: str,
    hops: int = Query(2, ge=1, le=3),
    rels: str | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    from aiintel.services.knowledge.retrieval import neighbors

    graph = await neighbors(node_id, hops=hops, limit=limit)
    if rels:
        allow = set(rels.split(","))
        graph["nodes"] = [n for n in graph["nodes"] if n["rel"] in allow]
    return graph


@router.post("/enrich/backfill", status_code=202, dependencies=[Auth])
async def backfill(payload: dict, background: BackgroundTasks) -> dict[str, Any]:
    """离线批量补富化（建议钉在闲时时段跑，见成本治理）。"""

    from aiintel.services.enrich.agent import EnrichAgent

    task_id = f"tsk_{uuid.uuid4().hex[:12]}"
    vuln_ids: list[str] = payload.get("vuln_ids") or []
    dimensions: list[str] | None = payload.get("dimensions")

    async def _run() -> None:
        try:
            await EnrichAgent().backfill(vuln_ids, dimensions)
        except Exception:  # noqa: BLE001
            logger.exception("backfill 失败 task=%s", task_id)

    spawn(background, _run, name=task_id)
    return {"task_id": task_id, "queued": len(vuln_ids)}

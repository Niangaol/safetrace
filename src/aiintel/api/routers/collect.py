"""采集相关端点：手动触发、webhook 接收、状态查询。"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from aiintel.api.deps import Auth, DBSession, spawn
from aiintel.db.models import SyncWatermark
from aiintel.services.collectors.ghsa import parse_webhook_event, verify_signature

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/collect", tags=["collect"])


class SyncRequest(BaseModel):
    sources: list[str] | None = None
    mode: str = Field(default="incremental", pattern="^(incremental|full)$")


@router.post("/sync", status_code=202, dependencies=[Auth])
async def trigger_sync(payload: SyncRequest, background: BackgroundTasks) -> dict[str, Any]:
    """手动触发一轮采集（演示/补数）。异步执行，立即返回 task_id。"""

    from aiintel.agents.graph import run_monitor_cycle

    task_id = f"tsk_{uuid.uuid4().hex[:12]}"
    trace = f"trace_{uuid.uuid4().hex[:8]}"
    accepted = [s for s in (payload.sources or []) if s] or None

    async def _run() -> None:
        try:
            await run_monitor_cycle(sources=accepted, mode=payload.mode, trace_id=trace)
        except Exception:  # noqa: BLE001 - 后台任务异常只记录
            logger.exception("采集任务失败 task=%s", task_id)

    spawn(background, _run, name=task_id)
    return {"task_id": task_id, "trace_id": trace, "accepted_sources": accepted or "all"}


@router.post("/hook/ghsa", status_code=202, dependencies=[Auth])
async def ghsa_webhook(request: Request, background: BackgroundTasks) -> dict[str, Any]:
    """GitHub webhook：实时链路。校验签名后直接入库，延迟接近 0。"""

    from aiintel.config import get_settings

    body = await request.body()
    secret = get_settings().github_webhook_secret
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(body, signature, secret):
        return {"received": 0, "enqueued": 0, "error": "invalid signature"}

    import json

    payload = json.loads(body or b"{}")
    items = parse_webhook_event(request.headers.get("X-GitHub-Event", ""), payload)
    if not items:
        return {"received": 0, "enqueued": 0}

    from aiintel.services.ingest.pipeline import persist_raw_items

    enqueued = await persist_raw_items([i.to_dict() for i in items])
    return {"received": len(items), "enqueued": enqueued}


@router.get("/status", dependencies=[Auth])
def collect_status(session: Session = DBSession) -> dict[str, Any]:
    rows = session.query(SyncWatermark).all()
    return {
        "watermarks": [
            {
                "source": r.source,
                # last_sync_at 用本轮采集时间。只报 last_full_sync 会让大屏看起来像很久没更新
                "last_sync_at": (
                    r.last_sync_at.isoformat()
                    if r.last_sync_at
                    else (r.last_full_sync.isoformat() if r.last_full_sync else None)
                ),
                "last_full_sync_at": r.last_full_sync.isoformat() if r.last_full_sync else None,
                "last_published_at": r.last_published_at.isoformat()
                if r.last_published_at
                else None,
                "items_last_run": r.items_last_run,
                "success": not r.last_error,
                "error": r.last_error,
            }
            for r in rows
        ],
        "queue_depth": _running_tasks(session),
    }


def _running_tasks(session: Session) -> int:
    """在跑的 Agent 轮次数量。

    事件总线用的是 Pub/Sub，没有可查询的积压深度；契约里的 queue_depth
    用运行中的 AgentRun 数量来近似，比报一个恒为 0 的值更贴近真实负载。
    """

    from sqlalchemy import func

    from aiintel.db.models import AgentRun

    return session.execute(
        select(func.count()).select_from(AgentRun).where(AgentRun.state.in_(("running", "pending")))
    ).scalar_one()

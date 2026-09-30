"""问答端点：SSE 流式 + 非流式。"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from aiintel.api.deps import Auth
from aiintel.services.qa.agent import QAAgent, dumps_event

router = APIRouter(prefix="/qa", tags=["qa"])


class ChatRequest(BaseModel):
    session_id: str | None = None
    question: str = Field(min_length=2, max_length=1000)
    top_k: int = Field(default=8, ge=1, le=20)
    stream: bool = True
    filters: dict[str, Any] | None = None
    # C-05 数据域（public/private）：private 只许本地/隔离边界出网，否则硬拒。
    data_domain: str = Field(default="public", pattern="^(public|private)$")


async def _sse(events: AsyncIterator[dict[str, Any]]) -> AsyncIterator[str]:
    """把 agent 的事件字典序列化成 SSE 帧（data: {json}\\n\\n）。"""

    async for event in events:
        yield dumps_event(event)


@router.post("/chat", dependencies=[Auth])
async def chat(payload: ChatRequest):
    agent = QAAgent()
    if payload.stream:
        return StreamingResponse(
            _sse(
                agent.answer_stream(
                    payload.question,
                    session_id=payload.session_id,
                    filters=payload.filters,
                    top_k=payload.top_k,
                    data_domain=payload.data_domain,
                )
            ),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    return await agent.answer(
        payload.question,
        session_id=payload.session_id,
        filters=payload.filters,
        top_k=payload.top_k,
        data_domain=payload.data_domain,
    )

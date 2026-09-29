"""API 依赖：鉴权与会话。"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine, Iterator
from typing import Any

from fastapi import BackgroundTasks, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from aiintel.config import get_settings
from aiintel.db.base import get_session

logger = logging.getLogger(__name__)


def require_token(authorization: str = Header(default="")) -> None:
    settings = get_settings()
    if settings.app_env == "dev" and not authorization:
        return
    expected = f"Bearer {settings.api_token}"
    if authorization != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "UNAUTHORIZED", "message": "Token 缺失或错误"}},
        )


def db_session() -> Iterator[Session]:
    yield from get_session()


Auth = Depends(require_token)
DBSession = Depends(db_session)


def spawn(
    background: BackgroundTasks, coro: Callable[[], Coroutine[Any, Any, None]], *, name: str
) -> None:
    """把协程工厂挂到 BackgroundTasks。

    BackgroundTasks 会把同步 callable 丢进线程池执行，那里没有运行中的事件循环，
    直接 asyncio.create_task 会抛 RuntimeError。因此在请求线程里先抓住 loop，
    再注册一个只负责 create_task 的同步函数。传工厂而非协程对象，避免提前创建
    协程却没人 await 而泄漏。
    """

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # pragma: no cover - 有 uvicorn 就有 loop
        logger.warning("无运行中的事件循环，跳过后台任务 %s", name)
        return

    def _run() -> None:
        task: asyncio.Task[None] = loop.create_task(coro())
        task.add_done_callback(lambda t: _log_failure(t, name))

    background.add_task(_run)


def _log_failure(task: asyncio.Task[None], name: str) -> None:
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("后台任务 %s 失败: %s", name, exc, exc_info=exc)

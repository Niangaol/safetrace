"""FastAPI 入口。"""

from __future__ import annotations

import locale
import logging
import socket
import subprocess
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from aiintel.api.routers import collect, metrics, qa, vulns
from aiintel.config import get_settings
from aiintel.core.metrics import setup_logging

logger = logging.getLogger(__name__)
settings = get_settings()


def _local_hosts() -> list[str]:
    """本机可能被用来访问前端的地址：机器名 + 每张网卡的 IPv4。

    getaddrinfo 只跟着机器名解析，多网卡时给不全，所以再兜底扫一遍 ipconfig。
    这一段在导入期执行，任何一步失败都只应缩小放行范围，绝不能让 app 导入不了。
    """

    hosts = {socket.gethostname()}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = str(info[4][0])
            if addr and not addr.startswith(("127.", "169.254.")):
                hosts.add(addr)
    except OSError:  # pragma: no cover - 取决于宿主机 DNS
        logger.debug("解析本机地址失败，仅放行 localhost")

    # 中文 Windows 的 ipconfig 输出是 GBK：必须显式给 encoding，
    # 否则 PYTHONUTF8=1 时解码在子线程里炸掉，stdout 变 None
    try:
        proc = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            timeout=5,
            check=False,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
        )
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            # 形如 "  IPv4 Address. . . . . . . . . . . : 10.40.133.189"
            if "IPv4" in line and ":" in line:
                candidate = line.rsplit(":", 1)[1].strip()
                if candidate and not candidate.startswith(("127.", "169.254.")):
                    hosts.add(candidate)
    except Exception:  # pragma: no cover - 非 Windows / 沙箱里没有 ipconfig
        logger.debug("ipconfig 不可用，仅放行已解析到的地址", exc_info=True)

    return sorted(hosts)


_LOCAL_HOSTS = _local_hosts()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.log_level)
    logger.info("启动 %s env=%s", app.title, settings.app_env)
    yield
    from aiintel.core.llm import get_llm

    await get_llm().aclose()


app = FastAPI(
    title="AI 安全知识情报系统 API",
    version="0.1.0",
    description="智能体驱动的 AI 安全知识情报系统（赛题九）",
    lifespan=lifespan,
)
# 前端走 vite 代理时是同源请求，CORS 只在直连 8000 时才生效。
# 只放行本机地址（localhost / 127.0.0.1 / 机器名 / 各网卡 IP），不放行任意来源。
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://[::1]:5173",
] + [f"http://{host}:5173" for host in _LOCAL_HOSTS]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api/v1"
app.include_router(collect.router, prefix=API_PREFIX)
app.include_router(vulns.router, prefix=API_PREFIX)
app.include_router(qa.router, prefix=API_PREFIX)
app.include_router(metrics.router, prefix=API_PREFIX)
app.mount("/metrics", make_asgi_app())


@app.get("/health", tags=["system"])
def health() -> dict[str, Any]:
    return {"status": "ok", "version": app.version, "env": settings.app_env}


@app.get(f"{API_PREFIX}/system/health", tags=["system"])
def system_health() -> dict[str, Any]:
    """健康检查 + 自愈状态（答辩自愈演示用）。"""

    from aiintel.core.cost import get_cost_guard

    guard = get_cost_guard()
    return {
        "status": "ok",
        "llm": {
            "provider": settings.llm_provider,
            "flash_model": settings.llm_flash_model,
            "pro_model": settings.llm_pro_model,
            "local_model": settings.llm_local_model,
            "degraded": guard.exceeded(),
        },
        "cost": {
            "spent_today_cny": round(guard.spent_today(), 4),
            "daily_budget_cny": guard.daily_budget,
        },
    }

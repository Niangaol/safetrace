"""真实启动 uvicorn 并跑 HTTP 冒烟，验证 lifespan / 路由 / SSE 帧格式。

不走 TestClient，因为这里要验证的是进程级行为（lifespan、真实 uvicorn 栈）。
不需要数据库/Redis/LLM：被测端点都在鉴权通过后立刻返回，且 lifespan 里
只做日志初始化与 LLM 客户端懒加载。
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn

BASE = "http://127.0.0.1:8124"


@pytest.fixture(scope="module")
def server():
    os.environ.setdefault("APP_ENV", "dev")
    os.environ.setdefault("API_TOKEN", "")
    config = uvicorn.Config(
        "aiintel.api.main:app",
        host="127.0.0.1",
        port=8124,
        log_level="warning",
        lifespan="on",
    )
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()

    deadline = time.time() + 20
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{BASE}/health", timeout=1).read()
            break
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
            if not thread.is_alive():
                raise AssertionError("uvicorn 线程提前退出") from exc
            time.sleep(0.3)
    else:  # pragma: no cover - 仅在启动超时时触发
        raise AssertionError(f"uvicorn 启动超时：{last_error}")

    yield srv
    srv.should_exit = True
    thread.join(timeout=10)


def _get(path: str) -> tuple[int, object]:
    with urllib.request.urlopen(f"{BASE}{path}", timeout=10) as res:
        body = res.read().decode()
        return res.status, json.loads(body) if body else None


def test_health(server):
    status, body = _get("/health")
    assert status == 200
    assert body["status"] == "ok"


def test_system_health(server):
    _, body = _get("/api/v1/system/health")
    assert body["llm"]["flash_model"]
    assert body["cost"]["daily_budget_cny"] > 0


def test_openapi_exposes_all_routers(server):
    _, schema = _get("/openapi.json")
    paths = set(schema["paths"])
    for path in (
        "/api/v1/collect/sync",
        "/api/v1/collect/status",
        "/api/v1/vulns",
        "/api/v1/vulns/{vuln_id}/evidence",
        "/api/v1/enrich/backfill",
        "/api/v1/qa/chat",
        "/api/v1/metrics/overview",
        "/api/v1/reports/daily",
    ):
        assert path in paths, f"缺少 {path}"


def test_prometheus_metrics_exposed(server):
    with urllib.request.urlopen(f"{BASE}/metrics", timeout=10) as res:
        text = res.read().decode()
    assert res.status == 200
    # prometheus_client 至少要吐出 HELP/TYPE
    assert "# HELP" in text


def test_sse_stream_returns_sse_frames(server):
    """问答流必须吐 data: {json} 帧，而不是 Python dict 的 repr。"""

    req = urllib.request.Request(
        f"{BASE}/api/v1/qa/chat",
        data=json.dumps({"question": "最近有哪些高危漏洞？", "stream": True, "top_k": 3}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    frames: list[str] = []
    with urllib.request.urlopen(req, timeout=30) as res:
        assert res.status == 200
        assert res.headers.get("content-type", "").startswith("text/event-stream")
        for raw in res:
            line = raw.decode().strip()
            if line.startswith("data:"):
                frames.append(line[5:].strip())

    assert frames, "没有收到任何 SSE 帧"
    # 每一帧都得是合法 JSON，且带事件名
    for frame in frames:
        assert json.loads(frame) is not None
    kinds = {json.loads(f).get("event") for f in frames}
    assert kinds & {"stage", "done", "error"}, f"事件类型异常：{kinds}"

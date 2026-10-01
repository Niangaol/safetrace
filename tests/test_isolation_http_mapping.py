"""隔离/策略拒绝必须返回**可读业务错误码**，而不是通用 500。

## 这条测试守的是什么

前端在 `docs/前后端交接.md` §4.2 明确要求：

> 若日后策略拒绝，请返回**可读的业务错误码/正文**（前端原样上屏），
> **不要吞成通用 500**。

而此前全仓没有任何异常处理器 —— 策略拒绝（C-05 `private`→cloud 硬拒、
A-03 出网载荷命中私域标记）会冒泡成 FastAPI 的通用 500，
前端只能显示"服务器内部错误"，用户看不到"这是策略拒绝"这个关键信息。

## 两条不能破的约束（一并钉住）

1. **不回显命中内容**：`ScopeViolationError` 只带「标记 + 路径」，
   响应里绝不能出现被扫到的正文（否则隔离机制自己泄漏了私域内容）；
2. **状态码语义**：422（业务策略拒绝）而不是 500（系统故障）——
   前端据此区分"配置/合规问题"与"服务坏了"。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aiintel.api.main import app
from aiintel.core.isolation import (
    IsolationRejectionError,
    ScopeViolation,
    ScopeViolationError,
)

#: 私域正文样例：**绝不能出现在响应里**
SECRET_BODY = "asset_id=SRV-0001 phone=13800000000"


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def reject_routes():
    """临时挂两条会抛隔离错误的路由（避免依赖真实 provider 配置）。"""

    @app.get("/__test__/isolation-reject")
    async def _reject() -> None:
        raise IsolationRejectionError("private 数据域不允许经 cloud 边界出网")

    @app.get("/__test__/scope-violation")
    async def _scope() -> None:
        raise ScopeViolationError(
            [ScopeViolation(marker="asset_id", path="$.messages[0].content")],
            "cloud:deepseek",
        )

    yield
    app.router.routes = [
        r for r in app.router.routes if not getattr(r, "path", "").startswith("/__test__/")
    ]


def test_policy_rejection_returns_422_not_500(client: TestClient, reject_routes) -> None:
    """**核心**：策略拒绝必须是 422 + 可读 code，不能是 500。"""

    resp = client.get("/__test__/isolation-reject")
    assert resp.status_code == 422, (
        f"期望 422，实得 {resp.status_code}（通用 500 会被前端读成系统故障）"
    )
    body = resp.json()
    assert "error" in body, body
    assert body["error"]["code"] == "ISOLATION_POLICY_REJECTED"
    assert body["error"]["message"], "必须给出可读原因"
    assert body["error"].get("hint"), "必须给出可操作提示"


def test_scope_violation_returns_readable_code_without_content(
    client: TestClient, reject_routes
) -> None:
    """出网守卫命中：422 + `EGRESS_SCOPE_VIOLATION`，且**不回显命中内容**。"""

    resp = client.get("/__test__/scope-violation")
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "EGRESS_SCOPE_VIOLATION"
    # 只给标记与路径
    assert body["error"]["violations"] == [{"marker": "asset_id", "path": "$.messages[0].content"}]


def test_response_never_echoes_private_content(client: TestClient, reject_routes) -> None:
    """**脱敏红线**：响应全文不得出现被扫到的私域内容。"""

    for path in ("/__test__/isolation-reject", "/__test__/scope-violation"):
        raw = client.get(path).text
        assert "SRV-0001" not in raw, f"{path} 回显了私域正文"
        assert "13800000000" not in raw, f"{path} 回显了私域正文"


def test_error_shape_matches_existing_convention(client: TestClient, reject_routes) -> None:
    """错误形状与仓内既有约定一致（`{"error": {"code", "message"}}`）。"""

    body = client.get("/__test__/isolation-reject").json()
    assert set(body) == {"error"}
    assert {"code", "message"} <= set(body["error"])

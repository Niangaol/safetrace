"""C-05 数据域隔离闸单测：private 只许本地边界，云端/缓存/占位一律策略拒绝并 fail-closed。

对齐全仓红线：拒绝必须**显式可见**（抛 `IsolationRejectionError`），不许静默降级
到模板/缓存/demo（那等于用占位冒充模型回答私有数据）。
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from aiintel.core.cost import Usage
from aiintel.core.isolation import (
    BOUNDARY_CACHE,
    BOUNDARY_CLOUD,
    BOUNDARY_LOCAL,
    IsolationRejectionError,
    egress_allowed,
    normalize_boundary,
    normalize_domain,
)
from aiintel.core.llm import LLMRouter


def _settings(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "llm_api_key": "",
        "llm_base_url": "https://api.deepseek.com",
        "llm_flash_model": "deepseek-flash",
        "llm_pro_model": "deepseek-v4-pro",
        "llm_local_enabled": True,
        "llm_local_base_url": "http://localhost:11434",
        "llm_local_model": "qwen2.5:7b-instruct",
        "demo_mode": False,
        "llm_cloud_trust_boundary": BOUNDARY_CLOUD,
        "llm_local_trust_boundary": BOUNDARY_LOCAL,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class FakeLLM(LLMRouter):
    """不联网的路由：本地调用打桩，隔离事件不真发。"""

    def __init__(self, settings: SimpleNamespace) -> None:
        super().__init__(
            guard=SimpleNamespace(exceeded=lambda: False, record=lambda *a, **k: 0.0)  # type: ignore[arg-type]
        )
        self.settings = settings  # type: ignore[assignment]
        self.rejects: list[str] = []
        self.local_calls = 0

    async def _call_local(
        self, model: str, messages: list[dict], thinking: bool, max_tokens: int
    ) -> tuple[str, Usage]:
        self.local_calls += 1
        return "本地答案", Usage(prompt_tokens=1, completion_tokens=1)

    async def _isolation_reject(self, node: str, reason: str) -> None:  # noqa: D102
        self.rejects.append(reason)


# ---------------------------------------------------------------- 判定函数


def test_egress_allowed_private_only_local() -> None:
    assert not egress_allowed("private", BOUNDARY_CLOUD)
    assert not egress_allowed("private", BOUNDARY_CACHE)
    assert egress_allowed("private", BOUNDARY_LOCAL)
    assert egress_allowed("public", BOUNDARY_CLOUD)
    assert egress_allowed("PUBLIC", BOUNDARY_CLOUD)
    assert egress_allowed("", BOUNDARY_CACHE)  # 缺省 public


def test_normalize_domain_and_boundary() -> None:
    assert normalize_domain(None) == "public"
    assert normalize_domain("PRIVATE") == "private"
    assert normalize_domain("nonsense") == "public"
    assert normalize_boundary(None) == BOUNDARY_CLOUD  # 未知兜底按最严光谱
    assert normalize_boundary("LOCAL") == BOUNDARY_LOCAL
    assert normalize_boundary("nonsense") == BOUNDARY_CLOUD


# ---------------------------------------------------------------- complete


async def test_complete_private_uses_local_only() -> None:
    """private + 有云端 key 也**必须**走本地边界，绝不允许云端出网。"""

    router = FakeLLM(_settings(llm_api_key="secret-key"))
    result = await router.complete(
        [{"role": "user", "content": "问题"}],
        task="reason",
        node="t",
        agent="t",
        data_domain="private",
    )
    assert result.model == "qwen2.5:7b-instruct"
    assert result.degraded is True
    assert result.text == "本地答案"
    assert router.local_calls == 1


async def test_complete_private_no_local_fail_closed() -> None:
    """private + 无本地通道（且云端边界 cloud）→ 硬拒，即使 demo_mode 也不许占位。"""

    router = FakeLLM(_settings(llm_api_key="secret-key", llm_local_enabled=False, demo_mode=True))
    with pytest.raises(IsolationRejectionError):
        await router.complete(
            [{"role": "user", "content": "问题"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="private",
        )
    assert len(router.rejects) == 1
    assert router.local_calls == 0


async def test_complete_private_local_down_fail_closed() -> None:
    """private + 本地通道调用失败 → 硬拒，不许 demo 兜底掩盖。"""

    router = FakeLLM(_settings(demo_mode=True))

    async def boom(*_a: Any, **_k: Any) -> tuple[str, Usage]:
        raise httpx.HTTPError("local down")

    router._call_local = boom  # type: ignore[method-assign]
    with pytest.raises(IsolationRejectionError):
        await router.complete(
            [{"role": "user", "content": "问题"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="private",
        )
    assert len(router.rejects) == 1


async def test_complete_private_cloud_boundary_local_allowed() -> None:
    """自托管网关把 cloud 边界标为 local：private 可放行，但本仓仍走本地通道。"""

    router = FakeLLM(_settings(llm_api_key="", llm_cloud_trust_boundary="local"))
    result = await router.complete(
        [{"role": "user", "content": "问题"}],
        task="reason",
        node="t",
        agent="t",
        data_domain="private",
    )
    assert result.degraded is True
    assert router.rejects == []


async def test_complete_public_behavior_unchanged() -> None:
    """public 走原逻辑：无云端 key 时降级本地（既有行为不回归）。"""

    router = FakeLLM(_settings(llm_api_key=""))
    result = await router.complete(
        [{"role": "user", "content": "问题"}],
        task="reason",
        node="t",
        agent="t",
        data_domain="public",
    )
    assert result.model == "qwen2.5:7b-instruct"
    assert result.degraded is True


# ---------------------------------------------------------------- stream


async def test_stream_private_uses_local_only() -> None:
    router = FakeLLM(_settings(llm_api_key="secret-key"))
    pieces = [
        piece
        async for piece in router.stream(
            [{"role": "user", "content": "问题"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="private",
        )
    ]
    assert "".join(pieces) == "本地答案"
    assert router.local_calls == 1


async def test_stream_private_no_local_fail_closed() -> None:
    router = FakeLLM(_settings(llm_local_enabled=False, demo_mode=True))
    with pytest.raises(IsolationRejectionError):
        async for _ in router.stream(
            [{"role": "user", "content": "问题"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="private",
        ):
            pass

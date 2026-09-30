"""A-03 出网 egress 守卫单测：出网载荷扫私域标记，命中即策略拒绝、终止降级链、不回显内容。

纪律：标记扫描是**兜底的机械闸门**——即使调用方没标 data_domain=private，只要出网载荷
含私域标记也必须硬拒；拒绝属策略拒绝（不是 provider 故障），不得本地/下家兜底。
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aiintel.core.cost import Usage
from aiintel.core.isolation import (
    BOUNDARY_CLOUD,
    BOUNDARY_LOCAL,
    ScopeViolationError,
    assert_public_scope,
    scan_private_markers,
)
from aiintel.core.llm import LLMRouter


def _settings(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "llm_api_key": "secret-key",
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
    """不联网：拦截隔离事件记录，统计本地调用次数（云端路径应一次都不触发）。"""

    def __init__(self, settings: SimpleNamespace) -> None:
        super().__init__(
            guard=SimpleNamespace(exceeded=lambda: False, record=lambda *a, **k: 0.0)  # type: ignore[arg-type]
        )
        self.settings = settings  # type: ignore[assignment]
        self.rejects: list[tuple[str, str]] = []
        self.local_calls = 0

    async def _call_local(
        self, model: str, messages: list[dict], thinking: bool, max_tokens: int
    ) -> tuple[str, Usage]:
        self.local_calls += 1
        return "本地答案", Usage(prompt_tokens=1, completion_tokens=1)

    async def _isolation_reject(
        self,
        node: str,
        reason: str,
        action: str = "isolation_policy_rejection",  # noqa: D102
    ) -> None:
        self.rejects.append((action, reason))


# ---------------------------------------------------------------- 扫描器


def test_scan_finds_marker_in_nested_string() -> None:
    payload = {"messages": [{"role": "user", "content": "请连到 intranet 主机查一下"}]}
    hits = scan_private_markers(payload)
    assert any(v.marker == "intranet" for v in hits)
    assert any("content" in v.path for v in hits)


def test_scan_is_case_insensitive_and_scans_key_names() -> None:
    payload = {"tenant_id": "acme", "note": "host is INTRANET"}
    hits = {v.marker for v in scan_private_markers(payload)}
    assert "tenant_id" in hits
    assert "intranet" in hits
    key_hit = [v for v in scan_private_markers(payload) if "（键名）" in v.path]
    assert any(v.marker == "tenant_id" for v in key_hit)


def test_violation_never_echoes_content() -> None:
    secret = "共享租户号 tenant_id=acme-9f2c 与内网密钥 -----BEGIN PRIVATE KEY----"
    hits = scan_private_markers(secret)
    detail = ", ".join(f"{v.marker}@{v.path}" for v in hits)
    assert secret not in detail
    for v in hits:
        assert not hasattr(v, "content")


def test_scan_respects_depth_limit() -> None:
    node: Any = {"leaf": "intranet"}
    for _ in range(12):
        node = {"next": node}
    assert scan_private_markers(node) == []


def test_assert_public_scope_raises_and_clean_passes() -> None:
    with pytest.raises(ScopeViolationError):
        assert_public_scope({"msg": "请访问 corp.internal 机器人"}, "egress")
    assert_public_scope({"msg": "公开的 CVE 情报"}, "egress")  # 不抛即通过


# ---------------------------------------------------------------- LLM 出网点


async def test_complete_cloud_egress_rejects_marker_payload() -> None:
    """data_domain=public 但载荷含私域标记 → 同样硬拒（兜底闸门）且不本地兜底。"""

    router = FakeLLM(_settings())
    with pytest.raises(ScopeViolationError):
        await router.complete(
            [{"role": "user", "content": "把这份 internal_host 清单出网"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="public",
        )
    assert router.local_calls == 0
    assert any(action == "egress_guard_rejection" for action, _ in router.rejects)


async def test_complete_cloud_egress_rejects_marker_async() -> None:
    router = FakeLLM(_settings())
    with pytest.raises(ScopeViolationError):
        await router.complete(
            [{"role": "user", "content": "assets: asset_id=gw-03 的修复建议"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="public",
        )
    assert router.local_calls == 0
    assert router.rejects and router.rejects[0][0] == "egress_guard_rejection"


async def test_stream_cloud_egress_rejects_marker_payload() -> None:
    router = FakeLLM(_settings())
    with pytest.raises(ScopeViolationError):
        async for _ in router.stream(
            [{"role": "user", "content": "tenant:hr 的员工数据能问吗"}],
            task="reason",
            node="t",
            agent="t",
            data_domain="public",
        ):
            pass
    assert router.local_calls == 0
    assert any(action == "egress_guard_rejection" for action, _ in router.rejects)


async def test_local_destination_is_not_scanned() -> None:
    """本地边界（Ollama）是合法目的地：private 数据本地作答不扫出网标记。"""

    router = FakeLLM(_settings())
    result = await router.complete(
        [{"role": "user", "content": "intranet 主机清单"}],
        task="reason",
        node="t",
        agent="t",
        data_domain="private",
    )
    assert result.model == "qwen2.5:7b-instruct"
    assert result.degraded is True
    assert router.rejects == []

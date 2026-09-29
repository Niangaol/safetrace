"""LLMRouter：任务分级、成本落账、预算熔断降级。"""

from __future__ import annotations

import httpx
import pytest

from aiintel.core.cost import Usage
from aiintel.core.llm import LLMError, LLMRouter


@pytest.fixture()
def router(cost_guard, monkeypatch):
    monkeypatch.setenv("LLM_LOCAL_ENABLED", "true")
    r = LLMRouter(guard=cost_guard)
    # 多数用例测的是云端路径；没配 key 时 LLMRouter 会直接跳过云端转本地
    monkeypatch.setattr(r.settings, "llm_api_key", "sk-test", raising=False)
    return r


def _fake_client(payload: dict) -> httpx.AsyncClient:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json=payload, request=request)
    )
    return httpx.AsyncClient(
        base_url="https://llm.invalid", transport=transport, headers={"Authorization": "Bearer x"}
    )


def _ok_payload() -> dict:
    return {
        "choices": [{"message": {"content": '{"category": "模型投毒"}'}}],
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "prompt_cache_hit_tokens": 400,
        },
    }


def test_route_picks_flash_for_simple_task(router):
    tier, model, thinking = router.route("extract")
    assert tier == "flash"
    assert thinking is False
    assert model


def test_route_picks_pro_for_reasoning_task(router):
    tier, model, thinking = router.route("reason")
    assert tier == "pro"
    assert thinking is True


def test_route_pro_tasks_are_subset_of_thinking(router):
    for task in ("extract", "classify", "dedup", "judge"):
        tier, _, thinking = router.route(task)
        assert tier == "flash"
        assert thinking is False


async def test_complete_parses_content_and_records_cost(router, monkeypatch):
    router._client = _fake_client(_ok_payload())
    result = await router.complete([{"role": "user", "content": "hi"}], task="extract", node="n")
    assert result.text == '{"category": "模型投毒"}'
    assert result.model == router.settings.llm_flash_model
    assert result.degraded is False
    assert result.usage.prompt_tokens == 1000
    assert result.usage.cache_hit_tokens == 400
    assert result.cost_cny > 0
    assert router.guard.spent_today() == pytest.approx(result.cost_cny)


async def test_complete_falls_back_to_local_on_http_error(router, monkeypatch):
    transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("超时")))
    router._client = httpx.AsyncClient(base_url="https://llm.invalid", transport=transport)

    async def fake_local(model, messages, thinking, max_tokens):
        return "本地兜底回答", Usage(10, 0, 10)

    monkeypatch.setattr(router, "_call_local", fake_local)
    result = await router.complete([{"role": "user", "content": "hi"}], task="extract")
    assert result.degraded is True
    assert result.model == router.settings.llm_local_model
    assert result.cost_cny == 0.0
    assert result.text == "本地兜底回答"


async def test_complete_raises_when_local_disabled(router, monkeypatch):
    monkeypatch.setattr(router.settings, "llm_local_enabled", False, raising=False)
    transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("down")))
    router._client = httpx.AsyncClient(base_url="https://llm.invalid", transport=transport)
    with pytest.raises(LLMError):
        await router.complete([{"role": "user", "content": "hi"}], task="extract")


async def test_budget_exhausted_short_circuits_to_local(router, monkeypatch):
    router.guard.record(Usage(10_000_000, 0, 1_000_000), "flash", model="m")
    assert router.guard.exceeded() is True

    called = {"remote": False}

    async def fake_local(model, messages, thinking, max_tokens):
        return "预算熔断后的本地回答", Usage(5, 0, 5)

    monkeypatch.setattr(router, "_call_local", fake_local)

    def _fail(request):
        called["remote"] = True
        return httpx.Response(500, request=request)

    router._client = httpx.AsyncClient(
        base_url="https://llm.invalid", transport=httpx.MockTransport(_fail)
    )
    result = await router.complete([{"role": "user", "content": "hi"}], task="extract")
    assert called["remote"] is False
    assert result.degraded is True
    assert "预算" in result.text


async def test_stream_yields_pieces_and_records_usage(router):
    body = (
        b'data: {"choices":[{"delta":{"content":"\\u4f60"}}]}\n\n'
        b'data: {"choices":[{"delta":{"content":"\\u597d"}}],'
        b'"usage":{"prompt_tokens":10,"completion_tokens":2}}\n\n'
        b"data: [DONE]\n\n"
    )

    router._client = httpx.AsyncClient(
        base_url="https://llm.invalid",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=body, request=request)
        ),
    )
    pieces = [p async for p in router.stream([{"role": "user", "content": "hi"}], task="chat")]
    assert "".join(pieces) == "你好"
    assert router.guard.spent_today() > 0


async def test_empty_api_key_does_not_send_broken_auth_header(router, monkeypatch):
    """空 key 时发 "Bearer " 会被 httpx 直接拒：
    LocalProtocolError: Illegal header value b'Bearer '，用户只看到这句天书。
    """

    monkeypatch.setattr(router.settings, "llm_api_key", "", raising=False)
    monkeypatch.setattr(router.settings, "llm_api_key", "   ", raising=False)
    router._client = None

    client = router.client

    assert "Authorization" not in client.headers


async def test_blank_api_key_is_treated_as_missing(router, monkeypatch):
    monkeypatch.setattr(router.settings, "llm_api_key", "  \t ", raising=False)
    assert router.has_cloud_key is False

    monkeypatch.setattr(router.settings, "llm_api_key", "sk-real", raising=False)
    assert router.has_cloud_key is True


async def test_no_key_skips_cloud_and_falls_back(router, monkeypatch):
    """没有云端凭据就不该去打云端，省一次往返也不泄漏 401 噪音。"""

    monkeypatch.setattr(router.settings, "llm_api_key", "", raising=False)
    monkeypatch.setattr(router.settings, "demo_mode", True, raising=False)
    monkeypatch.setattr(router.settings, "llm_local_enabled", False, raising=False)
    called = {"cloud": False}

    def _explode(request):  # pragma: no cover - 走到就说明守卫失效
        called["cloud"] = True
        return httpx.Response(500, request=request)

    router._client = httpx.AsyncClient(
        base_url="https://llm.invalid", transport=httpx.MockTransport(_explode)
    )

    result = await router.complete([{"role": "user", "content": "hi"}], task="extract")

    assert called["cloud"] is False
    assert "演示模式" in result.text


async def test_no_key_and_no_backend_raises_actionable_error(router, monkeypatch):
    monkeypatch.setattr(router.settings, "llm_api_key", "", raising=False)
    monkeypatch.setattr(router.settings, "demo_mode", False, raising=False)
    monkeypatch.setattr(router.settings, "llm_local_enabled", False, raising=False)

    with pytest.raises(LLMError) as excinfo:
        await router.complete([{"role": "user", "content": "hi"}], task="extract")

    message = str(excinfo.value)
    assert "LLM_API_KEY" in message
    assert "DEMO_MODE" in message


async def test_stream_without_key_yields_demo_text(router, monkeypatch):
    monkeypatch.setattr(router.settings, "llm_api_key", "", raising=False)
    monkeypatch.setattr(router.settings, "demo_mode", True, raising=False)
    monkeypatch.setattr(router.settings, "llm_local_enabled", False, raising=False)
    called = {"cloud": False}

    def _explode(request):  # pragma: no cover - 走到就说明守卫失效
        called["cloud"] = True
        return httpx.Response(500, request=request)

    router._client = httpx.AsyncClient(
        base_url="https://llm.invalid", transport=httpx.MockTransport(_explode)
    )

    pieces = [p async for p in router.stream([{"role": "user", "content": "hi"}], task="chat")]

    assert called["cloud"] is False
    assert "演示模式" in "".join(pieces)


async def test_stream_degrades_when_budget_exhausted(router, monkeypatch):
    router.guard.record(Usage(10_000_000, 0, 1_000_000), "flash", model="m")

    async def fake_local(model, messages, thinking, max_tokens):
        return "降级流式回答", Usage(1, 0, 1)

    monkeypatch.setattr(router, "_call_local", fake_local)
    pieces = [p async for p in router.stream([{"role": "user", "content": "hi"}], task="chat")]
    assert "".join(pieces) == "降级流式回答"


def test_result_json_tolerates_code_fence(fake_result):
    result = fake_result('```json\n{"a": 1}\n```')
    assert result.json() == {"a": 1}


def test_result_json_parses_surrounding_prose(fake_result):
    result = fake_result('好的，结果如下：{"a": 1} 以上。')
    assert result.json() == {"a": 1}


def test_result_json_raises_on_non_json(fake_result):
    with pytest.raises(LLMError):
        fake_result("完全没有 JSON").json()


def test_parse_usage_defaults_to_zero(fake_result):
    usage = LLMRouter._parse_usage({})
    assert usage == Usage(0, 0, 0)

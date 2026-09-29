"""嵌入器失败熔断的回归测试。

**为什么必须有**：原实现 `_load()` 没有失败记忆，每次 `embed()` 都重试一次网络加载。
在 huggingface.co 不可达的环境里（本机实测），**每一次问答都要白等 3.5 分钟**
（生产 trace 里 `retrieve.2` 的 elapsed_ms 达 210972），然后仍然退化为关键词 ——
又慢又没结果。加熔断后：第一次失败即隔离，期内后续调用**立即返回**，不再发起网络请求。
"""

from __future__ import annotations

import asyncio
import time

import pytest

from aiintel.services.knowledge.embedder import (
    FAILURE_QUARANTINE_SECONDS,
    Embedder,
    Reranker,
)


@pytest.fixture()
def embedder(monkeypatch) -> Embedder:
    e = Embedder()
    return e


@pytest.mark.asyncio
async def test_failure_is_remembered_and_not_retried(embedder: Embedder, monkeypatch) -> None:
    """第一次失败后，后续调用不得再触发加载（这是"不再白等 3.5 分钟"的关键）。"""

    calls = {"n": 0}

    def boom() -> None:
        calls["n"] += 1
        raise OSError("模拟 huggingface 不可达")

    monkeypatch.setattr(embedder, "_load", boom)

    assert await embedder.embed("第一次") is None
    assert calls["n"] == 1, "第一次应当尝试加载一次"

    # 后续多次调用都不得再尝试
    for i in range(5):
        assert await embedder.embed(f"第{i + 2}次") is None
    assert calls["n"] == 1, f"隔离期内不应重试，实际尝试了 {calls['n']} 次"
    assert not embedder.available
    assert "huggingface" in embedder.failure_reason or "OSError" in embedder.failure_reason


@pytest.mark.asyncio
async def test_quarantine_expires_and_allows_retry(embedder: Embedder, monkeypatch) -> None:
    """隔离期满后应允许再试（模型被放进本地缓存卷时可自动恢复，无需重启进程）。"""

    calls = {"n": 0}

    def boom() -> None:
        calls["n"] += 1
        raise OSError("still down")

    monkeypatch.setattr(embedder, "_load", boom)
    await embedder.embed("a")
    assert calls["n"] == 1

    # 把失败时间往前推，模拟隔离期已过
    embedder._failed_at = time.monotonic() - FAILURE_QUARANTINE_SECONDS - 1
    await embedder.embed("b")
    assert calls["n"] == 2, "隔离期满后应允许重试一次"


@pytest.mark.asyncio
async def test_concurrent_calls_do_not_stampede(embedder: Embedder, monkeypatch) -> None:
    """并发场景下也不能每个协程都去加载一次（双重检查的意义）。"""

    calls = {"n": 0}

    def slow_boom() -> None:
        calls["n"] += 1
        time.sleep(0.05)  # 模拟一次较慢的失败
        raise OSError("down")

    monkeypatch.setattr(embedder, "_load", slow_boom)
    await asyncio.gather(*[embedder.embed(f"q{i}") for i in range(6)])
    # 允许 1~2 次（等锁期间可能有一个协程已经进入），但绝不能是 6 次
    assert calls["n"] <= 2, f"并发击穿：加载被尝试了 {calls['n']} 次"


@pytest.mark.asyncio
async def test_success_clears_failure_state(embedder: Embedder, monkeypatch) -> None:
    """一旦加载成功，应清除失败标记（避免已被隔离却长期不恢复）。

    注意 `_failed_at` 要设成**隔离期之前**的时间：设成"现在"会直接命中隔离分支
    而短路，测不到成功路径（我第一版就写错了）。
    """

    class FakeModel:
        def encode(self, texts, normalize_embeddings=True):  # noqa: ANN001, ARG002
            return [[0.1, 0.2, 0.3] for _ in texts]

    embedder._failed_at = time.monotonic() - FAILURE_QUARANTINE_SECONDS - 1
    embedder._failure_reason = "previous failure"

    # 模拟一次真实的成功加载：真实 `_load()` 会把模型存进 `self._model`，
    # 而 `available` 正是看 `_model`。只 patch 返回值而不设 `_model` 就不忠实于真实行为
    # （我第二版就漏了这点，导致 available 仍为 False）。
    def fake_load():
        embedder._model = FakeModel()
        return embedder._model

    monkeypatch.setattr(embedder, "_load", fake_load)

    out = await embedder.embed("ok")
    assert out == [0.1, 0.2, 0.3]
    assert embedder._failed_at is None, "成功后应清除失败标记"
    assert embedder.available is True


@pytest.mark.asyncio
async def test_reranker_also_quarantines(monkeypatch) -> None:
    r = Reranker()
    calls = {"n": 0}

    def boom() -> None:
        calls["n"] += 1
        raise OSError("down")

    monkeypatch.setattr(r, "_load", boom)
    assert await r.rerank("q", ["d1", "d2"]) == [0.0, 0.0]
    assert await r.rerank("q", ["d1", "d2"]) == [0.0, 0.0]
    assert calls["n"] == 1, "重排也应只尝试一次"


@pytest.mark.asyncio
async def test_empty_input_short_circuits(embedder: Embedder) -> None:
    """空文本不该触发任何加载。"""

    assert await embedder.embed("") is None
    assert embedder._failed_at is None

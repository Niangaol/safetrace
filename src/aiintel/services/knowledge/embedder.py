"""本地嵌入与重排（bge-m3 / bge-reranker-v2-m3），零 API 成本。

未安装 sentence-transformers、或模型权重取不到时，检索自动退化为关键词模式。

## ⚠️ 为什么要做「失败熔断 + 快速失败」

实测（容器内）：`huggingface.co` 在本机网络**不可达**，`SentenceTransformer(...)`
首次加载会**重试到超时**。原实现每次调用都重试一次，而 `_load()` 没有失败记忆，
于是**每一次问答都要白等 3.5 分钟**（实测 trace 里 `retrieve.2` 的
`elapsed_ms` 达 210972），最后仍然退化为关键词 —— 又慢又没结果，演示不可用。

三处修复：
1. **失败熔断**：加载失败后进入隔离期（默认 600s），期内直接返回「不可用」，
   不再发起网络请求。隔离结束后允许再试（比如运维把模型放到本地卷里了）。
2. **限制重试/超时**：由 compose 注入 `HF_HUB_DOWNLOAD_TIMEOUT` /
   `HF_HUB_ETAG_TIMEOUT`，把单次尝试压到秒级。
3. 熔断是**进程级单例**，与 `get_embedder()` 的单例一致。
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from aiintel.config import get_settings

logger = logging.getLogger(__name__)

#: 加载失败后的隔离时长（秒）。期内不再尝试加载，避免每次请求都白等。
#: 之所以是"隔离一段时间"而不是"永久放弃"：模型可能后来被放进本地缓存卷，
#: 那时无需重启进程即可恢复。
FAILURE_QUARANTINE_SECONDS = 600


class Embedder:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._model: Any = None
        self._lock = asyncio.Lock()
        #: 上次加载失败的时间戳（None 表示没失败过）
        self._failed_at: float | None = None
        #: 上次失败原因，便于日志里说清"为什么降级"
        self._failure_reason: str = ""

    def _quarantined(self) -> bool:
        if self._failed_at is None:
            return False
        if time.monotonic() - self._failed_at >= FAILURE_QUARANTINE_SECONDS:
            # 隔离期满，放行一次重试
            self._failed_at = None
            return False
        return True

    def _load(self) -> Any:
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.settings.embedding_model)
        return self._model

    async def embed(self, text: str) -> list[float] | None:
        if not text:
            return None
        if self._quarantined():
            # 关键：隔离期内**不发任何网络请求**，立即降级
            return None
        try:
            async with self._lock:
                # 双重检查：等锁期间可能已被别的协程标记失败
                if self._quarantined():
                    return None
                model = await asyncio.to_thread(self._load)
                vector = await asyncio.to_thread(model.encode, [text], normalize_embeddings=True)
            self._failed_at = None
            return [float(x) for x in vector[0]]
        except Exception as exc:  # noqa: BLE001 - 缺依赖/取不到权重时降级
            self._failed_at = time.monotonic()
            self._failure_reason = f"{type(exc).__name__}: {str(exc)[:160]}"
            logger.warning(
                "嵌入不可用，降级为关键词检索（%ds 内不再重试）: %s",
                FAILURE_QUARANTINE_SECONDS,
                self._failure_reason,
            )
            return None

    @property
    def available(self) -> bool:
        """当前是否可用（供 health/诊断接口如实报告，而不是让调用方猜）。"""

        return self._model is not None and not self._quarantined()

    @property
    def failure_reason(self) -> str:
        return self._failure_reason


class Reranker:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._model: Any = None
        self._failed_at: float | None = None

    def _quarantined(self) -> bool:
        if self._failed_at is None:
            return False
        if time.monotonic() - self._failed_at >= FAILURE_QUARANTINE_SECONDS:
            self._failed_at = None
            return False
        return True

    def _load(self) -> Any:
        if self._model is None:
            from sentence_transformers import CrossEncoder

            self._model = CrossEncoder(self.settings.reranker_model)
        return self._model

    async def rerank(self, query: str, documents: list[str]) -> list[float]:
        if not documents:
            return []
        if self._quarantined():
            return [0.0] * len(documents)
        try:
            model = await asyncio.to_thread(self._load)
            scores = await asyncio.to_thread(model.predict, [(query, d) for d in documents])
            self._failed_at = None
            return [float(s) for s in scores]
        except Exception as exc:  # noqa: BLE001
            self._failed_at = time.monotonic()
            logger.debug("重排不可用，降级为原序: %s", exc)
            return [0.0] * len(documents)


_embedder: Embedder | None = None
_reranker: Reranker | None = None


def get_embedder() -> Embedder:
    global _embedder
    if _embedder is None:
        _embedder = Embedder()
    return _embedder


def get_reranker() -> Reranker:
    global _reranker
    if _reranker is None:
        _reranker = Reranker()
    return _reranker

"""本地嵌入与重排（bge-m3 / bge-reranker-v2-m3），零 API 成本。

未安装 sentence-transformers 时全部降级为 None，检索自动退化为关键词模式。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aiintel.config import get_settings

logger = logging.getLogger(__name__)


class Embedder:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._model: Any = None
        self._lock = asyncio.Lock()

    def _load(self) -> Any:
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.settings.embedding_model)
        return self._model

    async def embed(self, text: str) -> list[float] | None:
        if not text:
            return None
        try:
            async with self._lock:
                model = await asyncio.to_thread(self._load)
                vector = await asyncio.to_thread(model.encode, [text], normalize_embeddings=True)
            return [float(x) for x in vector[0]]
        except Exception as exc:  # noqa: BLE001 - 缺依赖/缺模型时降级
            logger.warning("嵌入不可用，降级为关键词检索: %s", exc)
            return None


class Reranker:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._model: Any = None

    def _load(self) -> Any:
        if self._model is None:
            from sentence_transformers import CrossEncoder

            self._model = CrossEncoder(self.settings.reranker_model)
        return self._model

    async def rerank(self, query: str, documents: list[str]) -> list[float]:
        if not documents:
            return []
        try:
            model = await asyncio.to_thread(self._load)
            scores = await asyncio.to_thread(model.predict, [(query, d) for d in documents])
            return [float(s) for s in scores]
        except Exception as exc:  # noqa: BLE001
            logger.debug("重排不可用: %s", exc)
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

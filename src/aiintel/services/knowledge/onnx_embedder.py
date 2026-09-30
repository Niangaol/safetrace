"""本地 ONNX 嵌入 —— **不需要 torch**。

## 为什么单独做一条路

原 `embedder.py` 走 `sentence-transformers`，而它依赖 `torch`（约 2.5GB）：

- 本机构建时 PyPI 连接中断过一次（`api` 镜像至今没装成 `[embed]`）；
- 本机 `huggingface.co` **不可达**，权重也取不到 → 装了也用不上。

改用 **ONNX Runtime + 量化模型**后：依赖从 ~2.5GB 降到 ~15MB，
模型用 `hf-mirror.com`（**实测可达**）下载。于是"本机也能真做语义检索"。

## 模型选择（有实测依据）

对比两个候选（见 `scripts/fetch_embedding_model.py --all` 与对比脚本）：

| 模型 | 产品名被切 `[UNK]` | 同义/无关相似度间隔 | 体积 |
| --- | --- | --- | --- |
| `bge-small-zh-v1.5` | **5/5**（`vLLM`/`LangChain`/`Transformers`/`CVE-…`/`Ollama` 全变 `[UNK]`） | 0.28 | 22.9MB |
| `paraphrase-multilingual-MiniLM-L12-v2` | **0/5** | **0.42** | 113MB |

本仓语料满是英文产品名（`vLLM`、`LangChain`…），中文 BERT 词表把它们全切成 `[UNK]`，
等于**丢掉最关键的检索线索**。所以默认用**多语言版**（384 维）。

## 与 `sentence-transformers` 的口径一致性

`bge`/`MiniLM` 这类句向量的标准做法是 **mean-pooling + L2 归一化**，
本模块照做（`attention_mask` 加权，避免把 padding 算进去）。
若两种后端混用，**向量不可比**，所以索引与查询必须同源 —— 见 `indexer` 里
对维度变化的处理，以及冒烟脚本里的维度一致性检查。
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: 加载失败后的隔离时长（秒）。与 `embedder.py` 保持一致：
#: 失败后短期内不再重试，避免每次问答都白等。
FAILURE_QUARANTINE_SECONDS = 600

#: 默认模型目录名（相对 `settings.embedding_onnx_dir` 的父目录）
DEFAULT_ONNX_MODEL_DIR = "paraphrase-multilingual-MiniLM-L12-v2"


class OnnxEmbedder:
    """ONNX 句向量。对外契约与 `Embedder` 一致：`embed()` / `available` / `failure_reason`。"""

    def __init__(self, model_dir: str | Path | None = None) -> None:
        self._model: Any = None
        self._tokenizer: Any = None
        self._input_names: set[str] = set()
        self._lock = asyncio.Lock()
        self._failed_at: float | None = None
        self._failure_reason: str = ""
        self._dim: int | None = None
        self._model_dir = Path(model_dir) if model_dir else None

    # ---------- 内部 ----------

    def _resolve_dir(self) -> Path:
        if self._model_dir is not None:
            return self._model_dir
        from aiintel.config import get_settings

        s = get_settings()
        base = Path(getattr(s, "embedding_onnx_dir", "data/models"))
        return base / DEFAULT_ONNX_MODEL_DIR

    def _quarantined(self) -> bool:
        if self._failed_at is None:
            return False
        if time.monotonic() - self._failed_at >= FAILURE_QUARANTINE_SECONDS:
            self._failed_at = None
            return False
        return True

    def _fail(self, reason: str) -> None:
        self._failed_at = time.monotonic()
        self._failure_reason = reason
        logger.warning(
            "ONNX 嵌入不可用，降级为关键词检索（%ds 内不再重试）: %s",
            FAILURE_QUARANTINE_SECONDS,
            reason,
        )

    def _load(self) -> None:
        """加载模型与分词器。缺文件/缺依赖都在这里抛，由调用方转成降级。"""

        if self._model is not None:
            return

        directory = self._resolve_dir()
        onnx_path = directory / "model_quantized.onnx"
        tok_path = directory / "tokenizer.json"
        if not onnx_path.exists():
            raise FileNotFoundError(
                f"缺少 ONNX 模型 {onnx_path}；先跑 `python -m scripts.fetch_embedding_model`"
            )
        if not tok_path.exists():
            raise FileNotFoundError(f"缺少分词器 {tok_path}")

        import onnxruntime as ort
        from tokenizers import Tokenizer

        # 静音 onnxruntime 的启动横幅，别污染 CLI 输出
        opts = ort.SessionOptions()
        opts.log_severity_level = 3
        self._model = ort.InferenceSession(str(onnx_path), opts, providers=["CPUExecutionProvider"])
        self._tokenizer = Tokenizer.from_file(str(tok_path))
        self._input_names = {i.name for i in self._model.get_inputs()}
        out_shape = self._model.get_outputs()[0].shape
        self._dim = int(out_shape[-1]) if isinstance(out_shape[-1], int) else None

    def _encode_sync(self, texts: list[str]) -> list[list[float]]:
        import numpy as np

        self._load()
        assert self._tokenizer is not None and self._model is not None

        encodings = self._tokenizer.encode_batch(texts)
        input_ids = np.array([e.ids for e in encodings], dtype=np.int64)
        attention = np.array([e.attention_mask for e in encodings], dtype=np.int64)

        feed: dict[str, Any] = {"input_ids": input_ids}
        if "attention_mask" in self._input_names:
            feed["attention_mask"] = attention
        if "token_type_ids" in self._input_names:
            feed["token_type_ids"] = np.array([e.type_ids for e in encodings], dtype=np.int64)

        hidden = self._model.run(None, feed)[0]  # (batch, seq, hidden)
        mask = attention[..., None].astype(np.float32)
        pooled = (hidden * mask).sum(axis=1) / np.clip(mask.sum(axis=1), 1e-9, None)
        norms = np.linalg.norm(pooled, axis=1, keepdims=True)
        normalised = pooled / np.clip(norms, 1e-9, None)
        return [[float(x) for x in row] for row in normalised]

    # ---------- 对外 ----------

    async def embed(self, text: str) -> list[float] | None:
        if not text:
            return None
        if self._quarantined():
            return None
        try:
            async with self._lock:
                if self._quarantined():
                    return None
                vectors = await asyncio.to_thread(self._encode_sync, [text])
            self._failed_at = None
            return vectors[0] if vectors else None
        except Exception as exc:  # noqa: BLE001 - 缺依赖/缺模型都应降级而不是炸掉问答
            self._fail(f"{type(exc).__name__}: {str(exc)[:160]}")
            return None

    async def embed_many(self, texts: list[str]) -> list[list[float]]:
        """批量编码。失败时返回零向量（与 `Reranker` 的降级风格一致，长度对齐）。"""

        if not texts:
            return []
        if self._quarantined():
            return [[0.0] * (self._dim or 384) for _ in texts]
        try:
            async with self._lock:
                if self._quarantined():
                    return [[0.0] * (self._dim or 384) for _ in texts]
                vectors = await asyncio.to_thread(self._encode_sync, texts)
            self._failed_at = None
            return vectors
        except Exception as exc:  # noqa: BLE001
            self._fail(f"{type(exc).__name__}: {str(exc)[:160]}")
            return [[0.0] * (self._dim or 384) for _ in texts]

    @property
    def available(self) -> bool:
        return self._model is not None and not self._quarantined()

    @property
    def failure_reason(self) -> str:
        return self._failure_reason

    @property
    def dim(self) -> int | None:
        """向量维度（未加载时为 None）。用于校验与 DB 列维度是否一致。"""

        return self._dim

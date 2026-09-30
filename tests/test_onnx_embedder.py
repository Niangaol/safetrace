"""ONNX 嵌入后端：让本机也能真做语义检索。

## 为什么值得为它写测试

本机长期**做不了语义检索**，原因有两条叠加：

1. `sentence-transformers` 依赖 `torch`（约 2.5GB）—— PyPI 连接中断过一次，装不成；
2. `huggingface.co` **不可达**，就算装上 `torch` 也拿不到权重。

于是检索一直退化为关键词、`citation.score` 恒为 0。
而 `hf-mirror.com` **实测可达**、`onnxruntime` 只有约 15MB ——
所以这条路是"把语义检索从不可用变成可用"的关键。

测试重点：
- **回归防线**：ONNX 后端必须能被选中（否则静默退回不可用的 local 后端）；
- **降级要显式**：模型缺失时返回 None 并给得出原因，**不能抛异常炸掉问答**，
  也不能静默返回零向量冒充"算过了"；
- **维度自洽**：向量维度必须与模型一致（384），调用方据此校验。

模型文件不在仓库里（`data/models/` 已 gitignore），所以这里对"文件缺失"
的情形也做断言 —— 那正是 CI 上的状态。
"""

from __future__ import annotations

from pathlib import Path

import pytest

MODEL_DIR = Path("data/models/paraphrase-multilingual-MiniLM-L12-v2")
HAS_MODEL = (MODEL_DIR / "model_quantized.onnx").exists()


@pytest.fixture()
def onnx_env(monkeypatch):
    monkeypatch.setenv("EMBEDDING_BACKEND", "onnx")
    monkeypatch.setenv("EMBEDDING_DIM", "384")
    # settings 有 lru_cache，必须清掉才能让新环境变量生效
    from aiintel.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_backend_dispatch_selects_onnx(onnx_env) -> None:
    """**回归防线**：配置为 onnx 时必须真的选到 OnnxEmbedder。

    若这里退回 `Embedder`（sentence-transformers），本机就会永远不可用 ——
    而失败是静默的（`embed()` 只返回 None），没有测试根本发现不了。
    """

    import aiintel.services.knowledge.embedder as emb_module

    emb_module._embedder = None  # 清单例
    inst = emb_module.get_embedder()
    assert type(inst).__name__ == "OnnxEmbedder", f"选到了 {type(inst).__name__}"
    emb_module._embedder = None


def test_local_backend_still_selectable(monkeypatch) -> None:
    """`local` 后端不能被删掉（换到有 torch 的机器仍要用它）。"""

    monkeypatch.setenv("EMBEDDING_BACKEND", "local")
    from aiintel.config import get_settings

    get_settings.cache_clear()
    import aiintel.services.knowledge.embedder as emb_module

    emb_module._embedder = None
    inst = emb_module.get_embedder()
    assert type(inst).__name__ == "Embedder"
    emb_module._embedder = None
    get_settings.cache_clear()


def test_missing_model_degrades_with_reason_and_does_not_raise() -> None:
    """模型文件不存在时：返回 None + 说得出原因 + **不抛异常**。

    这是 CI / 新机器上的真实状态（模型 113MB，不入库）。
    降级必须显式（红线 3），不能静默返回零向量冒充"算过了"。
    """

    import asyncio

    from aiintel.services.knowledge.onnx_embedder import OnnxEmbedder

    emb = OnnxEmbedder(model_dir=Path("data/models/__definitely_not_here__"))
    result = asyncio.run(emb.embed("测试"))
    assert result is None, "缺模型时必须返回 None，不能抛异常也不能给假向量"
    assert emb.failure_reason, "必须给出失败原因，否则用户不知道为何降级"
    assert "onnx" in emb.failure_reason.lower() or "模型" in emb.failure_reason
    assert emb.available is False


def test_empty_text_returns_none_without_loading() -> None:
    """空文本直接返回 None，不该触发模型加载。"""

    import asyncio

    from aiintel.services.knowledge.onnx_embedder import OnnxEmbedder

    emb = OnnxEmbedder(model_dir=Path("data/models/__definitely_not_here__"))
    assert asyncio.run(emb.embed("")) is None
    assert emb.failure_reason == "", "空文本不是失败，不该记失败原因"


@pytest.mark.skipif(not HAS_MODEL, reason="ONNX 模型未下载（data/models 已 gitignore）")
def test_real_model_dimensions_and_semantics() -> None:
    """有模型时：维度 384、L2 归一化、且**语义**能区分同义与无关。"""

    import asyncio

    import numpy as np

    from aiintel.services.knowledge.onnx_embedder import OnnxEmbedder

    emb = OnnxEmbedder(model_dir=MODEL_DIR)

    vec = asyncio.run(emb.embed("vLLM 存在远程代码执行漏洞"))
    assert vec is not None, f"加载失败: {emb.failure_reason}"
    assert len(vec) == 384, f"维度应为 384，实得 {len(vec)}"
    assert emb.dim == 384
    # L2 归一化：范数应接近 1（余弦相似度才有意义）
    assert abs(float(np.linalg.norm(vec)) - 1.0) < 1e-4

    async def e(text: str) -> np.ndarray:
        v = await emb.embed(text)
        assert v is not None
        return np.asarray(v, dtype=np.float32)

    async def run() -> tuple[float, float]:
        a = await e("vLLM 存在远程代码执行漏洞")
        b = await e("推理服务框架有一个可以执行任意命令的缺陷")
        c = await e("今天天气很好适合出门散步")
        return float(a @ b), float(a @ c)

    same, unrelated = asyncio.run(run())
    assert same > unrelated + 0.15, f"语义区分度不足：同义 {same:.4f} vs 无关 {unrelated:.4f}"


@pytest.mark.skipif(not HAS_MODEL, reason="ONNX 模型未下载")
def test_product_names_are_not_unknown_tokens() -> None:
    """**模型选型的依据**：英文产品名不得被切成 [UNK]。

    这是选多语言版而非中文 `bge-small-zh` 的决定性理由：
    实测中文版把 `vLLM`/`LangChain`/`Transformers`/`CVE-…`/`Ollama`
    **5/5 全切成 [UNK]**，而这些正是本仓语料里最关键的检索线索。
    """

    from tokenizers import Tokenizer

    tok = Tokenizer.from_file(str(MODEL_DIR / "tokenizer.json"))
    for name in ("vLLM", "LangChain", "Transformers", "Ollama"):
        ids = tok.encode(name).ids
        assert 100 not in ids and 1 not in ids, f"{name} 被切成 [UNK]（ids={ids}）"

"""AI 相关性判定：把"关键词命中"升级为"**词元级**命中 + 排除误判"。

## 为什么需要它

采集侧用 `AI_KEYWORDS` 做 **NVD 服务端关键词搜索**，那是**子串匹配**，
于是 `rag` / `triton` / `llama` 这几个词带来了大量**非 AI** 结果：

| 被误采的内容 | 命中的子串 |
| --- | --- |
| **Rage** 1.01 / **Ragnarok** Online | `rag`（"**rag**e" 里就有 rag） |
| **Triton** CMS Pro / Websense **TRITON** | `triton` |
| **Quotes llama** WordPress 插件 | `llama` |
| **Triton** is a Minecraft plugin | `triton` |

实测后果（`scripts/audit_ai_relevance.py`，1698 条真实数据）：

```
strong     1444 (85.0%)   ← 真相关
weak_only   123 ( 7.2%)   ← Triton CMS / Websense TRITON
unclear     120 ( 7.1%)   ← Rage / Ragnarok
non_ai       11 ( 0.6%)   ← WordPress llama 插件 / Minecraft Triton
```

这些噪音会**出现在检索结果里被评委看到**：实测查 `ollama DNS rebinding`
把 **Windows XP 的 DNSAPI 漏洞**排在第一 —— 一眼就能看穿。

## 判定口径

- **强标识**：AI/ML 生态的专有产品名或概念词，按**词元边界**匹配
  （`embedding` 不该命中 "embedded"，但 `llm` 要允许出现在 `llm-based` 里）。
- **弱标识**（`triton` / `rag` / `llama` / `agent`）**单独出现不采信** ——
  它们必须是 AI 语境的一部分才有效，判据是"与强标识共现"。
- **非 AI 线索**（WordPress / Minecraft / Windows XP 等）出现且无强标识时判非 AI。

只保留 `strong` 的条目，规模仍有 ~1400 条真实数据（不是砍到几十条）。
"""

from __future__ import annotations

import re
from typing import Literal

Verdict = Literal["strong", "weak_only", "non_ai", "unclear"]

#: 强 AI 标识。词元边界匹配（`\b`）。
#: 注意 `triton` / `rag` / `llama` **故意不在**这里 —— 见 WEAK_AI。
STRONG_AI = (
    # 推理/服务框架
    "vllm",
    "ollama",
    "langchain",
    "llamaindex",
    "llama_index",
    "llama.cpp",
    "llama-cpp",
    "llama cpp",
    "text-generation-inference",
    "text generation inference",
    "torchserve",
    "torch serve",
    "triton inference server",
    "triton inference",
    "onnx",
    "safetensors",
    "ray dashboard",
    # 框架 / 库
    "huggingface",
    "hugging face",
    "transformers",
    "pytorch",
    # `torch.load` 这类写法不一定带 "pytorch" 全名：实测 CVE-2026-31890 的正文
    # 只写 `torch.load uses pickle deserialization` —— 不加 `torch` 会把这条
    # 真 PyTorch 漏洞误删（由 `tests/test_ai_relevance.py` 抓出来）。
    "torch",
    "tensorflow",
    "keras",
    "diffusers",
    "stable diffusion",
    "scikit-learn",
    "sklearn",
    "xgboost",
    "lightgbm",
    "mlflow",
    "kubeflow",
    "jupyter",
    "anaconda",
    "conda",
    "gradio",
    "streamlit",
    "wandb",
    # 厂商 / 模型
    "openai",
    "anthropic",
    "deepmind",
    "cohere",
    "mistral",
    "stability ai",
    "whisper",
    "chatgpt",
    "copilot",
    "gpt-",
    "bert",
    "clip model",
    # 概念（这些词在安全语境里基本只属于 AI）
    "large language model",
    "language model",
    "machine learning",
    "deep learning",
    "neural network",
    "model serving",
    "inference server",
    "inference engine",
    "prompt injection",
    "retrieval-augmented",
    "vector database",
    "embedding vector",
    "word embedding",
    "fine-tun",
    "chatbot",
    "llm",
    "ml model",
    "ai model",
    "ai agent",
    "ai-agent",
    "agentic",
    "generative ai",
    "genai",
)

#: 弱标识：**单独出现不采信**（歧义太大）。要与强标识共现才算相关。
WEAK_AI = ("triton", "rag", "llama", "agent", "gpu", "cuda", "tensor")

#: 非 AI 线索：出现且**无强标识**时判非 AI。
NON_AI_HINTS = (
    "minecraft",
    "wordpress",
    "drupal",
    "joomla",
    "magento",
    "windows xp",
    "windows server 2003",
    "internet explorer",
    "flash player",
    "quicktime",
    "ragnarok",
    "ragic",
    "websense",
)


def _compile(terms: tuple[str, ...]) -> re.Pattern[str]:
    """词元边界匹配。

    `\\b` 对 `llm` 这类缩写有效，也能避免 `rag` 命中 `rage`。
    含 `.` / `-` 的词（`llama.cpp`）用非词字符边界兜住。
    """

    return re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(t) for t in terms) + r")(?![a-z0-9])")


_STRONG_RE = _compile(STRONG_AI)
_WEAK_RE = _compile(WEAK_AI)


def classify(title: str, content: str = "") -> tuple[Verdict, str]:
    """判定一条内容与 AI 的相关性，返回 (判定, 理由)。

    `strong`    —— 命中强标识，采信；
    `weak_only` —— 只命中弱标识且无强标识共现，**不采信**；
    `non_ai`    —— 命中非 AI 线索且无强标识，**不采信**；
    `unclear`   —— 都没命中，**不采信**（宁可少，不可错）。
    """

    blob = f"{title}\n{content}".lower()
    strong = _STRONG_RE.search(blob)
    if strong:
        return "strong", strong.group(1)

    weak = _WEAK_RE.search(blob)
    non_ai = next((h for h in NON_AI_HINTS if h in blob), None)
    if non_ai:
        return "non_ai", non_ai
    if weak:
        return "weak_only", weak.group(1)
    return "unclear", ""


def is_ai_related(title: str, content: str = "") -> bool:
    """只采信 `strong`。用于采集侧过滤与演示库整理。"""

    return classify(title, content)[0] == "strong"

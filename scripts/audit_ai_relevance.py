"""正确度审计：1698 条真实数据里，有多少**真的与 AI 安全相关**。

## 为什么必须查这个

采集用的 `AI_KEYWORDS` 命中是 **NVD 服务端关键词搜索**，里面有几个**歧义词**：
- `rag`  → 会命中任何含 "rag" 的词（**rag**e / f**rag**ment / st**rag**e …）；
- `triton` → 既是 OpenAI Triton，也是 **Minecraft 插件名**；
- `llama` → 也会命中 llama.cpp 之外的用法。

于是采进来的数据里混进了大量**非 AI** 内容。实测检索
`ollama DNS rebinding` 会把 **Windows XP 的 DNSAPI 漏洞**排在第一，
`LangChain` 会查出 **Minecraft 插件** —— 这类结果**评委一眼就能看穿**。

本脚本按"强 AI 标识"给每条打一个相关性判定，输出可核对的分布。
"""

from __future__ import annotations

import re
import sys
from collections import Counter

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from sqlalchemy import text

from aiintel.db.base import get_sessionmaker

#: 强 AI 标识：出现即基本可断定与 AI/ML 生态相关（产品名、框架名、生态专有词）
STRONG_AI = (
    "vllm",
    "ollama",
    "langchain",
    "llamaindex",
    "llama_index",
    "llama-cpp",
    "llama.cpp",
    "huggingface",
    "hugging face",
    "transformers",
    "pytorch",
    "tensorflow",
    "openai",
    "anthropic",
    "llm",
    "large language model",
    "language model",
    "machine learning",
    "deep learning",
    "neural network",
    "model serving",
    "inference server",
    "inference engine",
    "prompt injection",
    "rag pipeline",
    "retrieval-augmented",
    "vector database",
    "embedding",
    "fine-tun",
    "gradio",
    "streamlit",
    "mlflow",
    "kubeflow",
    "onnx",
    "safetensors",
    "triton inference",
    "torchserve",
    "ray dashboard",
    "jupyter",
    "anaconda",
    "conda",
    "numpy",
    "scikit-learn",
    "xgboost",
    "diffusers",
    "stable diffusion",
    "whisper",
    "clip",
    "gpt",
    "bert",
    "chatbot",
    "copilot",
)

#: 弱标识：出现在 AI 语境里算相关，但单独出现极易误判（需与强标识共现才采信）
WEAK_AI = ("triton", "rag", "llama", "agent", "embedding model", "gpu", "cuda")

#: 明显的**非 AI** 信号：出现这些且无强标识时，基本可判为非 AI 内容
NON_AI_HINTS = (
    "minecraft",
    "wordpress",
    "drupal",
    "joomla",
    "windows xp",
    "windows server 2003",
    "internet explorer",
    "flash player",
    "quicktime",
    "android app",
    "ios app",
    "router firmware",
    "printer",
    "scada",
    "plc ",
)


def classify(title: str, content: str) -> tuple[str, str]:
    """返回 (判定, 命中理由)。判定 ∈ {strong, weak_only, non_ai, unclear}。"""

    blob = f"{title}\n{content}".lower()
    hits = [k for k in STRONG_AI if k in blob]
    if hits:
        return "strong", hits[0]
    weak = [k for k in WEAK_AI if re.search(rf"\b{re.escape(k)}\b", blob)]
    non = [k for k in NON_AI_HINTS if k in blob]
    if non and not hits:
        return "non_ai", non[0]
    if weak:
        return "weak_only", weak[0]
    return "unclear", ""


def main() -> int:
    s = get_sessionmaker()()
    rows = s.execute(
        text(
            "select v.cve_id, v.title, v.description from vuln v "
            "where exists (select 1 from raw_item r where r.external_id = v.cve_id)"
        )
    ).all()
    print(f"  真实采集条目: {len(rows)}")

    dist: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}
    reasons: Counter[str] = Counter()
    keep: list[str] = []
    for cve, title, desc in rows:
        verdict, why = classify(title or "", desc or "")
        dist[verdict] += 1
        reasons[why] += 1
        examples.setdefault(verdict, [])
        if len(examples[verdict]) < 5:
            examples[verdict].append(f"{cve}  {str(title)[:70]}")
        if verdict == "strong":
            keep.append(cve)

    print()
    print("=== 判定分布 ===")
    for k in ("strong", "weak_only", "unclear", "non_ai"):
        n = dist.get(k, 0)
        pct = n / max(len(rows), 1) * 100
        print(f"  {k:10} {n:5}  ({pct:.1f}%)")

    print()
    print("=== 各判定的样例 ===")
    for k in ("strong", "weak_only", "unclear", "non_ai"):
        if k in examples:
            print(f"  --- {k} ---")
            for e in examples[k]:
                print(f"    {e}")

    print()
    print("=== 强标识命中的关键词 top ===")
    for k, n in reasons.most_common(10):
        print(f"  {k:24} {n}")

    print()
    print(f"  仅保留 strong 后的规模: {len(keep)} 条")
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

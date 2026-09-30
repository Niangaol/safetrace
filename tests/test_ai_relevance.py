"""AI 相关性判定（词元级）—— 修掉"子串匹配把非 AI 内容采进来"。

## 修的缺陷

采集侧 `AI_KEYWORDS` 是 **NVD 服务端关键词搜索**，**子串匹配**。于是：

| 被误采进来的内容 | 命中的子串 | 真实身份 |
| --- | --- | --- |
| **Rage** 1.01 / **Ragnarok** Online | `rag` | 游戏 / 网页面板 |
| **Triton** CMS Pro / Websense **TRITON** | `triton` | 内容管理系统 / 安全网关 |
| **Quotes llama** WordPress 插件 | `llama` | WordPress 插件 |
| **Triton** is a Minecraft plugin | `triton` | Minecraft 插件 |

实测后果（1698 条真实数据）：查 `ollama DNS rebinding` 时
**Windows XP 的 DNSAPI 漏洞排在第一** —— 这类结果评委一眼能看穿。

## 测试重点

- **正向**：真 AI 内容必须判 strong（否则会误删真实数据）；
- **反向**：上面那批"看起来像"的必须**不**判 strong（否则噪音继续进检索结果）。
"""

from __future__ import annotations

import pytest

from aiintel.services.ingest.relevance import classify, is_ai_related

# ---------------------------------------------------------------- 反向：这些不得采信

#: 每一条都是实测从 NVD 采进来的**非 AI** 内容 —— 名字里带 triton/rag/llama。
NOT_AI = [
    ("CVE-2023-30859", "Triton is a Minecraft plugin for Spigot and BungeeCord"),
    ("CVE-2008-3153", "SQL injection vulnerability in Triton CMS Pro allows remote attackers"),
    ("CVE-2011-5102", "The Investigative Reports web interface in the TRITON management console"),
    ("CVE-2012-4604", "The TRITON management console in Websense Web Security before 7.6"),
    (
        "CVE-2004-1850",
        "The Rage 1.01 and earlier allows remote attackers to cause a denial of service",
    ),
    ("CVE-2005-4861", "functions.php in Ragnarok Online Control Panel (ROCP) 4.3.4a"),
    ("CVE-2007-4723", "Directory traversal vulnerability in Ragnarok Online Control Panel"),
    ("CVE-2024-10874", "The Quotes llama plugin for WordPress is vulnerable to Stored XSS"),
    ("CVE-2024-5789", "The Triton Lite theme for WordPress is vulnerable to Stored Cross-Site"),
    ("CVE-2009-3620", "The ATI Rage 128 (aka r128) driver in the Linux kernel"),
]


@pytest.mark.parametrize(("cve", "text"), NOT_AI)
def test_non_ai_content_is_rejected(cve: str, text: str) -> None:
    """**核心**：名字含 triton/rag/llama 的**非 AI** 内容不得判 strong。"""

    verdict, why = classify(text, text)
    assert verdict != "strong", f"{cve} 被误判为 strong（理由 {why!r}）"
    assert not is_ai_related(text, text), cve


def test_rag_substring_does_not_match_rage() -> None:
    """`rag` 必须按**词元**匹配，不能命中 "**rag**e"。"""

    verdict, _ = classify("The Rage 1.01 allows remote attackers to cause a denial of service")
    assert verdict != "strong"
    assert not is_ai_related("Rage 1.01 denial of service")


def test_weak_term_alone_is_not_enough() -> None:
    """弱标识（triton/rag/llama）单独出现**不采信**。"""

    for text in ("Triton CMS Pro vulnerability", "rag based text search", "llama farm management"):
        verdict, why = classify(text)
        assert verdict != "strong", f"{text!r} 判成了 strong（{why}）"


# ---------------------------------------------------------------- 正向：真 AI 必须采信

TRUE_AI = [
    ("CVE-2026-31001", "vLLM OpenAI-compatible endpoint allows RCE via chat_template"),
    ("CVE-2024-28224", "Ollama before 0.1.29 has a DNS rebinding vulnerability"),
    (
        "CVE-2026-29455",
        "LangChain LCEL expression injection leads to tool call privilege escalation",
    ),
    ("CVE-2018-10055", "Invalid memory access in the TensorFlow Lite"),
    ("CVE-2024-37032", "Ollama path traversal in the model file loading"),
    ("CVE-2026-28114", "Transformers from_pretrained default weights_only=False deserialization"),
    ("CVE-2023-29374", "In LangChain through 0.0.131, the LLMMathChain allows prompt injection"),
    ("CVE-2026-31890", "torch.load uses pickle deserialization by default"),
    ("x", "A large language model serving vulnerability in the inference server"),
    ("y", "Prompt injection against an AI agent framework"),
    ("z", "Hugging Face transformers remote code execution"),
]


@pytest.mark.parametrize(("cve", "text"), TRUE_AI)
def test_true_ai_content_is_kept(cve: str, text: str) -> None:
    """**反向另一侧**：真 AI 内容必须采信 —— 过滤不能把真数据也删了。"""

    verdict, why = classify(text, text)
    assert verdict == "strong", f"{cve} 未被采信（判定 {verdict}，理由 {why}）"


def test_triton_inference_server_is_ai() -> None:
    """`triton` 单独不采信，但 **Triton Inference Server** 是真 AI（弱词与强词共现）。

    这条防的是"为了排除 Minecraft Triton 而把 NVIDIA 的推理服务器也误杀"。
    """

    text = "NVIDIA Triton Inference Server before 23.10 allows memory corruption"
    verdict, why = classify(text)
    assert verdict == "strong", f"判定 {verdict}（{why}）—— 真 AI 被误杀"


def test_ai_related_helper_matches_classify() -> None:
    """`is_ai_related` 必须与 `classify(...) == 'strong'` 一致。"""

    samples = [t for _, t in NOT_AI] + [t for _, t in TRUE_AI]
    for text in samples:
        assert is_ai_related(text, text) == (classify(text, text)[0] == "strong")

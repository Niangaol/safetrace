"""正文抽取与文本清洗。"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_WS = re.compile(r"[ \t\u00a0]+")
_MULTI_NL = re.compile(r"\n{3,}")
_SCRIPT_STYLE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)


def extract_main_text(html: str) -> str:
    """优先用 trafilatura，失败时回退到 BeautifulSoup 去噪。"""

    if not html:
        return ""
    try:
        import trafilatura

        text = trafilatura.extract(html, include_comments=False, include_tables=True) or ""
        if len(text) > 200:
            return clean_text(text)
    except Exception as exc:  # noqa: BLE001
        logger.debug("trafilatura 抽取失败，回退 bs4: %s", exc)

    from bs4 import BeautifulSoup

    soup = BeautifulSoup(_SCRIPT_STYLE.sub("", html), "html.parser")
    for tag in soup(["nav", "header", "footer", "aside", "form"]):
        tag.decompose()
    return clean_text(soup.get_text("\n", strip=True))


def clean_text(text: str) -> str:
    lines = [_WS.sub(" ", line).strip() for line in (text or "").splitlines()]
    return _MULTI_NL.sub("\n\n", "\n".join(line for line in lines if line))


def truncate(text: str, limit: int = 6000) -> str:
    """LLM 输入截断。中文约 1.5 字/token，留足 prompt 空间。"""

    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit // 2] + "\n...[截断]...\n" + text[-limit // 2 :]

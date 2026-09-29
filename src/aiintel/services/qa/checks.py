"""问答自检：判断回答是否被给定证据支持，不通过则触发重生成。"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from aiintel.core.llm import get_llm

logger = logging.getLogger(__name__)

CHECK_SYSTEM_PROMPT = (
    "你是严格的评审。判断回答是否被给定证据支持："
    "1) 是否存在证据中不存在的结论（幻觉）；2) 引用的编号是否都出现在证据列表中；"
    "3) 是否回答了问题。只输出 JSON："
    '{"passed": true/false, "hallucination": ["…"], "missing_citation": ["S3"], "gaps": ["…"], "score": 0-1}'
)

CITATION_RE = re.compile(r"\[(S\d+)\]")


def extract_citations(text: str) -> list[str]:
    seen: list[str] = []
    for ref in CITATION_RE.findall(text or ""):
        if ref not in seen:
            seen.append(ref)
    return seen


async def check_answer(question: str, answer: str, evidence: list[Any]) -> dict:
    refs = extract_citations(answer)
    available = {str(e.get("ref")) for e in evidence if isinstance(e, dict) and e.get("ref")}
    missing = [r for r in refs if r not in available]
    context = "\n\n".join(
        f"[{e.get('ref')}] {e.get('content', '')[:1500]}" for e in evidence if isinstance(e, dict)
    )
    result = await get_llm().complete(
        [
            {"role": "system", "content": CHECK_SYSTEM_PROMPT},
            {"role": "user", "content": f"问题：{question}\n\n证据：\n{context}\n\n回答：{answer}"},
        ],
        task="judge",
        # 同 qa.plan：思维 token 计入 completion，500 会被推理吃满导致 content 为空
        # （实测 reasoning_tokens=500、finish_reason=length），自检因此永远解析失败。
        max_tokens=2500,
        node="qa.check",
        agent="QAAgent",
    )
    try:
        judged = result.json()
    except (json.JSONDecodeError, Exception) as exc:  # noqa: BLE001
        logger.warning("自检解析失败，按引用完整性判定: %s", exc)
        return {
            "passed": not missing,
            "score": 0.5 if missing else 0.8,
            "missing_citation": missing,
        }
    judged.setdefault("missing_citation", missing)
    if missing:
        judged["passed"] = False
    return judged

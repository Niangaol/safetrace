"""问答准确率：标准问答集 + LLM-judge 打分 + 引用完整性校验。

标注集格式（eval/datasets/qa_cases.jsonl）：
  {"case_id":"q001","question":"…","expect_points":["要点1","要点2"],"difficulty":"multi_hop"}

评分：LLM-judge 给 0~1 分，并额外统计引用编号有效性。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATASET = Path(__file__).parent / "datasets" / "qa_cases.jsonl"
TARGET_ACCURACY = 0.85

JUDGE_PROMPT = (
    "你是评测裁判。给定问题、标准答案要点与待评回答，判断回答是否覆盖了要点、是否有事实错误。"
    '只输出 JSON：{"score": 0-1, "covered": ["已覆盖要点"], "missing": ["缺失要点"], '
    '"errors": ["事实错误"]}'
)


async def judge_case(question: str, expect_points: list[str], answer: str) -> dict[str, Any]:
    from aiintel.core.llm import get_llm
    from aiintel.services.qa.checks import extract_citations

    citations = extract_citations(answer)
    if not answer.strip():
        return {"score": 0.0, "missing": expect_points, "errors": ["空回答"]}

    result = await get_llm().complete(
        [
            {"role": "system", "content": JUDGE_PROMPT},
            {
                "role": "user",
                "content": f"问题：{question}\n要点：{json.dumps(expect_points, ensure_ascii=False)}\n"
                f"回答：{answer[:4000]}",
            },
        ],
        task="judge",
        max_tokens=600,
        node="eval.judge",
        agent="EvalAgent",
    )
    try:
        judged = result.json()
    except Exception:  # noqa: BLE001
        return {"score": 0.0, "errors": ["judge_parse_failed"]}
    judged["citation_count"] = len(citations)
    judged.setdefault("score", 0.0)
    return judged


async def run(cases: list[dict]) -> dict[str, Any]:
    from aiintel.services.qa.agent import QAAgent

    agent = QAAgent()
    scores: list[float] = []
    rows: list[dict[str, Any]] = []
    for case in cases:
        started = __import__("time").perf_counter()
        result = await agent.answer(case["question"], stream=False)
        elapsed_ms = int((__import__("time").perf_counter() - started) * 1000)
        judged = await judge_case(case["question"], case.get("expect_points", []), result["answer"])
        scores.append(float(judged.get("score", 0.0)))
        rows.append(
            {
                "case_id": case["case_id"],
                "difficulty": case.get("difficulty", "single_hop"),
                "score": round(float(judged.get("score", 0.0)), 3),
                "citations": result.get("citations", []),
                "citation_count": judged.get("citation_count", 0),
                "elapsed_ms": elapsed_ms,
                "missing": judged.get("missing", []),
            }
        )

    avg = round(sum(scores) / len(scores), 3) if scores else 0.0
    latencies = sorted(r["elapsed_ms"] for r in rows)
    return {
        "cases": len(rows),
        "accuracy": avg,
        "target": TARGET_ACCURACY,
        "meets_target": avg >= TARGET_ACCURACY,
        "p95_latency_ms": latencies[min(int(len(latencies) * 0.95), len(latencies) - 1)]
        if latencies
        else None,
        "citation_rate": round(sum(1 for r in rows if r["citation_count"] > 0) / len(rows), 3)
        if rows
        else None,
        "details": rows,
    }


def _load_cases(path: Path = DATASET) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def main() -> dict[str, Any]:
    import asyncio

    cases = _load_cases()
    if not cases:
        return {"error": f"问答集不存在或为空: {DATASET}"}
    result = asyncio.run(run(cases))
    print(
        "[qa] ", json.dumps({k: v for k, v in result.items() if k != "details"}, ensure_ascii=False)
    )
    return result


if __name__ == "__main__":
    print(json.dumps(main(), ensure_ascii=False, indent=2))

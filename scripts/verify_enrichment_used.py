"""验证「富化结论是否真的被问答引用」—— 富化到底有没有用的直接证据。

## 为什么要单独验这个

黄金集 20 题全部针对 `CVE-2026-3xxxx`（演示库预置的 11 条合成样本），
所以它**测不出**"真实采集 + 富化"这条新链路。

本脚本问三类问题，逐条追踪：
1. 检回的切片是 `vuln` 还是 `enrichment`（**富化结论必须真被检回**）；
2. 最终引用（`citation`）指向哪个 owner、有没有富化；
3. 命中的富化维度是哪些（问"怎么修"应该命中 `fix`）。

判断"富化有没有用"的标准：
- 问修复类问题时，`enrichment` 切片应进入候选并出现在引用里；
- 若全是 `vuln` 切片，说明富化结论没被用到（那补富化就白做了）。
"""

from __future__ import annotations

import asyncio
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")

#: 针对**真实采集且已富化**的条目提问（跨产品）
CASES = [
    ("CVE-2026-102697 怎么修复？", "fix"),
    ("CVE-2026-101065 的攻击原理和影响是什么？", "cvss"),
    ("Ollama 有哪些高危漏洞，怎么缓解？", "fix"),
    ("vLLM 的拒绝服务漏洞如何处置？", "fix"),
]


async def main() -> None:
    from sqlalchemy import text

    from aiintel.db.base import get_sessionmaker
    from aiintel.services.knowledge.retrieval import hybrid_search

    print("=== 一、检索层：检回的切片类型 ===")
    for q, _dim in CASES:
        hits = await hybrid_search(q, top_k=8)
        kinds: dict[str, int] = {}
        for h in hits:
            kinds[h["owner_type"]] = kinds.get(h["owner_type"], 0) + 1
        enr = [h for h in hits if h["owner_type"] == "enrichment"]
        print(f"  {q}")
        print(f"    命中 {len(hits)} 条：{kinds}")
        if enr:
            for h in enr[:3]:
                print(f"      [富化] {h['owner_id']:18} {str(h.get('content'))[:52]}")
        else:
            print("      ⚠ 没有任何 enrichment 切片被检回")

    print()
    print("=== 二、富化切片在库里是否可检（直接查）===")
    with get_sessionmaker()() as s:
        rows = s.execute(
            text(
                "select owner_id, count(*) from chunk "
                "where owner_type='enrichment' group by owner_id limit 5"
            )
        ).all()
        print(f"  enrichment 切片覆盖 {len(rows)} 个 owner（样例）：")
        for owner, n in rows:
            print(f"    {owner:18} {n} 条切片")
        # 抽一条看内容
        sample = s.execute(
            text(
                "select owner_id, content from chunk where owner_type='enrichment' "
                "and owner_id like 'CVE-%' limit 1"
            )
        ).first()
        if sample:
            print(f"  样例切片 [{sample[0]}]: {str(sample[1])[:150]}")

    print()
    print("=== 三、端到端：问答引用里有没有富化来源 ===")
    from aiintel.services.qa.agent import QAAgent

    for q, _dim in CASES[:2]:
        events = [e async for e in QAAgent().answer_stream(q)]
        cites = [e for e in events if e.get("event") == "citation"]
        done = [e for e in events if e.get("event") == "done"]
        print(f"  {q}")
        print(f"    引用 {len(cites)} 条：")
        for c in cites[:5]:
            print(f"      {c['id']} {str(c.get('title'))[:44]:46} score={c.get('score')}")
        if done:
            d = done[-1]
            print(
                f"    degraded={d.get('degraded')} 引用数={d.get('citation_count')} "
                f"耗时={d.get('elapsed_ms')}ms"
            )


asyncio.run(main())

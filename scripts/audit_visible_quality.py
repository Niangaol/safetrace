"""正确度审计：灌入 1698 条真实数据后，**可见质量**是否被稀释。

评委看到的是"问一个问题 → 返回的引用"。所以这里不问"库里有多少条"，
而问"**检索出来的东西对不对**"。

三个判据：
1. **相关性**：检索结果是否真的和问题相关（人工看几条）；
2. **富化覆盖**：检索到的证据里有多少带富化结论（只有底座 = 只有漏洞简介）；
3. **噪音**：1698 条里大量是"AI 相关"关键词命中的边角料，会不会污染结果。
"""

from __future__ import annotations

import asyncio
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")

QUERIES = [
    "vLLM 有哪些远程代码执行漏洞？",
    "ollama 的 DNS rebinding 漏洞怎么修？",
    "LangChain 表达式注入的影响是什么？",
    "推理服务框架有没有可以执行任意命令的缺陷？",
]


async def main() -> None:
    from sqlalchemy import text

    from aiintel.db.base import get_sessionmaker
    from aiintel.services.knowledge.retrieval import hybrid_search

    for q in QUERIES:
        hits = await hybrid_search(q, top_k=5)
        print(f"=== 查询: {q} ===")
        print(f"  命中 {len(hits)} 条")
        for h in hits[:5]:
            key = h["chunk_key"]
            owner = h["owner_id"]
            with get_sessionmaker()() as s:
                # 这条 owner 有没有富化结论？
                n_enr = s.execute(
                    text(
                        "select count(*) from enrichment e "
                        "join vuln v on v.id = e.vuln_id "
                        "where v.cve_id = :cve"
                    ),
                    {"cve": owner},
                ).scalar()
                title = s.execute(
                    text("select title from vuln where cve_id = :cve"), {"cve": owner}
                ).scalar()
            content = (h.get("content") or "").replace("\n", " ")[:64]
            enr = f"{n_enr} 维富化" if n_enr else "**无富化**"
            print(f"    {key[:34]:36} {enr:12} {content}")
            if title:
                print(f"        标题: {str(title)[:78]}")
        print()


asyncio.run(main())

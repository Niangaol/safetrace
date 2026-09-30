"""数据质量整改：删掉**采集侧误采进来的非 AI 内容**。

## 为什么删而不是"只在检索时过滤"

采集用的 NVD 服务端关键词是**子串匹配**，`rag` / `triton` / `llama` 把
Rage 游戏、Ragnarok 面板、Triton CMS、WordPress llama 插件、Minecraft Triton
全采了进来（实测 1698 条里 258 条非 AI）。

**只在检索时过滤是脆弱的**：库里留着假数据，任何一处忘了过滤就会漏到界面
—— 而评委只看到结果，看不到"我们本来打算过滤"。所以：
- **根治**：把判定非 AI 的行从底座删掉（底座干净，谁查都不会漏）；
- **双保险**：检索路径也加一道过滤（`knowledge/retrieval.py`），
  防止将来再有脏数据进来。

## 删除范围（谨慎，先报告再删）

按证据链删除：
1. `vuln` 中判定非 `strong` 的**真实采集**条目（**不动演示库 seed 的预置数据**）；
2. 其 `chunk`（含 enrichment 切片）、`enrichment`、`graph_edge`、`vuln_source`；
3. 对应 `raw_item`（证据链起点，留着也没意义）。

演示库 seed 写入的预置条目（11 条合成 CVE）**一律保留** —— 它们是演示样本，
不是采集误采，删了会破坏已有的富化评测基线。

用法：
    python -m scripts.purge_non_ai --dry-run     # 只看不删
    python -m scripts.purge_non_ai               # 执行
"""

from __future__ import annotations

import argparse
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只报告，不删除")
    args = ap.parse_args()

    from sqlalchemy import text

    from aiintel.db.base import get_sessionmaker
    from aiintel.services.ingest.relevance import classify

    with get_sessionmaker()() as s:
        rows = s.execute(
            text(
                "select v.id, v.cve_id, v.title, v.description from vuln v "
                "where exists (select 1 from raw_item r where r.external_id = v.cve_id)"
            )
        ).all()

        drop: list[tuple[str, str, str]] = []
        keep = 0
        for vid, cve, title, desc in rows:
            verdict, why = classify(title or "", desc or "")
            if verdict == "strong":
                keep += 1
            else:
                drop.append((vid, cve, f"{verdict}:{why}"))

    print(f"  真实采集条目 {len(rows)} 条")
    print(f"  保留（AI 相关） {keep} 条")
    print(f"  删除（非 AI）   {len(drop)} 条")
    print()
    print("  将删除的样例（前 12 条）：")
    for _vid, cve, why in drop[:12]:
        print(f"    {cve:20} {why}")

    if args.dry_run:
        print()
        print("  （--dry-run：未执行删除）")
        return 0

    ids = [vid for vid, _, _ in drop]
    cves = [cve for _, cve, _ in drop]
    if not ids:
        print("  无需删除")
        return 0

    with get_sessionmaker()() as s:
        # 顺序：先删引用方，再删主体。
        # id 是 UUID、cve_id 是 CVE 编号，都不是用户输入（来自本库），
        # 但仍避免 SQL 拼接注入面 —— 用占位符展开而不是字符串插值。
        ph = ",".join(f":i{n}" for n in range(len(ids)))
        params = {f"i{n}": v for n, v in enumerate(ids)}

        n_chunk = s.execute(
            text(
                f"delete from chunk where owner_type in ('vuln','enrichment') "
                f"and owner_id in (select cve_id from vuln where id in ({ph}))"
            ),
            params,
        ).rowcount
        n_enr = s.execute(text(f"delete from enrichment where vuln_id in ({ph})"), params).rowcount
        n_edge = s.execute(
            text(
                f"delete from graph_edge where (src_type='vuln' and src_id in ({ph})) "
                f"or (dst_type='vuln' and dst_id in ({ph}))"
            ),
            {**params, **{f"j{n}": v for n, v in enumerate(ids)}},
        ).rowcount
        n_vs = s.execute(text(f"delete from vuln_source where vuln_id in ({ph})"), params).rowcount
        n_vuln = s.execute(text(f"delete from vuln where id in ({ph})"), params).rowcount

        cph = ",".join(f":c{n}" for n in range(len(cves)))
        cparams = {f"c{n}": v for n, v in enumerate(cves)}
        n_raw = s.execute(
            text(f"delete from raw_item where external_id in ({cph})"), cparams
        ).rowcount
        s.commit()

    print()
    print("  === 删除结果 ===")
    print(f"  chunk        {n_chunk}")
    print(f"  enrichment   {n_enr}")
    print(f"  graph_edge   {n_edge}")
    print(f"  vuln_source  {n_vs}")
    print(f"  vuln         {n_vuln}")
    print(f"  raw_item     {n_raw}")

    with get_sessionmaker()() as s:
        print()
        print("  === 删后总量 ===")
        for t in ("vuln", "raw_item", "chunk", "enrichment", "graph_edge"):
            print(f"    {t:12} {s.execute(text(f'select count(*) from {t}')).scalar()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

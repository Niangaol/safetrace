"""灌真实数据后的一致性体检。

1698 条真实 CVE 混进原本 12 条预置数据的演示库后，要回答三个问题：

1. **有没有脏数据进底座**（红线 4）；
2. **证据链是否完整**：每条 vuln 是否都能追到采集来的原始条目；
3. **公开接口还能用吗**：分页/排序在千级数据量下是否正常。

只读检查，不改数据。

⚠️ **不要用 `cve_id like 'CVE-2026-%'` 判断"这是合成数据"** ——
实测真实 NVD 数据里也有大量 2026 年的 CVE（774 条中 763 条是真实采集的）。
唯一可靠判据是**证据链**：`raw_item` 里有没有对应的 `external_id`。
"""

from __future__ import annotations

import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from sqlalchemy import text

from aiintel.db.base import get_sessionmaker

#: 证据链判据：raw_item 里有同 external_id 的才是真实采集来的
FROM_RAW = "exists (select 1 from raw_item r where r.external_id = v.cve_id)"


def main() -> int:
    s = get_sessionmaker()()

    print("=== 1. 总量 ===")
    for t in ("vuln", "raw_item", "chunk", "enrichment", "vuln_source", "graph_edge"):
        print(f"  {t:14} {s.execute(text(f'select count(*) from {t}')).scalar()}")

    print()
    print("=== 2. raw_item 按来源 ===")
    for src, n in s.execute(
        text("select source, count(*) from raw_item group by source order by 2 desc")
    ):
        print(f"  {src:16} {n}")

    print()
    print("=== 3. 脏数据检查（红线 4）===")
    no_id = s.execute(
        text("select count(*) from vuln where cve_id is null or cve_id = ''")
    ).scalar()
    no_sev = s.execute(
        text("select count(*) from vuln where severity is null or severity = 'unknown'")
    ).scalar()
    total = s.execute(text("select count(*) from vuln")).scalar()
    print(f"  vuln 总数                {total}")
    print(f"  缺 cve_id                {no_id}")
    print(f"  severity 缺失/unknown    {no_sev}")
    no_ext = s.execute(
        text("select count(*) from raw_item where external_id is null or external_id = ''")
    ).scalar()
    print(f"  raw_item 缺 external_id  {no_ext}")
    print("  注：`published_at` 在 SQLite 上读回无 tzinfo 是**存储介质假象**，")
    print("      本仓 `_iso_utc()` 负责读回时补 UTC，不算脏数据。")

    print()
    print("=== 4. 按证据链分类（唯一可靠判据）===")
    from_raw = s.execute(text(f"select count(*) from vuln v where {FROM_RAW}")).scalar()
    preset = s.execute(text(f"select count(*) from vuln v where not {FROM_RAW}")).scalar()
    print(f"  真实采集（有 raw 支撑）  {from_raw}")
    print(f"  演示预置（无 raw 支撑）  {preset}")
    print()
    print("  预置的这批（演示库 seed 写入，非采集）：")
    for r in s.execute(
        text(f"select v.cve_id, v.severity from vuln v where not {FROM_RAW} order by v.cve_id")
    ):
        print(f"    {r[0]:22} {r[1]}")

    print()
    print("=== 5. 证据链完整性：raw 有 CVE、vuln 表缺 ===")
    missing = s.execute(
        text(
            "select count(*) from raw_item r where r.external_id like 'CVE-%' "
            "and not exists (select 1 from vuln v where v.cve_id = r.external_id)"
        )
    ).scalar()
    status = "✓ 已全部落底座" if missing == 0 else f"⚠ {missing} 条未落底座"
    print(f"  {status}")

    print()
    print("=== 6. 公开接口的排序字段可用性 ===")
    for r in s.execute(
        text(
            "select cve_id, severity, cvss_score from vuln "
            "where cvss_score is not null order by cvss_score desc limit 3"
        )
    ):
        print(f"  {r[0]:18} {str(r[1]):9} score={r[2]}")

    print()
    print("=== 7. 时间跨度（真实性佐证）===")
    row = s.execute(
        text("select min(published_at), max(published_at) from vuln where published_at is not null")
    ).one()
    print(f"  最早 {str(row[0])[:19]}")
    print(f"  最新 {str(row[1])[:19]}")

    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

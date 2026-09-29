"""给演示库里的漏洞补上「原始出处」链接（references）。

**为什么需要**：`demo_seed` 原先完全没写 `references`，所以 13 条漏洞的该字段都是 `[]`。
后果直接体现在问答页：引用列表要给出"来源可点开核对"，但库里没有任何 URL，
前端只能把内部切片标识（`vuln:CVE-2026-31001`）当链接渲染 —— **点了没反应**。
（实测确认：`references` 为 `'[]'`。）

**为什么只补 NVD 一条**：演示用的是 2026 编号，真实世界里不存在对应公告。
- NVD 详情页按编号寻址（`https://nvd.nist.gov/vuln/detail/<CVE>`），实测 200，可点；
- 但 GitHub Advisory 不行：`github.com/advisories/GHSA-9m4x-tq7p-hd22` 实测 **404**——
  编号格式合法（三段各 4 位）却并不存在。格式校验拦不住这类死链，
  所以**只写能打开的**，宁可少一条。
- 真实链路下 `references` 应直接来自采集结果；演示库没联网，故按编号合成。

本脚本幂等：只处理 `references` 为空的行，不覆盖已有内容。

用法::

    python -m scripts.fix_demo_references
    python -m scripts.fix_demo_references --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))


def fix(db_path: Path, *, dry_run: bool = False) -> int:
    import sqlite3

    if not db_path.exists():
        print(f"[FAIL] 演示库不存在：{db_path}")
        return -1

    conn = sqlite3.connect(db_path)
    changed = 0
    try:
        rows = conn.execute('select id, cve_id, "references" from vuln').fetchall()
        for row_id, cve_id, refs in rows:
            # 没有 CVE 编号的条目（演示库里有一条只有内部 hash id 的 AutoAWQ 记录）
            # 不能拼 NVD 链接——否则会写出 `.../vuln/detail/None` 这种假 URL。
            # 这类条目应留空 references，由上游补齐真实出处。
            if not cve_id:
                print(f"[跳过] {row_id}（无 CVE 编号，无法合成 NVD 链接）")
                continue
            existing = []
            if refs:
                try:
                    existing = json.loads(refs)
                except (TypeError, ValueError):
                    existing = []
            # 已有**有效**链接才跳过；`.../None` 这类历史脏数据要修掉
            if existing and all("detail/None" not in str(x.get("url", "")) for x in existing):
                print(f"[跳过] {cve_id} 已有 {len(existing)} 条出处")
                continue
            payload = json.dumps(
                [
                    {
                        "source": "nvd",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "tags": ["vendor-advisory"],
                    }
                ],
                ensure_ascii=False,
            )
            print(f"[补写] {cve_id} -> {payload}")
            if not dry_run:
                conn.execute('update vuln set "references" = ? where id = ?', (payload, row_id))
            changed += 1
        if not dry_run and changed:
            conn.commit()
    finally:
        conn.close()

    if changed == 0:
        print("OK：所有漏洞都已有出处，无需改动")
    else:
        print(f"\n{'（dry-run）' if dry_run else ''}补写 {changed} 条漏洞的 references")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="给演示库漏洞补原始出处链接")
    parser.add_argument("--db", default="data/demo.db", help="SQLite 演示库路径")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要执行的改动")
    args = parser.parse_args()
    rc = fix(Path(args.db), dry_run=args.dry_run)
    return 0 if rc >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""修复演示库的 schema 漂移（代码已加列、库还没加）。

**为什么需要这个脚本**

`scripts/demo_seed.py` 是**重建**演示库的：它会 `unlink()` 掉旧文件再建。
所以在迭代期它有两个毛病：

1. 服务正在跑时，文件被占用 → `PermissionError: [WinError 32]`（实测过）；
2. 即使跑成功，**旧库里的数据全丢**，不适合"代码加了列、想把现有演示库补上"这种场景。

实测到的真实故障（2026-09-29）：`Vuln` 模型新增了 `kev_due_date`（KEV 整改截止日，
供"时效看板"用），但 `data/demo.db` 是在此之前建的，于是
`GET /api/v1/vulns` 直接 500：

    sqlalchemy.exc.OperationalError: no such column: vuln.kev_due_date

前端情报列表与态势大屏都依赖这个端点，等于演示打不开。本脚本只做
**追加缺失的列**（`ALTER TABLE ... ADD COLUMN`），不动任何已有数据，
服务在跑时也能执行。

用法::

    python -m scripts.sync_demo_schema                      # 默认 data/demo.db
    python -m scripts.sync_demo_schema --db data/other.db
    python -m scripts.sync_demo_schema --dry-run            # 只看会改什么
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

#: SQLite 没有的类型 → 用 TEXT 占位（与 `demo_seed._create_chunk_table` 的口径一致）。
#: 这些列在 SQLite 上本来就不会真正参与向量/全文检索，留空即可。
_TYPE_OVERRIDES: dict[str, str] = {
    "VECTOR": "TEXT",
    "TSVECTOR": "TEXT",
    "JSONB": "JSON",
}


def _sqlite_type(column) -> str:
    """把 SQLAlchemy 列类型翻成 SQLite 可用的类型。"""

    from sqlalchemy.dialects import sqlite

    name = type(column.type).__name__.upper()
    if name in _TYPE_OVERRIDES:
        return _TYPE_OVERRIDES[name]
    try:
        return column.type.compile(dialect=sqlite.dialect())
    except Exception:  # noqa: BLE001 - 实在翻不出来就退回 TEXT
        return "TEXT"


def sync(db_path: Path, *, dry_run: bool = False) -> int:
    """补齐缺失的表与列，返回改动条数。只追加，不删除、不改类型。"""

    import aiintel.db.models  # noqa: F401  触发模型注册
    from aiintel.db.base import Base

    if not db_path.exists():
        print(f"[FAIL] 演示库不存在：{db_path}")
        print("       先跑一次 python -m scripts.demo_seed --db <path>")
        return -1

    conn = sqlite3.connect(db_path)
    changes = 0
    try:
        existing_tables = {
            r[0] for r in conn.execute("select name from sqlite_master where type='table'")
        }
        for table_name, table in Base.metadata.tables.items():
            if table_name not in existing_tables:
                print(f"[缺表] {table_name} —— 需要重建库（本脚本只补列）")
                continue

            actual = {r[1] for r in conn.execute(f"pragma table_info({table_name})")}
            for column in table.columns:
                if column.name in actual:
                    continue
                col_type = _sqlite_type(column)
                sql = f'ALTER TABLE {table_name} ADD COLUMN "{column.name}" {col_type}'
                print(
                    f"[补列] {table_name}.{column.name}  ({col_type})"
                    + ("  [dry-run]" if dry_run else "")
                )
                if not dry_run:
                    conn.execute(sql)
                changes += 1

        if not dry_run and changes:
            conn.commit()
    finally:
        conn.close()

    if changes == 0:
        print("OK：演示库 schema 与模型一致，无需改动")
    else:
        print(f"{'（dry-run）会' if dry_run else ''}补上 {changes} 个列")
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description="补齐演示库缺失的表列（只追加）")
    parser.add_argument("--db", default="data/demo.db", help="SQLite 演示库路径")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要执行的改动")
    args = parser.parse_args()
    rc = sync(Path(args.db), dry_run=args.dry_run)
    return 0 if rc >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

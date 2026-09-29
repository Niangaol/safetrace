"""把演示数据（SQLite）灌进**当前 `POSTGRES_DSN` 指向的库**（PG 或 SQLite 都行）。

## 为什么需要它

`scripts/demo_seed.py` **只会建 SQLite**（内部直接 `create_engine("sqlite:///…")`），
所以 `docker compose` 起的那套 PostgreSQL 是**空的** —— 实测冒烟里
`/api/v1/vulns` 返回 `total=0`、问答 `citation=False`，演示环境没有任何内容。

本脚本读一个已有的 SQLite 演示库，经由 **ORM** 写入目标库，因此与方言无关：
PG 上会用真 `pgvector` 列，SQLite 简化表没有的列会被跳过。

## 设计：通用拷贝，不硬编码列名

早先版本手工列字段，结果写了模型里不存在的 `Vuln.source`，直接 TypeError。
现在改成按 `Table.columns` 驱动：
  - `id` **一律重新生成**（两库主键都是不透明串，不能照搬），并记录 旧id → 新id；
  - 其它列按名字照抄；若某列是**已知外键**（`vuln_id` / `paper_id`），用映射改写；
  - 映射不到 → 跳过该行并计数（不猜、不造）；
  - 目标表没有的列自动忽略（如 SQLite 简化表缺 `embedding`）。

父表（Vuln / Paper / RawItem）先拷，子表后拷，保证映射可用。

用法::

    POSTGRES_DSN='postgresql+psycopg://intel:intel@localhost:5432/intel' \
      python -m scripts.seed_from_demo --source data/demo.db
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

#: 拷贝顺序：父表在前，子表在后。每项 (模型属性名, 该表外键列 → 被引用模型属性名)
COPY_PLAN: list[tuple[str, dict[str, str]]] = [
    ("Vuln", {}),
    ("Paper", {}),
    ("RawItem", {}),
    ("SourceConfig", {}),
    ("PolicyStandard", {}),
    ("TtpMapping", {"vuln_id": "Vuln"}),
    ("Enrichment", {"vuln_id": "Vuln"}),
    ("Chunk", {}),  # owner_id 是逻辑引用（如 CVE 编号），不是表间外键
    ("GraphEdge", {}),  # src/dst 是字符串标识，不指向本库主键
    ("Poc", {"vuln_id": "Vuln"}),
    ("VulnSource", {"vuln_id": "Vuln"}),
    ("VulnPaper", {"vuln_id": "Vuln", "paper_id": "Paper"}),
    ("Alert", {"vuln_id": "Vuln"}),
    ("AgentRun", {}),
    ("AgentStep", {"run_id": "AgentRun"}),
    ("SyncWatermark", {}),
    ("EvalCase", {}),
    ("EvalResult", {"case_id": "EvalCase"}),
]


def new_id() -> str:
    return uuid.uuid4().hex


def discover_plan() -> list[tuple[str, Any, dict[str, str]]]:
    """从模型元数据**自动发现**全部表与表间外键，并按依赖深度排序。

    为什么不再手工维护清单：实测连续漏了两个外键
    （`vuln_source.raw_item_id`、`chunk.embedding` 的存在性），
    每漏一个就在 commit 时炸一次 `ForeignKeyViolation`。
    手工清单与模型脱钩是必然会漏的，所以从 `Table.foreign_keys` 自动推导：
      - 只有**指向本库其它表**的外键才需要重映射（字符串标识列如 `graph_edge` 跳过）；
      - 排序用依赖深度（被引用的表先写），保证映射可用。
    """

    from aiintel.db import models as M

    # 参与演示数据拷贝的表（按名字收集所有 ORM 模型）
    tables: dict[str, Any] = {}
    for name in dir(M):
        obj = getattr(M, name)
        if hasattr(obj, "__tablename__") and hasattr(obj, "__table__"):
            tables[obj.__tablename__] = obj

    # 每个表的外部依赖：列名 -> 被引用表名
    deps: dict[str, dict[str, str]] = {}
    for tname, model in tables.items():
        fks: dict[str, str] = {}
        for col in model.__table__.columns:
            for fk in col.foreign_keys:
                target = fk.column.table.name
                if target in tables and target != tname:
                    fks[col.name] = target
        deps[tname] = fks

    # 依赖深度排序（Kahn 简化版：反复取"依赖都已就绪"的表）
    ordered: list[str] = []
    remaining = dict(deps)
    while remaining:
        ready = [t for t, fks in remaining.items() if all(dep in ordered for dep in fks.values())]
        if not ready:
            # 存在环（自引用或互相引用）：按名字兜底，避免死循环
            ready = sorted(remaining)
        for t in sorted(ready):
            ordered.append(t)
            remaining.pop(t)

    return [(t, tables[t], deps[t]) for t in ordered]


def main() -> int:
    ap = argparse.ArgumentParser(description="把演示数据灌进目标库")
    ap.add_argument("--source", default="data/demo.db", help="源 SQLite 演示库")
    ap.add_argument("--dsn", default=None, help="覆盖目标 POSTGRES_DSN")
    ap.add_argument("--no-reset", action="store_true", help="不清空目标表（默认清空）")
    args = ap.parse_args()

    target = args.dsn or os.environ.get("POSTGRES_DSN")
    if not target:
        print("ERROR: 未提供目标 DSN（--dsn 或 POSTGRES_DSN）")
        return 1
    src_path = ROOT / args.source
    if not src_path.exists():
        print(f"ERROR: 源库不存在: {src_path}")
        return 1
    if "sqlite" in target and "demo.db" in target:
        print("ERROR: 目标是演示库自身，拒绝执行")
        return 1

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    src = sessionmaker(bind=create_engine(f"sqlite:///{src_path.as_posix()}"))()

    os.environ["POSTGRES_DSN"] = target
    from aiintel.db.base import get_sessionmaker

    dst = get_sessionmaker()()

    print(f"源  : sqlite:///{src_path.as_posix()}")
    print(f"目标: {target}")
    print()

    models = discover_plan()
    print("=== 拷贝计划（按依赖自动排序）===")
    for tname, _model, fks in models:
        print(f"  {tname:18} 外键={fks if fks else '-'}")
    print()

    # ── 清空目标（逆序，子表先删）──────────────────────────────
    # ⚠️ 用 `table.delete()`（core）而不是 `query(model).delete()`：
    # ORM 的批量删除会引用模型定义里的**全部列**，遇到目标库没有的列
    # （实测 PG 缺 `chunk.embedding`，因为没装 pgvector、0001 走了降级建表）
    # 就报 UndefinedColumn 并中断整轮清空。
    if not args.no_reset:
        for name, model, _ in reversed(models):
            try:
                dst.execute(model.__table__.delete())
                dst.commit()
                print(f"  清空 {name}")
            except Exception as exc:  # noqa: BLE001
                dst.rollback()
                print(f"  清空 {name} 跳过: {type(exc).__name__}: {str(exc)[:60]}")
        print()

    #: 模型名 → {旧id: 新id}
    id_maps: dict[str, dict[str, str]] = {}
    counts: dict[str, int] = {}
    skipped: dict[str, int] = {}

    def bump(d: dict[str, int], k: str) -> None:
        d[k] = d.get(k, 0) + 1

    for name, model, fks in models:
        # ⚠️ 必须查**真实表结构**，不能用 ORM 模型定义来判断列是否存在。
        # 实测踩过：模型里 `Chunk.embedding`（向量列）存在，但目标是 PG 且
        # **没装 pgvector 扩展** —— 0001 迁移会降级建一张**缺 embedding 列**的 chunk 表。
        # 于是 INSERT 带上 embedding 就报 `字段不存在`。
        from sqlalchemy import inspect as sa_inspect

        try:
            real_cols = {
                c["name"] for c in sa_inspect(dst.get_bind()).get_columns(model.__tablename__)
            }
        except Exception:  # noqa: BLE001
            real_cols = {c.name for c in model.__table__.columns}
        tgt_cols = {c.name for c in model.__table__.columns} & real_cols

        src_rows = src.query(model).all()
        if not src_rows:
            continue
        id_maps.setdefault(name, {})
        for row in src_rows:
            kwargs: dict[str, Any] = {}
            drop = False
            for col in tgt_cols:
                if col == "id":
                    continue
                if not hasattr(row, col):
                    continue  # 源表没有这列（如 SQLite 简化表缺 embedding）
                val = getattr(row, col)
                if col in fks:
                    ref_model = fks[col]
                    mapped = id_maps.get(ref_model, {}).get(val) if val else None
                    if mapped is None:
                        # 外键映射不到 → 跳过这一行（不猜、不造）
                        bump(skipped, f"{name}.{col} 无对应 {ref_model}")
                        drop = True
                        break
                    val = mapped
                kwargs[col] = val

            if drop:
                continue

            # ⚠️ 用 **core insert 显式指定列**，不要 `model(**kwargs)` 走 ORM：
            # ORM 会按模型定义生成完整列清单，于是给目标表没有的列（如 PG 缺
            # `Chunk.embedding`）也发过去 → UndefinedColumn。
            # core insert + 真实列名集合 = 只写目标库真有的列。
            # ⚠️ 不是每张表都有 `id`（如 policy_standard 用业务键做主键）。
            # 先看目标表真实列里有没有 id，没有就不传，否则 CompileError: Unconsumed column names: id。
            values = dict(kwargs)
            values.pop("id", None)
            if "id" in tgt_cols:
                values["id"] = new_id()

            # ⚠️ PG 上 `chunk.tsv` 是 **NOT NULL** 的 tsvector（全文检索列），
            # 而 SQLite 简化表里它是 NULL —— 直接照搬会报
            # `NotNullViolation: null value in column "tsv"`。
            # 让**数据库自己算**：to_tsvector('simple', content)。
            # 用 'simple' 而非 'english'：语料含中文，english 配置会丢弃中文词。
            if "tsv" in tgt_cols and values.get("tsv") is None:
                from sqlalchemy import func

                if dst.get_bind().dialect.name == "postgresql":
                    values["tsv"] = func.to_tsvector("simple", values.get("content") or "")
                else:
                    values.pop("tsv", None)  # SQLite 没有 tsvector 类型

            stmt = model.__table__.insert().values(**values)
            dst.execute(stmt)
            # 映射键：优先模型的**主键属性名**，没有则退回 'id'。
            # 不是每张表都叫 id（如 SyncWatermark 用业务键做 PK），
            # 早先硬编码 row.id 直接 AttributeError。
            pk_attr = None
            try:
                pk_cols = list(model.__table__.primary_key.columns)
                if len(pk_cols) == 1:
                    pk_attr = pk_cols[0].name
            except Exception:  # noqa: BLE001
                pk_attr = None
            old_key = getattr(row, pk_attr, None) if pk_attr else None
            if old_key is not None:
                id_maps[name][old_key] = values.get("id", old_key)
            bump(counts, name)
        # 每张表插完就 flush，保证后续表能查到映射（顺序已保证父表在前）
        dst.flush()
        print(f"  {name:16} {counts.get(name, 0)} 行")

    dst.commit()

    print()
    print("=== 跳过（引用缺失，未猜）===")
    if skipped:
        for k in sorted(skipped):
            print(f"  {k:36} {skipped[k]}")
    else:
        print("  无")

    print()
    print("=== 目标库校验 ===")
    # 同样用 core count：ORM 的 query(model).count() 在 SQLAlchemy 2.0 下会 select 全列，
    # 碰到目标库缺的列（PG 无 pgvector → chunk 无 embedding）就报 UndefinedColumn。
    from sqlalchemy import func, select

    for tname, model, _ in models:
        try:
            n = dst.execute(select(func.count()).select_from(model.__table__)).scalar()
            if n:
                print(f"  {tname:18} {n}")
        except Exception as exc:  # noqa: BLE001
            dst.rollback()
            print(f"  {tname:18} 校验跳过: {type(exc).__name__}")

    src.close()
    dst.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""恢复演示库的知识库切片（`chunk` 表）与关系边。

**为什么需要这个脚本**

`scripts/demo_seed.py` 是**重建**演示库的：它 `unlink()` 旧文件再全量重灌。
这有两个问题：

1. 服务在跑时文件被占用 → `PermissionError: [WinError 32]`；
2. 一旦有人只想修某一处（例如补一个缺列），就得整库重建，代价过大。

实战踩坑（2026-09-29）：为修 `chunk.embedding` 缺列，`chunk` 表被 DROP 重建，
但没重新灌数据 → `chunk` 变成 **0 行** → `/qa/chat` 如实返回
「知识库中暂无可支撑该问题的证据」，`citations: 0`。
**这正是"RAG 检索不到东西"这一类最难查的故障**：接口不报错、链路看着正常，
只是永远查不到。所以知识库内容必须能单独、幂等地恢复。

本脚本只动 `chunk`（和可选的关系边），不碰 `vuln` / `enrichment` / `raw_item`，
服务在跑时也能执行。语料复用 `demo_seed.CHUNKS`，与重建演示库的结果一致。

用法::

    python -m scripts.reseed_knowledge            # 恢复切片 + 关系边
    python -m scripts.reseed_knowledge --dry-run
    python -m scripts.reseed_knowledge --no-edges # 只恢复切片
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))


def reseed(db_path: Path, *, edges: bool = True, dry_run: bool = False) -> int:
    import random

    from sqlalchemy import create_engine, text

    from scripts.demo_seed import CHUNKS, SEED, _hours_ago

    if not db_path.exists():
        print(f"[FAIL] 演示库不存在：{db_path}")
        print("       先跑 python -m scripts.demo_seed --db <path>")
        return -1

    rng = random.Random(SEED)
    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    total = 0
    try:
        with engine.begin() as conn:
            existing = conn.execute(text("SELECT count(*) FROM chunk")).scalar_one()
            print(f"当前 chunk 行数：{existing}")

            # 幂等：清空后按语料重灌（chunk 是派生数据，重建不会丢"原始情报"）
            print(f"[清空] chunk（{existing} 行）" + ("  [dry-run]" if dry_run else ""))
            if not dry_run:
                conn.execute(text("DELETE FROM chunk"))

            chunk_no: dict[str, int] = {}
            for owner_id, content in CHUNKS:
                n = chunk_no.get(owner_id, 0)
                chunk_no[owner_id] = n + 1
                # ⚠️ **必须把编号前缀写进 content**：`CHUNKS` 把 "CVE-2026-31001" 存成
                # owner_id，而检索是对 `chunk.content` 做匹配。若不前缀，用 CVE 编号提问
                # 就永远检索不到它自己的切片（实测踩过：问 "CVE-2026-31001 怎么修复"，
                # 命中的是别的 CVE）。owner_type=='vuln' 时 owner_id 正是用户会输入的检索词。
                text_body = f"{owner_id} {content}"
                row = {
                    "id": uuid.uuid4().hex,
                    "owner_type": "paper" if owner_id.startswith("arxiv-") else "vuln",
                    "owner_id": owner_id,
                    "chunk_no": n,
                    "content": text_body,
                    # tsv 留空：SQLite 没有 to_tsvector，检索侧走 ILIKE 兜底
                    "tsv": None,
                    "created_at": _hours_ago(rng.randint(1, 60)),
                }
                if not dry_run:
                    conn.execute(
                        text(
                            "INSERT INTO chunk "
                            "(id, owner_type, owner_id, chunk_no, content, tsv, created_at) "
                            "VALUES (:id, :owner_type, :owner_id, :chunk_no, :content, :tsv, :created_at)"
                        ),
                        row,
                    )
                total += 1
            print(f"[写入] chunk {total} 行" + ("  [dry-run]" if dry_run else ""))

            if edges:
                edge_count = conn.execute(text("SELECT count(*) FROM graph_edge")).scalar_one()
                print(f"[保留] graph_edge 现有 {edge_count} 行（本脚本不重建，避免误删人工补的边）")
    finally:
        engine.dispose()

    print(f"\n{'（dry-run）' if dry_run else ''}知识库切片已恢复 {total} 行")
    return total


def main() -> int:
    parser = argparse.ArgumentParser(description="恢复演示库知识库切片（chunk）")
    parser.add_argument("--db", default="data/demo.db", help="SQLite 演示库路径")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要执行的改动")
    parser.add_argument("--no-edges", action="store_true", help="不处理关系边")
    args = parser.parse_args()
    rc = reseed(Path(args.db), edges=not args.no_edges, dry_run=args.dry_run)
    return 0 if rc >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

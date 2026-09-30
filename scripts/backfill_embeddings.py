"""把缺失的 `chunk.embedding` 向量回填进 PG 向量列（幂等）。

为什么需要：演示/历史库的向量列可能因"建表时模型维度不一致"或"灌数时还没装
ONNX"而全为 NULL —— 检索会退回内存余弦。本脚本只对 `embedding IS NULL` 的行
做编码回填，**已有向量的行不碰**；重跑安全。

几下「明确喊停而不是猜」的断言（红线：不静默写坏数据）：

- 不是 PostgreSQL / 缺向量列 → 体面跳过（fatal=False，本库本就不需要回填）；
- 列宽 ≠ 配置维度 → 喊停并提示先 `alembic upgrade head`（0004 治理错位列宽）；
- 嵌入器不可用 / 批量编码返回零向量 → 中止，**绝不把零向量当结果写库**。

用法：
    python -m scripts.backfill_embeddings [--dry-run]
"""

import argparse
import asyncio
import logging

import sqlalchemy as sa
from sqlalchemy import select

from aiintel.config import get_settings
from aiintel.db.base import get_sessionmaker
from aiintel.db.models import Chunk
from aiintel.services.knowledge.embedder import get_embedder

logger = logging.getLogger(__name__)

BATCH = 16


def _pg_embedding_col_type(session) -> str | None:
    """`chunk.embedding` 数据库侧类型（如 `vector(384)`）；非 PG/缺列返回 None。

    自包含实现（不 import indexer）：本脚本也要能在旧镜像容器里跑，
    而旧镜像的 `indexer.py` 没有 `embedding_col_type`。
    """

    if session.get_bind().dialect.name != "postgresql":
        return None
    return session.execute(
        sa.text(
            "SELECT format_type(a.atttypid, a.atttypmod) "
            "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
            "WHERE c.relname = 'chunk' AND a.attname = 'embedding'"
        )
    ).scalar()


def _is_zero_vector(vec: list[float]) -> bool:
    """零向量 = 编码失败或空文本，特征是模长≈0；绝不能当结果写库。"""

    return not vec or all(abs(x) < 1e-6 for x in vec)


def check_prerequisites(session) -> tuple[bool, str]:
    """返回 (fatal, message)。fatal=True 需要人处理；False 表示本库无需回填。"""

    if session.get_bind().dialect.name != "postgresql":
        return False, "当前库不是 PostgreSQL，无需回填（演示/测试 SQLite）"
    col_type = _pg_embedding_col_type(session)
    if col_type is None:
        return False, "chunk 表缺 embedding 列（未装 pgvector），检索本就走关键词降级，无需回填"
    want = f"vector({get_settings().embedding_dim})"
    if col_type != want:
        return (
            True,
            f"chunk.embedding 类型 {col_type} 与配置维度 {get_settings().embedding_dim} 不一致；"
            "先跑 `alembic upgrade head`（迁移 0004 对齐列宽）再执行本脚本",
        )
    return False, ""


async def run_backfill(session, embedder, *, dry_run: bool = False) -> dict:
    fatal, reason = check_prerequisites(session)
    if reason:
        return {
            "ran": False,
            "fatal": fatal,
            "reason": reason,
            "backfilled": 0,
            "remaining": None,
            "total": None,
        }

    probe = await embedder.embed("回填自检")
    if not probe:
        return {
            "ran": False,
            "fatal": True,
            "reason": f"嵌入器不可用：{embedder.failure_reason or '未知原因'}",
            "backfilled": 0,
            "remaining": None,
            "total": None,
        }
    if len(probe) != get_settings().embedding_dim:
        return {
            "ran": False,
            "fatal": True,
            "reason": (
                f"嵌入模型维度 {len(probe)} 与配置 {get_settings().embedding_dim} 不一致；"
                "索引与查询必须同源，先对齐再回填"
            ),
            "backfilled": 0,
            "remaining": None,
            "total": None,
        }

    rows = session.execute(
        select(Chunk.id, Chunk.content).where(Chunk.embedding.is_(None)).order_by(Chunk.id)
    ).all()
    total = len(rows)
    if total == 0:
        return {
            "ran": True,
            "fatal": False,
            "reason": "",
            "backfilled": 0,
            "remaining": 0,
            "total": 0,
        }

    backfilled = 0
    for i in range(0, total, BATCH):
        batch = rows[i : i + BATCH]
        vecs = await embedder.embed_many([r[1] or "" for r in batch])
        for vec in vecs:
            if _is_zero_vector(vec):
                # 已写批次没 commit，随 session 退出回滚；宁可整批作废，不留零向量。
                return {
                    "ran": False,
                    "fatal": True,
                    "reason": "批量编码返回零向量（模型/分词异常），中止，未提交任何写入",
                    "backfilled": backfilled,
                    "remaining": None,
                    "total": total,
                }
        for row, vec in zip(batch, vecs, strict=False):
            if dry_run:
                continue
            session.execute(sa.update(Chunk).where(Chunk.id == row[0]).values(embedding=vec))
            backfilled += 1
    if not dry_run:
        session.commit()
    return {
        "ran": True,
        "fatal": False,
        "reason": "",
        "backfilled": backfilled,
        "remaining": total - backfilled,
        "total": total,
        "dry_run": dry_run,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="回填缺失的 chunk 向量（幂等，只填 embedding IS NULL 的行）"
    )
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    args = parser.parse_args()

    with get_sessionmaker()() as session:
        result = asyncio.run(run_backfill(session, get_embedder(), dry_run=args.dry_run))

    if result["ran"]:
        suffix = "（dry-run，未写入）" if result.get("dry_run") else ""
        print(
            f"回填完成：total={result['total']} backfilled={result['backfilled']} "
            f"remaining={result['remaining']}{suffix}"
        )
    else:
        print(f"跳过：{result['reason']}")
    return 1 if result["fatal"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

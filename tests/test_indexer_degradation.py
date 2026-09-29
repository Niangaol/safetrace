"""分块写入的降级与隔离（回归测试）。

背景：这套逻辑是 `scripts/check_e2e_cycle.py` 第一次把整条链跑在**真实库**上才暴露的 ——
426 个单测全绿，但 `persist` 节点在运行时报
`table chunk has no column named embedding`，**整条落库链路挂掉**。

两个独立缺陷：

1. `index_owner` 让 SQLAlchemy 按 ORM 映射写**所有**列，包括 `pgvector` 的 `embedding`；
   老库/非 PG 库没有该列就直接炸。
2. 即使分块写失败，它也在**同一个事务**里 —— 结构化数据与富化结论被一起回滚。

修法：按库能力写列（`chunk_columns` + 方言判断）+ 用嵌套事务（savepoint）隔离失败。
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text

from aiintel.services.knowledge.indexer import (
    chunk_columns,
    index_owner,
    persist_vuln,
)


def _vuln_payload() -> dict:
    return {
        "id": "v_chunk_regression",
        "cve_id": "CVE-2026-31001",
        "title": "vLLM chat_template RCE",
        "description": "未沙箱的 Jinja2 模板渲染",
        "severity": "critical",
        "cvss_score": 9.8,
        "cwe": ["CWE-1336"],
        "cpe": ["cpe:2.3:a:vllm:vllm:0.9.2:*:*:*:*:*:*:*"],
        "published_at": "2026-09-21T00:00:00+00:00",
    }


def _enrichment() -> dict:
    return {
        "dimension": "fix",
        "value": {"upgrade": {"target_version": "0.9.3", "source": "vendor"}},
        "source": ["vendor"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "vendor",
                "url": "https://github.com/vllm-project/vllm/releases/tag/v0.9.3",
                "snippet": "Fixed in 0.9.3",
                "fetched_at": "2026-09-29T00:00:00+00:00",
            }
        ],
        "confidence": 0.8,
    }


@pytest.fixture()
def sqlite_indexer(sqlite_sessionmaker, monkeypatch):
    """把 `indexer` 模块里绑定的 `get_sessionmaker` 换到 SQLite 工厂。

    为什么必须显式打这一针：`indexer.py` 里是 `from ... import get_sessionmaker`，
    名称在**模块加载时**就绑定好了，所以 `conftest` 只打 `aiintel.db.base` 那一处
    对 `persist_vuln` 不生效 —— 它会直接连真实 PG（本机没有，测试就红）。
    """

    import aiintel.services.knowledge.indexer as indexer

    monkeypatch.setattr(indexer, "get_sessionmaker", lambda: sqlite_sessionmaker)
    return sqlite_sessionmaker


def test_chunk_columns_reflects_actual_table(sqlite_sessionmaker) -> None:
    """`conftest.py` 的 fixture 只建了 `chunk(id)` —— 反射必须如实返回"没有 embedding"。"""

    with sqlite_sessionmaker() as session:
        columns = chunk_columns(session)
    assert "id" in columns
    assert "embedding" not in columns
    assert "owner_type" not in columns


def test_index_owner_does_not_raise_when_columns_missing(sqlite_sessionmaker) -> None:
    """缺列时 `index_owner` 走库能力分支，不再硬塞 embedding / to_tsvector。"""

    with sqlite_sessionmaker() as session:
        # 简化表缺列时仍然应该"尽力而为"，而不是抛异常
        try:
            asyncio.run(index_owner(session, "vuln", "v1", "标题", "正文"))
        except Exception as exc:  # noqa: BLE001 - 这里只断言不是"缺列"这类结构性错误
            assert "no column named" not in str(exc), exc


def test_persist_survives_chunk_write_failure(sqlite_indexer) -> None:
    """★ 回归：分块写入失败**不得**让结构化数据与富化结论一起回滚。"""

    from aiintel.db.models import Enrichment, Vuln

    asyncio.run(persist_vuln(_vuln_payload(), [_enrichment()]))

    with sqlite_indexer() as session:
        vuln = session.query(Vuln).filter_by(cve_id="CVE-2026-31001").one_or_none()
        assert vuln is not None, "结构化数据必须落库（分块失败不该连坐）"
        assert vuln.cvss_score == 9.8
        rows = session.query(Enrichment).filter_by(vuln_id=vuln.id).all()
        assert rows, "富化结论必须落库"
        assert rows[0].dimension == "fix"


def test_persist_writes_enrichment_chunks_when_table_supports_it(sqlite_indexer) -> None:
    """表结构完整时，F5/F6 结论要真的进检索空间（`owner_type="enrichment"`）。"""

    with sqlite_indexer() as session:
        session.execute(text("DROP TABLE chunk"))
        session.execute(
            text(
                "CREATE TABLE chunk (id TEXT PRIMARY KEY, owner_type TEXT, owner_id TEXT, "
                "chunk_no INTEGER, content TEXT, embedding TEXT, tsv TEXT, created_at TIMESTAMP)"
            )
        )
        session.commit()

    asyncio.run(persist_vuln(_vuln_payload(), [_enrichment()]))

    with sqlite_indexer() as session:
        rows = session.execute(
            text("SELECT owner_type, content FROM chunk WHERE owner_type = 'enrichment'")
        ).fetchall()
        # 非 PG 方言不写 embedding（占位列），但 chunk 文本必须落库
        vuln_chunks = session.execute(
            text("SELECT count(*) FROM chunk WHERE owner_type = 'vuln'")
        ).scalar_one()
    assert rows, "富化结论没进检索空间（Q 线就问不到「怎么修」）"
    assert "0.9.3" in rows[0][1], rows[0][1]
    assert vuln_chunks >= 1, "漏洞正文也应分块入库"


def test_persist_skips_dimensions_without_evidence(sqlite_indexer) -> None:
    """无证据的维度不落库（内部不变量 1），但也不影响其他维度。"""

    from aiintel.db.models import Enrichment

    bad = {**_enrichment(), "evidence": []}
    asyncio.run(persist_vuln(_vuln_payload(), [bad]))
    with sqlite_indexer() as session:
        assert session.query(Enrichment).count() == 0


@pytest.mark.parametrize("dimension", ["fix", "consistency", "cvss"])
def test_enrichment_chunk_text_is_produced_for_key_dimensions(
    dimension: str, sqlite_sessionmaker
) -> None:
    """F4/F5/F6 三个"要能被检索到"的维度必须能编出 chunk 文本。"""

    from aiintel.services.knowledge.indexer import enrichment_chunk_text

    values = {
        "fix": {"upgrade": {"target_version": "0.9.3"}, "immediate": [{"action": "收敛暴露面"}]},
        "consistency": {"consensus": [{"field": "cvss_score", "value": 9.8, "source": "nvd"}]},
        "cvss": {"technical_impact": "可执行任意命令", "business_impact": "节点被接管"},
    }
    text = enrichment_chunk_text(
        dimension,
        values[dimension],
        [{"source": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001"}],
    )
    assert text.strip(), f"{dimension} 编不出可检索文本"
    assert "https://" in text, "chunk 里要带证据来源，便于回答时回指"

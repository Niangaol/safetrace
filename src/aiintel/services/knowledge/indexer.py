"""知识库写入：结构化表 + 检索分块 + 向量 + 关系边表。"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any

from sqlalchemy import func, text

from aiintel.config import get_settings
from aiintel.db.base import get_sessionmaker
from aiintel.db.models import Chunk, Enrichment, GraphEdge, Poc, TtpMapping, Vuln
from aiintel.services.knowledge.embedder import get_embedder

logger = logging.getLogger(__name__)

CHUNK_SIZE = 800
CHUNK_OVERLAP = 120


def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """优先在句号/换行处切分，避免把句子截断影响检索质量。"""

    text = (text or "").strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            cut = max(
                text.rfind("。", start + size // 2, end),
                text.rfind("\n", start + size // 2, end),
            )
            if cut > start:
                end = cut + 1
        chunks.append(text[start:end])
        start = max(end - overlap, start + 1)
    return chunks


def _tsvector(text: str) -> Any:
    """tsvector 由数据库侧生成（simple 配置对中文按空白切词，检索侧另有 ILIKE 兜底）。"""

    return func.to_tsvector("simple", text)


#: `chunk` 表的列名缓存（按引擎缓存，避免每次写入都反射一遍表结构）。
#: 键形如 `"sqlite:140234"`（方言 + 引擎对象 id），所以是 `dict[str, set[str]]`。
_CHUNK_COLUMNS: dict[str, set[str]] = {}


def chunk_columns(session) -> set[str]:
    """当前库 `chunk` 表**实际存在**的列。

    为什么要反射：`Chunk.embedding` 是 `pgvector` 列，**SQLite 建不出来**，
    所以本地/演示库的 `chunk` 表可能没有这一列（`tests/conftest.py` 就手工补了一张
    只有 id 的空表）。而 SQLAlchemy 的 INSERT 会带上**映射里声明的所有列**，
    于是 `table chunk has no column named embedding` 这种错误会让整条 persist 链路失败。

    拿到列名后按列构造写入，实现"**库支持向量就写向量，不支持就退化为关键词检索**"，
    与 `embedder.py` 的降级语义一致，而不是让整条链路炸掉。

    ⚠️ **必须用 `session.connection()` 反射，不能用 `inspect(engine)`**：
    后者会**另开一条连接**去读表结构。测试/演示用的是 `StaticPool`（全池只有一条连接），
    另开连接会抢占并归还 session 正在用的那条，触发一次隐式回滚 ——
    实测表现为"`persist_vuln` 里 commit 之后数据凭空消失"。
    这也是"能力探测只读、不该有副作用"的应有之义。
    """

    from sqlalchemy import inspect as sa_inspect

    connection = session.connection()
    dialect = connection.dialect.name
    try:
        key = f"{dialect}:{id(connection.engine)}"
        cached = _CHUNK_COLUMNS.get(key)
        if cached is None:
            cached = {
                col["name"] for col in sa_inspect(connection).get_columns(Chunk.__tablename__)
            }
            _CHUNK_COLUMNS[key] = cached
        return cached
    except Exception:  # noqa: BLE001 - 反射失败就按"全列可用"处理（PG 正常路径）
        logger.debug("反射 chunk 列失败，按映射全列写入", exc_info=True)
        return {c.name for c in Chunk.__table__.columns}


def embedding_col_type(session) -> str | None:
    """`chunk.embedding` 数据库侧的类型字符串（如 `vector(384)`）；非 PG/缺列返回 None。

    用途：写入前核对**列宽**与模型维度一致，避免把 N 维向量塞进 `vector(M)` 列
    （pgvector 会抛 `expected M dimensions, not N`）——那会让 `persist_vuln` 的
    整段分块索引被跳过、向量列永远为空（实测：早期镜像以 1024 建列、ONNX 模型 384 维）。
    """

    if session.get_bind().dialect.name != "postgresql":
        return None
    return session.execute(
        text(
            "SELECT format_type(a.atttypid, a.atttypmod) "
            "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
            "WHERE c.relname = 'chunk' AND a.attname = 'embedding'"
        )
    ).scalar()


async def index_owner(session, owner_type: str, owner_id: str, title: str, content: str) -> int:
    """写入分块 + 全文索引 + 向量（幂等：先删后写）。

    `embedding` / `tsv` 两列**按库能力写入**：SQLite 没有向量列、也没有
    `to_tsvector` 函数，缺列时自动退化，不阻断主链路（降级语义见 `chunk_columns`）。

    **缺必需列时直接返回 0，不发任何 SQL**：语句级失败会把 session 打脏
    （`sqlite3.OperationalError` 之后外层事务在退出时回滚，
    连带丢掉已 flush 的结构化数据）。所以这里做的是"能力探测 + 体面跳过"，
    而不是"试一下、失败再回滚"。
    """

    columns = chunk_columns(session)
    required = {"id", "owner_type", "owner_id", "chunk_no", "content"}
    missing = required - columns
    if missing:
        logger.info("chunk 表缺少列 %s，跳过检索索引（结构化数据照常落库）", sorted(missing))
        return 0

    embedder = get_embedder()
    parts = chunk_text(f"{title}\n\n{content}")
    is_postgres = session.get_bind().dialect.name == "postgresql"
    # 向量只在 PG 上写：非 PG 方言（SQLite 演示/测试库）里的 `embedding` 只是占位列，
    # 塞 Python list 进去会触发类型处理错误。这正与 `embedder.py` 的降级语义一致
    # —— 没有向量库就退化为关键词检索，而不是让 persist 崩掉。
    has_embedding = "embedding" in columns and is_postgres
    if has_embedding:
        # ⚠️ 列宽守卫：`vector(1024)` 列塞不进 384 维向量（pgvector 报维度错），
        # 而任何 DB 语句级失败会把 session 打脏、反噬已 flush 的结构化数据。
        # 与其让 persist 整体降级，不如明确跳过向量列、让检索自动走降级路径。
        col_type = embedding_col_type(session)
        want = f"vector({get_settings().embedding_dim})"
        if col_type is not None and col_type != want:
            logger.warning(
                "chunk.embedding 类型 %s 与配置维度 %s 不一致，跳过向量写入（检索自动降级）",
                col_type,
                get_settings().embedding_dim,
            )
            has_embedding = False
    has_tsv = "tsv" in columns

    session.query(Chunk).filter_by(owner_type=owner_type, owner_id=owner_id).delete()
    for idx, part in enumerate(parts):
        row = Chunk(
            owner_type=owner_type,
            owner_id=owner_id,
            chunk_no=idx,
            content=part,
        )
        if has_embedding:
            row.embedding = await embedder.embed(part)
        if has_tsv and is_postgres:
            # `to_tsvector` 是 PG 函数；其它方言即便有 tsv 列也不能这么塞
            row.tsv = _tsvector(part)
        session.add(row)
    return len(parts)


def _upsert_vuln(session, vuln: dict[str, Any]) -> Vuln:
    cve_id = vuln.get("cve_id")
    row = session.query(Vuln).filter_by(cve_id=cve_id).one_or_none() if cve_id else None
    if row is None and vuln.get("id"):
        row = session.query(Vuln).filter_by(id=vuln["id"]).one_or_none()
    if row is None:
        row = Vuln(id=vuln.get("id") or uuid.uuid4().hex)
        session.add(row)

    for field in (
        "cve_id",
        "ghsa_id",
        "title",
        "description",
        "summary",
        "severity",
        "cvss_vector",
        "cvss_score",
        "ai_risk_category",
        "exploit_status",
        "quality_score",
        "kev_due_date",
    ):
        if vuln.get(field) not in (None, "", []):
            setattr(row, field, vuln[field])
    # KEV / EPSS 不在上面那个循环里：它们是**累积型**信号，语义与普通字段不同。
    #   - kev 只能 False→True，源顺序不应该能把"已确认在野利用"降级回 false；
    #   - epss 取更大值，被利用概率宁可高估（理由同 services/ingest/dedup.py）。
    if vuln.get("kev"):
        row.kev = True
    other_epss = vuln.get("epss")
    if (
        isinstance(other_epss, (int, float))
        and not isinstance(other_epss, bool)
        and (row.epss is None or float(other_epss) > float(row.epss))
    ):
        row.epss = float(other_epss)
    if vuln.get("cwe"):
        row.cwe = vuln["cwe"]
    if vuln.get("cpe"):
        row.cpe = vuln["cpe"]
    # Y ↔ F 接口字段：F1/F2/F3/F5 的输入，缺了就写空列表而不是留 NULL
    for json_field in ("affected_products", "references", "version_ranges"):
        if vuln.get(json_field) is not None:
            setattr(row, json_field, vuln[json_field] or [])
    if vuln.get("published_at"):
        row.published_at = dt.datetime.fromisoformat(vuln["published_at"])
    if vuln.get("cvss_score") and row.severity in (None, "", "unknown"):
        from aiintel.services.enrich.cvss import severity_label

        row.severity = severity_label(float(vuln["cvss_score"]))
    session.flush()
    return row


def _next_version(session, vuln_id: str, dimension: str) -> int:
    latest = (
        session.query(Enrichment)
        .filter_by(vuln_id=vuln_id, dimension=dimension)
        .order_by(Enrichment.version.desc())
        .first()
    )
    return (latest.version + 1) if latest else 1


def _add_edge(session, rel: str, dst_type: str, dst_id: str, src_id: str) -> None:
    if not dst_id:
        return
    exists = (
        session.query(GraphEdge)
        .filter_by(src_type="vuln", src_id=src_id, rel=rel, dst_type=dst_type, dst_id=dst_id)
        .first()
    )
    if exists is None:
        session.add(
            GraphEdge(src_type="vuln", src_id=src_id, rel=rel, dst_type=dst_type, dst_id=dst_id)
        )


def _persist_enrichments(session, row: Vuln, enrichments: list[dict]) -> None:
    for item in enrichments:
        dimension = item.get("dimension")
        if not dimension or item.get("error") or not item.get("evidence"):
            continue  # 无证据的富化不落库（verify 节点会把它们标成待人工确认）
        session.add(
            Enrichment(
                vuln_id=row.id,
                dimension=dimension,
                value=item.get("value", {}),
                evidence=item.get("evidence", []),
                source=list(item.get("source") or []),
                confidence=float(item.get("confidence") or 0.0),
                model=item.get("model", ""),
                agent=item.get("agent", "EnrichAgent"),
                version=_next_version(session, row.id, dimension),
                mock=bool(item.get("mock")),
                degraded_to=item.get("degraded_to"),
                degraded_reason=str(item.get("degraded_reason") or ""),
                quality_score=item.get("quality_score"),
                trace_id=item.get("trace_id"),
            )
        )


def enrichment_chunk_text(dimension: str, value: dict[str, Any], evidence: list[dict]) -> str:
    """把富化结论压成可检索文本。

    这一步是"富化 → 问答"的关键：没有它，Q 线问"这个漏洞怎么修"召回不到 F5 的结论。
    只索引**结论本身**，不索引内部溯源字段（那属于证据链，走 `/evidence` 接口）。
    """

    lines: list[str] = []
    if dimension == "fix":
        upgrade = value.get("upgrade") or {}
        if upgrade.get("target_version"):
            lines.append(f"修复建议：升级到 {upgrade['target_version']}")
        for action in value.get("immediate") or []:
            if isinstance(action, dict) and action.get("action"):
                lines.append(f"立即缓解：{action['action']}（理由：{action.get('rationale', '')}）")
        for action in value.get("hardening") or []:
            lines.append(f"加固建议：{action}")
        for action in value.get("detection") or []:
            lines.append(f"检测建议：{action}")
    elif dimension == "consistency":
        for item in value.get("consensus") or []:
            lines.append(
                f"多源共识 {item.get('field')} = {item.get('value')}（来源 {item.get('source')}）"
            )
        for item in value.get("conflicts") or []:
            lines.append(
                f"来源冲突 {item.get('field')}：仲裁为 {item.get('resolved_to')}（规则 {item.get('rule')}）"
            )
    elif dimension == "cvss":
        lines.append(str(value.get("technical_impact") or ""))
        lines.append(str(value.get("business_impact") or ""))
    elif dimension == "paper":
        for paper in value.get("papers") or []:
            lines.append(f"论文支撑：{paper.get('title')}（{paper.get('relation_type')}）")
    elif dimension == "poc":
        for poc in value.get("pocs") or []:
            lines.append(f"POC 候选：{poc.get('url')}（可信度 {poc.get('tier')}）")
    elif dimension == "asset":
        for product in value.get("products") or []:
            lines.append(
                f"受影响资产：{product.get('vendor') or ''}:{product.get('product')} "
                f"版本 {product.get('affected_versions')}"
            )
    elif dimension == "ai_risk":
        lines.append(
            f"AI 风险分类：{value.get('label') or value.get('category')}（{value.get('reason')}）"
        )

    text = "\n".join(line for line in lines if line and line.strip())
    if not text:
        return ""
    degraded = ""
    if evidence:
        urls = [e.get("url") for e in evidence if e.get("url")]
        if urls:
            degraded = f"\n证据来源：{', '.join(str(u) for u in urls[:3])}"
    return text + degraded


def _upsert_edges(session, row: Vuln, enrichments: list[dict]) -> None:
    for item in enrichments:
        value = item.get("value") or {}
        if item.get("dimension") == "poc":
            for poc in value.get("pocs", []):
                _add_edge(session, "HAS_POC", "repo", poc.get("repo", ""), row.id)
        elif item.get("dimension") == "paper":
            for paper in value.get("papers", []):
                _add_edge(session, "MENTIONED_IN", "paper", paper.get("arxiv_id", ""), row.id)
        elif item.get("dimension") == "ai_risk":
            _add_edge(session, "CATEGORY", "risk", value.get("category", ""), row.id)
            for technique in value.get("techniques", []):
                _add_edge(session, "MAPS_TO", "technique", technique.get("id", ""), row.id)
        elif item.get("dimension") == "fix":
            upgrade = value.get("upgrade") or {}
            _add_edge(
                session, "FIXED_BY", "version", upgrade.get("target_version", "") or "", row.id
            )
            for ref in value.get("patch_refs", []):
                _add_edge(session, "FIXED_BY", "patch", ref.get("url", ""), row.id)
        elif item.get("dimension") == "consistency":
            for conflict in value.get("conflicts", []):
                _add_edge(session, "CONFLICTS_WITH", "field", conflict.get("field", ""), row.id)
        elif item.get("dimension") == "asset":
            for product in value.get("products", []):
                name = product.get("product") or product.get("cpe") or ""
                _add_edge(session, "AFFECTS", "product", name, row.id)
    for cpe in row.cpe or []:
        parts = cpe.split(":")
        if len(parts) >= 5 and parts[3] not in {"*", "-"}:
            _add_edge(session, "AFFECTS", "product", parts[3], row.id)
            if parts[4] not in {"*", "-"}:
                _add_edge(session, "AFFECTS", "product", f"{parts[3]}:{parts[4]}", row.id)


def _persist_side_tables(session, row: Vuln, enrichments: list[dict]) -> None:
    for item in enrichments:
        value = item.get("value") or {}
        if item.get("dimension") == "poc":
            for poc in value.get("pocs", []):
                session.add(
                    Poc(
                        vuln_id=row.id,
                        url=poc.get("repo", ""),
                        repo=poc.get("repo"),
                        kind=poc.get("kind", "poc"),
                        language=poc.get("language"),
                        stars=int(poc.get("stars") or 0),
                        verified=bool(poc.get("verified")),
                    )
                )
        elif item.get("dimension") == "ai_risk":
            if value.get("category"):
                row.ai_risk_category = value["category"]
            for technique in value.get("techniques", []):
                session.add(
                    TtpMapping(
                        vuln_id=row.id,
                        tactic=technique.get("tactic", ""),
                        technique_id=technique.get("id", ""),
                        technique_name=technique.get("name"),
                        confidence=float(item.get("confidence") or 0.0),
                    )
                )


def ensure_fts(session) -> None:
    """建 HNSW 向量索引与全文索引（幂等）。

    每次尝试都用嵌套事务/回滚隔开：DDL 失败（如未装 vector 扩展）后必须
    rollback，否则整个 session 处于 aborted 状态，后续写入全部失败。
    """

    for ddl in (
        "CREATE EXTENSION IF NOT EXISTS vector",
        "CREATE INDEX IF NOT EXISTS ix_chunk_embedding ON chunk USING hnsw (embedding vector_cosine_ops)",
        "CREATE INDEX IF NOT EXISTS ix_chunk_tsv ON chunk USING gin (tsv)",
    ):
        nested = session.begin_nested()
        try:
            session.execute(text(ddl))
            nested.commit()
        except Exception as exc:  # noqa: BLE001 - 缺扩展时降级为纯 ILIKE 检索
            nested.rollback()
            logger.debug("建索引跳过(%s): %s", ddl.split()[0], exc)
    session.commit()


async def persist_vuln(vuln: dict[str, Any], enrichments: list[dict]) -> str:
    """落库入口：结构化 + 富化 + 分块向量 + 关系边 + **富化结论入检索空间**。

    **两级降级**，保证"检索索引失败 ≠ 数据丢失"：

    1. `index_owner` 先做能力探测（`chunk_columns`），缺列就体面跳过、**不发 SQL**
       —— 语句级失败会打脏 session（实测：SQLite 上 `OperationalError` 之后外层事务
       在退出时回滚，连带丢掉已 flush 的结构化数据）；
    2. 仍有异常（例如 PG 缺 vector 扩展）时只记 warning，**不阻断结构化落库**。

    注意：这里**故意不用 `begin_nested()`**。在 SQLite 上实测
    "flush → begin_nested → 空 savepoint → commit" 会让外层已 flush 的数据消失
    （不需要 savepoint 也就没有这个风险）；能力探测已经覆盖了真实触发场景。
    """

    with get_sessionmaker()() as session:
        row = _upsert_vuln(session, vuln)
        _persist_enrichments(session, row, enrichments)
        _persist_side_tables(session, row, enrichments)
        _upsert_edges(session, row, enrichments)
        # 先把结构化 + 富化 + 边表刷出去，再碰检索索引
        session.flush()

        indexed = True
        try:
            await index_owner(
                session, "vuln", row.id, row.title or "", f"{row.description}\n{row.summary or ''}"
            )
            # 富化结论单独成 chunk：否则 Q 线问"这个漏洞怎么修"召回不到 F5 的结论
            for item in enrichments:
                if item.get("error") or not item.get("evidence"):
                    continue
                text = enrichment_chunk_text(
                    str(item.get("dimension") or ""),
                    item.get("value") or {},
                    item.get("evidence") or [],
                )
                if text:
                    await index_owner(session, "enrichment", row.id, row.title or "", text)
        except Exception as exc:  # noqa: BLE001 - 索引失败不阻断结构化落库
            indexed = False
            logger.warning("分块写入失败，该漏洞检索索引降级（结构化与富化结论仍已落库）: %s", exc)

        session.commit()
        if indexed:
            try:
                ensure_fts(session)
            except Exception as exc:  # noqa: BLE001 - 索引失败不影响数据写入
                logger.warning("建索引失败，向量检索降级: %s", exc)
        return row.id


__all__ = [
    "chunk_columns",
    "chunk_text",
    "enrichment_chunk_text",
    "ensure_fts",
    "index_owner",
    "persist_vuln",
]

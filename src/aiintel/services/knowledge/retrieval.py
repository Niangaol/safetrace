"""混合检索：向量召回 + 关键词召回 → RRF 融合 → 本地 reranker 重排。

不引入 ES/专用向量库，用 pgvector + PG 全文，省一个运维组件（15 天工期下的取舍）。
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy import func, or_, select, text

from aiintel.config import get_settings
from aiintel.db.base import get_sessionmaker
from aiintel.db.models import Chunk, GraphEdge

logger = logging.getLogger(__name__)

VECTOR_RECALL = 50
KEYWORD_RECALL = 50
RRF_K = 60

# 分隔符不能用 ":"：owner_id 可能是 arXiv 全文链接（http://arxiv.org/abs/xxx），
# 按 ":" 切分会把它拆碎。
DOC_SEP = "::"

# 中文停用词：做 2-gram 之前先剔掉，否则"的漏洞"这类片段会拉低召回质量
_CJK_STOP = set("的是有哪些哪些和与及了在对于关于怎么如何什么哪些一个这个那个我们请帮")
_SPLIT_RE = re.compile(r"[\s,.;:!?，。；：！？、（）()\[\]{}\"'`/\\|+*=<>~-]+")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_ASCII_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9._\-]*|\d{4,}")
MAX_QUERY_TERMS = 16


def query_terms(query: str, limit: int = MAX_QUERY_TERMS) -> list[str]:
    """把自然语言查询切成适合 ILIKE 的检索词。

    - ASCII 词（含 CVE-2024-1234、vLLM 这类）整体保留，它们区分度最高
    - 中文按 2-gram 切，避免整句匹配不到
    - 长的 ASCII 词额外补前缀，防止 "vulnerability" 匹配不到 "vuln"
    """

    terms: list[str] = []

    def _push(term: str) -> None:
        term = term.strip()
        if len(term) >= 2 and term not in terms:
            terms.append(term)

    for token in _SPLIT_RE.split(query):
        if not token:
            continue
        if _CJK_RE.search(token):
            chars = [c for c in token if _CJK_RE.match(c) and c not in _CJK_STOP]
            for i in range(len(chars) - 1):
                _push(chars[i] + chars[i + 1])
            if len(chars) == 1:
                _push(chars[0])
        else:
            _push(token)

    for match in _ASCII_TOKEN_RE.findall(query):
        _push(match)
        if len(match) > 8 and not match.isdigit():
            _push(match[:4])

    return terms[:limit]


def doc_key(owner_type: str, owner_id: str, chunk_no: int) -> str:
    return f"{owner_type}{DOC_SEP}{owner_id}{DOC_SEP}{chunk_no}"


def parse_doc_key(doc: str) -> tuple[str, str, str]:
    owner_type, owner_id, chunk_no = doc.split(DOC_SEP, 2)
    return owner_type, owner_id, chunk_no


async def embed(text: str) -> list[float] | None:
    """本地 bge-m3 嵌入。未安装时返回 None，检索自动降级为纯关键词。"""

    from aiintel.services.knowledge.embedder import get_embedder

    return await get_embedder().embed(text)


async def _keyword_recall(
    session, query: str, top_k: int, owner_type: str | None
) -> list[tuple[str, float]]:
    stmt = (
        select(Chunk.owner_type, Chunk.owner_id, Chunk.chunk_no, Chunk.content)
        .where(Chunk.tsv.op("@@")(func.plainto_tsquery("simple", query)))
        .limit(top_k)
    )
    if owner_type:
        stmt = stmt.where(Chunk.owner_type == owner_type)
    return [(doc_key(r[0], r[1], r[2]), 1.0) for r in session.execute(stmt).all()]


async def _fallback_recall(
    session, query: str, top_k: int, owner_type: str | None
) -> list[tuple[str, float]]:
    """无全文索引时的模糊兜底：ILIKE。

    必须先分词再 OR：直接拿整句做 ILIKE 只会在"切片内容恰好等于整个问题"时命中，
    实际等于永远检索不到。中文没有空格，按 2-gram 切；ASCII 词整体保留。
    """

    terms = query_terms(query)
    if not terms:
        return []
    stmt = select(Chunk.owner_type, Chunk.owner_id, Chunk.chunk_no, Chunk.content).where(
        or_(*[Chunk.content.ilike(f"%{t}%") for t in terms])
    )
    if owner_type:
        stmt = stmt.where(Chunk.owner_type == owner_type)
    return [(doc_key(r[0], r[1], r[2]), 1.0) for r in session.execute(stmt.limit(top_k)).all()]


def _rrf_fuse(rankings: list[list[str]], k: int = RRF_K) -> list[str]:
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, doc in enumerate(ranking, start=1):
            scores[doc] = scores.get(doc, 0.0) + 1 / (k + rank)
    return [doc for doc, _ in sorted(scores.items(), key=lambda kv: -kv[1])]


async def hybrid_search(
    query: str, top_k: int = 8, owner_type: str | None = None
) -> list[dict[str, Any]]:
    settings = get_settings()
    results: list[dict[str, Any]] = []
    with get_sessionmaker()() as session:
        vector = await embed(query)
        rankings: list[list[str]] = []
        if vector:
            stmt = (
                select(Chunk.owner_type, Chunk.owner_id, Chunk.chunk_no, Chunk.content)
                .where(Chunk.embedding.isnot(None))
                .order_by(Chunk.embedding.cosine_distance(vector))
            )
            if owner_type:
                # 过滤必须在 LIMIT 之前：否则先取 top-N 再按类型筛，很容易筛成空
                stmt = stmt.where(Chunk.owner_type == owner_type)
            rows = session.execute(stmt.limit(VECTOR_RECALL)).all()
            rankings.append([doc_key(r[0], r[1], r[2]) for r in rows])
        try:
            keyword = await _keyword_recall(session, query, KEYWORD_RECALL, owner_type)
        except Exception as exc:  # noqa: BLE001 - 中文全文检索配置可能缺失
            logger.debug("全文检索不可用，回退模糊匹配: %s", exc)
            keyword = await _fallback_recall(session, query, KEYWORD_RECALL, owner_type)
        rankings.append([doc for doc, _ in keyword])

        fused = _rrf_fuse([r for r in rankings if r])[: top_k * 3]
        if not fused:
            return []

        keys = {parse_doc_key(doc) for doc in fused}
        rows = session.execute(
            select(Chunk.owner_type, Chunk.owner_id, Chunk.chunk_no, Chunk.content).where(
                Chunk.owner_type.in_({k[0] for k in keys}),
                Chunk.owner_id.in_({k[1] for k in keys}),
            )
        ).all()
        content_map = {doc_key(r[0], r[1], r[2]): r[3] for r in rows}
        # 原始出处：引用要能"点开核对"。没有它，前端只能把内部切片标识
        # （`vuln:CVE-...`）当链接渲染 —— 点了没反应（实测过）。
        url_map = _source_url_map(
            session, {(k[0], k[1]) for k in (parse_doc_key(doc) for doc in fused)}
        )
        meta_map = _source_meta_map(
            session, {(k[0], k[1]) for k in (parse_doc_key(doc) for doc in fused)}
        )
        for rank, doc in enumerate(fused, start=1):
            owner_type, owner_id, _ = parse_doc_key(doc)
            item: dict[str, Any] = {
                "ref": f"S{rank}",
                "chunk_key": doc,
                "owner_type": owner_type,
                "owner_id": owner_id,
                "content": content_map.get(doc, ""),
                "url": url_map.get((owner_type, owner_id)),
                "rrf_rank": rank,
            }
            # 契约 v1.1.1 的可选字段：**推导不出就不放**（缺省 = 未知），
            # 而不是塞一个 None 让下游误以为"评估过了，结果是空"。
            meta = meta_map.get((owner_type, owner_id)) or {}
            if meta.get("published_at"):
                item["published_at"] = meta["published_at"]
            if meta.get("trust"):
                item["trust"] = meta["trust"]
            results.append(item)

    if settings.reranker_model:
        try:
            results = await _rerank(query, results)
        except Exception as exc:  # noqa: BLE001
            logger.debug("重排失败，沿用 RRF 顺序: %s", exc)
    return results[:top_k]


def _source_url_map(session: Any, keys: set[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """取每个 owner 的**可点开**的原始出处链接。

    - `vuln`：用 `Vuln.references` 里第一条带 url 的（采集/演示库写入）；
    - 其余（论文等）：`chunk` 表没有 url 字段，故不提供 —— 宁可不给链接，
      也不要拼一个打不开的假地址。
    """

    import json

    from aiintel.db.models import Vuln

    wanted = {owner_id for owner_type, owner_id in keys if owner_type == "vuln"}
    if not wanted:
        return {}

    out: dict[tuple[str, str], str] = {}
    rows = session.execute(
        select(Vuln.cve_id, Vuln.references).where(Vuln.cve_id.in_(wanted))
    ).all()
    for cve_id, refs in rows:
        if not cve_id:
            continue
        entries = refs if isinstance(refs, list) else []
        if isinstance(refs, str) and refs:
            try:
                entries = json.loads(refs)
            except ValueError:
                entries = []
        for item in entries or []:
            url = item.get("url") if isinstance(item, dict) else None
            if url:
                out[("vuln", cve_id)] = str(url)
                break
    return out


def _source_meta_map(
    session: Any, keys: set[tuple[str, str]]
) -> dict[tuple[str, str], dict[str, Any]]:
    """取每个 owner 的**出处元数据**：`published_at` 与 `trust`。

    为什么需要：上游契约 v1.1.1 给 `RetrievalResponse.chunk` 追加了可选
    `published_at` / `trust`，用途是让问答能告诉用户**这条证据是否权威、是否过时**。
    缺省语义是「未知」，所以推导不出来时**必须留空**，不能填个乐观值。

    推导依据（都是真实数据，不编造）：
    - `published_at` ← `Vuln.published_at`（本仓每条漏洞都有值）；
    - `trust` ← 该漏洞的 `VulnSource.source` 集合，按与上游 `sourceTrust()`
      同一套口径合成（见 `services/knowledge/trust.py`）。
    """

    from aiintel.db.models import Vuln, VulnSource
    from aiintel.services.knowledge.trust import combine_trust

    wanted = {owner_id for owner_type, owner_id in keys if owner_type == "vuln"}
    if not wanted:
        return {}

    out: dict[tuple[str, str], dict[str, Any]] = {}
    rows = session.execute(
        select(Vuln.cve_id, Vuln.id, Vuln.published_at).where(Vuln.cve_id.in_(wanted))
    ).all()
    if not rows:
        return out

    id_by_cve = {cve_id: vid for cve_id, vid, _ in rows if cve_id}
    sources: dict[str, list[str]] = {}
    if id_by_cve:
        for vid, src in session.execute(
            select(VulnSource.vuln_id, VulnSource.source).where(
                VulnSource.vuln_id.in_(set(id_by_cve.values()))
            )
        ).all():
            sources.setdefault(vid, []).append(str(src))

    for cve_id, vid, published_at in rows:
        if not cve_id:
            continue
        meta: dict[str, Any] = {}
        if published_at is not None:
            meta["published_at"] = published_at.isoformat()
        trust = combine_trust(sources.get(vid))
        if trust is not None:
            meta["trust"] = trust
        if meta:
            out[("vuln", cve_id)] = meta
    return out


async def _rerank(query: str, results: list[dict]) -> list[dict]:
    from aiintel.services.knowledge.embedder import get_reranker

    if not results:
        return results
    scores = await get_reranker().rerank(query, [r["content"] for r in results])
    for item, score in zip(results, scores, strict=False):
        item["rerank_score"] = round(float(score), 4)
    return sorted(results, key=lambda r: -r.get("rerank_score", 0.0))


async def neighbors(node_id: str, hops: int = 2, limit: int = 50) -> dict[str, Any]:
    """边表多跳扩展（替代图数据库）。"""

    with get_sessionmaker()() as session:
        session.execute(
            select(
                GraphEdge.src_type,
                GraphEdge.src_id,
                GraphEdge.rel,
                GraphEdge.dst_type,
                GraphEdge.dst_id,
            ).where(GraphEdge.src_id == node_id)
        ).all()
        seen_edges: set[tuple[str, str, str]] = set()
        nodes: dict[tuple[str, str, str], dict] = {}
        frontier = {node_id}
        for depth in range(1, hops + 1):
            next_frontier: set[str] = set()
            for current in frontier:
                q = session.execute(
                    select(
                        GraphEdge.src_type,
                        GraphEdge.src_id,
                        GraphEdge.rel,
                        GraphEdge.dst_type,
                        GraphEdge.dst_id,
                    )
                    .where((GraphEdge.src_id == current) | (GraphEdge.dst_id == current))
                    .limit(limit)
                ).all()
                for src_type, src_id, rel, dst_type, dst_id in q:
                    key = (src_id, rel, dst_id)
                    if key in seen_edges:
                        continue
                    seen_edges.add(key)
                    nodes[(src_id, rel, dst_id)] = {
                        "src": src_id,
                        "rel": rel,
                        "dst": dst_id,
                        "depth": depth,
                        "src_type": src_type,
                        "dst_type": dst_type,
                    }
                    next_frontier.update({src_id, dst_id})
            frontier = next_frontier - frontier
            if not frontier or len(seen_edges) >= limit:
                break
    return {"nodes": list(nodes.values()), "edges": list(nodes.values())}


async def graph_stats() -> dict[str, int]:
    with get_sessionmaker()() as session:
        return {
            "chunks": session.execute(select(func.count()).select_from(Chunk)).scalar_one(),
            "edges": session.execute(select(func.count()).select_from(GraphEdge)).scalar_one(),
        }


async def ensure_fts(session) -> None:
    """建全文索引与相似度索引（幂等）。"""

    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_chunk_embedding ON chunk "
            "USING hnsw (embedding vector_cosine_ops)"
        )
    )
    session.execute(text("CREATE INDEX IF NOT EXISTS ix_chunk_tsv ON chunk USING gin (tsv)"))
    session.commit()

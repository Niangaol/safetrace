"""ORM 模型：结构化情报 + 关系边表（替代图数据库）+ 检索单元 + 评测与轨迹。"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aiintel.config import get_settings
from aiintel.db.base import Base

EMBED_DIM = get_settings().embedding_dim


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


# ---------------------------------------------------------------- 采集


class RawItem(Base, TimestampMixin):
    """原始情报落地。时效指标 = fetched_at - published_at。"""

    __tablename__ = "raw_item"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    source: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(128), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text, default="")
    content_text: Mapped[str] = mapped_column(Text, default="")
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
    etag: Mapped[str | None] = mapped_column(String(128))
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    # ⚠️ 必须是 BigInteger：simhash 是 **64 位**指纹，实测取值到 8.99e18，
    # 而 Integer 在 PostgreSQL 上是 int4（上限 2147483647）→
    # 往 PG 灌数据时 22/22 行全部 `NumericValueOutOfRange`。
    # SQLite 不校验整型宽度，所以这个问题只在 PG 上暴露（演示库一直是 SQLite，掩盖了它）。
    simhash: Mapped[int | None] = mapped_column(BigInteger, index=True)
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_raw_source_external"),
        Index("ix_raw_source_published", "source", "published_at"),
    )

    @property
    def latency_seconds(self) -> float | None:
        if self.published_at is None:
            return None
        return (self.fetched_at - self.published_at).total_seconds()


class SyncWatermark(Base):
    """增量同步游标。"""

    __tablename__ = "sync_watermark"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_full_sync: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    etag: Mapped[str | None] = mapped_column(String(128))
    items_last_run: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)


class SourceConfig(Base):
    __tablename__ = "source_config"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    rate_limit_per_min: Mapped[int] = mapped_column(Integer, default=20)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


# ---------------------------------------------------------------- 漏洞


class Vuln(Base, TimestampMixin):
    """去重合并后的漏洞主表。"""

    __tablename__ = "vuln"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    cve_id: Mapped[str | None] = mapped_column(String(32), unique=True, index=True)
    ghsa_id: Mapped[str | None] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cwe: Mapped[list[str]] = mapped_column(JSON, default=list)
    cpe: Mapped[list[str]] = mapped_column(JSON, default=list)
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    # CISA KEV 官方目录给出的联邦机构强制修复截止日（services/collectors/kev.py）。
    # 只从 KEV 源写入；NVD 二次加工的镜像字段不提供这个值，所以这里是唯一来源。
    # 未列入 KEV 或取不到时保持 None——"没有截止日"和"截止日未知"是两种不同状态，
    # 不要用默认值糊掉（会让 triage 把"未知"当成"不急"）。
    kev_due_date: Mapped[str | None] = mapped_column(String(10))
    ai_risk_category: Mapped[str | None] = mapped_column(String(32), index=True)
    exploit_status: Mapped[str | None] = mapped_column(String(32))
    # ---- Y 线与 F 线的接口字段（F1/F2/F3/F5 依赖；缺失时 F 线走降级路径，不得猜）----
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    version_ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    quality_score: Mapped[float | None] = mapped_column(Float, index=True)
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    modified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    sources: Mapped[list[VulnSource]] = relationship(back_populates="vuln", lazy="selectin")
    enrichments: Mapped[list[Enrichment]] = relationship(
        back_populates="vuln", lazy="selectin", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_vuln_published_severity", "published_at", "severity"),)


class VulnSource(Base):
    """多源关联，支撑交叉验证与合并率统计。"""

    __tablename__ = "vuln_source"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vuln.id", ondelete="CASCADE"), index=True)
    raw_item_id: Mapped[str | None] = mapped_column(ForeignKey("raw_item.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(32), index=True)
    merged_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    vuln: Mapped[Vuln] = relationship(back_populates="sources")


# ---------------------------------------------------------------- 富化


class Enrichment(Base):
    """富化统一表：每个维度一条记录，value + source + evidence + confidence。

    证据链是本项目核心设计——前端可点开溯源，直接支撑"富化准确率"与
    "推理链可解释"两个评分点。

    字段口径（契约 `contracts/schemas/EnrichmentResult.json`）：
    - `source`：本条结论实际依据的数据源列表（赛题硬要求"每条富化带 source"）；
    - `degraded_to`：FB1 降级标记，非空即"降级产物"，必须对用户可见；
    - `quality_score`：仅 consistency 维度产出。
    """

    __tablename__ = "enrichment"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vuln.id", ondelete="CASCADE"), index=True)
    dimension: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    source: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    model: Mapped[str] = mapped_column(String(64), default="")
    agent: Mapped[str] = mapped_column(String(32), default="EnrichAgent")
    version: Mapped[int] = mapped_column(Integer, default=1)
    mock: Mapped[bool] = mapped_column(Boolean, default=False)
    degraded_to: Mapped[str | None] = mapped_column(String(16), index=True)
    degraded_reason: Mapped[str] = mapped_column(Text, default="")
    quality_score: Mapped[float | None] = mapped_column(Float)
    trace_id: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )

    vuln: Mapped[Vuln] = relationship(back_populates="enrichments")

    __table_args__ = (
        UniqueConstraint("vuln_id", "dimension", "version", name="uq_enrichment_version"),
    )


class Paper(Base):
    __tablename__ = "paper"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    arxiv_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    doi: Mapped[str | None] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    abstract: Mapped[str] = mapped_column(Text, default="")
    year: Mapped[int | None] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class VulnPaper(Base):
    __tablename__ = "vuln_paper"

    vuln_id: Mapped[str] = mapped_column(
        ForeignKey("vuln.id", ondelete="CASCADE"), primary_key=True
    )
    paper_id: Mapped[str] = mapped_column(
        ForeignKey("paper.id", ondelete="CASCADE"), primary_key=True
    )
    relation_type: Mapped[str] = mapped_column(String(32), default="mentions")
    note: Mapped[str] = mapped_column(Text, default="")


class Poc(Base):
    __tablename__ = "poc"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vuln.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    repo: Mapped[str | None] = mapped_column(String(256), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="poc")
    language: Mapped[str | None] = mapped_column(String(32))
    stars: Mapped[int] = mapped_column(Integer, default=0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class PolicyStandard(Base):
    __tablename__ = "policy_standard"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    issuer: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str | None] = mapped_column(Text)
    effective_date: Mapped[dt.date | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class TtpMapping(Base):
    __tablename__ = "ttp_mapping"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vuln.id", ondelete="CASCADE"), index=True)
    tactic: Mapped[str] = mapped_column(String(64))
    technique_id: Mapped[str] = mapped_column(String(16))
    technique_name: Mapped[str | None] = mapped_column(String(128))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)


# ---------------------------------------------------------------- 知识库


class Chunk(Base):
    """检索单元，多态关联漏洞/论文/标准。"""

    __tablename__ = "chunk"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    owner_type: Mapped[str] = mapped_column(String(16), index=True)
    owner_id: Mapped[str] = mapped_column(String(32), index=True)
    chunk_no: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[str] = mapped_column(Text, default="")
    embedding: Mapped[list[float] | None] = mapped_column(Vector(EMBED_DIM))
    # 必须是 PG 的 `tsvector` 而不是 `text`：
    #   - 检索侧用 `Chunk.tsv @@ plainto_tsquery(...)`（retrieval.py:93），那是
    #     tsvector 专有运算符，text 列上直接报 operator does not exist；
    #   - `CREATE INDEX ... USING gin (tsv)` 需要算子类，text 列会报
    #     "access method gin does not support data type text"（PG 16 实测）。
    # 其它方言（SQLite 测试）走 with_variant 落成 TEXT —— conftest / demo_seed
    # 本来就不建 chunk 表，这里只是保证不会因类型而编译失败。
    tsv: Mapped[Any] = mapped_column(Text().with_variant(TSVECTOR, "postgresql"), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        UniqueConstraint("owner_type", "owner_id", "chunk_no", name="uq_chunk_owner_no"),
        Index("ix_chunk_owner", "owner_type", "owner_id"),
    )


class GraphEdge(Base):
    """关系边表，替代图数据库支撑多跳查询。"""

    __tablename__ = "graph_edge"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    src_type: Mapped[str] = mapped_column(String(16), index=True)
    src_id: Mapped[str] = mapped_column(String(32), index=True)
    rel: Mapped[str] = mapped_column(String(32), index=True)
    dst_type: Mapped[str] = mapped_column(String(16), index=True)
    dst_id: Mapped[str] = mapped_column(String(32), index=True)
    props: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    __table_args__ = (
        UniqueConstraint("src_type", "src_id", "rel", "dst_type", "dst_id", name="uq_edge"),
    )


# ---------------------------------------------------------------- 运行与评测


class AgentRun(Base):
    __tablename__ = "agent_run"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    graph: Mapped[str] = mapped_column(String(32), default="monitor")
    trigger: Mapped[str] = mapped_column(String(32), default="schedule")
    state: Mapped[str] = mapped_column(String(32), default="running", index=True)
    input_summary: Mapped[str] = mapped_column(Text, default="")
    output_summary: Mapped[str] = mapped_column(Text, default="")
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_cny: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )


class AgentStep(Base):
    __tablename__ = "agent_step"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("agent_run.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    node: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(16), default="ok")
    input_summary: Mapped[str] = mapped_column(Text, default="")
    output_summary: Mapped[str] = mapped_column(Text, default="")
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_cny: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class Alert(Base):
    __tablename__ = "alert"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    level: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    vuln_id: Mapped[str | None] = mapped_column(String(32), index=True)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)
    acked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )


class EvalCase(Base):
    """人工标注集：漏洞 30 / 富化 40 / 问答 30。"""

    __tablename__ = "eval_case"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    question: Mapped[str] = mapped_column(Text, default="")
    expected: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class EvalResult(Base):
    __tablename__ = "eval_result"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    case_id: Mapped[str] = mapped_column(ForeignKey("eval_case.id", ondelete="CASCADE"), index=True)
    answer: Mapped[str] = mapped_column(Text, default="")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    judge_model: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

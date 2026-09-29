"""pytest 公共夹具。"""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

os.environ.setdefault("APP_ENV", "dev")
os.environ.setdefault("API_TOKEN", "")
os.environ.setdefault("COST_DAILY_BUDGET_CNY", "1000")
os.environ.setdefault("LLM_API_KEY", "")
os.environ.setdefault("POSTGRES_DSN", "postgresql+psycopg://intel:intel@localhost:5432/intel")


@pytest.fixture()
def cost_guard(tmp_path):
    from aiintel.core.cost import CostGuard

    return CostGuard(daily_budget=0.01, tracker_path=str(tmp_path / "cost.jsonl"))


def dimension_contract_errors(result: dict, *, intel_id: str = "intel_test") -> list[str]:
    """把 `evidence.build_result()` 内部对象投影到 `DimensionEvidence` 契约并校验。

    权威 `EnrichmentResult` 是 `additionalProperties: false` 的瘦交接口，装不下
    `value`/`evidence`/`degraded_reason` 等明细；7 维明细走本仓扩展契约
    `DimensionEvidence.json`（见 docs/契约对齐-SafeTrace.md §5）。
    """

    from scripts.contracts import load_schema, validate

    from aiintel.core.contracts import to_dimension_evidence

    return validate(
        load_schema("DimensionEvidence.json"), to_dimension_evidence(result, intel_id=intel_id)
    )


def enrichment_result_errors(
    results: list[dict], *, intel_id: str = "intel_test", failed: list[dict] | None = None
) -> list[str]:
    """把一组内部维度结果投影到权威 `EnrichmentResult` 契约并校验。"""

    from scripts.contracts import load_schema, validate

    from aiintel.core.contracts import to_enrich_result

    payload = to_enrich_result(intel_id, results, failed=failed)
    return validate(load_schema("EnrichmentResult.json"), payload)


_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture()
def nvd_payload() -> dict:
    """真实形态的 NVD CVE 2.0 响应（离线）。"""

    return json.loads((_FIXTURES / "nvd_cve.sample.json").read_text(encoding="utf-8"))


@pytest.fixture()
def intel_item() -> dict:
    """F 线边界的输入：权威 `IntelItem` + `raw_refs` 回读 → 内部富化视图。

    权威 `IntelItem` 是 `additionalProperties: false` 的精简对象，不带
    `references` / `cvss_vector` / `severity` / `description` 等明细；这些由
    `raw_refs` 指向的原始 payload 承载，对标 SafeTrace `f4-cvss.ts`
    的 `loadScoreSourcesFromRawRefs`。本 fixture 复刻这条真实链路，
    因此维度测试拿到的输入与生产环境经 `EnrichAgent.run()` 归一后的形状一致。
    """

    from aiintel.core.contracts import to_enrich_input
    from aiintel.services.enrich.nvd import parse_nvd

    authoritative = json.loads((_FIXTURES / "intelitem.sample.json").read_text(encoding="utf-8"))
    cve_json = json.loads((_FIXTURES / "nvd_cve.sample.json").read_text(encoding="utf-8"))
    # `parse_nvd` 按 `_plain_cve_json` 约定从 `raw` 键取原始 CVE JSON，并需显式给出 cve_id
    parsed = parse_nvd({"cve_id": (authoritative.get("cve_ids") or [None])[0], "raw": cve_json})
    return to_enrich_input(authoritative, parsed)


@pytest.fixture()
def fake_result():
    """构造 LLMResult 的工厂。"""

    from aiintel.core.cost import Usage
    from aiintel.core.llm import LLMResult

    def _make(text: str, **kw):
        return LLMResult(
            text=text,
            usage=kw.pop("usage", Usage(100, 0, 100)),
            model=kw.pop("model", "fake-model"),
            cost_cny=kw.pop("cost_cny", 0.0),
            **kw,
        )

    return _make


@pytest.fixture()
def stub_llm(monkeypatch, fake_result):
    """把 get_llm() 换成返回固定文本的桩。

    注意：各服务模块都是 `from aiintel.core.llm import get_llm` 直接导入，
    所以必须逐个模块打补丁，只改 core.llm 不生效。
    """

    def _install(text: str = '{"ok": true}', model: str = "fake-model"):
        import aiintel.core.llm as llm_module

        class StubRouter:
            def __init__(self) -> None:
                self.calls: list[dict] = []

            def route(self, task):
                return "flash", model, False

            async def complete(self, messages, **kwargs):
                self.calls.append({"messages": messages, **kwargs})
                return fake_result(text, model=model)

            async def stream(self, messages, **kwargs):
                # 必须是 async generator：调用方直接 `async for ... in stream(...)`
                for ch in text:
                    yield ch

            async def aclose(self) -> None:
                return None

        router = StubRouter()
        monkeypatch.setattr(llm_module, "get_llm", lambda: router)
        for module_path in (
            "aiintel.services.qa.checks",
            "aiintel.services.qa.agent",
            "aiintel.services.ingest.pipeline",
            "aiintel.services.enrich.dimensions",
        ):
            module = importlib.import_module(module_path)
            if hasattr(module, "get_llm"):
                monkeypatch.setattr(module, "get_llm", lambda: router)
        return router

    return _install


@pytest.fixture()
def fake_bus():
    """内存版 EventBus（替换 Redis）。"""

    from aiintel.core.events import EventBus

    class FakeRedis:
        def __init__(self) -> None:
            self.published: list[tuple[str, str]] = []

        async def publish(self, channel: str, message: str) -> int:
            self.published.append((channel, message))
            return 1

    redis = FakeRedis()
    return EventBus(redis_client=redis), redis


@pytest.fixture()
def db_session() -> Iterator[object]:
    from aiintel.db.base import get_sessionmaker

    with get_sessionmaker()() as session:
        yield session


@pytest.fixture()
def sqlite_sessionmaker(monkeypatch):
    """把 get_sessionmaker 换成内存 SQLite。

    带库运行的测试不该依赖开发机上真的有 PostgreSQL；chunk 的 embedding 是
    pgvector 列，SQLite 建不出来，所以跳过该表并补一张同名空表让 count(*) 能跑。
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import aiintel.db.models  # noqa: F401  触发模型注册
    from aiintel.db.base import Base

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[t for name, t in Base.metadata.tables.items() if name != "chunk"],
    )
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE chunk (id TEXT PRIMARY KEY)"))

    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    monkeypatch.setattr("aiintel.db.base.get_sessionmaker", lambda: factory)
    return factory

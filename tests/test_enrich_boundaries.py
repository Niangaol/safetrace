"""富化线边界测试：分工不能越界，兜底不能静默。

这些断言对应计划里的三条工程红线中的两条：
① 模型接入必须走 MG1（禁止直接 import provider SDK）；
③ 兜底必须显式可见（禁止静默兜底）。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ENRICH_DIR = Path(__file__).resolve().parent.parent / "src" / "aiintel" / "services" / "enrich"

# F 线禁止直接依赖的东西：模型 SDK 与向量库客户端
FORBIDDEN_IMPORTS = (
    "openai",
    "anthropic",
    "ollama",
    "cohere",
    "google.generativeai",
    "qdrant_client",
    "weaviate",
    "pinecone",
    "chromadb",
)

# 只有这些模块允许直接碰 httpx / core.llm（取数层与网关层）
ALLOWED_HTTPX = {"paper.py", "poc.py"}
ALLOWED_LLM_IMPORT = {"mg1.py"}


def _iter_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append(node.module)
    return found


@pytest.mark.parametrize("path", sorted(ENRICH_DIR.glob("*.py")), ids=lambda p: p.name)
def test_no_provider_sdk_imports(path: Path) -> None:
    imports = _iter_imports(path)
    for module in imports:
        for forbidden in FORBIDDEN_IMPORTS:
            assert not module.startswith(forbidden), (
                f"{path.name} 直接 import 了 {module}；模型调用必须走 mg1.py（计划工程红线 1）"
            )


@pytest.mark.parametrize("path", sorted(ENRICH_DIR.glob("*.py")), ids=lambda p: p.name)
def test_llm_only_reachable_through_gateway(path: Path) -> None:
    if path.name in ALLOWED_LLM_IMPORT:
        return
    imports = _iter_imports(path)
    assert "aiintel.core.llm" not in imports, (
        f"{path.name} 绕过了 MG1 直接 import core.llm；请改为 from aiintel.services.enrich import mg1"
    )


@pytest.mark.parametrize("path", sorted(ENRICH_DIR.glob("*.py")), ids=lambda p: p.name)
def test_httpx_confined_to_fetch_layer(path: Path) -> None:
    if path.name in ALLOWED_HTTPX:
        return
    imports = _iter_imports(path)
    assert "httpx" not in imports, (
        f"{path.name} 直接使用 httpx；网络取数应集中在 paper.py / poc.py（分工边界）"
    )


@pytest.mark.parametrize("path", sorted(ENRICH_DIR.glob("*.py")), ids=lambda p: p.name)
def test_dimensions_do_not_write_database(path: Path) -> None:
    """维度实现禁止自己落库：出库必须走 s1_knowledge（F 线唯一出口）。"""

    if path.name in {"s1_knowledge.py", "agent.py"}:
        return
    imports = _iter_imports(path)
    for module in imports:
        assert "aiintel.services.knowledge.indexer" not in module, (
            f"{path.name} 直接调用 indexer；出库请走 s1_knowledge.store_enrichment"
        )


def test_s1_stub_mode_defaults_on() -> None:
    from aiintel.config import get_settings

    get_settings.cache_clear()
    assert get_settings().s1_stub_mode is True, "默认桩模式：F 线不该在无库环境下被迫连库"


def test_asset_scan_disabled_by_default() -> None:
    from aiintel.config import get_settings

    get_settings.cache_clear()
    assert get_settings().asset_scan_enabled is False, "合规红线：主动测绘默认关闭"


async def test_s1_stub_does_not_store() -> None:
    from aiintel.services.enrich import s1_knowledge

    result = await s1_knowledge.store_enrichment({"id": "v1"}, [{"dimension": "paper"}])
    assert result.stub is True
    assert result.stored is False
    assert result.dimensions == ["paper"]


async def test_s2_rejects_out_of_scope_topics() -> None:
    """F 线不许替 Y 线/Q 线发事件。"""

    from aiintel.core.events import TOPIC_RAW_DOCS
    from aiintel.services.enrich import s2_events

    # 权威主题不归 F 线发
    assert await s2_events.publish(None, TOPIC_RAW_DOCS, {}) is False
    # 已迁移的旧主题名也算越界（F 线白名单只认当前权威名）
    assert await s2_events.publish(None, "intel.enrich.completed", {}) is False
    assert await s2_events.publish(None, s2_events.TOPIC_ENRICH_ITEMS, {}) in {True, False}


def test_enrichment_invariants_helper_detects_violations() -> None:
    from aiintel.services.enrich.evidence import check_invariants

    bad = {
        "dimension": "paper",
        "source": [],
        "evidence": [],
        "confidence": 0.9,
        "degraded_to": "rule",
        "degraded_reason": "",
    }
    problems = check_invariants(bad)
    # 无证据 / 无 source / 降级但高置信 / 降级但没写原因
    assert len(problems) == 4
    assert any("evidence" in p for p in problems)
    assert any("source" in p for p in problems)
    assert any("confidence" in p for p in problems)
    assert any("degraded_reason" in p for p in problems)


def test_build_result_rejects_silent_degradation() -> None:
    from aiintel.services.enrich.evidence import EvidenceBuilder, build_result

    builder = EvidenceBuilder()
    builder.add("rule", None, "snippet")
    with pytest.raises(ValueError, match="degraded_reason"):
        build_result("paper", {}, builder, 0.5, degraded_to="rule")


def test_build_result_caps_confidence_on_degradation() -> None:
    from aiintel.services.enrich.evidence import EvidenceBuilder, build_result

    builder = EvidenceBuilder()
    builder.add("rule", None, "snippet")
    result = build_result(
        "paper", {}, builder, 0.95, degraded_to="mock", degraded_reason="预置数据"
    )
    assert result["confidence"] == 0.6
    assert result["mock"] is False


def test_build_result_rejects_unknown_degraded_value() -> None:
    from aiintel.services.enrich.evidence import build_result

    with pytest.raises(ValueError, match="degraded_to"):
        build_result("paper", {}, [], 0.5, degraded_to="whatever", degraded_reason="x")

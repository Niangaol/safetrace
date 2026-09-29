"""包结构与导出：防止拼写错误级故障。"""

from __future__ import annotations

import importlib

import pytest

MODULES = [
    "aiintel.config",
    "aiintel.core.cost",
    "aiintel.core.llm",
    "aiintel.core.events",
    "aiintel.core.alerts",
    "aiintel.core.metrics",
    "aiintel.db.base",
    "aiintel.db.models",
    "aiintel.agents.state",
    "aiintel.agents.tools",
    "aiintel.agents.nodes",
    "aiintel.agents.graph",
    "aiintel.agents.watchdog",
    "aiintel.agents.report",
    "aiintel.services.ingest.text",
    "aiintel.services.ingest.dedup",
    "aiintel.services.ingest.pipeline",
    "aiintel.services.enrich.cvss",
    "aiintel.services.enrich.dimensions",
    "aiintel.services.enrich.agent",
    "aiintel.services.collectors.base",
    "aiintel.services.collectors.nvd",
    "aiintel.services.collectors.ghsa",
    "aiintel.services.collectors.arxiv",
    "aiintel.services.collectors.community_rss",
    "aiintel.services.collectors.registry",
    "aiintel.services.knowledge.embedder",
    "aiintel.services.knowledge.retrieval",
    "aiintel.services.knowledge.indexer",
    "aiintel.services.qa.checks",
    "aiintel.services.qa.agent",
    "aiintel.api.main",
    "aiintel.api.deps",
    "aiintel.api.routers.collect",
    "aiintel.api.routers.vulns",
    "aiintel.api.routers.qa",
    "aiintel.api.routers.metrics",
    "aiintel.cli",
    "eval.run_all",
    "eval.collect_latency",
    "eval.enrich_accuracy",
    "eval.qa_accuracy",
]


@pytest.mark.parametrize("module", MODULES)
def test_module_importable(module: str):
    importlib.import_module(module)


def test_node_exports_are_attribute_names():
    from aiintel.agents import nodes

    for name in nodes.__all__:
        assert name.isidentifier(), f"__all__ 含非法标识符: {name!r}"
        assert hasattr(nodes, name), f"__all__ 导出了不存在的名字: {name!r}"


def test_node_registry_keys_match_all_exports():
    from aiintel.agents.nodes import NODES

    assert {
        "collect",
        "normalize",
        "dedup",
        "triage",
        "enrich",
        "verify",
        "persist",
        "alert",
        "report",
        "repair",
    } <= set(NODES)


def test_pipeline_covers_every_node_except_repair():
    from aiintel.agents.graph import PIPELINE
    from aiintel.agents.nodes import NODES

    assert set(PIPELINE) == set(NODES) - {"repair"}


def test_tool_registry_catalog_shape():
    from aiintel.agents.tools import registry

    catalog = registry.catalog()
    assert isinstance(catalog, list) and catalog
    for tool in catalog:
        assert {"name", "description"} <= set(tool)


def test_collectors_registered():
    from aiintel.services.collectors.registry import get_registry

    # kev = CISA KEV 官方目录（services/collectors/kev.py），"在野利用"的权威来源。
    # 刻意列出全集而不是断言 len()：加源时漏改这里会静默通过。
    assert set(get_registry().names()) == {"kev", "nvd", "ghsa", "arxiv", "community_rss"}


def test_publish_topics_cover_pipeline():
    from aiintel.agents.nodes import NODES
    from aiintel.core import events

    used = {getattr(events, name) for name in dir(events) if name.startswith("TOPIC_")}
    assert used  # topic 常量存在
    assert set(NODES)


def test_enrich_dimensions_cover_all_axes():
    """维度清单：6 个计划维度（F1–F6）+ 1 个 AI 安全专项维度。

    改这个列表要同步 6 处，见 `docs/富化线详细设计.md` §6.6。
    """

    from aiintel.services.enrich.dimensions import DIMENSIONS

    assert set(DIMENSIONS) == {
        "paper",  # F1
        "asset",  # F2
        "poc",  # F3
        "cvss",  # F4
        "fix",  # F5
        "consistency",  # F6
        "ai_risk",  # AI 安全专项
    }


def test_env_example_and_settings_in_sync():
    """防止文档/配置漂移：.env.example 的变量名必须都能被 Settings 接受。"""

    from pathlib import Path

    from aiintel.config import Settings

    root = Path(__file__).resolve().parents[1]
    env_file = root / ".env.example"
    text = env_file.read_text(encoding="utf-8")
    declared = {
        line.split("=", 1)[0].strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#") and "=" in line
    }
    fields = set(Settings.model_fields)
    unknown = {k for k in declared if k.lower() not in fields}
    assert not unknown, f".env.example 存在 Settings 中不存在的变量: {sorted(unknown)}"

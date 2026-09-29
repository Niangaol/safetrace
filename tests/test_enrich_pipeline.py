"""富化线端到端测试：7 个维度一起跑，全部符合契约、全部可溯源。

这是"接线对齐"的守门测试：任何一个维度偷偷改了输出结构、丢了 source/evidence、
或者静默降级，这里都会红。全程离线（arXiv / GitHub / MG1 都是桩）。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.contracts import load_schema, validate
from tests.conftest import dimension_contract_errors

from aiintel.core.contracts import to_enrichment_result
from aiintel.services.enrich import mg1
from aiintel.services.enrich.agent import EnrichAgent
from aiintel.services.enrich.evidence import check_invariants
from aiintel.services.enrich.paper import PaperCandidate

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2609.01234v1</id>
    <title>Deserialization Attacks Against Model Serving Stacks</title>
    <summary>pickle payload model serving stacks are remotely exploitable.</summary>
    <published>2026-09-01T00:00:00Z</published>
    <updated>2026-09-02T00:00:00Z</updated>
    <author><name>A. Researcher</name></author>
  </entry>
</feed>
"""


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """把三个外部依赖全部换成本地桩：arXiv、GitHub、MG1。"""

    from aiintel.config import get_settings
    from aiintel.services.enrich import paper as paper_module
    from aiintel.services.enrich import poc as poc_module

    monkeypatch.setenv("ENRICH_PAPER_SOURCES", "arxiv")
    monkeypatch.setenv("ENRICH_OPENALEX_ENABLED", "false")
    monkeypatch.setenv("ENRICH_BADCASE_DIR", str(tmp_path))
    get_settings.cache_clear()

    async def fake_paper_fetch(query: str, limit: int = 5):  # noqa: ANN001
        from aiintel.services.collectors.arxiv import _arxiv_id, _clean, _parse_atom

        return [
            PaperCandidate(
                source="arxiv",
                title=_clean(entry.get("title", "")),
                url=entry.get("id", ""),
                arxiv_id=_arxiv_id(entry.get("id", "")),
                year=2026,
                abstract=_clean(entry.get("summary", "")),
            )
            for entry in _parse_atom(ATOM)
        ]

    async def fake_github(vuln: dict, limit: int = 5):  # noqa: ANN001
        return [], "github:stubbed-offline"

    async def fake_mg1(messages, **kwargs):  # noqa: ANN001
        class _Result:
            ok = True
            model = "stub-model"
            degraded = None
            error = ""
            cost_cny = 0.0

        return {
            "relevant": True,
            "relation_type": "same_attack_surface",
            "relevance": 0.8,
        }, _Result()

    monkeypatch.setattr(paper_module, "fetch_arxiv", fake_paper_fetch)
    monkeypatch.setattr(poc_module, "_github_search", fake_github)
    monkeypatch.setattr(mg1, "json_complete", fake_mg1)
    yield
    get_settings.cache_clear()


async def test_all_dimensions_produce_contract_compliant_results(intel_item: dict) -> None:
    results = await EnrichAgent().run(intel_item, trace_id="trace-e2e")

    assert {r["dimension"] for r in results} == {
        "paper",
        "asset",
        "poc",
        "cvss",
        "fix",
        "consistency",
        "ai_risk",
    }
    schema = load_schema("EnrichmentResult.json")
    for item in results:
        # 7 维明细走扩展契约 DimensionEvidence（权威 EnrichmentResult 是瘦交接口）
        errors = dimension_contract_errors(item, intel_id=intel_item["intel_id"])
        assert errors == [], f"{item['dimension']} 不符合契约: {errors}"
        assert check_invariants(item) == [], f"{item['dimension']} 违反不变量"
        # 赛题硬要求：每条富化带 source 与可溯源证据
        assert item["source"], f"{item['dimension']} 没有 source"
        assert item["evidence"], f"{item['dimension']} 没有 evidence"
        assert item["trace_id"] == "trace-e2e"

    # 同一批结果投影为权威 EnrichmentResult 必须合规，且 ai_risk 不得泄漏进 6 值枚举
    summary = to_enrichment_result(intel_item["intel_id"], results)
    assert validate(schema, summary) == []
    assert set(summary["dimensions_completed"]) <= {
        "paper",
        "asset",
        "poc",
        "cvss",
        "remediation",
        "triage",
    }
    assert "ai_risk" not in summary["dimensions_completed"]


async def test_every_evidence_url_or_computation_is_traceable(intel_item: dict) -> None:
    """证据要么有 URL，要么是"可复核的本地计算"（computed/rule），不能两者皆无。"""

    results = await EnrichAgent().run(intel_item)
    for item in results:
        for evidence in item["evidence"]:
            assert evidence["evidence_id"], f"{item['dimension']} 证据缺编号"
            assert evidence["source"], f"{item['dimension']} 证据缺来源"
            assert evidence["url"] or evidence["source"] in {"computed", "rule", "mock"}, (
                f"{item['dimension']} 的证据既没有 URL 也不是本地计算"
            )
            assert evidence["snippet"], f"{item['dimension']} 证据缺原文片段"


async def test_degraded_results_are_visible_and_low_confidence(intel_item: dict) -> None:
    results = await EnrichAgent().run(intel_item)
    degraded = [r for r in results if r.get("degraded_to")]
    assert degraded, "测试环境无 MG1/LLM，至少 asset 与 poc 必须是降级产物"
    for item in degraded:
        assert item["degraded_reason"], f"{item['dimension']} 降级但没写原因"
        assert item["confidence"] <= 0.6


async def test_quality_gate_skips_low_quality_item(intel_item: dict) -> None:
    """DQ1 协同：质量分过低直接不富化，避免浪费预算。"""

    intel_item["quality_score"] = 0.2
    assert await EnrichAgent().run(intel_item) == []


async def test_quality_gate_runs_core_dimensions_only(intel_item: dict) -> None:
    intel_item["quality_score"] = 0.5
    results = await EnrichAgent().run(intel_item)
    assert {r["dimension"] for r in results} <= {"cvss", "fix", "consistency"}


async def test_explicit_dimensions_bypass_quality_gate(intel_item: dict) -> None:
    intel_item["quality_score"] = 0.2
    results = await EnrichAgent().run(intel_item, dimensions=["cvss"])
    assert [r["dimension"] for r in results] == ["cvss"]


async def test_single_dimension_failure_does_not_break_others(
    intel_item: dict, monkeypatch
) -> None:
    from aiintel.services.enrich import dimensions as dimensions_module

    async def boom(vuln, trace_id=None):  # noqa: ANN001
        raise RuntimeError("intentional failure")

    monkeypatch.setitem(dimensions_module.DIMENSIONS, "paper", boom)
    results = await EnrichAgent().run(intel_item)
    by_dim = {r["dimension"]: r for r in results}
    assert by_dim["paper"]["error"]
    assert by_dim["paper"]["degraded_to"] == "rule"
    assert by_dim["cvss"]["value"]["base_score"] == 9.8, "其他维度不受影响"


async def test_consistency_consumes_fix_output(intel_item: dict) -> None:
    """接线测试：F5 的产出必须成为 F6 的输入，否则一致性校验只是空转。

    真实冲突的检测由 `tests/test_enrich_consistency.py` 用注入样例严格验证；
    这里守的是"F6 确实拿到了 F5 的结论"。
    """

    intel_item["references"] = [
        {
            "url": "https://vendor.example.com/advisory/v0.6.5",
            "kind": "advisory",
            "title": "Vendor advisory: fixed in 0.6.5",
        },
        {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-10001",
            "kind": "advisory",
            "title": "NVD",
        },
    ]
    # fix 是纯规则实现（不依赖 MG1），consistency 排在它之后拿它的产出
    results = await EnrichAgent().run(intel_item, dimensions=["fix", "consistency"])
    by_dim = {r["dimension"]: r for r in results}

    assert by_dim["fix"]["value"]["upgrade"]["target_version"] == "0.6.2"
    assert by_dim["fix"]["value"]["version_confidence"] == "confirmed"

    value = by_dim["consistency"]["value"]
    fixed_claims = [
        item
        for entry in value["consensus"]
        if entry["field"] == "fixed_version"
        for item in entry["values"]
    ]
    assert fixed_claims, "F6 必须能看到 fixed_version 的声明（证明拿到了 F5 的产出）"
    assert {c["source"] for c in fixed_claims} >= {"vendor"}
    assert value["quality_score"] is not None


async def test_fix_upgrade_version_is_traceable(intel_item: dict) -> None:
    results = await EnrichAgent().run(intel_item, dimensions=["fix"])
    value = results[0]["value"]
    assert value["upgrade"]["target_version"] == "0.6.2"
    assert value["upgrade"]["url"], "版本号必须能追到公告 URL"
    assert value["version_confidence"] == "confirmed"

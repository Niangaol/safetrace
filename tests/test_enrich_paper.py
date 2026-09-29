"""F1 论文关联测试：双源降级、规则兜底、证据链可溯源。

全部离线：arXiv 响应与 MG1 返回都是桩，因此这组测试也是"fixture 优先"的落地示范。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import dimension_contract_errors

from aiintel.services.enrich import mg1
from aiintel.services.enrich.paper import (
    PaperCandidate,
    build_query,
    collect_candidates,
    paper_association,
    rule_judge,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

ATOM_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2609.01234v1</id>
    <title>Deserialization Attacks Against {product} Serving Stacks</title>
    <summary>We show that model-serving stacks accepting pickle payloads are remotely exploitable. {extra}</summary>
    <published>2026-09-01T00:00:00Z</published>
    <updated>2026-09-02T00:00:00Z</updated>
    <author><name>A. Researcher</name></author>
  </entry>
  <entry>
    <id>http://arxiv.org/abs/2609.09999v1</id>
    <title>Unrelated Work On Tokenizer Compression</title>
    <summary>We study vocabulary pruning for smaller tokenizers, unrelated to security.</summary>
    <published>2026-08-15T00:00:00Z</published>
    <updated>2026-08-16T00:00:00Z</updated>
    <author><name>B. Author</name></author>
  </entry>
</feed>
"""


@pytest.fixture(autouse=True)
def _fresh_settings(monkeypatch):
    """默认关掉 OpenAlex，避免单测真的发外网请求；需要时由用例自己打开。"""

    from aiintel.config import get_settings

    monkeypatch.setenv("ENRICH_OPENALEX_ENABLED", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _stub_arxiv(monkeypatch, xml: str) -> None:
    """把 arXiv 取数换成本地 Atom。"""

    async def fake_fetch(query: str, limit: int = 5):  # noqa: ANN001
        from aiintel.services.collectors.arxiv import _arxiv_id, _clean, _parse_atom

        out = []
        for entry in _parse_atom(xml)[:limit]:
            published = str(entry.get("published") or "")
            out.append(
                PaperCandidate(
                    source="arxiv",
                    title=_clean(entry.get("title", "")),
                    url=entry.get("id", ""),
                    arxiv_id=_arxiv_id(entry.get("id", "")),
                    year=int(published[:4]) if published[:4].isdigit() else None,
                    abstract=_clean(entry.get("summary", "")),
                )
            )
        return out

    from aiintel.services.enrich import paper as paper_module

    monkeypatch.setattr(paper_module, "fetch_arxiv", fake_fetch)


def _stub_mg1(monkeypatch, payload: dict | None, *, per_call=None) -> None:
    """把 MG1 换成本地桩：payload=None 表示网关不可用。

    `per_call(messages)` 可按提示词内容返回不同判定，用来模拟"只认相关的那篇"。
    """

    class _Result:
        ok = payload is not None
        model = "stub-model"
        degraded = None
        error = "" if payload is not None else "stub-unavailable"
        cost_cny = 0.0

    async def fake_json_complete(messages, **kwargs):  # noqa: ANN001
        if per_call is not None:
            return per_call(messages), _Result()
        return (payload, _Result())

    monkeypatch.setattr(mg1, "json_complete", fake_json_complete)


def test_build_query_prefers_cve_then_product() -> None:
    assert build_query({"cve_id": "CVE-2026-1"}) == '"CVE-2026-1"'
    assert "vLLM" in build_query({"affected_products": ["vLLM"]})
    assert "AI" in build_query({})


def test_rule_judge_accepts_keyword_overlap() -> None:
    vuln = {
        "title": "vLLM deserialization remote code execution",
        "description": "pickle payload model serving stacks",
        "affected_products": ["vLLM"],
    }
    candidate = PaperCandidate(
        source="arxiv",
        title="Deserialization Attacks Against Model Serving Stacks",
        url="https://arxiv.org/abs/1",
        abstract="pickle payload model serving stacks remain exploitable",
    )
    verdict = rule_judge(vuln, candidate)
    assert verdict["relevant"] is True
    assert verdict["relation_type"] in {"same_attack_surface", "same_vuln"}


def test_rule_judge_rejects_unrelated_paper() -> None:
    vuln = {"title": "vLLM RCE", "description": "pickle payload"}
    candidate = PaperCandidate(
        source="arxiv",
        title="Tokenizer Compression Study",
        url="https://arxiv.org/abs/2",
        abstract="vocabulary pruning for smaller tokenizers",
    )
    assert rule_judge(vuln, candidate)["relevant"] is False


async def test_llm_path_keeps_relevant_paper(monkeypatch, intel_item: dict) -> None:
    _stub_arxiv(monkeypatch, ATOM_TEMPLATE.format(product="Model", extra=""))

    def judge(messages):  # noqa: ANN001
        """只认与漏洞相关的第一篇，模拟真实的 LLM 判定行为。"""

        user = messages[-1]["content"]
        if "Tokenizer" in user:
            return {"relevant": False, "relation_type": "none", "relevance": 0.0, "reason": "无关"}
        return {
            "relevant": True,
            "relation_type": "same_attack_surface",
            "relevance": 0.82,
            "reason": "同一攻击面",
            "findings": ["模型加载路径可被利用", "建议强制 safetensors"],
        }

    _stub_mg1(monkeypatch, None, per_call=judge)

    result = await paper_association(intel_item, trace_id="trace-paper")
    assert dimension_contract_errors(result) == []
    assert result["degraded_to"] is None
    assert result["source"] == ["arxiv"]
    assert result["trace_id"] == "trace-paper"
    papers = result["value"]["papers"]
    assert len(papers) == 1, "无关论文必须被剔除"
    first = papers[0]
    assert first["arxiv_id"] == "2609.01234"
    assert first["evidence_ref"] == "ev-1"
    assert first["findings"]
    # 证据必须能回指到论文 URL 与摘要片段
    assert result["evidence"][0]["url"].endswith("2609.01234v1")
    assert "pickle" in result["evidence"][0]["snippet"]


async def test_llm_unavailable_falls_back_to_rules(monkeypatch, intel_item: dict) -> None:
    _stub_arxiv(monkeypatch, ATOM_TEMPLATE.format(product="Model", extra=""))
    _stub_mg1(monkeypatch, None)

    result = await paper_association(intel_item)
    assert dimension_contract_errors(result) == []
    assert result["degraded_to"] == "rule"
    assert result["degraded_reason"]
    assert result["confidence"] <= 0.6
    assert result["model"] == "rule-based"


async def test_all_sources_failing_is_reported_not_hidden(monkeypatch, intel_item: dict) -> None:
    from aiintel.services.enrich import paper as paper_module

    async def boom(query: str, limit: int = 5):  # noqa: ANN001
        raise RuntimeError("arxiv down")

    monkeypatch.setattr(paper_module, "fetch_arxiv", boom)
    _stub_mg1(monkeypatch, {"relevant": True})

    result = await paper_association(intel_item)
    assert dimension_contract_errors(result) == []
    assert result["value"]["papers"] == []
    assert result["value"]["source_failures"]
    assert result["degraded_to"] == "rule"
    assert result["confidence"] <= 0.6


async def test_collect_candidates_dedupes_across_sources(monkeypatch) -> None:
    async def fake_arxiv(query: str, limit: int = 5):  # noqa: ANN001
        return [
            PaperCandidate(
                source="arxiv", title="Same Paper", url="https://arxiv.org/abs/1", doi="10.1/x"
            )
        ]

    async def fake_openalex(query: str, limit: int = 5):  # noqa: ANN001
        return [
            PaperCandidate(
                source="openalex", title="Same Paper", url="https://doi.org/10.1/x", doi="10.1/X"
            )
        ]

    from aiintel.services.enrich import paper as paper_module

    monkeypatch.setattr(paper_module, "fetch_arxiv", fake_arxiv)
    monkeypatch.setattr(paper_module, "fetch_openalex", fake_openalex)

    candidates, ok, failures = await collect_candidates("q", ["arxiv", "openalex"])
    assert len(candidates) == 1, "同一 DOI 不应被两个源重复收录"
    assert set(ok) == {"arxiv", "openalex"}
    assert failures == []


async def test_collect_candidates_isolates_source_failure(monkeypatch) -> None:
    async def fake_arxiv(query: str, limit: int = 5):  # noqa: ANN001
        return [PaperCandidate(source="arxiv", title="Only One", url="https://arxiv.org/abs/9")]

    async def boom(query: str, limit: int = 5):  # noqa: ANN001
        raise RuntimeError("openalex 403")

    from aiintel.services.enrich import paper as paper_module

    monkeypatch.setattr(paper_module, "fetch_arxiv", fake_arxiv)
    monkeypatch.setattr(paper_module, "fetch_openalex", boom)

    candidates, ok, failures = await collect_candidates("q", ["arxiv", "openalex"])
    assert len(candidates) == 1
    assert ok == ["arxiv"]
    assert failures and "openalex" in failures[0]

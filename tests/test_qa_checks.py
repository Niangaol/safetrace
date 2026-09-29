"""引用完整性提取与自检判定。"""

from __future__ import annotations

import pytest

from aiintel.services.qa.checks import check_answer, extract_citations


def test_extract_citations_detects_refs():
    assert extract_citations("CVE-2026-0001 影响 vLLM [S1]。POC 见 [S2]。") == ["S1", "S2"]


def test_extract_citations_dedupes():
    assert extract_citations("见 [S1]，又见 [S1] 和 [S2]") == ["S1", "S2"]


def test_extract_citations_handles_adjacent_refs():
    assert extract_citations("结论 [S1][S2][S3]") == ["S1", "S2", "S3"]


def test_extract_citations_no_refs():
    assert extract_citations("没有任何引用") == []
    assert extract_citations("") == []


def test_extract_citations_ignores_wrong_format():
    assert extract_citations("[1] 不是 S 前缀") == []


EVIDENCE = [{"ref": "S1", "content": "CVE-2026-0001 影响 vLLM 0.4.0 之前的版本。"}]


async def test_check_answer_passes_with_valid_citation(stub_llm):
    stub_llm('{"passed": true, "score": 0.95, "gaps": []}')
    verdict = await check_answer("有哪些高危漏洞？", "CVE-2026-0001 是高危漏洞 [S1]。", EVIDENCE)
    assert verdict["passed"] is True
    assert verdict["missing_citation"] == []


async def test_check_answer_forces_fail_on_missing_ref(stub_llm):
    stub_llm('{"passed": true, "score": 1.0}')
    verdict = await check_answer("问题", "结论见 [S9]。", EVIDENCE)
    assert verdict["passed"] is False
    assert verdict["missing_citation"] == ["S9"]


async def test_check_answer_honours_llm_verdict(stub_llm):
    stub_llm('{"passed": false, "score": 0.3, "gaps": ["未回答影响版本"]}')
    verdict = await check_answer("问题", "回答 [S1]", EVIDENCE)
    assert verdict["passed"] is False
    assert verdict["gaps"] == ["未回答影响版本"]


async def test_check_answer_falls_back_to_ref_check_on_bad_json(stub_llm):
    stub_llm("这不是 JSON")
    ok = await check_answer("问题", "回答 [S1]", EVIDENCE)
    assert ok["passed"] is True
    assert ok["score"] >= 0.5

    bad = await check_answer("问题", "回答 [S7]", EVIDENCE)
    assert bad["passed"] is False
    assert bad["missing_citation"] == ["S7"]


async def test_check_answer_with_empty_evidence(stub_llm):
    stub_llm('{"passed": true, "score": 0.9}')
    verdict = await check_answer("问题", "没有任何引用", [])
    assert verdict["passed"] is True


async def test_check_answer_evidence_without_ref_ignored(stub_llm):
    stub_llm('{"passed": true, "score": 0.9}')
    verdict = await check_answer("问题", "见 [S1]", [{"content": "无 ref 字段"}])
    assert verdict["missing_citation"] == ["S1"]


@pytest.mark.parametrize("refs", [[], ["S1"], ["S1", "S2", "S3"]])
async def test_check_answer_various_ref_counts(stub_llm, refs):
    stub_llm('{"passed": true, "score": 0.9}')
    answer = "结论 " + "".join(f"[{r}]" for r in refs)
    verdict = await check_answer("问题", answer, EVIDENCE)
    assert isinstance(verdict, dict)
    assert "passed" in verdict

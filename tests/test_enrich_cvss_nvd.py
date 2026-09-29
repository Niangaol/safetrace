"""F4 CVSS 解析与 NVD JSON 解析的真实用例（离线，用 fixture）。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import dimension_contract_errors

from aiintel.services.enrich.cvss import (
    is_valid_vector,
    resolve_score,
    score_vector_31,
    vector_version,
)
from aiintel.services.enrich.nvd import parse_nvd

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture()
def nvd_payload() -> dict:
    return json.loads((FIXTURES / "nvd_cve.sample.json").read_text(encoding="utf-8"))


def test_score_vector_31_matches_nvd(nvd_payload: dict) -> None:
    """本地算出来的分数必须与 NVD 官方一致（可复核是这一维的立身之本）。"""

    vector = nvd_payload["metrics"]["cvssMetricV31"][0]["cvssData"]["vectorString"]
    official = nvd_payload["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    assert score_vector_31(vector) == official == 9.8


def test_score_source_is_computed_for_31_vector(nvd_payload: dict) -> None:
    parsed = parse_nvd({"cve_id": "CVE-2026-10001", "raw_json": {"cve": nvd_payload}})
    assert parsed["score_source"] == "computed"
    assert parsed["base_score"] == 9.8
    assert parsed["severity"] == "critical"


def test_parses_cvss_40_block_without_local_computation(nvd_payload: dict) -> None:
    """CVSS 4.0 只取官方值并如实标注，不做本地 MacroVector 计算。"""

    parsed = parse_nvd({"cve_id": "CVE-2026-10001", "raw_json": {"cve": nvd_payload}})
    assert parsed["vector_40"].startswith("CVSS:4.0/")
    assert parsed["score_40"] == 9.3
    assert vector_version(parsed["vector_40"]) == "4.0"
    assert is_valid_vector(parsed["vector_40"]) is True


def test_extracts_cpe_and_version_range(nvd_payload: dict) -> None:
    parsed = parse_nvd({"cve_id": "CVE-2026-10001", "raw_json": {"cve": nvd_payload}})
    assert parsed["cpe"] == ["cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*"]
    assert parsed["version_ranges"] == [
        {"product": "vllm", "introduced": "0.6.0", "fixed": "0.6.2", "source": "nvd", "url": None}
    ]


def test_extracts_reference_kinds(nvd_payload: dict) -> None:
    parsed = parse_nvd({"cve_id": "CVE-2026-10001", "raw_json": {"cve": nvd_payload}})
    kinds = {ref["kind"] for ref in parsed["references"]}
    assert "advisory" in kinds
    assert "patch" in kinds


def test_extracts_cwe(nvd_payload: dict) -> None:
    parsed = parse_nvd({"cve_id": "CVE-2026-10001", "raw_json": {"cve": nvd_payload}})
    assert parsed["cwe"] == ["CWE-502"]


def test_missing_vector_yields_no_guess() -> None:
    """拿不到向量就不给分数——绝不猜。"""

    parsed = parse_nvd({"cve_id": "CVE-2026-9", "description": "no vector here"})
    assert parsed["cvss_vector"] is None
    assert parsed["base_score"] is None
    assert parsed["score_source"] == "unavailable"
    assert parsed["severity"] == "unknown"


def test_official_score_used_when_vector_unparsable() -> None:
    score, source = resolve_score("CVSS:3.1/AV:N/AC:L", official_score=7.5)
    assert (score, source) == (7.5, "official")


def test_invalid_vector_detection() -> None:
    assert is_valid_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is True
    assert is_valid_vector("CVSS:3.1/AV:N") is False
    assert is_valid_vector(None) is False


async def test_cvss_dimension_is_contract_compliant(intel_item: dict, monkeypatch) -> None:
    """真实维度输出必须过契约（这才是"契约对齐"的验收）。"""

    from aiintel.services.enrich.cvss_impact import cvss_and_impact

    result = await cvss_and_impact(intel_item)
    assert dimension_contract_errors(result) == []
    assert result["value"]["score_source"] == "computed"
    assert "nvd" in result["source"]
    assert result["value"]["base_score"] == 9.8
    # MG1 在测试环境不可用 → 必须显式降级，而不是静默给一份编造的影响说明
    assert result["degraded_to"] in {"rule", "local"}
    assert result["degraded_reason"]

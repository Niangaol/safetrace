"""F2 / F3 / F5 的 Mock 与规则路径测试。

这一组测试守的是**诚实性**：Mock 必须标 `mock=true`、降级必须标 `degraded_to`、
**不得出现"已验证"**、**不得编造版本号**。这些比"功能跑通"更容易在答辩上翻车。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import dimension_contract_errors

from aiintel.services.enrich.asset import asset_impact, parse_cpe, parse_version_range
from aiintel.services.enrich.fix import (
    classify_reference,
    extract_target_version,
    fix_recommendation,
    known_versions,
)
from aiintel.services.enrich.poc import poc_search

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def _fresh_settings():
    from aiintel.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------- F2 资产


def test_parse_cpe_23_form() -> None:
    parsed = parse_cpe("cpe:2.3:a:vllm:vllm:0.6.0:*:*:*:*:*:*:*")
    assert parsed == {
        "vendor": "vllm",
        "product": "vllm",
        "version": "0.6.0",
        "raw": "cpe:2.3:a:vllm:vllm:0.6.0:*:*:*:*:*:*:*",
    }


def test_parse_cpe_22_uri_form() -> None:
    parsed = parse_cpe("cpe:/a:ollama:ollama:0.1.32")
    assert parsed["vendor"] == "ollama"
    assert parsed["product"] == "ollama"
    assert parsed["version"] == "0.1.32"


def test_parse_cpe_wildcards_become_none() -> None:
    parsed = parse_cpe("cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*")
    assert parsed["version"] is None


def test_parse_cpe_rejects_garbage() -> None:
    assert parse_cpe("not-a-cpe") == {}


def test_parse_version_range_variants() -> None:
    assert (
        parse_version_range({"introduced": "0.6.0", "fixed": "0.6.2"})["affected_versions"]
        == ">=0.6.0,<0.6.2"
    )
    assert parse_version_range({"fixed": "1.0"})["affected_versions"] == "<1.0"
    assert parse_version_range({"introduced": "1.0"})["affected_versions"] == ">=1.0"
    assert parse_version_range({})["affected_versions"] == "unknown"


async def test_asset_is_mock_and_scan_disabled(intel_item: dict, monkeypatch, tmp_path) -> None:
    """合作方合规要求：主动测绘默认关闭，结果必须显式标 Mock。"""

    monkeypatch.setenv("ASSET_SCAN_ENABLED", "false")
    monkeypatch.setenv("ASSET_INVENTORY_PATH", str(tmp_path / "missing.json"))
    from aiintel.config import get_settings

    get_settings.cache_clear()

    result = await asset_impact(intel_item)
    assert dimension_contract_errors(result) == []
    assert result["value"]["mock"] is True
    assert result["value"]["exposed_assets"] == []
    assert result["value"]["asset_scan_enabled"] is False
    assert result["degraded_to"] == "mock"
    assert result["degraded_reason"]
    assert result["confidence"] <= 0.6
    # 真跑的部分仍然要有：CPE 与版本区间解析
    products = result["value"]["products"]
    assert any(p["product"] == "vllm" for p in products)
    assert any(p["affected_versions"] == ">=0.6.0,<0.6.2" for p in products)


async def test_asset_matches_imported_inventory(intel_item: dict, monkeypatch, tmp_path) -> None:
    inventory = tmp_path / "assets.json"
    inventory.write_text(
        json.dumps(
            [{"name": "inference-01", "product": "vllm", "version": "0.6.0", "exposure": "high"}]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASSET_SCAN_ENABLED", "true")
    monkeypatch.setenv("ASSET_INVENTORY_PATH", str(inventory))
    from aiintel.config import get_settings

    get_settings.cache_clear()

    result = await asset_impact(intel_item)
    assert result["value"]["exposed_assets"], "导入清单匹配是允许的（非主动扫描）"
    assert result["value"]["exposure_level"] == "high"
    assert result["value"]["inventory_loaded"] is True


# ---------------------------------------------------------------- F3 POC


async def test_poc_never_claims_runtime_verified(intel_item: dict) -> None:
    """旧实现把 verified 硬编码 true，这里守住"检索到 ≠ 已验证"。"""

    result = await poc_search(intel_item)
    assert dimension_contract_errors(result) == []
    assert result["value"]["runtime_verified_any"] is False
    for poc in result["value"]["pocs"]:
        assert poc["runtime_verified"] is False
        assert poc["tier"] in {"confirmed", "likely", "mention"}


async def test_poc_rules_path_is_marked_as_degraded(intel_item: dict) -> None:
    """无网络时走公告 references 的规则筛选，必须标降级而不是假装检索成功。"""

    result = await poc_search(intel_item)
    if not result["value"]["pocs"]:
        assert result["degraded_to"] == "rule"
    elif "github" not in result["value"]["sources_used"]:
        assert result["degraded_to"] == "rule"
        assert result["degraded_reason"]
        assert result["confidence"] <= 0.6


async def test_poc_marks_patch_references_as_patch_kind(intel_item: dict) -> None:
    result = await poc_search(intel_item)
    kinds = {poc["kind"] for poc in result["value"]["pocs"]}
    if kinds:
        assert kinds <= {"exploit", "patch", "template", "analysis"}


# ---------------------------------------------------------------- F5 修复建议


def test_classify_reference_uses_tags_then_hints() -> None:
    assert classify_reference({"kind": "patch"}) == "patch"
    assert classify_reference({"url": "https://github.com/x/y/pull/1"}) == "patch"
    assert classify_reference({"url": "https://github.com/advisories/GHSA-1"}) == "advisory"
    assert classify_reference({"url": "https://example.com/blog/post"}) == "other"


def test_extract_target_version_from_version_ranges(intel_item: dict) -> None:
    target, confidence, url = extract_target_version(intel_item, [])
    assert target == "0.6.2"
    assert confidence == "confirmed"
    assert url


def test_extract_target_version_rejects_invented_version() -> None:
    """公告里根本没出现的版本号，一律不认。"""

    vuln = {"references": [{"url": "https://vendor.example.com/advisory/1", "kind": "advisory"}]}
    target, confidence, _ = extract_target_version(vuln, vuln["references"])
    assert target is None
    assert confidence == "unknown"


def test_known_versions_harvests_from_urls_and_fields() -> None:
    vuln = {
        "version_ranges": [{"introduced": "1.2.0", "fixed": "1.2.4"}],
        "references": [{"url": "https://x.example.com/v2.0.1/notes"}],
    }
    versions = known_versions(vuln, vuln["references"])
    assert {"1.2.0", "1.2.4", "2.0.1"} <= versions


async def test_fix_is_honest_when_no_patch_reference() -> None:
    vuln = {"id": "v_nopatch", "cve_id": "CVE-2026-50005", "title": "某漏洞", "references": []}
    result = await fix_recommendation(vuln)
    assert dimension_contract_errors(result) == []
    assert result["value"]["upgrade"]["target_version"] is None
    assert result["value"]["version_confidence"] == "unknown"
    assert "未找到" in result["note"]
    assert result["degraded_to"] == "rule"
    assert result["mock"] is True  # 通用建议是模板，必须承认


async def test_fix_marks_mock_parts(intel_item: dict) -> None:
    result = await fix_recommendation(intel_item)
    assert dimension_contract_errors(result) == []
    assert result["value"]["upgrade"]["target_version"] == "0.6.2"
    assert result["value"]["version_confidence"] == "confirmed"
    assert result["mock"] is True
    assert set(result["value"]["mock_parts"]) == {"hardening", "detection"}
    # 立即缓解建议必须给出依据（本 fixture 是 CWE-502）
    assert any("反序列化" in item["rationale"] for item in result["value"]["immediate"])

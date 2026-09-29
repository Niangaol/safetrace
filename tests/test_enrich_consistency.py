"""F6 一致性校验测试：冲突必被检出、仲裁规则可复现、降级可见。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.conftest import dimension_contract_errors

from aiintel.services.enrich.consistency import (
    Claim,
    collect_claims,
    compare_field,
    consistency_check,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _set_env(monkeypatch, tmp_path, **env: str) -> None:
    """改环境变量并让 `get_settings()` 的 lru_cache 失效（否则测试读到旧配置）。"""

    from aiintel.config import get_settings

    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _fresh_settings():
    """每次测试前后清 `get_settings()` 缓存，避免读到上一个测试的环境变量。"""

    from aiintel.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _nvd_item() -> dict:
    """NVD 说 9.8，厂商公告说 8.1 —— 经典的跨源冲突。"""
    return {
        "id": "v_conflict",
        "cve_id": "CVE-2026-20002",
        "title": "推理框架反序列化 RCE",
        "description": "desc",
        "cvss_score": 9.8,
        "severity": "critical",
        "affected_products": ["vLLM"],
        "sources": [
            {"source": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-20002"},
            {"source": "vendor", "url": "https://vendor.example.com/advisory/20002"},
        ],
        "version_ranges": [
            {
                "product": "vllm",
                "introduced": "0.6.0",
                "fixed": "0.6.2",
                "source": "vendor",
                "url": "https://vendor.example.com/advisory/20002",
            }
        ],
        "references": [
            {
                "url": "https://vendor.example.com/advisory/20002",
                "kind": "advisory",
                "title": "Vendor advisory: CVSS 8.1",
            }
        ],
        "published_at": "2026-09-20T08:00:00+08:00",
    }


def test_single_source_caps_quality_score(tmp_path, monkeypatch) -> None:
    _set_env(monkeypatch, tmp_path, ENRICH_BADCASE_DIR=str(tmp_path))
    item = {
        "id": "v_single",
        "cve_id": "CVE-2026-30003",
        "cvss_score": 7.5,
        "severity": "high",
        "sources": [{"source": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-30003"}],
    }
    claims = collect_claims(item, [])
    cmp = compare_field("cvss_score", claims, ("nvd", "vendor"), 0.1)
    assert cmp.conflict is False
    assert cmp.rule == "single_source"


def test_compare_field_detects_cvss_conflict() -> None:
    claims = [
        Claim("cvss_score", 9.8, "nvd", "https://nvd.nist.gov/vuln/detail/CVE-2026-20002"),
        Claim("cvss_score", 8.1, "vendor", "https://vendor.example.com/advisory/20002"),
    ]
    cmp = compare_field("cvss_score", claims, ("nvd", "vendor"), 0.1)
    assert cmp.conflict is True
    assert cmp.resolved_to == 9.8
    assert cmp.rule == "source_priority:nvd"


def test_compare_field_respects_priority_order() -> None:
    """优先级反转时仲裁结果必须跟着变——证明仲裁是规则而不是硬编码。"""

    claims = [
        Claim("cvss_score", 9.8, "nvd", "https://nvd.nist.gov/vuln/detail/CVE-1"),
        Claim("cvss_score", 8.1, "vendor", "https://vendor.example.com/a"),
    ]
    cmp = compare_field("cvss_score", claims, ("vendor", "nvd"), 0.1)
    assert cmp.resolved_to == 8.1
    assert cmp.rule == "source_priority:vendor"


def test_compare_field_within_tolerance_is_not_conflict() -> None:
    claims = [
        Claim("cvss_score", 9.8, "nvd", "https://nvd.nist.gov/vuln/detail/CVE-1"),
        Claim("cvss_score", 9.9, "vendor", "https://vendor.example.com/a"),
    ]
    cmp = compare_field("cvss_score", claims, ("nvd", "vendor"), 0.1)
    assert cmp.conflict is False


async def test_consistency_flags_fixed_version_conflict(tmp_path, monkeypatch) -> None:
    """厂商说 0.6.5、版本区间说 0.6.2 —— 注入式冲突必须被检出并写入 badcase。"""

    _set_env(
        monkeypatch,
        tmp_path,
        ENRICH_BADCASE_DIR=str(tmp_path),
        ENRICH_SOURCE_PRIORITY="nvd,vendor",
    )
    item = _nvd_item()
    injected = [
        {
            "dimension": "fix",
            "value": {
                "upgrade": {
                    "target_version": "0.6.5",
                    "source": "vendor",
                    "url": "https://vendor.example.com/advisory/20002",
                }
            },
            "source": ["vendor"],
            "evidence": [
                {
                    "evidence_id": "ev-1",
                    "source": "vendor",
                    "url": "https://vendor.example.com/advisory/20002",
                    "snippet": "fixed in 0.6.5",
                }
            ],
        }
    ]
    result = await consistency_check(item, injected)
    fixed = [c for c in result["value"]["conflicts"] if c["field"] == "fixed_version"]
    assert fixed, "版本区间 0.6.2 与厂商 0.6.5 不一致必须被检出"
    assert fixed[0]["rule"].startswith("source_priority:")
    assert fixed[0]["severity"] == "high"
    assert (tmp_path / "conflicts.jsonl").exists()


async def test_consistency_flags_cvss_conflict_from_raw_nvd(tmp_path, monkeypatch) -> None:
    """IntelItem 归一分数与 NVD 原始 JSON 分数不一致也要被检出。"""

    _set_env(monkeypatch, tmp_path, ENRICH_BADCASE_DIR=str(tmp_path))
    nvd = json.loads((FIXTURES / "nvd_cve.sample.json").read_text(encoding="utf-8"))
    item = _nvd_item()
    item["cvss_score"] = 8.1
    item["raw_json"] = {"cve": nvd}
    result = await consistency_check(item, [])
    conflicts = [c for c in result["value"]["conflicts"] if c["field"] == "cvss_score"]
    assert conflicts, "8.1 与 NVD 原始 9.8 的差异必须被检出"
    assert conflicts[0]["resolved_to"] == 9.8  # 仲裁取优先级更高的 NVD


async def test_consistency_conflict_goes_to_badcase(tmp_path, monkeypatch) -> None:
    _set_env(
        monkeypatch,
        tmp_path,
        ENRICH_BADCASE_DIR=str(tmp_path),
        ENRICH_SOURCE_PRIORITY="nvd,vendor",
    )
    item = _nvd_item()
    item["cvss_score"] = 8.1  # 让 IntelItem 侧与 NVD raw 侧产生分歧
    enrichments = [
        {
            "dimension": "fix",
            "value": {
                "upgrade": {
                    "target_version": "0.6.5",
                    "source": "vendor",
                    "url": "https://vendor.example.com/a",
                }
            },
            "source": ["vendor"],
            "evidence": [
                {"evidence_id": "ev-1", "source": "vendor", "url": "https://vendor.example.com/a"}
            ],
        }
    ]
    result = await consistency_check(item, enrichments, trace_id="trace-test")

    assert dimension_contract_errors(result) == []
    assert result["quality_score"] is not None
    assert result["quality_score"] <= 1.0

    badcase = tmp_path / "conflicts.jsonl"
    assert badcase.exists(), "冲突必须落 badcase，答辩素材不能丢"
    record = json.loads(badcase.read_text(encoding="utf-8").strip().splitlines()[0])
    assert record["vuln_id"] == "v_conflict"
    assert record["conflicts"]
    # 冲突字段必须是 cvss_score，且仲裁规则要写在记录里（可复核）
    conflict = record["conflicts"][0]
    assert "rule" in conflict
    assert conflict["field"] in {"cvss_score", "fixed_version"}


async def test_consistency_marks_degraded_when_rule_only(tmp_path, monkeypatch) -> None:
    """MG1 不可用时仲裁理由用模板句，但必须显式标 degraded_to=rule。"""

    _set_env(monkeypatch, tmp_path, ENRICH_BADCASE_DIR=str(tmp_path))
    result = await consistency_check(_nvd_item(), [], trace_id="trace-test")
    assert result["degraded_to"] in {"rule", None}
    if result["degraded_to"]:
        assert result["degraded_reason"]
        assert result["confidence"] <= 0.6


async def test_consistency_timeline_has_stages(tmp_path, monkeypatch) -> None:
    _set_env(monkeypatch, tmp_path, ENRICH_BADCASE_DIR=str(tmp_path))
    enrichments = [
        {
            "dimension": "poc",
            "value": {"pocs": [{"url": "https://github.com/x/y", "tier": "likely"}]},
            "source": ["github"],
            "evidence": [
                {"evidence_id": "ev-1", "source": "github", "url": "https://github.com/x/y"}
            ],
        }
    ]
    result = await consistency_check(_nvd_item(), enrichments)
    stages = {event["stage"] for event in result["value"]["timeline"]}
    assert "disclosed" in stages
    assert "poc" in stages


def test_single_source_quality_score_capped(tmp_path, monkeypatch) -> None:
    _set_env(monkeypatch, tmp_path, ENRICH_BADCASE_DIR=str(tmp_path))
    item = {
        "id": "v_only_nvd",
        "cve_id": "CVE-2026-40004",
        "cvss_score": 5.0,
        "severity": "medium",
        "sources": [{"source": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-40004"}],
    }
    claims = collect_claims(item, [])
    assert {c.source for c in claims} == {"nvd"}

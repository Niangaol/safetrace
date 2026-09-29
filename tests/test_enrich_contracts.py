"""契约测试：权威冻结集 + 本仓扩展契约，双层都要被 CI 拦下。

这是"契约对齐"的自动化落点 —— 契约不是文档里的一段话，而是会被 CI 拦下的判据。

三层守门：

1. **冻结守门**：SafeTrace 的 8 个权威 Schema 必须与上游逐字节一致（本仓无权改动）。
2. **交接口守门**：`EnrichmentResult.json` 是 `additionalProperties: false` 的瘦交接口，
   维度枚举只有 6 值，`artifacts` 只允许 `papers` / `score_assessment`。
3. **明细守门**：7 维明细走扩展契约 `DimensionEvidence.json`；三条不变量
   （source 非空 / 证据非空 / 降级压置信）在此继续强制，一条都不放松。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.contracts import load_schema, validate

from aiintel.core.contracts import (
    CONTRACT_DIMENSIONS,
    DIMENSION_TO_CONTRACT,
    ContractProjectionError,
    to_contract_degrade,
    to_contract_dimension,
    to_enrichment_result,
    to_intel_item,
)
from aiintel.services.enrich.evidence import DEGRADED_VALUES, check_invariants

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

ENRICHMENT_FIXTURES = (
    "enrichment_paper.sample.json",
    "enrichment_cvss.sample.json",
    "enrichment_consistency.sample.json",
    "enrichment_mock.sample.json",
)

EVIDENCE_FIXTURES = (
    "evidence_paper.sample.json",
    "evidence_ai_risk.sample.json",
)

AUTHORITATIVE = (
    "RawDoc.json",
    "IntelItem.json",
    "EnrichmentResult.json",
    "DecisionRequest.json",
    "DecisionReply.json",
    "RetrievalRequest.json",
    "RetrievalResponse.json",
    "ToolRegistration.json",
)


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- 冻结守门


def test_authoritative_schemas_are_present_and_loadable() -> None:
    for name in AUTHORITATIVE:
        schema = load_schema(name)
        assert schema.get("title"), f"{name} 缺 title"
        assert "properties" in schema, f"{name} 缺 properties"


def test_authoritative_schemas_match_upstream_byte_for_byte() -> None:
    """SafeTrace 已冻结的 8 个 Schema，本仓一字不改。

    校验基准是**仓内指纹表**（`contracts/schemas/FROZEN_MANIFEST.json`），
    不依赖任何外部路径 —— 换台机器同样有效。
    """

    from scripts.validate_contracts import check_authoritative_frozen

    assert check_authoritative_frozen() == []


def test_frozen_manifest_covers_every_authoritative_schema() -> None:
    """指纹表必须覆盖全部 8 个冻结件，且不是占位值。"""

    from scripts.validate_contracts import AUTHORITATIVE_SCHEMAS, load_manifest

    schemas = load_manifest()["schemas"]
    assert set(schemas) == set(AUTHORITATIVE_SCHEMAS)
    for name, digest in schemas.items():
        assert digest.startswith("sha256:") and len(digest) == 71, f"{name} 指纹格式不对: {digest}"


def test_frozen_check_detects_tampering(tmp_path, monkeypatch) -> None:
    """★ 保护必须**真的会拦**：篡改一份副本，冻结校验必须报错。

    旧实现对不可达的上游路径 `return []`，等于保护是假的；这条测试保证它不再退化。
    """

    import scripts.validate_contracts as vc
    from scripts.contracts import SCHEMA_DIR

    copied = tmp_path / "schemas"
    copied.mkdir()
    for path in SCHEMA_DIR.glob("*.json"):
        (copied / path.name).write_bytes(path.read_bytes())

    # 未篡改 → 通过
    monkeypatch.setattr(vc, "SCHEMA_DIR", copied)
    assert vc.check_authoritative_frozen() == []

    # 篡改一个字节 → 必须报"被本仓改动"
    target = copied / "IntelItem.json"
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    problems = vc.check_authoritative_frozen()
    assert any("被本仓改动" in p and "IntelItem.json" in p for p in problems), problems


def test_frozen_check_reports_missing_manifest_instead_of_passing(tmp_path, monkeypatch) -> None:
    """指纹表缺失时必须**明确报一条**，而不是静默返回通过。"""

    import scripts.validate_contracts as vc

    monkeypatch.setattr(vc, "MANIFEST_PATH", tmp_path / "nope.json")
    problems = vc.check_authoritative_frozen()
    assert problems and "冻结指纹表不可用" in problems[0]


def test_upstream_cross_check_reports_bad_env_instead_of_silent_skip(monkeypatch) -> None:
    """配了错误的上游路径要报错；没配则不加戏（只靠仓内指纹）。"""

    from scripts.validate_contracts import UPSTREAM_ENV, check_upstream_cross_check

    monkeypatch.delenv(UPSTREAM_ENV, raising=False)
    assert check_upstream_cross_check() == []

    monkeypatch.setenv(UPSTREAM_ENV, r"Z:\definitely\not\here")
    problems = check_upstream_cross_check()
    assert problems and UPSTREAM_ENV in problems[0]


# ------------------------------------------------------------ 交接口守门


@pytest.mark.parametrize("name", ENRICHMENT_FIXTURES)
def test_fixture_matches_authoritative_enrichment_contract(name: str) -> None:
    assert validate(load_schema("EnrichmentResult.json"), _load(name)) == []


@pytest.mark.parametrize("name", EVIDENCE_FIXTURES)
def test_fixture_matches_dimension_evidence_contract(name: str) -> None:
    assert validate(load_schema("DimensionEvidence.json"), _load(name)) == []


def test_intelitem_fixture_matches_contract() -> None:
    assert validate(load_schema("IntelItem.json"), _load("intelitem.sample.json")) == []


def test_rawdoc_fixture_matches_contract() -> None:
    assert validate(load_schema("RawDoc.json"), _load("rawdoc.sample.json")) == []


def test_intelitem_fixture_carries_f_line_inputs() -> None:
    """权威 `IntelItem` 刻意精简，F 线输入靠 `raw_refs` 回读原始 payload，不靠顶层字段。"""

    payload = _load("intelitem.sample.json")
    assert payload["raw_refs"], "raw_refs 是 F3/F4/F5 回读 references/cvss/epss 的唯一入口"
    assert payload["source_ids"], "source_ids 是富化 source 与可靠度权重的依据"
    assert payload["entities"]["version_range"], "version_range 是 F2/F5 的输入"
    assert payload["cve_ids"], "cve_ids 是 F 线定位情报的依据"
    assert payload["source_reliability"] is not None


def test_authoritative_enrichment_result_rejects_ai_risk() -> None:
    """第 7 维 `ai_risk` 不得进入权威 6 值枚举 —— 这正是扩展契约存在的原因。"""

    payload = _load("enrichment_paper.sample.json")
    payload["dimensions_completed"].append("ai_risk")
    errors = validate(load_schema("EnrichmentResult.json"), payload)
    assert any("枚举" in e or "enum" in e for e in errors)


def test_authoritative_enrichment_result_rejects_extra_properties() -> None:
    """`additionalProperties: false`：明细塞进交接口即违约。"""

    payload = _load("enrichment_cvss.sample.json")
    payload["evidence"] = [{"url": "https://example.com", "snippet": "x"}]
    errors = validate(load_schema("EnrichmentResult.json"), payload)
    assert any("额外字段" in e for e in errors)


def test_dimension_evidence_accepts_all_seven_dimensions() -> None:
    """扩展契约承载 7 维；前 6 维与权威主键同名，第 7 维为 ai_risk。"""

    schema = load_schema("DimensionEvidence.json")
    assert set(DIMENSION_TO_CONTRACT) == {
        "paper",
        "asset",
        "poc",
        "cvss",
        "fix",
        "consistency",
        "ai_risk",
    }
    for internal in DIMENSION_TO_CONTRACT:
        payload = _load("evidence_paper.sample.json")
        payload["dimension"] = to_contract_dimension(internal)
        assert validate(schema, payload) == [], f"{internal} 投影后不合扩展契约"


def test_dimension_mapping_matches_authoritative_keys() -> None:
    assert DIMENSION_TO_CONTRACT["fix"] == "remediation"
    assert DIMENSION_TO_CONTRACT["consistency"] == "triage"
    assert (
        frozenset({"paper", "asset", "poc", "cvss", "remediation", "triage"}) == CONTRACT_DIMENSIONS
    )


# ------------------------------------------------------- 不变量（一条不放松）


def test_validator_rejects_missing_source() -> None:
    """不变量 3：source 非空 —— 赛题硬要求"每条富化带 source"。"""

    schema = load_schema("DimensionEvidence.json")
    payload = _load("evidence_paper.sample.json")
    payload["sources"] = []
    errors = validate(schema, payload)
    assert any("sources" in e for e in errors)


def test_degraded_conclusion_cannot_be_dressed_as_high_confidence() -> None:
    """不变量 2：降级结论不许包装成高置信。

    这是**跨字段**约束，Schema 表达不了，由 `check_invariants` 强制执行。
    """

    payload = _load("evidence_paper.sample.json")
    payload["degraded_to"] = "template"
    payload["degraded_state"] = {
        "label": "规则模板兜底",
        "since": "2026-09-29T00:00:00Z",
        "detail_ref": "urn:aiintel:evidence:intel_x",
    }
    assert validate(load_schema("DimensionEvidence.json"), payload) == []

    payload["confidence"] = 0.95
    problems = check_invariants(payload)
    assert any("confidence" in p for p in problems), problems


def test_degraded_marker_requires_declared_reason() -> None:
    """`degraded_to` 非空必须带 `degraded_reason`（用户可见降级，红线）。"""

    payload = _load("evidence_paper.sample.json")
    payload["degraded_to"] = "template"
    payload["degraded_state"] = {
        "label": "规则模板兜底",
        "since": "2026-09-29T00:00:00Z",
        "detail_ref": "urn:aiintel:evidence:intel_x",
    }
    payload["degraded_reason"] = ""
    problems = check_invariants(payload)
    assert any("degraded_reason" in p for p in problems), problems


def test_validator_rejects_unknown_dimension() -> None:
    schema = load_schema("DimensionEvidence.json")
    payload = _load("evidence_paper.sample.json")
    payload["dimension"] = "made_up"
    errors = validate(schema, payload)
    assert any("枚举" in e or "enum" in e for e in errors)


def test_validator_rejects_bad_degraded_value() -> None:
    """`degraded_to` 必须是权威 6 值枚举，禁止自造通道名。"""

    schema = load_schema("DimensionEvidence.json")
    payload = _load("evidence_paper.sample.json")
    payload["degraded_to"] = "silently_ok"
    errors = validate(schema, payload)
    assert any("枚举" in e or "enum" in e for e in errors)


def test_internal_degrade_channels_all_map_into_authoritative_enum() -> None:
    """内部通道名（rule/mock/local…）必须全部有权威枚举落点，否则投影会炸。"""

    for channel in DEGRADED_VALUES:
        assert to_contract_degrade(channel) in {
            "cache",
            "memory_index",
            "template",
            "fixture",
            "source_switch",
            "provider_switch",
        }, f"{channel} 没有权威降级枚举落点"


def test_unknown_degrade_channel_raises_instead_of_passing_through() -> None:
    """未知通道必须报错，禁止静默透传 —— 静默透传就是静默兜底。"""

    with pytest.raises(ContractProjectionError):
        to_contract_degrade("totally_made_up")


def test_unknown_dimension_raises_instead_of_passing_through() -> None:
    with pytest.raises(ContractProjectionError):
        to_contract_dimension("dimension_8")


# --------------------------------------------------------------- 投影行为


def test_projection_keeps_ai_risk_out_of_authoritative_result() -> None:
    """把 7 维结果投影成权威交接口时，ai_risk 不得出现在 6 值枚举里。"""

    results = [
        {"dimension": d, "confidence": 0.8, "evidence": [], "source": ["rule"]}
        for d in DIMENSION_TO_CONTRACT
    ]
    summary = to_enrichment_result("intel_x", results)
    assert validate(load_schema("EnrichmentResult.json"), summary) == []
    assert "ai_risk" not in summary["dimensions_completed"]
    assert set(summary["dimensions_completed"]) == CONTRACT_DIMENSIONS


def test_intel_item_projection_round_trips_required_fields() -> None:
    internal = {
        "vuln_id": "v1",
        "cve_id": "CVE-2026-10001",
        "title": "示例漏洞",
        "description": "描述",
        "sources": ["nvd"],
        "references": [{"url": "https://example.com/a"}],
        "cpe": ["cpe:2.3:a:v:v:1.0:*:*:*:*:*:*:*"],
        "cwe": ["CWE-502"],
        "version_ranges": [{"fixed": "1.1"}],
        "affected_products": ["vllm"],
    }
    item = to_intel_item(internal)
    assert validate(load_schema("IntelItem.json"), item) == []
    assert item["intel_id"] == "intel_CVE_2026_10001"
    assert item["cve_ids"] == ["CVE-2026-10001"]
    assert item["entities"]["cwe"] == ["CWE-502"]
    assert item["raw_refs"], "无 references 时仍须给出可回溯的 raw_refs"


# ------------------------------------------------------------------- 门禁


def test_degrade_mapping_has_a_single_source_of_truth(monkeypatch) -> None:
    """★ 降级口径只有一处：`core/degrade.py::degrade()`。

    以前 `to_dimension_evidence` 自带一份 `DEGRADE_TO_CONTRACT` 映射，
    等于降级口径有两处定义。这条测试用"把 contracts 里的映射函数打断"来证明
    投影路径确实不再依赖它 —— 若谁把映射搬回去，这里立刻红。
    """

    import aiintel.core.contracts as contracts
    from aiintel.core.degrade import degrade

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("投影路径不应再直接调用 contracts.to_contract_degrade")

    monkeypatch.setattr(contracts, "to_contract_degrade", _boom)

    payload = contracts.to_dimension_evidence(
        {
            "dimension": "asset",
            "value": {"products": []},
            "source": ["rule"],
            "evidence": [{"evidence_id": "ev-1", "source": "rule", "url": None, "snippet": "x"}],
            "confidence": 0.5,
            "degraded_to": "mock",
            "degraded_reason": "预置数据",
            "trace_id": "trace-1",
        },
        intel_id="intel_x",
    )
    assert validate(load_schema("DimensionEvidence.json"), payload) == []
    assert payload["degraded_to"] == "fixture"  # mock → fixture（权威枚举）
    assert payload["degraded_detail"] == "mock"  # 内部细名不丢
    assert payload["degraded_state"]["detail_ref"] == "trace-1"
    assert payload["recovery_hint"]

    # 权威降级三件套的形状与 degrade() 完全一致
    marker = degrade("mock", trace_id="trace-1")
    assert payload["degraded_to"] == marker.contract_value
    assert set(payload["degraded_state"]) == {"label", "since", "detail_ref"}


def test_every_internal_channel_maps_through_degrade() -> None:
    """内部通道 → 权威枚举 → degraded_state 三件套，逐个走一遍。"""

    from aiintel.core.degrade import degrade

    for channel in DEGRADED_VALUES:
        marker = degrade(channel, trace_id="trace-x")
        assert marker.contract_value
        assert marker.label
        assert marker.state()["detail_ref"] == "trace-x"
        assert marker.state()["since"]


def test_degrade_is_not_silent_when_trace_missing() -> None:
    """缺 trace_id 时用占位符而不是丢字段 —— 缺 detail_ref 才是缺陷。"""

    from aiintel.core.degrade import degrade

    assert degrade("rule").state()["detail_ref"] == "trace_unavailable"


def test_validate_contracts_script_passes() -> None:
    """`python -m scripts.validate_contracts` 必须全绿（CI 门禁）。"""

    from scripts.validate_contracts import (
        check_authoritative_frozen,
        check_fixtures,
        check_schemas,
    )

    assert check_schemas() == []
    assert check_authoritative_frozen() == []
    assert check_fixtures() == []
    assert validate(load_schema("IntelItem.json"), _load("intelitem.sample.json")) == []

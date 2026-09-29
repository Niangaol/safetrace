"""演示库富化数据的**内部一致性**测试。

## 为什么需要

`demo_seed.py::DIMENSIONS` 原本是按 CVE-2026-31001 一条写死的模板，套给全部 13 条漏洞，
产生了两类"一眼就能看出是复制粘贴"的矛盾：

1. `cvss.base_score` 恒为 **9.8**，而 13 条的向量各不相同（独立算出 3.3 ~ 10.0）；
   可核对的 11 条里 **8 条与自己的向量矛盾**。
2. `asset.products[].vendor` 恒为 `vllm`，而每条漏洞的 CPE 其实不同。

这类矛盾不需要领域专家就能判定 —— 同一个对象里"向量写着 AV:L/AC:L（本地低权限）
却报 9.8"是硬错误。本测试把它钉死：**演示数据也必须与自己的输入证据自洽**。

推导逻辑在 `scripts/demo_derive.py`（复用 `services/enrich` 的同一套计分口径）。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from scripts.demo_derive import derive  # noqa: E402

#: 真实种子数据里的代表性向量（覆盖不同分数档）
VECTORS = [
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
]


def _vuln(vector: str, cpe: list[str] | None = None) -> dict:
    return {
        "cve_id": "CVE-2026-00000",
        "cvss_vector": vector,
        "cvss_score": None,
        "cpe": cpe or [],
        "cwe": ["CWE-000"],
        "epss": 0.5,
        "kev": False,
        "fetched_at": None,
    }


def test_derived_score_matches_vector() -> None:
    """回归：推导出的 base_score 必须与向量一致，**不能**恒为 9.8。"""

    seen: set[float] = set()
    for vector, expect in VECTORS:
        cvss = derive("cvss", _vuln(vector))
        assert cvss is not None, f"未能推导 {vector}"
        got = cvss["value"]["base_score"]
        assert got == expect, f"{vector} 期望 {expect}，实得 {got}"
        seen.add(got)

    # 关键断言：不同向量必须产出不同分数
    # （原模板对全部 13 条都返回 9.8，这条会失败）
    assert len(seen) >= 6, f"不同向量只产出 {len(seen)} 个不同分数，说明仍是模板"


def test_severity_label_follows_score() -> None:
    """severity 标签必须由分数决定，不能写死 critical。"""

    expectations = {
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": "low",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": "medium",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": "high",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "critical",
    }
    for vector, want in expectations.items():
        got = derive("cvss", _vuln(vector))["value"]["severity"]
        assert got == want, f"{vector} 期望 {want}，实得 {got}"


def test_asset_vendor_comes_from_own_cpe() -> None:
    """回归：asset 的产品必须来自该条的 CPE，**不能**恒为 vllm。"""

    cases = [
        ("cpe:2.3:a:vllm:vllm:0.9.2:*:*:*:*:*:*:*", "vllm"),
        ("cpe:2.3:a:ollama:ollama:0.1.2:*:*:*:*:*:*:*", "ollama"),
        ("cpe:2.3:a:langchain:langchain:0.2.0:*:*:*:*:*:*:*", "langchain"),
        ("cpe:2.3:a:pytorch:pytorch:2.4.0:*:*:*:*:*:*:*", "pytorch"),
    ]
    vendors = set()
    for cpe, want in cases:
        asset = derive("asset", _vuln("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", [cpe]))
        assert asset is not None, f"未能解析 {cpe}"
        got = asset["value"]["products"][0]["vendor"]
        assert got == want, f"{cpe} 期望 vendor={want}，实得 {got}"
        vendors.add(got)
    assert len(vendors) == len(cases), "不同 CPE 必须给出不同 vendor（原模板恒为 vllm）"


def test_missing_inputs_abstain_instead_of_guessing() -> None:
    """没有向量 / 没有 CPE 时**不产出**，绝不编一个默认值。"""

    assert derive("cvss", _vuln("")) is None, "无向量时不该猜分数"
    assert derive("asset", _vuln("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", [])) is None, (
        "无 CPE 时不该猜产品"
    )


def test_unrelated_dimensions_are_not_derived() -> None:
    """只推导 cvss / asset；poc / paper 必须仍走模板（它们无法凭空推导）。"""

    for dim in ("poc", "paper", "fix", "consistency", "ai_risk"):
        assert derive(dim, _vuln("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) is None, (
            f'{dim} 不应被"推导"—— 那等于编造'
        )


def test_real_seed_vectors_all_derive_distinctly() -> None:
    """用真实的 13 条种子数据跑一遍：分数必须分布开，而不是全 9.8。"""

    from scripts.demo_seed import VULNS

    scores = []
    for spec in VULNS:
        cvss = derive("cvss", spec)
        if cvss is not None:
            scores.append(cvss["value"]["base_score"])

    assert len(scores) >= 10, f"只推导出 {len(scores)} 条，种子数据可能变了"
    distinct = len(set(scores))
    assert distinct >= 5, f"13 条只产出 {distinct} 个不同分数（{sorted(set(scores))}），仍是模板"
    # 不应全部等于 9.8（原模板的行为）
    assert set(scores) != {9.8}, "全部分数都是 9.8，说明推导没生效"


def test_derived_evidence_is_self_checkable() -> None:
    """推导出的证据必须写明"向量 → 分数"，让人能自行复核。"""

    cvss = derive("cvss", _vuln("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"))
    joined = " ".join(str(e.get("snippet") or "") for e in cvss["evidence"])
    assert "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" in joined
    assert "3.3" in joined

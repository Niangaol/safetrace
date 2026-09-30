"""规则抽取必须能拿到 CVE 编号（LLM 兜底路径的关键字段）。

## 修的 bug

`NvdCollector._to_item()` 把 CVE 编号放在 `external_id`
（`raw` 字典里**没有** `cve_id` 字段），而 `_rule_extract()` 原先只读
`raw.cve_id` / `item.cve_id` —— 两边不对接，于是**NVD 来源的条目 `cve_id` 恒为 None**。

为什么长期没暴露：正常路径走 **LLM 抽取**，LLM 会自己从正文里认出 CVE；
只有 LLM 不可用或输出被 `max_tokens` 截断时才落到规则路径。
而本机实测 LLM 抽取一直被截断（思维 token 占满 800、正文为空），
于是**所有真实 NVD 条目都丢了 CVE 编号** —— 证据链因此断在第一步。

## 反向要求

`external_id` 只在**形如 CVE 编号**时才采用。RSS / arXiv 的 external_id
是普通标识（`post-12345`、`2401.00001`），当成 CVE 会把脏数据写进底座（红线 4）。
"""

from __future__ import annotations

import pytest

from aiintel.services.ingest.pipeline import _rule_extract


def _nvd_item(external_id: str = "CVE-2024-28224") -> dict:
    """复刻 `NvdCollector._to_item()` 的真实形状（cve 只在 external_id）。"""

    return {
        "source": "nvd",
        "external_id": external_id,
        "title": "Ollama before 0.1.29 has a DNS rebinding vulnerability",
        "content_text": "Ollama before 0.1.29 has a DNS rebinding vulnerability.",
        "raw": {"cvss_score": 6.6, "severity": "medium", "cvss_vector": None},
    }


def test_nvd_external_id_is_used_as_cve() -> None:
    """**核心回归**：NVD 的 external_id 就是 CVE 编号，必须取到。"""

    assert _rule_extract(_nvd_item())["cve_id"] == "CVE-2024-28224"


def test_cve_priority_keeps_explicit_field() -> None:
    """`raw.cve_id` 存在时优先用它（显式字段比 external_id 更可信）。"""

    item = _nvd_item()
    item["raw"]["cve_id"] = "CVE-2020-1111"
    assert _rule_extract(item)["cve_id"] == "CVE-2020-1111"


def test_explicit_cve_field_beats_external_id() -> None:
    item = _nvd_item()
    item["cve_id"] = "CVE-2019-2222"
    assert _rule_extract(item)["cve_id"] == "CVE-2019-2222"


@pytest.mark.parametrize(
    "external_id",
    [
        "post-12345",  # 社区 RSS
        "2401.00001",  # arXiv
        "GHSA-7f3q-vllm-rce",  # GHSA 不是 CVE（另有字段承载）
        "CVE-2024-1234-extra",  # 形似但不是合法编号
        "",  # 空
        "not-a-cve",
    ],
)
def test_non_cve_external_id_is_not_used_as_cve(external_id: str) -> None:
    """**反向红线**：非 CVE 形状的 external_id 绝不能当 CVE 写进底座。"""

    item = _nvd_item(external_id)
    assert _rule_extract(item)["cve_id"] is None, external_id


def test_other_fields_still_extracted() -> None:
    """补 external_id 兜底不能影响其它字段的抽取。"""

    out = _rule_extract(_nvd_item())
    assert out["severity"] == "medium"
    assert "ollama" in out["affected_products"]
    assert out["impact"].startswith("Ollama")

"""钉住"富化结论能不能被检索到"这条链路 —— 修了 6 处缺陷，全部不能回退。

## 背景

验证"富化到底有没有被问答用上"时，发现这条链路**同时**在写入侧和读取侧出问题，
而且全是静默的（不报错、只是结论检不到）。逐条钉住：

| # | 缺陷 | 后果 |
| --- | --- | --- |
| 1 | 富化切片正文**不含 CVE 编号** | 按编号提问检不到该漏洞的富化结论 |
| 2 | `vuln` 切片正文也不含编号 | 按编号提问检不到该漏洞自己 |
| 3 | `index_owner` 逐次"先删后写"，富化循环每维调一次 | 7 维只剩 1 维 |
| 4 | `(owner_type, owner_id)` 被拆成两个 `.in_()` | 笛卡尔放宽、跨 owner 串数据 |
| 5 | `_prefer_enriched` 只提升"已富化漏洞的 **vuln** 切片" | **结论**排在漏洞简介后面 |
| 6 | 一个 owner 多条切片占满 `top_k`；且"只有身份"的空壳切片进入检索空间 | 结论排不进来 / 噪音挤掉结论 |
"""

from __future__ import annotations

import pytest

from aiintel.services.knowledge.indexer import enrichment_chunk_text
from aiintel.services.knowledge.retrieval import (
    _converge_by_owner,
    _prefer_enriched,
    parse_doc_key,
)

# ---------------------------------------------------------------- ① 身份必须进正文

FIX_VALUE = {
    "upgrade": {"target_version": "0.9.3"},
    "immediate": [{"action": "在反向代理层校验 chat_template", "rationale": "模板注入"}],
}


def test_enrichment_text_carries_identity() -> None:
    """富化切片正文必须含漏洞编号，否则按编号提问检不到它。"""

    out = enrichment_chunk_text("fix", FIX_VALUE, [], identity="CVE-2026-31001")
    assert "CVE-2026-31001" in out, "编号必须进正文（否则关键词召回匹配不上）"
    assert out.index("CVE-2026-31001") < 20, "编号应在**段首**：切片有长度上限，放末尾会被截掉"
    assert "修复建议" in out, "结论本体也必须在"


def test_enrichment_text_without_identity_still_works() -> None:
    """不传 identity 时行为不变（向后兼容）。"""

    out = enrichment_chunk_text("fix", FIX_VALUE, [])
    assert "修复建议" in out
    assert "CVE-" not in out


# ---------------------------------------------------------------- ⑥ 空壳切片必须被拦掉


def test_identity_only_chunk_is_dropped() -> None:
    """**只有身份、没有正文**的切片不能建 —— 它对任何查询都像弱匹配，会挤掉真结论。

    实测来源：`asset` 维度的 `products` 为空（`degraded_to=mock`）时，
    切片只剩编号（14 字），却在 RRF 里排到 `fix` 结论前面。
    """

    assert enrichment_chunk_text("asset", {"products": []}, [], identity="CVE-2026-31001") == ""
    assert enrichment_chunk_text("unknown_dim", {"x": 1}, [], identity="CVE-2026-31001") == ""
    # 对照：有实际内容时不能误杀
    assert enrichment_chunk_text("asset", {"exposure_level": "high"}, [], identity="CVE-1")


def test_empty_value_returns_empty() -> None:
    """值为空时返回空串（调用方据此跳过建切片）。"""

    assert enrichment_chunk_text("fix", {}, [], identity="CVE-2026-31001") == ""
    assert enrichment_chunk_text("poc", {"pocs": []}, [], identity="CVE-2026-31001") == ""


# ---------------------------------------------------------------- ⑤ 结论优先于漏洞简介


class _FakeResult:
    def __init__(self, rows: list[tuple[str]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str]]:
        return self._rows


class _FakeSession:
    """只应答 `_prefer_enriched` 的那条 SQL（按 cve_id 查有哪些漏洞有富化）。"""

    def __init__(self, enriched: set[str]) -> None:
        self.enriched = enriched

    def execute(self, _stmt: object) -> _FakeResult:
        return _FakeResult([(c,) for c in sorted(self.enriched)])


def test_conclusion_ranks_before_vuln_summary() -> None:
    """**核心回归**：`enrichment` 结论必须排在"已富化漏洞的 `vuln` 简介"之前。

    早期实现只提升了后者，导致问"怎么修复"时 6 条引用**全是漏洞简介、
    没有一条修复结论**。
    """

    docs = [
        "vuln::CVE-2026-31001::0",
        "vuln::CVE-2026-28114::0",
        "enrichment::CVE-2026-31001::4",
        "enrichment::CVE-2026-28114::4",
        "vuln::CVE-2026-99999::0",
    ]
    out = _prefer_enriched(_FakeSession({"CVE-2026-31001", "CVE-2026-28114"}), docs)
    assert out[0].startswith("enrichment::"), f"结论应排第一，实得 {out[0]}"
    assert out[1].startswith("enrichment::"), f"结论应排第二，实得 {out[1]}"
    # 未富化的漏洞排最后
    assert out[-1] == "vuln::CVE-2026-99999::0"


def test_prefer_enriched_keeps_original_order_within_group() -> None:
    """分区是**稳定**的：各组内部相对顺序不变（不重排相关性）。"""

    docs = [
        "enrichment::CVE-A::0",
        "enrichment::CVE-B::0",
        "enrichment::CVE-C::0",
    ]
    out = _prefer_enriched(_FakeSession(set()), docs)
    assert out == docs


def test_prefer_enriched_survives_query_failure() -> None:
    """偏好计算失败时保持原序，**不清空结果**（过滤器不能变成"把功能关掉"）。"""

    class _Boom:
        def execute(self, _stmt: object) -> None:
            raise RuntimeError("boom")

    docs = ["vuln::CVE-1::0", "enrichment::CVE-1::0"]
    assert _prefer_enriched(_Boom(), docs) == docs


# ---------------------------------------------------------------- ⑥ 每个 owner 只占一个名额


def test_converge_by_owner_keeps_first_per_owner() -> None:
    """一个 owner 几十条切片时，只保留排名最前的那条。"""

    docs = [
        "vuln::CVE-A::0",
        "vuln::CVE-A::1",
        "vuln::CVE-A::2",
        "vuln::CVE-B::0",
        "enrichment::CVE-A::4",
    ]
    out = _converge_by_owner(docs)
    assert out == ["vuln::CVE-A::0", "vuln::CVE-B::0", "enrichment::CVE-A::4"]


def test_converge_allows_multiple_dimensions_when_asked() -> None:
    """`per_owner>1` 时保留多条（留给"同一漏洞多看几个维度"的场景）。"""

    docs = ["enrichment::CVE-A::0", "enrichment::CVE-A::1", "enrichment::CVE-A::2"]
    assert _converge_by_owner(docs, per_owner=2) == docs[:2]


def test_doc_key_roundtrip() -> None:
    """`parse_doc_key` 与切片键格式必须一致（否则组合键匹配会静默失效）。"""

    assert parse_doc_key("vuln::CVE-2026-31001::0") == ("vuln", "CVE-2026-31001", "0")
    assert parse_doc_key("enrichment::arxiv-2609.01234::3") == (
        "enrichment",
        "arxiv-2609.01234",
        "3",
    )


@pytest.mark.parametrize(
    "bad",
    ["vuln", "vuln::CVE-1", ""],
)
def test_parse_doc_key_tolerates_malformed(bad: str) -> None:
    """畸形键不能让检索崩（宁可跳过一条，不可整轮失败）。"""

    key = parse_doc_key(bad)
    assert isinstance(key, tuple) and len(key) == 3

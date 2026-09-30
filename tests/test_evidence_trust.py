"""证据信任级（`trust`）与出处时间（`published_at`）。

## 背景：上游契约把这两个字段变成了可选新字段

上游 `contracts/schemas/RetrievalResponse.json` 在 v1.1.1 给 `chunk` 追加了
可选 `published_at`（date-time）与 `trust`（`trusted`/`untrusted`），
本仓已同步该契约（见 `FROZEN_MANIFEST.json`）。用途是让问答能告诉用户
**这条证据是否权威、是否过时**。

契约对缺省的措辞很硬：「缺省 = 未知，调用方必须按未知处理，**不得假定新鲜**」
「缺省 = 未知，**不得当作 trusted 使用**」。所以本测试的重点不只是"能填上"，
更是**推导不出来时必须留空**，不能乐观地给一个值。

分级口径与上游 `sourceTrust()` 一致（见 `services/knowledge/trust.py` 的注释）。
"""

from __future__ import annotations

import pytest

from aiintel.services.knowledge.trust import (
    UNTRUSTED_SOURCES,
    combine_trust,
    source_trust,
)


@pytest.mark.parametrize(
    "source",
    ["nvd", "cve_org", "ghsa", "osv", "kev", "arxiv", "computed", "rule"],
)
def test_authoritative_sources_are_trusted(source: str) -> None:
    """上游 `sourceTrust()` 判 trusted 的来源，翻译到本仓命名后也必须 trusted。"""

    assert source_trust(source) == "trusted"


@pytest.mark.parametrize(
    "source",
    ["community_rss", "vendor_advisory", "security_blog", "poec_source", "github_search"],
)
def test_external_text_sources_are_untrusted(source: str) -> None:
    """网页/文档类外部文本按 untrusted（标准正文也算外部可控文本）。"""

    assert source_trust(source) == "untrusted"


def test_unknown_source_is_none_not_untrusted() -> None:
    """**核心**：认不出的来源必须返回 None（未知）。

    契约把"缺省"定义为未知。把它硬说成 `untrusted` 同样失真 ——
    会无端降低证据可信度；说成 `trusted` 更糟，等于凭空提高可信度。
    """

    assert source_trust("some_new_source_we_never_saw") is None
    assert source_trust("") is None
    assert source_trust(None) is None


def test_trusted_wins_when_sources_are_mixed() -> None:
    """多来源合成：**有一个权威源即 trusted**（权威记录已确认该条目）。"""

    assert combine_trust(["nvd", "community_rss"]) == "trusted"
    assert combine_trust(["ghsa", "vendor_advisory"]) == "trusted"


def test_all_untrusted_sources_give_untrusted() -> None:
    assert combine_trust(["community_rss", "vendor_advisory"]) == "untrusted"


def test_no_recognisable_source_gives_none() -> None:
    """全部认不出 → None，不猜。"""

    assert combine_trust(["mystery_a", "mystery_b"]) is None
    assert combine_trust([]) is None
    assert combine_trust(None) is None


def test_taxonomy_is_disjoint() -> None:
    """两级分类不得重叠（否则 `source_trust` 的结果取决于判断顺序）。"""

    overlap = UNTRUSTED_SOURCES & {"nvd", "kev", "ghsa", "arxiv", "osv", "cve_org"}
    assert not overlap, f"同一来源被同时归入两级: {overlap}"


def test_citation_projection_omits_unknown_fields() -> None:
    """引用投影：**缺省字段不得出现**（不能塞 None/空串冒充"已评估"）。"""

    from aiintel.services.qa.agent import _project_citation

    # 已知 trust + published_at → 带上
    full = _project_citation(
        {
            "id": "S1",
            "url": "https://x",
            "trust": "trusted",
            "published_at": "2026-09-28T07:00:00+00:00",
        }
    )
    assert full["trust"] == "trusted"
    assert full["published_at"].startswith("2026-09-28")

    # 未知 → 键**不出现**（而不是 None）
    bare = _project_citation({"id": "S2", "url": ""})
    assert "trust" not in bare, "未知 trust 不能出现该键（契约：缺省=未知）"
    assert "published_at" not in bare, "未知 published_at 不能出现该键"
    assert bare == {"chunk_id": "S2", "url": ""}

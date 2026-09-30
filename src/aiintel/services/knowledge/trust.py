"""证据信任级（`trust`）—— 与上游 `sourceTrust(sourceType)` **同一套口径**。

## 为什么需要

上游契约 `RetrievalResponse.chunk` 在 v1.1.1 追加了可选字段 `trust`
（`trusted` / `untrusted`），语义是：**证据是可信到什么程度的**。

- `trusted`  = 结构化权威源 API 直读（NVD / KEV / CVE.org / OSV / GHSA / arXiv）
              或本系统由其派生；
- `untrusted` = 网页/文档类外部文本（厂商公告页、安全社区、博客、PoC）。

**缺省 = 未知**，契约明确要求「不得当作 trusted 使用」。所以本模块对认不出的来源
返回 `None`（未知），而不是乐观地给 `trusted` —— 那等于凭空提高证据可信度。

## 口径来源

逐条对齐 `upstream/main:src/ingest/src/evidence-chunks.ts::sourceTrust()`。
上游的 `nvd_cve` 在本仓叫 `nvd`，`paper` 在本仓是采集源 `arxiv`；两者都是 trusted。
"""

from __future__ import annotations

#: 上游 `sourceTrust()` 判为 trusted 的来源（已按本仓命名翻译）。
#: 注意不要再加"看起来权威"的来源：这份表就是与团队对齐的**唯一定义**。
TRUSTED_SOURCES: frozenset[str] = frozenset(
    {
        "nvd",  # 上游 nvd_cve
        "cve_org",
        "ghsa",
        "osv",
        "kev",
        "arxiv",  # 上游 paper
        "paper",
        # 本系统由权威源派生的结论（与上游「或本系统由其派生」一致）
        "computed",
        "rule",
    }
)

#: 明确判为 untrusted 的外部文本类来源（上游 default 分支，这里显式列出便于审计）。
UNTRUSTED_SOURCES: frozenset[str] = frozenset(
    {
        "community_rss",  # 上游 security_community
        "vendor_advisory",  # 厂商公告页：标准正文仍是外部可控文本
        "security_blog",
        "poec_source",
        "github_search",  # PoC 仓库检索
        "web",
    }
)


def source_trust(source: str | None) -> str | None:
    """单个来源 → `trusted` / `untrusted`；**认不出返回 None（未知）**。

    认不出时返回 None 而不是 `untrusted`：契约把"缺省"定义为未知，
    把未知硬说成 untrusted 同样是一种失真（会无端降低证据可信度）。
    """

    if not source:
        return None
    key = str(source).strip().lower()
    if key in TRUSTED_SOURCES:
        return "trusted"
    if key in UNTRUSTED_SOURCES:
        return "untrusted"
    return None


def combine_trust(sources: list[str] | tuple[str, ...] | None) -> str | None:
    """多个来源合成一个信任级：**只要有一个权威源即 trusted**。

    依据：权威源一旦给出该条目，证据链就建立在可核对的权威记录上；
    社区转载只影响"增量信息"的可信度，不降低已确认部分。
    全部来源都认不出时返回 None（未知），不猜。
    """

    if not sources:
        return None
    levels = [source_trust(s) for s in sources]
    if "trusted" in levels:
        return "trusted"
    if "untrusted" in levels:
        return "untrusted"
    return None

"""去重与跨源合并：SimHash 近似、来源可信度覆盖。"""

from __future__ import annotations

from aiintel.services.ingest.dedup import (
    SIMHASH_MAX_DISTANCE,
    SOURCE_TRUST,
    hamming,
    merge_items,
    simhash,
)


def _item(item_id: str, **kw) -> dict:
    base = {
        "id": item_id,
        "source": "nvd",
        "cve_id": "CVE-2026-0001",
        "title": "vLLM remote code execution",
        "content_text": "A vulnerability in vllm allows remote attackers to execute code.",
        "content_hash": "",
    }
    base.update(kw)
    base["content_hash"] = base.get("content_hash") or item_id
    return base


def test_simhash_is_deterministic():
    a = simhash("CVE-2026-0001 vLLM remote code execution in inference server")
    b = simhash("CVE-2026-0001 vLLM remote code execution in inference server")
    assert a == b


def test_simhash_similar_texts_are_close():
    a = simhash(
        "A vulnerability in vllm allows remote attackers to execute arbitrary code "
        "via the tokenizer API endpoint and gain full server access"
    )
    b = simhash(
        "A vulnerability in vllm allows remote attackers to execute arbitrary code "
        "via the tokenizer API endpoint"
    )
    assert hamming(a, b) <= SIMHASH_MAX_DISTANCE


def test_simhash_unrelated_texts_are_far():
    a = simhash("CVE-2025-1111 missing auth in kubernetes dashboard")
    b = simhash("CVE-2026-2222 RCE in pytorch serve")
    assert hamming(a, b) > SIMHASH_MAX_DISTANCE


def test_simhash_empty_text():
    assert simhash("") == 0


def test_exact_duplicate_collapsed_by_content_hash():
    items = [
        _item("r1", content_hash="same"),
        _item("r2", content_hash="same"),
    ]
    merged = merge_items(items)
    assert len(merged) == 1


def test_cross_source_same_cve_merged():
    """同一 CVE 的不同源条目：正文不同 → 走 cve_id 事件级合并。"""

    items = [
        _item(
            "r1", source="nvd", cve_id="CVE-2026-0001", content_text="NVD 官方描述：远程代码执行。"
        ),
        _item(
            "r2",
            source="ghsa",
            cve_id="CVE-2026-0001",
            ghsa_id="GHSA-aaaa-bbbb-cccc",
            content_text="GHSA 描述：the tokenizer endpoint allows remote attackers to run code",
        ),
    ]
    merged = merge_items(items)
    assert len(merged) == 1
    assert merged[0]["merge_type"] == "cross_source"
    assert merged[0]["source_count"] == 2
    assert merged[0]["source"] == "nvd"  # 可信度更高


def test_nvd_wins_field_conflict():
    """GHSA 先到也不能压过 NVD 的分数。"""

    items = [
        _item(
            "r1",
            source="ghsa",
            cve_id="CVE-2026-0002",
            cvss_score=5.0,
            content_text="GHSA 侧描述：影响较弱的越权问题",
        ),
        _item(
            "r2",
            source="nvd",
            cve_id="CVE-2026-0002",
            cvss_score=9.8,
            content_text="NVD 侧描述：critical remote code execution in the server",
        ),
    ]
    merged = merge_items(items)
    assert len(merged) == 1
    assert merged[0]["cvss_score"] == 9.8
    assert merged[0]["source"] == "nvd"


def test_longer_content_text_wins():
    short = _item("r1", cve_id="CVE-2026-0003", content_text="short")
    long = _item(
        "r2", cve_id="CVE-2026-0003", content_text="a much longer description of the issue " * 20
    )
    merged = merge_items([short, long])
    assert len(merged[0]["content_text"]) > len("short")


def test_trust_order_respected():
    assert SOURCE_TRUST["nvd"] > SOURCE_TRUST["ghsa"] > SOURCE_TRUST["community_rss"]
    assert SOURCE_TRUST["community_rss"] > SOURCE_TRUST["arxiv"]


def test_distinct_vulns_not_merged():
    a = _item(
        "r1",
        cve_id="CVE-2026-1000",
        title="vLLM remote code execution",
        content_text="vllm inference server remote code execution vulnerability detail",
    )
    b = _item(
        "r2",
        cve_id="CVE-2026-2000",
        title="LangChain path traversal in file loader",
        content_text="path traversal in langchain file loader allows reading arbitrary files",
    )
    merged = merge_items([a, b])
    assert len(merged) == 2


def test_item_without_cve_key_is_kept():
    a = _item(
        "r1", cve_id=None, title="blog post about AI security", content_text="random thoughts"
    )
    b = _item("r2", cve_id=None, title="another blog about LLM safety", content_text="other random")
    merged = merge_items([a, b])
    assert len(merged) >= 1


def test_empty_input():
    assert merge_items([]) == []


def test_merge_is_idempotent():
    items = [
        _item("r1", source="nvd", cve_id="CVE-2026-0007"),
        _item("r2", source="ghsa", cve_id="CVE-2026-0007"),
    ]
    once = merge_items(items)
    twice = merge_items(once)
    assert len(once) == len(twice) == 1

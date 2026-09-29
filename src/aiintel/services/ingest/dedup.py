"""去重与跨源事件合并。

- 精确：正文归一化后的 content_hash
- 近似：SimHash 64 位 + 汉明距离阈值
- 合并：同一 cve_id/ghsa_id 的多条 raw 合并为一个事件，字段按来源可信度覆盖
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

SIMHASH_BITS = 64
# 实测：同源/近似情报汉明距离 0~11，无关情报 31~35。阈值取 12 兼顾召回与准确率。
SIMHASH_MAX_DISTANCE = 12
# 同一漏洞多源冲突时的字段优先级（越大越可信）
# KEV 给 120：它是 CISA 官方目录，是"是否在野利用 / 强制修复期限"的**唯一权威来源**，
# 高于 NVD（100）——NVD 侧的 cisaExploitAdd 只是二手镜像，覆盖不全（见 collectors/nvd.py:52）。
# 注意它仍只影响下面 (cvss/severity/cwe/cpe) 那组字段的覆盖；kev/epss/kev_due_date
# 走各自的累积语义（并集 / 取大 / 取最早），不看 SOURCE_TRUST。
SOURCE_TRUST: dict[str, int] = {
    "kev": 120,
    "nvd": 100,
    "ghsa": 90,
    "community_rss": 40,
    "arxiv": 30,
}


def simhash(text: str) -> int:
    """经典 SimHash：token 化 → 64 位加权累加 → 符号位取指纹。"""

    import hashlib
    import re

    tokens = re.findall(r"[a-z0-9]+|[\u4e00-\u9fff]", (text or "").lower())
    if not tokens:
        return 0
    vector = [0] * SIMHASH_BITS
    for token in tokens:
        digest = int.from_bytes(hashlib.md5(token.encode()).digest()[:8], "big")
        for i in range(SIMHASH_BITS):
            vector[i] += 1 if (digest >> i) & 1 else -1
    fingerprint = 0
    for i in range(SIMHASH_BITS):
        if vector[i] > 0:
            fingerprint |= 1 << i
    return fingerprint


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _key(item: dict) -> str | None:
    raw = item.get("raw") or {}
    return (
        raw.get("cve_id")
        or item.get("cve_id")
        or (item.get("ghsa_id") if item.get("ghsa_id") else None)
    )


def _merge_fields(primary: dict, other: dict) -> None:
    """按来源可信度合并。

    权威字段（CVSS/严重性/CWE/CPE）冲突时，**高可信源直接覆盖**低可信源
    ——NVD 的分数比 GHSA 的权威，不能因为 GHSA 先到就保留错的值。
    描述类字段则是"长的/先有的更优"，只补空。
    """

    other_trust = SOURCE_TRUST.get(other.get("source", ""), 0)
    primary_trust = SOURCE_TRUST.get(primary.get("source", ""), 0)

    for field in ("cvss_vector", "cvss_score", "severity", "cwe", "cpe"):
        value = other.get(field) or (other.get("raw") or {}).get(field)
        if not value:
            continue
        if primary.get(field) in (None, "", []) or other_trust > primary_trust:
            primary[field] = value

    # KEV 是"或"语义：任一源说在野利用就是已利用（漏报比误报贵），
    # 所以不像上面那样让高可信源覆盖，而是取并集。
    if other.get("kev") and not primary.get("kev"):
        primary["kev"] = True
    # EPSS 取**更大值**：被利用概率是风险信号，宁可高估也不能因为来源顺序丢掉
    # （来源顺序取决于抓取先后，不该影响风险判断）。
    other_epss, primary_epss = other.get("epss"), primary.get("epss")
    if isinstance(other_epss, (int, float)) and (
        not isinstance(primary_epss, (int, float)) or float(other_epss) > float(primary_epss)
    ):
        primary["epss"] = other_epss

    # KEV 强制修复截止日：只从 KEV 官方源取（其他源没有这个字段）。
    # 同样取**最早**的截止日 —— 多个来源给不同期限时，最紧的那个才是约束。
    # 没有就不写：保持 None 表示"未知"，不要用宽松值覆盖已有的紧期限。
    other_due = other.get("kev_due_date") or (other.get("raw") or {}).get("kev_due_date")
    primary_due = primary.get("kev_due_date")
    if other_due and (not primary_due or str(other_due) < str(primary_due)):
        primary["kev_due_date"] = other_due

    for field in ("cve_id", "ghsa_id", "title", "description", "summary"):
        if not primary.get(field) and other.get(field):
            primary[field] = other[field]
    if len(other.get("content_text") or "") > len(primary.get("content_text") or ""):
        primary["content_text"] = other["content_text"]
    if len(other.get("title") or "") > len(primary.get("title") or ""):
        primary["title"] = other["title"]


def merge_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把同一漏洞的多源条目合并，返回带 merge_type 的事件列表。"""

    exact: dict[str, dict] = {}
    for item in items:
        item.setdefault("content_hash", "")
        item["simhash"] = simhash(f"{item.get('title', '')}{item.get('content_text', '')[:2000]}")
        exact.setdefault(item["content_hash"], item)

    fingerprints: list[tuple[int, dict]] = []
    for item in exact.values():
        for existing_fp, existing in fingerprints:
            if hamming(existing_fp, item["simhash"]) <= SIMHASH_MAX_DISTANCE:
                _merge_fields(existing, item)
                existing.setdefault("merged_raw_ids", []).append(item["id"])
                existing["merge_type"] = "simhash"
                break
        else:
            fingerprints.append((item["simhash"], item))

    # 按漏洞标识做事件级合并
    by_vuln: dict[str, dict] = {}
    for _, item in fingerprints:
        key = _key(item)
        if not key:
            continue
        winner = by_vuln.get(key)
        if winner is None:
            by_vuln[key] = item
            continue
        loser = item
        if SOURCE_TRUST.get(loser.get("source", ""), 0) > SOURCE_TRUST.get(
            winner.get("source", ""), 0
        ):
            by_vuln[key] = loser
            winner, loser = loser, winner
        _merge_fields(winner, loser)
        winner.setdefault("merged_raw_ids", []).append(loser["id"])
        winner["source_count"] = len(winner.get("merged_raw_ids", [])) + 1
        winner["merge_type"] = "cross_source"

    for key, item in by_vuln.items():
        item.setdefault("cve_id", key if key.startswith("CVE-") else None)
        item.setdefault("merge_type", "cross_source")
        item.setdefault("source_count", len(item.get("merged_raw_ids", [])) + 1)

    merged = [*by_vuln.values(), *[it for _, it in fingerprints if not _key(it)]]
    ratio = 1 - len(merged) / max(len(items), 1)
    logger.info("去重：%d → %d（合并率 %.1f%%）", len(items), len(merged), ratio * 100)
    return merged

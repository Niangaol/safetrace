"""NVD / CVE JSON 解析（F4 的数据入口）。

解析的是 **NVD CVE API 2.0** 的单条 CVE 结构（`raw_item.raw_json` 里存的就是它）。
只用标准库解析，不发请求——取数归 Y 线采集，F 线只做解析与判读（分工边界）。

产出是"尽量取到、取不到就留空"的字段集合，**绝不猜测**：
拿不到向量就 `cvss_vector=None`，拿不到分数就 `score_source="unavailable"`。
"""

from __future__ import annotations

from typing import Any

from aiintel.services.enrich.cvss import resolve_score, severity_label, vector_version

# NVD 参考链接的标签 → 本项目的参考文献分类
_TAG_KIND = {
    "patch": "patch",
    "vendor advisory": "advisory",
    "third party advisory": "advisory",
    "advisory": "advisory",
    "exploit": "exploit",
    "release notes": "patch",
    "mitigation": "advisory",
    "us government resource": "advisory",
}


def _first_description(cve: dict[str, Any]) -> tuple[str, str]:
    """优先英文描述（LLM 判定最稳），没有英文再用第一条。返回 (文本, 语言)。"""

    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if (item.get("lang") or "").lower().startswith("en"):
            return str(item.get("value") or ""), "en"
    if descriptions:
        return str(descriptions[0].get("value") or ""), str(descriptions[0].get("lang") or "")
    return "", ""


def _metric_block(metrics: dict[str, Any], key: str) -> dict[str, Any]:
    entries = metrics.get(key) or []
    for entry in entries:
        if (entry.get("type") or "").lower() == "primary":
            return entry
    return entries[0] if entries else {}


def extract_metrics(cve: dict[str, Any]) -> dict[str, Any]:
    """抽取 CVSS 3.1 / 4.0 与 EPSS/KEV 相关字段。"""

    metrics = cve.get("metrics") or {}
    block31 = _metric_block(metrics, "cvssMetricV31")
    block40 = _metric_block(metrics, "cvssMetricV40")
    data31 = block31.get("cvssData") or {}
    data40 = block40.get("cvssData") or {}

    vector = data31.get("vectorString") or data40.get("vectorString")
    official = data31.get("baseScore")
    if official is None:
        official = data40.get("baseScore")

    out: dict[str, Any] = {
        "cvss_vector": vector,
        "cvss_version": data31.get("version") or data40.get("version") or vector_version(vector),
        "official_score": float(official) if official is not None else None,
        "official_severity": (
            data31.get("baseSeverity") or data40.get("baseSeverity") or ""
        ).lower()
        or None,
        "vector_31": data31.get("vectorString"),
        "score_31": float(data31["baseScore"]) if data31.get("baseScore") is not None else None,
        "vector_40": data40.get("vectorString"),
        "score_40": float(data40["baseScore"]) if data40.get("baseScore") is not None else None,
    }

    # EPSS / KEV：NVD 2.0 有时放在 cve 顶层（cisaExploitAdd / cisaVulnerabilityName）
    kev = bool(cve.get("cisaExploitAdd") or cve.get("kev"))
    out["kev"] = kev
    epss = cve.get("epss")
    if isinstance(epss, list) and epss:
        epss = epss[0].get("epss") if isinstance(epss[0], dict) else None
    out["epss"] = float(epss) if isinstance(epss, (int, float)) else None
    return out


def extract_cwe(cve: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "").strip()
            if value.upper().startswith("CWE-") and value not in found:
                found.append(value.upper())
    return found


def extract_cpe(cve: dict[str, Any]) -> list[str]:
    """从 configurations 里取 vulnerable=true 的 CPE，并保留版本区间。"""

    out: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria")
                if criteria and criteria not in out:
                    out.append(str(criteria))
    return out


def extract_version_ranges(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """把 CPE 的 versionStart/End 转成结构化版本区间（F2/F5 的输入）。"""

    ranges: list[dict[str, Any]] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria") or "").split(":")
                product = parts[4] if len(parts) > 4 else ""
                introduced = match.get("versionStartIncluding") or match.get(
                    "versionStartExcluding"
                )
                fixed = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                if not (introduced or fixed):
                    continue
                ranges.append(
                    {
                        "product": product,
                        "introduced": introduced,
                        "fixed": fixed,
                        "source": "nvd",
                        "url": None,
                    }
                )
    return ranges


def extract_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """参考链接 + 分类（`patch` / `advisory` / `exploit` / `other`）。

    F5 修复建议的关键输入：只有 `patch` / `advisory` 才可能给出修复版本。
    """

    refs: list[dict[str, Any]] = []
    for ref in cve.get("references") or []:
        url = ref.get("url")
        if not url:
            continue
        kind = "other"
        for tag in ref.get("tags") or []:
            mapped = _TAG_KIND.get(str(tag).strip().lower())
            if mapped:
                kind = mapped
                break
        refs.append({"url": url, "kind": kind, "provider": ref.get("source"), "title": None})
    return refs


def cve_body(payload: Any) -> dict[str, Any]:
    """从各种包装里取出 **NVD CVE 主体**。

    实测存在的三种形态（都被真实数据用到，所以一个都不能漏）：

    1. `{"cve": {...}}` —— NVD 2.0 响应体（`raw_item.raw_json` 里存的就是它）；
    2. `{...descriptions/metrics...}` —— 裸 CVE 主体；
    3. `{"id": "CVE-...", ...}` —— 精简形态（字段可能不全）。

    取不到就返回 `{}`，让调用方按"缺字段"处理，而不是抛异常。
    `normalize_item` 与 `parse_nvd` 共用本函数，避免两处各写一套解包逻辑。
    """

    if not isinstance(payload, dict):
        return {}
    nested = payload.get("cve")
    if isinstance(nested, dict):
        return nested
    if "descriptions" in payload or "metrics" in payload or "id" in payload:
        return payload
    # CISA KEV 官方目录的条目（services/collectors/kev.py）：字段名与 NVD 完全不同
    # （cveID / dueDate / dateAdded...），既没有 id 也没有 descriptions/metrics。
    # 不认它的话，KEV 源抽出来的 kev / kev_due_date 会被 cve_body 判成"无主体"而全丢。
    if any(key.startswith("kev_") for key in payload):
        return payload
    return {}


def _plain_cve_json(vuln: dict[str, Any]) -> dict[str, Any]:
    """从 IntelItem / vuln 字典里找一份 NVD CVE JSON。"""

    return cve_body(vuln.get("raw_json") or vuln.get("raw") or {})


def parse_nvd(vuln: dict[str, Any]) -> dict[str, Any]:
    """解析可用的 NVD 信息；字段缺失即留空/None，由调用方决定降级方式。"""

    cve = _plain_cve_json(vuln)
    cve_id = vuln.get("cve_id") or cve.get("id")
    metrics = extract_metrics(cve) if cve else {}

    vector = metrics.get("cvss_vector") or vuln.get("cvss_vector")
    official = metrics.get("official_score")
    if official is None and vuln.get("cvss_score") is not None:
        official = float(vuln["cvss_score"])
    score, score_source = resolve_score(vector, official)

    description, description_lang = _first_description(cve) if cve else ("", "")
    if not description:
        description = str(vuln.get("description") or "")
        description_lang = "item"

    return {
        "cve_id": cve_id,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        "description": description,
        "description_lang": description_lang,
        "cvss_vector": vector,
        "cvss_version": metrics.get("cvss_version") or vector_version(vector),
        "official_score": official,
        "official_severity": metrics.get("official_severity"),
        "vector_31": metrics.get("vector_31"),
        "score_31": metrics.get("score_31"),
        "vector_40": metrics.get("vector_40"),
        "score_40": metrics.get("score_40"),
        "base_score": score,
        "score_source": score_source,
        "severity": severity_label(score),
        "epss": metrics.get("epss") if metrics.get("epss") is not None else vuln.get("epss"),
        "kev": bool(metrics.get("kev") or vuln.get("kev") or vuln.get("cisaExploitAdd")),
        "cwe": extract_cwe(cve) or list(vuln.get("cwe") or []),
        "cpe": extract_cpe(cve) or list(vuln.get("cpe") or []),
        "version_ranges": extract_version_ranges(cve) or list(vuln.get("version_ranges") or []),
        "references": extract_references(cve) or list(vuln.get("references") or []),
        "published": cve.get("published") or vuln.get("published_at"),
        "last_modified": cve.get("lastModified") or vuln.get("modified_at"),
    }

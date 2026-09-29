"""F5 修复建议生成（`fix`）：分级方案 + **版本号必须可溯源**。

本轮实现口径（诚实标注，不装成"已接 LLM"）：

- **规则版真跑**：参考文献分类、修复版本抽取、补丁链接整理全部确定性；
- **通用建议是模板**：`hardening` / `detection` 两个段落由模板 + 受影响产品名生成，
  在 `value.mock=true` 与 `degraded_reason` 里显式说明，报告「已知限制」也要写。

硬规则（写进测试）：**升版本号只能来自公告原文**。凡是 LLM（未来接入时）或模板里
出现的版本号，若在参考文献文本里找不到，一律丢弃并置 `version_confidence="unknown"`。
宁可说"未找到官方补丁"，也不给一个看起来很专业的错误版本号。
"""

from __future__ import annotations

import logging
import re
from typing import Any

from aiintel.services.enrich.evidence import EvidenceBuilder, build_result

logger = logging.getLogger(__name__)

# 从公告文本里捞版本号：v0.6.2 / 0.6.2 / 1.2.3-rc1
_VERSION_RE = re.compile(r"\b(?:v)?(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)?)\b")

_FIXED_HINT = re.compile(r"fixed|fix(?:ed)? in|patch(?:ed)? in|upgrade to|修复|升级到|请升级", re.I)

ADVISORY_HINT = re.compile(r"advisory|security|ghsa|cve-|cnvd|公告|通告", re.I)
PATCH_HINT = re.compile(r"patch|pull|commit|release|changelog|补丁|提交", re.I)


def classify_reference(ref: dict[str, Any]) -> str:
    """参考文献分类：patch / advisory / exploit / other。"""

    kind = str(ref.get("kind") or "").lower()
    if kind in {"patch", "advisory", "exploit"}:
        return kind
    haystack = f"{ref.get('url') or ''} {ref.get('title') or ''} {ref.get('provider') or ''}"
    if PATCH_HINT.search(haystack):
        return "patch"
    if ADVISORY_HINT.search(haystack):
        return "advisory"
    return "other"


def known_versions(vuln: dict[str, Any], references: list[dict[str, Any]]) -> set[str]:
    """项目里所有"有出处的"版本号集合：IntelItem 字段 + 参考文献 URL 文本。"""

    versions: set[str] = set()

    def harvest(text: str) -> None:
        for match in _VERSION_RE.finditer(text or ""):
            versions.add(match.group(1))

    for key in ("version", "target_version", "fixed"):
        value = vuln.get(key)
        if isinstance(value, str):
            harvest(value)
    for entry in vuln.get("version_ranges") or []:
        harvest(str(entry.get("introduced") or ""))
        harvest(str(entry.get("fixed") or ""))

    for ref in references:
        harvest(str(ref.get("url") or ""))
        harvest(str(ref.get("title") or ""))
        harvest(str(ref.get("snippet") or ""))
    return versions


def extract_target_version(
    vuln: dict[str, Any], references: list[dict[str, Any]]
) -> tuple[str | None, str, str | None]:
    """返回 (修复版本, 置信度, 来源 URL)。

    置信度：`confirmed`（来自 version_ranges.fixed 或公告原文）/ `unknown`。
    **没有 inferred 档**：本轮不猜版本号。
    """

    # 溯源兜底：CPE 配置派生的 version_range 本身没有 URL，但 `confirmed` 置信度
    # 必须可回溯，否则等于"没证据却声称确认"。回退到该情报的权威公告 URL。
    advisory_url = vuln.get("url") or (
        f"https://nvd.nist.gov/vuln/detail/{vuln['cve_id']}" if vuln.get("cve_id") else None
    )

    for entry in vuln.get("version_ranges") or []:
        fixed = entry.get("fixed")
        if fixed:
            return str(fixed), "confirmed", entry.get("url") or advisory_url

    allowed = known_versions(vuln, references)
    for ref in references:
        kind = classify_reference(ref)
        if kind not in {"patch", "advisory"}:
            continue
        text = f"{ref.get('title') or ''} {ref.get('url') or ''} {ref.get('snippet') or ''}"
        if not _FIXED_HINT.search(text):
            continue
        for candidate in _VERSION_RE.findall(text):
            if candidate in allowed and candidate not in {"0", "1", "2", "3"}:
                return candidate, "confirmed", ref.get("url")
    return None, "unknown", None


def _generic_actions(vuln: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """模板化的加固与检测建议（Mock 性质，已在 degraded_reason 声明）。"""

    product = (vuln.get("affected_products") or ["受影响组件"])[0]
    hardening = [
        f"收敛 {product} 的对外暴露面，仅允许必要来源访问",
        f"为 {product} 所在主机启用最小权限与出网限制",
        "开启关键操作审计日志并保留 30 天以上",
    ]
    detection = [
        f"检索 {product} 进程近期是否加载过异常依赖或配置",
        "比对外部资产清单与漏洞公告的受影响版本区间，确认暴露实例",
        "关注厂商公告与 CISA KEV 是否新增在野利用标记",
    ]
    return [], hardening, detection


async def fix_recommendation(vuln: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    """F5 入口。"""

    raw_refs = [r for r in (vuln.get("references") or []) if r.get("url")]
    references = [{**ref, "kind": classify_reference(ref)} for ref in raw_refs]
    patch_refs = [r for r in references if r["kind"] in {"patch", "advisory"}]

    evidence = EvidenceBuilder()
    for ref in patch_refs[:5]:
        evidence.add(
            str(ref.get("provider") or "vendor"),
            ref["url"],
            str(ref.get("title") or f"{ref['kind']} 参考链接"),
        )

    target, version_confidence, target_url = extract_target_version(vuln, references)

    immediate: list[dict[str, Any]] = []
    cwes = [str(c).upper() for c in (vuln.get("cwe") or [])]
    if "CWE-502" in cwes:
        immediate.append(
            {
                "action": "禁止从不可信来源加载模型权重/序列化对象，仅允许 safetensors 等安全格式",
                "rationale": "本漏洞的触发点是反序列化不可信数据（CWE-502）",
                "evidence_ref": evidence.items[0]["evidence_id"] if evidence.items else None,
            }
        )
    if "CWE-78" in cwes or "CWE-94" in cwes or "CWE-77" in cwes:
        immediate.append(
            {
                "action": "禁用受影响接口的外部可达性，直到完成升级",
                "rationale": "存在命令/代码注入类缺陷，暴露期间风险不可控",
                "evidence_ref": evidence.items[0]["evidence_id"] if evidence.items else None,
            }
        )
    if not immediate:
        immediate.append(
            {
                "action": "按影响面收敛对外暴露，优先限制受影响组件的入站访问",
                "rationale": "缺少 CWE 级别的确定性依据，给出保守的收窄建议",
                "evidence_ref": evidence.items[0]["evidence_id"] if evidence.items else None,
            }
        )

    _, hardening, detection = _generic_actions(vuln)

    if target:
        if target_url:
            evidence.add("vendor", target_url, f"公告写明修复版本 {target}")
        upgrade = {
            "target_version": target,
            "source": "vendor",
            "url": target_url,
            "confidence": version_confidence,
        }
        degraded_to: str | None = "rule"
        degraded_reason = (
            "F5 本轮为规则实现：版本号取自公告原文，通用建议为模板（未接 LLM 组织与正文抓取）"
        )
        mock = True
        confidence = 0.6
        note = "已定位官方修复版本（版本号来自公告原文）"
    else:
        upgrade = {
            "target_version": None,
            "source": None,
            "url": None,
            "confidence": "unknown",
        }
        degraded_to = "rule"
        degraded_reason = "未在任何参考文献中找到官方修复版本，仅给出缓解与检测建议（不编造版本号）"
        mock = True
        confidence = 0.35
        note = "未找到官方补丁版本"
        if not evidence:
            evidence.add("rule", None, "无 patch/advisory 类参考文献，无法定位官方补丁")

    value = {
        "immediate": immediate,
        "upgrade": upgrade,
        "hardening": hardening,
        "detection": detection,
        "patch_refs": [
            {"url": r["url"], "kind": r["kind"], "provider": r.get("provider")}
            for r in patch_refs[:10]
        ],
        "version_confidence": version_confidence,
        "reference_count": len(references),
        "mock": mock,
        "mock_parts": ["hardening", "detection"],
    }

    sources = sorted({str(r.get("provider") or "vendor") for r in patch_refs}) or ["rule"]

    return build_result(
        "fix",
        value,
        evidence,
        confidence,
        source=sources,
        model="rule-based",
        trace_id=trace_id,
        mock=mock,
        degraded_to=degraded_to,
        degraded_reason=degraded_reason,
        note=note,
    )

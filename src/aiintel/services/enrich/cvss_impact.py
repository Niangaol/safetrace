"""F4 CVSS 与影响评估（`cvss`）：分数本地算，影响面 LLM 解释，EPSS/KEV 补齐。

三条硬规则：

1. **分数不由 LLM 产出**。`resolve_score()` 只能本地计算或采用官方值，拿不到就
   `score_source="unavailable"` + `base_score=null`，**绝不猜**。
2. **影响说明必须有 CWE 依据**。规则兜底时按 CWE 分类给出影响描述，而不是让模型自由发挥。
3. 厂商公告、NVD、EPSS/KEV 的每个数值都带来源 URL，供 F6 做一致性比对。
"""

from __future__ import annotations

import logging
from typing import Any

from aiintel.services.enrich import mg1
from aiintel.services.enrich.cvss import qualitative
from aiintel.services.enrich.evidence import EvidenceBuilder, build_result
from aiintel.services.enrich.nvd import parse_nvd
from aiintel.services.ingest.text import truncate

logger = logging.getLogger(__name__)

IMPACT_SYSTEM_PROMPT = (
    "你是漏洞分析专家。基于给定信息输出 JSON："
    '{"technical_impact": "≤100字技术影响", "business_impact": "≤100字业务影响", '
    '"affected_scenarios": ["受影响场景"], "prerequisites": "利用前置条件"}。'
    "禁止输出 CVSS 分数、禁止输出修复版本号——分数由系统计算，版本号由 F5 从公告原文提取。"
)

# CWE 家族 → 规则兜底的技术影响描述（LLM 不可用时仍然给出有依据的影响判断）
_CWE_IMPACT: dict[str, str] = {
    "CWE-502": "反序列化不可信数据，可在目标进程内执行任意代码",
    "CWE-78": "命令注入，可借服务权限执行系统命令",
    "CWE-94": "代码注入，可执行攻击者控制的代码",
    "CWE-77": "命令拼接注入，可执行任意命令",
    "CWE-89": "SQL 注入，可读取或篡改后端数据库",
    "CWE-22": "路径穿越，可读取或覆盖服务进程可访问的文件",
    "CWE-918": "服务端请求伪造，可借服务访问内网资源",
    "CWE-287": "认证缺陷，可绕过身份校验",
    "CWE-862": "缺失授权校验，可越权访问资源",
    "CWE-416": "释放后使用，可导致内存破坏甚至代码执行",
    "CWE-787": "越界写入，可导致内存破坏甚至代码执行",
    "CWE-125": "越界读取，可泄露进程内存中的敏感信息",
    "CWE-400": "资源耗尽，可导致服务不可用",
    "CWE-611": "XXE，可读取本地文件或发起内网请求",
    "CWE-1333": "正则复杂度导致拒绝服务",
}


def rule_impact(vuln: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    """规则兜底影响说明：依据 CWE 与描述原文，不编造。"""

    cwes = [str(c).upper() for c in (parsed.get("cwe") or vuln.get("cwe") or [])]
    impacts = [_CWE_IMPACT[c] for c in cwes if c in _CWE_IMPACT]
    technical = "；".join(impacts) if impacts else truncate(parsed.get("description") or "", 120)
    if not technical:
        technical = "描述不足，无法给出技术影响判断（待人工确认）"

    scenarios: list[str] = []
    products = vuln.get("affected_products") or []
    if products:
        scenarios.append(f"部署了 {products[0]} 且可从外部访问的推理/服务实例")
    if parsed.get("kev"):
        scenarios.append("已在野被利用（CISA KEV），需优先处置")

    return {
        "technical_impact": technical,
        "business_impact": (
            "若被成功利用，受影响服务可能被完全控制或中断，需结合资产重要性评估业务损失。"
            if impacts
            else "影响面待评估（缺少 CWE 依据）。"
        ),
        "affected_scenarios": scenarios,
        "prerequisites": str(vuln.get("attack_prerequisites") or "")[:200],
    }


def _score_snippet(parsed: dict[str, Any]) -> str:
    vector = parsed.get("cvss_vector") or "(无向量)"
    score = parsed.get("base_score")
    source = parsed.get("score_source")
    if source == "computed":
        return f"{vector} → {score}（本地按 CVSS v3.1/v4.0 规范计算，可复核）"
    if source == "official":
        return f"{vector} → {score}（直接采用 NVD/厂商官方 baseScore）"
    return f"{vector} → 分数不可用（向量缺失或无法解析，未做任何猜测）"


async def cvss_and_impact(vuln: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    """F4 入口。"""

    parsed = parse_nvd(vuln)
    evidence = EvidenceBuilder()

    nvd_eid = evidence.add(
        "nvd",
        parsed.get("url"),
        parsed.get("description") or str(vuln.get("description") or ""),
    )
    score_eid = evidence.add("computed", parsed.get("url"), _score_snippet(parsed))

    # 厂商/公告类来源作为交叉证据（F6 会用它们做一致性比对）
    vendor_refs = [r for r in (parsed.get("references") or []) if r.get("url")]
    for ref in vendor_refs[:2]:
        evidence.add(
            str(ref.get("provider") or "vendor"), ref.get("url"), str(ref.get("kind") or "参考链接")
        )

    judged, mg1_result = await mg1.json_complete(
        [
            {"role": "system", "content": IMPACT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"标题：{vuln.get('title', '')}\n"
                    f"CWE：{parsed.get('cwe') or vuln.get('cwe') or []}\n"
                    f"受影响产品：{vuln.get('affected_products') or []}\n"
                    f"是否在野利用（KEV）：{parsed.get('kev')}\n"
                    f"EPSS：{parsed.get('epss')}\n"
                    f"描述：{truncate(parsed.get('description') or '', 2000)}"
                ),
            },
        ],
        task="enrich",
        # ⚠️ 700 偏低：`enrich` 属于 `THINKING_TASKS`，思维**计入 completion_tokens**，
        # 实测该档思维可达 1500+。预算不足时正文为空，`judged` 为空 → 静默降级到
        # 规则生成的通用影响说明（不报错，只是 LLM 那一路从不生效）。
        # 与 `qa.answer` 的 3000 对齐：这里输入更长（含描述 2000 字）。
        max_tokens=3000,
        node="enrich.cvss",
        agent="EnrichAgent",
    )

    degraded_to: str | None = None
    degraded_reason = ""
    model = "rule-based"

    if judged:
        model = mg1_result.model
        technical = str(judged.get("technical_impact") or "")[:300]
        impact = {
            "technical_impact": technical,
            "business_impact": str(judged.get("business_impact") or "")[:300],
            "affected_scenarios": [str(x) for x in (judged.get("affected_scenarios") or [])][:5],
            "prerequisites": str(judged.get("prerequisites") or "")[:300],
        }
        # 模型若越界输出分数/版本号，丢弃该字段（提示词禁令的可执行化）
        if any(ch.isdigit() for ch in technical) and "CVSS" in technical.upper():
            fallback = rule_impact(vuln, parsed)
            impact["technical_impact"] = fallback["technical_impact"]
            impact["affected_scenarios"] = fallback["affected_scenarios"]
        if mg1_result.degraded:
            degraded_to = "local"
            degraded_reason = "云端不可用，影响说明由本地兜底模型生成"
            model = mg1_result.model or "local"
    else:
        impact = rule_impact(vuln, parsed)
        degraded_to = "rule"
        degraded_reason = f"MG1 不可用（{mg1_result.error or '无返回'}），影响说明改用 CWE 规则生成"

    score = parsed.get("base_score")
    score_source = parsed.get("score_source", "unavailable")
    if score_source == "unavailable":
        # 分数拿不到本身不是"降级"，但置信度必须低，且要留一条"为什么没有分数"的证据
        if degraded_to is None:
            degraded_reason = "CVSS 向量缺失或不可解析，未给出分数"
        evidence.add("rule", None, "未取得可用 CVSS 向量，base_score 置 null（不做猜测）")

    value = {
        "vector": parsed.get("cvss_vector"),
        "vector_version": parsed.get("cvss_version"),
        "base_score": score,
        "official_score": parsed.get("official_score"),
        "score_source": score_source,
        "computed_locally": score_source == "computed",
        "severity": parsed.get("severity"),
        "qualitative": qualitative(score),
        "cvss_31": {"vector": parsed.get("vector_31"), "score": parsed.get("score_31")},
        "cvss_40": {"vector": parsed.get("vector_40"), "score": parsed.get("score_40")},
        "epss": parsed.get("epss"),
        "kev": parsed.get("kev"),
        "cwe": parsed.get("cwe") or [],
        "evidence_refs": [nvd_eid, score_eid],
        **impact,
    }

    confidence = (
        0.9 if score_source == "computed" else (0.6 if score_source == "official" else 0.35)
    )
    if degraded_to == "rule":
        confidence = min(confidence, 0.6)

    return build_result(
        "cvss",
        value,
        evidence,
        confidence,
        source=["nvd", "computed"] if score_source == "computed" else ["nvd"],
        model=model,
        trace_id=trace_id,
        degraded_to=degraded_to,
        degraded_reason=degraded_reason,
        note=f"CWE {','.join(value['cwe'])}" if value["cwe"] else "",
    )

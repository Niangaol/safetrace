"""富化维度注册表（F 线唯一入口）。

维度清单（6 个计划维度 F1–F6 + 1 个 AI 安全专项维度）：

| key | 中文 | 实现文件 |
| --- | --- | --- |
| `paper` | F1 论文关联 | `paper.py` |
| `asset` | F2 受影响资产 | `asset.py` |
| `poc` | F3 POC 搜集 | `poc.py` |
| `cvss` | F4 CVSS 与影响评估 | `cvss_impact.py`（算分在 `cvss.py`） |
| `fix` | F5 修复建议生成 | `fix.py` |
| `consistency` | F6 汇总与一致性校验 | `consistency.py` |
| `ai_risk` | AI 风险分类 + ATT&CK（专项） | 本文件 |

统一约定：每个维度是 `async def fn(vuln: dict, trace_id: str | None = None) -> EnrichmentResult`，
结果一律经 `evidence.build_result()` 构造，禁止自己拼 dict（三条不变量由它强制）。

本模块**不直接 import provider SDK，也不直接 import core.llm**，模型调用统一走 `mg1.py`。
"""

from __future__ import annotations

import logging
from typing import Any

from aiintel.services.enrich import mg1
from aiintel.services.enrich.asset import asset_impact
from aiintel.services.enrich.consistency import consistency_check
from aiintel.services.enrich.cvss_impact import cvss_and_impact
from aiintel.services.enrich.evidence import EvidenceBuilder, build_result
from aiintel.services.enrich.fix import fix_recommendation
from aiintel.services.enrich.paper import paper_association
from aiintel.services.enrich.poc import poc_search
from aiintel.services.ingest.text import truncate

logger = logging.getLogger(__name__)

AI_RISK_CATEGORIES = {
    "ai_infrastructure": "① AI 基础设施/推理框架风险（Ollama、vLLM、Triton 等框架漏洞）",
    "model_data": "② 模型与数据层风险（提示词注入、系统提示词泄露、数据投毒）",
    "ai_application": "③ AI 应用与智能体风险（Agent 框架、RAG 链路、工具调用）",
    "supply_chain": "④ 供应链风险（模型仓库、依赖包、数据集投毒）",
    "general": "⑤ 传统通用漏洞（与 AI 无直接关系）",
}

ATTACK_TECHNIQUES = {
    "T1190": "利用面向公众的应用",
    "T1203": "利用供应链漏洞",
    "T1059": "命令与脚本解释器",
    "T1055": "进程注入",
    "T1552": "从存储位置获取凭证或密钥",
    "T1499": "端点拒绝服务",
    "T1566": "钓鱼",
    "T1078": "有效账号",
}

CLASSIFY_SYSTEM_PROMPT = (
    "你是 AI 安全风险分类专家。根据漏洞描述与受影响产品，从以下分类中选择其一：\n"
    + "\n".join(f"{k}: {v}" for k, v in AI_RISK_CATEGORIES.items())
    + "\n并给出 MITRE ATT&CK 技术编号（最多 3 个，只能从这些里选："
    + ",".join(ATTACK_TECHNIQUES)
    + "）。只输出 JSON："
    '{"category": "…", "reason": "≤50字", "techniques": [{"id":"T1190","tactic":"Initial Access"}]}'
)


def rule_classify(title: str, description: str, cpe: list[str]) -> dict[str, Any]:
    """规则兜底分类：按产品与关键词命中，明确标注依据（不猜）。"""

    haystack = f"{title} {description} {' '.join(cpe)}".lower()
    rules = (
        ("ai_infrastructure", ("vllm", "ollama", "triton", "tensorrt", "onnx", "ray", "sglang")),
        ("model_data", ("prompt injection", "提示词注入", "system prompt", "poison", "投毒")),
        ("ai_application", ("langchain", "llamaindex", "agent", "rag", "mcp")),
        ("supply_chain", ("huggingface", "transformers", "pypi", "npm", "dataset", "model hub")),
    )
    for category, needles in rules:
        for needle in needles:
            if needle in haystack:
                return {
                    "category": category,
                    "reason": f"描述/CPE 命中关键词「{needle}」",
                    "techniques": [],
                }
    return {"category": "general", "reason": "未命中 AI 相关关键词", "techniques": []}


async def classify_ai_risk(title: str, description: str, cpe: list[str]) -> dict[str, Any]:
    """AI 风险分类。MG1 可用走 LLM，不可用走关键词规则（降级可见）。"""

    judged, mg1_result = await mg1.json_complete(
        [
            {"role": "system", "content": CLASSIFY_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"标题：{title}\n描述：{truncate(description, 2000)}\nCPE：{list(cpe)[:5]}",
            },
        ],
        task="classify",
        max_tokens=500,
        node="enrich.ai_risk",
        agent="EnrichAgent",
    )
    if not judged:
        fallback = rule_classify(title, description, cpe)
        return {
            **fallback,
            "label": AI_RISK_CATEGORIES.get(fallback["category"], ""),
            "degraded_to": "rule",
            "degraded_reason": f"MG1 不可用（{mg1_result.error or '无返回'}），改用关键词规则分类",
            "model": "rule-based",
        }

    techniques = [
        {
            "id": t.get("id"),
            "tactic": t.get("tactic", ""),
            "name": ATTACK_TECHNIQUES.get(t.get("id", ""), ""),
        }
        for t in judged.get("techniques", [])
        if t.get("id") in ATTACK_TECHNIQUES
    ]
    raw_category = judged.get("category")
    category = str(raw_category) if raw_category in AI_RISK_CATEGORIES else "general"
    return {
        "category": category,
        "label": AI_RISK_CATEGORIES.get(category, ""),
        "reason": str(judged.get("reason") or "")[:100],
        "techniques": techniques,
        "degraded_to": "local" if mg1_result.degraded else None,
        "degraded_reason": "云端不可用，分类由本地兜底模型给出" if mg1_result.degraded else "",
        "model": mg1_result.model,
    }


async def ai_risk_dimension(vuln: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    """AI 风险专项维度入口。"""

    judged = await classify_ai_risk(
        str(vuln.get("title") or ""),
        str(vuln.get("description") or ""),
        list(vuln.get("cpe") or []),
    )
    evidence = EvidenceBuilder()
    evidence.add(
        "nvd",
        f"https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id')}" if vuln.get("cve_id") else None,
        str(vuln.get("description") or vuln.get("title") or ""),
    )
    if judged.get("reason"):
        evidence.add("rule", None, f"分类依据：{judged['reason']}")

    techniques = judged.get("techniques") or []
    value = {
        "category": judged.get("category", "general"),
        "label": judged.get("label", ""),
        "reason": judged.get("reason", ""),
        "techniques": techniques,
    }

    return build_result(
        "ai_risk",
        value,
        evidence,
        0.75 if techniques else 0.6,
        source=["nvd", "rule"],
        model=str(judged.get("model") or "rule-based"),
        trace_id=trace_id,
        degraded_to=judged.get("degraded_to"),
        degraded_reason=str(judged.get("degraded_reason") or ""),
    )


# 注册表：`EnrichAgent` 按此顺序并发执行；顺序同时决定"砍范围"的先后
DIMENSIONS: dict[str, Any] = {
    "paper": paper_association,
    "asset": asset_impact,
    "poc": poc_search,
    "cvss": cvss_and_impact,
    "fix": fix_recommendation,
    "consistency": consistency_check,
    "ai_risk": ai_risk_dimension,
}

# 质量闸门（DQ1）消费策略：低于部分阈值时不富化，低于全量阈值时只跑核心维度
CORE_DIMENSIONS = ("cvss", "fix", "consistency")


def dimensions_for_quality(vuln: dict[str, Any]) -> list[str] | None:
    """按 `quality_score` 决定跑哪些维度。返回 None 表示"全部拒绝"。

    阈值口径**只有一处**：`services/dq1.py::thresholds_for()`（DQ1 判定与这里共用
    `enrich_min_quality_partial` / `enrich_min_quality_full`）。改阈值时两边一起变，
    有回归测试钉住两者一致。
    """

    from aiintel.services.dq1 import thresholds_for

    score = vuln.get("quality_score")
    if score is None:
        return list(DIMENSIONS)
    limits = thresholds_for()
    if float(score) <= limits["partial"]:
        return None
    if float(score) <= limits["full"]:
        return list(CORE_DIMENSIONS)
    return list(DIMENSIONS)


__all__ = [
    "AI_RISK_CATEGORIES",
    "ATTACK_TECHNIQUES",
    "CORE_DIMENSIONS",
    "DIMENSIONS",
    "ai_risk_dimension",
    "classify_ai_risk",
    "dimensions_for_quality",
    "rule_classify",
]

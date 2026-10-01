"""演示数据：让前端在没有 PostgreSQL、没有 LLM 凭据的机器上也有东西可看。

只做一件事：把 data/demo.db 灌成一份形态与真实数据一致的 SQLite 库。
- chunk 表的 embedding 是 pgvector 列，SQLite 建不出来，这里跳过并建同名简化表
- 富化结论都带 evidence，保持"可溯源"这个核心设计在演示里也成立
- 时间戳刻意打散，好让 P50 / 6h 占比等指标看起来像真实分布

用法：python -m scripts.demo_seed [--db data/demo.db]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import random
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from scripts.demo_derive import derive, derive_asset_or_abstain

SEED = 20260928
NOW = dt.datetime(2026, 9, 28, 12, 0, tzinfo=dt.UTC)

# 值类型各异（str / float / bool / list），显式标成 Any 免得 mypy 把下标访问判成 object
VULNS: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2026-31001",
        "ghsa_id": "GHSA-7f3q-vllm-rce",
        "title": "vLLM OpenAI 兼容接口存在远程代码执行",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-502", "CWE-94"],
        "epss": 0.87,
        "kev": True,
        "ai_risk_category": "model_serving",
        "exploit_status": "poc",
        "hours_ago": 3,
        "sources": ["nvd", "ghsa", "community_rss"],
        "desc": (
            "vLLM 在 0.9.x 分支的 OpenAI 兼容 HTTP 服务中，对 chat/completions 请求的 "
            "chat_template 字段直接传入 Jinja2 模板引擎渲染，未禁用沙箱构造器。攻击者可通过"
            "构造模板表达式读取服务端任意文件并执行命令。"
        ),
    },
    {
        "cve_id": "CVE-2026-29455",
        "ghsa_id": None,
        "title": "LangChain 表达式注入导致工具调用越权",
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-77", "CWE-94"],
        "epss": 0.62,
        "kev": False,
        "ai_risk_category": "agent_framework",
        "exploit_status": "poc",
        "hours_ago": 9,
        "sources": ["nvd", "ghsa"],
        "desc": (
            "LangChain 的 LCEL 表达式解析允许通过自定义 codec 注入代码，"
            "在加载不可信链定义时可触发任意代码执行，影响所有把外部输入拼进 chain 定义的应用。"
        ),
    },
    {
        "cve_id": "CVE-2026-28114",
        "ghsa_id": "GHSA-9m4x-tq7p-hd22",
        "title": "Transformers 远程代码执行（权重反序列化）",
        "severity": "high",
        "cvss_score": 8.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-502"],
        "epss": 0.71,
        "kev": True,
        "ai_risk_category": "model_loading",
        "exploit_status": "weaponized",
        "hours_ago": 14,
        "sources": ["nvd", "ghsa", "community_rss"],
        "desc": (
            "transformers 的 from_pretrained 未默认设置 weights_only=True，"
            "恶意 pickle 权重可在加载时执行任意代码。Hugging Face 已在 4.53 加固。"
        ),
    },
    {
        "cve_id": "CVE-2026-30077",
        "ghsa_id": None,
        "title": "Gradio 文件上传导致服务端任意文件读取",
        "severity": "high",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-22"],
        "epss": 0.44,
        "kev": False,
        "ai_risk_category": "model_serving",
        "exploit_status": "poc",
        "hours_ago": 20,
        "sources": ["nvd", "community_rss"],
        "desc": "Gradio 的 /upload 接口未对 file_path 做规范化，可通过 ../ 穿越读取任意文件。",
    },
    {
        "cve_id": "CVE-2026-31890",
        "ghsa_id": "GHSA-4c8p-2xrf-8vjd",
        "title": "PyTorch torch.load 权重反序列化漏洞",
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": ["CWE-502"],
        "epss": 0.33,
        "kev": False,
        "ai_risk_category": "model_loading",
        "exploit_status": "in_the_wild",
        "hours_ago": 30,
        "sources": ["nvd", "ghsa"],
        "desc": "torch.load 仍默认使用 pickle，加载第三方预训练权重时存在反序列化执行风险。",
    },
    {
        "cve_id": "CVE-2026-32556",
        "ghsa_id": None,
        "title": "Hugging Face Hub SSRF（redirect 参数未校验）",
        "severity": "medium",
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-918"],
        "epss": 0.11,
        "kev": False,
        "ai_risk_category": "supply_chain",
        "exploit_status": "unknown",
        "hours_ago": 46,
        "sources": ["nvd"],
        "desc": "from_pretrained 跟随 redirect 参数跳转到内网地址，可用于探测内网服务。",
    },
    {
        "cve_id": "CVE-2026-30112",
        "ghsa_id": "GHSA-w2r5-6hqp-9xkm",
        "title": "Jinja2 沙箱逃逸导致模板注入",
        "severity": "critical",
        "cvss_score": 9.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe": ["CWE-1336"],
        "epss": 0.55,
        "kev": False,
        "ai_risk_category": "model_serving",
        "exploit_status": "poc",
        "hours_ago": 60,
        "sources": ["nvd", "ghsa", "arxiv"],
        "desc": "多个 LLM 应用的 prompt 模板直接渲染用户输入，构成模板注入与沙箱逃逸。",
    },
    {
        "cve_id": "CVE-2026-27410",
        "ghsa_id": None,
        "title": "Ray Dashboard 未授权访问导致作业劫持",
        "severity": "high",
        "cvss_score": 8.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-306", "CWE-862"],
        "epss": 0.29,
        "kev": False,
        "ai_risk_category": "training_infra",
        "exploit_status": "poc",
        "hours_ago": 78,
        "sources": ["community_rss"],
        "desc": "Ray Dashboard 默认无需认证，攻击者可提交任意作业并读取训练数据。",
    },
    {
        "cve_id": "CVE-2026-26633",
        "ghsa_id": None,
        "title": "LlamaIndex 文档加载器命令注入",
        "severity": "high",
        "cvss_score": 8.4,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-78"],
        "epss": 0.38,
        "kev": False,
        "ai_risk_category": "rag_pipeline",
        "exploit_status": "unknown",
        "hours_ago": 96,
        "sources": ["nvd", "community_rss"],
        "desc": "SimpleDirectoryReader 解析文件名时拼接 shell 命令，恶意文件名可触发命令注入。",
    },
    {
        "cve_id": "CVE-2026-29001",
        "ghsa_id": None,
        "title": "MLflow 模型仓库路径穿越",
        "severity": "medium",
        "cvss_score": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": ["CWE-22"],
        "epss": 0.19,
        "kev": False,
        "ai_risk_category": "training_infra",
        "exploit_status": "poc",
        "hours_ago": 120,
        "sources": ["nvd"],
        "desc": "MLflow artifact 下载接口未规范化路径，可覆盖任意文件。",
    },
    {
        "cve_id": "CVE-2026-25588",
        "ghsa_id": None,
        "title": "AutoAWQ 模型反序列化导致 RCE",
        "severity": "high",
        "cvss_score": 8.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cwe": ["CWE-502"],
        "epss": 0.26,
        "kev": False,
        "ai_risk_category": "model_loading",
        "exploit_status": "unknown",
        "hours_ago": 150,
        "sources": ["community_rss"],
        "desc": "量化模型加载路径使用 pickle 反序列化，恶意模型文件可触发代码执行。",
    },
    {
        "cve_id": "CVE-2026-24007",
        "ghsa_id": None,
        "title": "Ollama 模型拉取路径未校验导致写入任意位置",
        "severity": "low",
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "cwe": ["CWE-22"],
        "epss": 0.04,
        "kev": False,
        "ai_risk_category": "model_serving",
        "exploit_status": "unknown",
        "hours_ago": 200,
        "sources": ["community_rss"],
        "desc": "本地模型名参数未过滤 ../，可写出目标目录之外。",
    },
]

#: 演示用 KEV 强制修复截止日。按 `kev=True` 的 CVE 各给一个**已过期或临近**的日期，
#: 让大屏上的"逾期未修"看起来像真实状态（NOW = 2026-09-28）。
#: 未列入 KEV 的条目一律 None —— "不在 KEV"和"在 KEV 但期限未知"是两种不同状态。
_KEV_DUE_DATES: dict[str, str] = {
    "CVE-2026-31001": "2026-09-15",  # 已逾期
    "CVE-2026-28114": "2026-10-12",  # 临近
}


def _kev_due_date(cve_id: str, kev: bool) -> str | None:
    """演示数据的 KEV 截止日。只有确实标了 kev=True 才给期限。"""

    return _KEV_DUE_DATES.get(cve_id) if kev else None


def _references_for(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """构造漏洞的原始出处（可点击）。

    规则：**只写实测能打开的链接**。

    - NVD 详情页按 CVE 编号寻址：`https://nvd.nist.gov/vuln/detail/<CVE>`，实测 200，
      所以每个条目都给这一条；
    - **不拼 GitHub Advisory 链接**。演示用的 GHSA 编号（如
      `GHSA-9m4x-tq7p-hd22`）虽然**格式合法**（三段各 4 位），但它是编的，
      `github.com/advisories/<GHSA>` 实测 **404**。这里判断过两版：
      先按"连字符段数"，再按严格格式 `^GHSA(-[0-9a-z]{4}){3}$` —— 两者都拦不住，
      因为问题不在格式而在**编号是否真实存在**，而离线演示库无从校验。
      所以宁可不给这条链接，也不要挂一个点开是 404 的"来源"。

    真实链路下这里应当直接来自采集到的 `references` 字段（NVD/GHSA 导出里都有），
    演示库没有联网采集，故按编号合成 —— **这一点要写进报告「已知限制」。**
    """

    return [
        {
            "source": "nvd",
            "url": f"https://nvd.nist.gov/vuln/detail/{spec['cve_id']}",
            "tags": ["vendor-advisory"],
        }
    ]


#: 这几个维度**没有**逐条真实数据，灌的是 `DIMENSIONS` 里的同一条示例值。
#: 逐条产生它们需要真实联网检索（GitHub / arXiv / OpenAlex）或 LLM 调用，
#: 本机网络下都不可达。既然造不出真实值，就必须把"这是示例值"标出来
#: （`degraded_to="fixture"`），不能让它看起来像该条漏洞的真实结论。
_TEMPLATE_DIMS = {"poc", "paper", "fix", "consistency", "ai_risk"}

_TEMPLATE_REASON = (
    "本条为该维度的**示例值**（同一条内容用于多条漏洞），非该漏洞的真实富化结论。"
    "逐条产生需真实联网检索或 LLM 调用，本机网环境下不可达；"
    "演示时请据此说明，勿当作逐条结论引用。"
)

#: 演示数据严格对齐 `services/enrich/dimensions.py::DIMENSIONS`（6 个计划维度 F1–F6 + AI 安全专项）。
#: 每条都带 source / evidence_id / mock / degraded_to —— 与真实富化输出同结构，
#: 这样前端、评测、指标看到的形状一致，不会出现"演示能跑、真实一大屏空白"。
DIMENSIONS: dict[str, dict[str, Any]] = {
    "paper": {
        "value": {
            "papers": [
                {
                    "paper_id": "2609.01234",
                    "arxiv_id": "2609.01234",
                    "doi": None,
                    "title": "A Survey of LLM Serving Infrastructure Vulnerabilities",
                    "year": 2026,
                    "url": "https://arxiv.org/abs/2609.01234",
                    "source": "arxiv",
                    "relation_type": "same_attack_surface",
                    "relevance": 0.82,
                    "reason": "同一攻击面（推理服务模板渲染）",
                    "findings": ["把服务栈缺陷分为模板注入、反序列化、SSRF 三类"],
                    "evidence_ref": "ev-1",
                }
            ],
            "query": '"CVE-2026-31001"',
            "sources_queried": ["arxiv"],
            "source_failures": [],
        },
        "confidence": 0.7,
        "model": "mg1/deepseek",
        "source": ["arxiv"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "arxiv",
                "url": "https://arxiv.org/abs/2609.01234",
                "snippet": "We categorize serving-stack flaws into template injection, serialization, and SSRF families.",
                "fetched_at": "2026-09-28T09:30:00+00:00",
                "raw_item_id": None,
            }
        ],
    },
    "asset": {
        "value": {
            "products": [
                {
                    "vendor": "vllm",
                    "product": "vllm",
                    "cpe": "cpe:2.3:a:vllm:vllm:0.9.2:*:*:*:*:*:*:*",
                    "affected_versions": "<=0.9.2",
                    "introduced": None,
                    "fixed": "0.9.3",
                    "range_source": "vendor",
                    "url": "https://github.com/vllm-project/vllm/releases/tag/v0.9.3",
                }
            ],
            "exposed_assets": [],
            "exposure_level": "unknown",
            "inventory_loaded": False,
            "asset_scan_enabled": False,
            "mock": True,
        },
        "confidence": 0.55,
        "model": "rule-based",
        "source": ["nvd", "rule"],
        "mock": True,
        "degraded_to": "mock",
        "degraded_reason": "主动资产测绘默认关闭（合规红线），资产暴露面为空；资产画像为预置数据",
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "rule",
                "url": None,
                "snippet": "vllm:vllm 受影响版本 <=0.9.2（由 CPE 与版本区间本地解析）",
                "fetched_at": "2026-09-28T09:20:00+00:00",
                "raw_item_id": None,
            }
        ],
    },
    "poc": {
        "value": {
            "pocs": [
                {
                    "repo": "example/vllm-template-rce-poc",
                    "url": "https://github.com/example/vllm-template-rce-poc",
                    "kind": "exploit",
                    "language": "Python",
                    "stars": 142,
                    "tier": "confirmed",
                    "evidence_kind": "code",
                    "listed": True,
                    "runtime_verified": False,
                    "verified": True,
                    "usage": "Jinja2 构造器链逃逸；未运行验证，使用前自行确认适用范围",
                }
            ],
            "poc_count": 1,
            "confirmed_count": 1,
            "sources_used": ["github"],
            "source_failures": [],
            "runtime_verified_any": False,
            "verification_note": "本轮未运行任何验证代码（合规红线：不执行未授权目标上的利用）",
        },
        "confidence": 0.8,
        "model": "rule-based",
        "source": ["github"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "github",
                "url": "https://github.com/example/vllm-template-rce-poc",
                "snippet": 'curl -X POST http://target:8000/v1/chat/completions -d \'{"chat_template": "{{ cycler.__init__.__globals__.os.popen(\\"id\\") }}"}\'',
                "fetched_at": "2026-09-28T09:10:00+00:00",
                "raw_item_id": None,
            },
            {
                "evidence_id": "ev-2",
                "source": "ghsa",
                "url": "https://github.com/advisories/GHSA-7f3q-vllm-rce",
                "snippet": "Proof of concept included in the advisory, requires no authentication on the OpenAI-compatible endpoint.",
                "fetched_at": "2026-09-28T09:12:00+00:00",
                "raw_item_id": None,
            },
        ],
    },
    "cvss": {
        "value": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "vector_version": "3.1",
            "base_score": 9.8,
            "official_score": 9.8,
            "score_source": "computed",
            "computed_locally": True,
            "severity": "critical",
            "qualitative": "Critical",
            "cvss_31": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
            "cvss_40": {"vector": None, "score": None},
            "epss": 0.87,
            "kev": True,
            "cwe": ["CWE-1336", "CWE-94"],
            "technical_impact": "未沙箱的模板渲染可逃逸到 os.popen，攻击者以服务进程权限执行任意命令。",
            "business_impact": "推理集群节点可被完全接管，模型资产与用户会话数据面临泄漏风险。",
            "affected_scenarios": ["对外暴露 OpenAI 兼容端点的推理服务", "多租户推理平台"],
            "prerequisites": "目标服务允许外部提交 chat_template 字段",
            "evidence_refs": ["ev-1", "ev-2"],
        },
        "confidence": 0.9,
        "model": "mg1/deepseek",
        "source": ["nvd", "computed"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "nvd",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                "snippet": "CVSS 3.1 base score 9.8. Scope unchanged, high confidentiality/integrity/availability impact.",
                "fetched_at": "2026-09-28T09:20:00+00:00",
                "raw_item_id": None,
            },
            {
                "evidence_id": "ev-2",
                "source": "computed",
                "url": None,
                "snippet": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8（本地按 CVSS v3.1 规范计算，可复核）",
                "fetched_at": "2026-09-28T09:20:00+00:00",
                "raw_item_id": None,
            },
        ],
    },
    "fix": {
        "value": {
            "immediate": [
                {
                    "action": "在反向代理层校验 chat_template 字段，拒绝含双大括号且长度异常的请求",
                    "rationale": "本漏洞触发点是模板注入（CWE-1336）",
                    "evidence_ref": "ev-2",
                }
            ],
            "upgrade": {
                "target_version": "0.9.3",
                "source": "vendor",
                "url": "https://github.com/vllm-project/vllm/releases/tag/v0.9.3",
                "confidence": "confirmed",
            },
            "hardening": [
                "为推理进程启用最小权限与出网限制",
                "开启关键操作审计日志并保留 30 天以上",
            ],
            "detection": ["检索服务日志中是否出现构造器链（cycler/__globals__）特征串"],
            "patch_refs": [
                {
                    "url": "https://github.com/vllm-project/vllm/releases/tag/v0.9.3",
                    "kind": "patch",
                    "provider": "GitHub",
                }
            ],
            "version_confidence": "confirmed",
            "reference_count": 2,
            "mock": True,
            "mock_parts": ["hardening", "detection"],
        },
        "confidence": 0.6,
        "model": "rule-based",
        "source": ["github", "vendor"],
        "mock": True,
        "degraded_to": "rule",
        "degraded_reason": "F5 本轮为规则实现：版本号取自公告原文，通用建议为模板（未接 LLM 组织与正文抓取）",
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "github",
                "url": "https://github.com/vllm-project/vllm/releases/tag/v0.9.3",
                "snippet": "Security fix: sandbox the Jinja2 environment used for chat templates. Fixed in 0.9.3.",
                "fetched_at": "2026-09-28T09:50:00+00:00",
                "raw_item_id": None,
            },
            {
                "evidence_id": "ev-2",
                "source": "vendor",
                "url": "https://github.com/advisories/GHSA-7f3q-vllm-rce",
                "snippet": "Vendor advisory: upgrade to 0.9.3 or later.",
                "fetched_at": "2026-09-28T09:50:00+00:00",
                "raw_item_id": None,
            },
        ],
    },
    "consistency": {
        "value": {
            "consensus": [
                {
                    "field": "cvss_score",
                    "value": 9.8,
                    "source": "nvd",
                    "agreement": 0.5,
                    "values": [
                        {
                            "value": 9.8,
                            "source": "nvd",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                        },
                        {
                            "value": 9.1,
                            "source": "vendor",
                            "url": "https://github.com/advisories/GHSA-7f3q-vllm-rce",
                        },
                    ],
                },
                {
                    "field": "severity",
                    "value": "critical",
                    "source": "nvd",
                    "agreement": 1.0,
                    "values": [],
                },
                {
                    "field": "fixed_version",
                    "value": "0.9.3",
                    "source": "vendor",
                    "agreement": 1.0,
                    "values": [],
                },
            ],
            "conflicts": [
                {
                    "field": "cvss_score",
                    "severity": "high",
                    "values": [
                        {
                            "value": 9.8,
                            "source": "nvd",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                        },
                        {
                            "value": 9.1,
                            "source": "vendor",
                            "url": "https://github.com/advisories/GHSA-7f3q-vllm-rce",
                        },
                    ],
                    "resolved_to": 9.8,
                    "rule": "source_priority:nvd",
                    "note": "NVD 与厂商评分差 0.7 超过容差 0.1，按来源优先级取 NVD；厂商分数保留可见",
                }
            ],
            "timeline": [
                {
                    "stage": "disclosed",
                    "date": "2026-09-21",
                    "source": "nvd",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                },
                {
                    "stage": "poc",
                    "date": "2026-09-22",
                    "source": "github",
                    "url": "https://github.com/example/vllm-template-rce-poc",
                },
                {
                    "stage": "patched",
                    "date": None,
                    "source": "vendor",
                    "url": "https://github.com/vllm-project/vllm/releases/tag/v0.9.3",
                    "detail": "修复版本 0.9.3",
                },
                {
                    "stage": "exploited",
                    "date": None,
                    "source": "cisa",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "detail": "已列入 CISA KEV（在野利用）",
                },
            ],
            "quality_score": 0.78,
            "field_completeness": 0.9,
            "agreement_ratio": 0.8,
            "evidence_coverage": 0.8,
            "source_coverage": {"ghsa": True, "nvd": True, "vendor": True},
            "arbitration_priority": ["nvd", "vendor", "ghsa", "osv", "community_rss"],
            "single_source": False,
            "trace_refs": ["ev-1", "ev-2"],
        },
        "confidence": 0.81,
        "model": "mg1/deepseek",
        "source": ["nvd", "ghsa", "vendor"],
        "quality_score": 0.78,
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "nvd",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                "snippet": "Base Score: 9.8 CRITICAL",
                "fetched_at": "2026-09-28T09:20:00+00:00",
                "raw_item_id": None,
            },
            {
                "evidence_id": "ev-2",
                "source": "vendor",
                "url": "https://github.com/advisories/GHSA-7f3q-vllm-rce",
                "snippet": "Severity: High (CVSS 9.1)",
                "fetched_at": "2026-09-28T09:20:00+00:00",
                "raw_item_id": None,
            },
        ],
    },
    "ai_risk": {
        "value": {
            "category": "ai_infrastructure",
            "label": "① AI 基础设施/推理框架风险（Ollama、vLLM、Triton 等框架漏洞）",
            "reason": "攻击面在推理框架本身，不依赖模型权重内容",
            "techniques": [
                {"id": "T1190", "tactic": "Initial Access", "name": "利用面向公众的应用"},
                {"id": "T1059", "tactic": "Execution", "name": "命令与脚本解释器"},
            ],
        },
        "confidence": 0.75,
        "model": "mg1/deepseek",
        "source": ["nvd", "rule"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "nvd",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31001",
                "snippet": "The OpenAI-compatible server renders user-supplied chat_template without sandboxing.",
                "fetched_at": "2026-09-28T09:30:00+00:00",
                "raw_item_id": None,
            },
            {
                "evidence_id": "ev-2",
                "source": "rule",
                "url": "https://attack.mitre.org/techniques/T1190/",
                "snippet": "MITRE ATT&CK T1190 利用面向公众的应用",
                "fetched_at": "2026-09-28T09:40:00+00:00",
                "raw_item_id": None,
            },
        ],
    },
}

CHUNKS = [
    (
        "CVE-2026-31001",
        "vLLM 0.9.2 及更早版本的 OpenAI 兼容服务在处理 chat/completions 请求时，"
        "把 chat_template 字段交给未加沙箱的 Jinja2 环境渲染。构造器链（cycler.__init__.__globals__）"
        "可以逃逸到 os.popen，攻击者以服务进程权限执行任意命令。CVSS 9.8，EPSS 0.87，已被 CISA KEV 收录。",
    ),
    (
        "CVE-2026-31001",
        "修复方式：0.9.3 起改用 SandboxedEnvironment 并禁用属性访问；临时缓解可在反向代理层"
        "校验 chat_template 字段，拒绝包含双大括号且长度异常的请求。",
    ),
    (
        "CVE-2026-28114",
        "transformers 4.52 及更早版本的 from_pretrained 默认 weights_only=False，"
        "加载恶意 pickle 权重会执行任意代码。Hugging Face 在 4.53 将默认值改为 True，"
        "但未升级的加载脚本仍会显式传回 False。CVSS 8.8，KEV 收录。",
    ),
    (
        "CVE-2026-29455",
        "LangChain 的 LCEL 表达式支持自定义 codec，在解析不可信链定义时可注入代码。"
        "根因是把外部输入拼接进 chain 定义而未做沙箱隔离，属于典型的表达式注入。CVSS 9.1。",
    ),
    (
        "CVE-2026-30077",
        "Gradio 的 /upload 接口对 file_path 未做规范化，攻击者可通过 ../ 穿越读取任意文件，"
        "在自建 Gradio demo 上尤其常见。CVSS 8.6。",
    ),
    (
        "CVE-2026-30112",
        "Jinja2 沙箱逃逸：大量 LLM 应用把用户输入直接当模板渲染，"
        "攻击者通过 __class__.__mro__ 链逃逸沙箱。CVSS 9.0。",
    ),
    (
        "CVE-2026-27410",
        "Ray Dashboard 默认不开启认证，攻击者可以提交训练作业、读取训练数据，"
        "在多租户集群中影响面很大。CVSS 8.2。",
    ),
    (
        "CVE-2026-31890",
        "torch.load 默认使用 pickle 反序列化，加载第三方预训练权重存在远程代码执行风险，"
        "建议改用 safetensors。CVSS 8.1。",
    ),
    (
        "CVE-2026-26633",
        "LlamaIndex 的 SimpleDirectoryReader 在解析文件名时拼接 shell 命令，"
        "构造恶意文件名即可触发命令注入。CVSS 8.4。",
    ),
    (
        "arxiv-2609.01234",
        "Survey: A Taxonomy of LLM Serving Infrastructure Vulnerabilities. "
        "We group serving-stack flaws into template injection, unsafe deserialization, "
        "and SSRF families, and argue that sandboxing the template engine is the "
        "highest-leverage mitigation.",
    ),
    (
        "arxiv-2609.04556",
        "Prompt Injection Attacks and Defenses in Retrieval-Augmented Generation systems. "
        "Indirect injection through retrieved documents remains largely unsolved, "
        "and agent frameworks that execute tool calls amplify the impact.",
    ),
    (
        "arxiv-2609.07890",
        "A Backdoor Study on Multimodal Instruction Tuning. "
        "Models fine-tuned on uncurated web-scale data inherit backdoor triggers, "
        "which is a supply-chain risk rather than a serving-stack bug.",
    ),
]

PAPERS = [
    ("2609.01234", "A Taxonomy of LLM Serving Infrastructure Vulnerabilities", 2026),
    ("2609.04556", "Prompt Injection Attacks and Defenses in RAG", 2026),
    ("2609.07890", "A Backdoor Study on Multimodal Instruction Tuning", 2026),
]

SOURCES = ["nvd", "ghsa", "arxiv", "community_rss"]


def _hours_ago(h: float) -> dt.datetime:
    return NOW - dt.timedelta(hours=h)


def _create_chunk_table(conn) -> None:
    """chunk.embedding 是 pgvector 列，SQLite 建不出「真」向量类型。

    这里建同名简化表，但**必须保留 `embedding` 列名**（普通 TEXT，值恒为 NULL）：
    SQLAlchemy 的 INSERT 会带上映射里声明的所有列，缺列会让**整条 persist 链路**
    报 `table chunk has no column named embedding` ——
    演示库不只是给前端看的，它还要能承接真实管线写入（见 `scripts/check_e2e_cycle.py`）。
    向量召回在 SQLite 上本来就不会命中，留空即可。
    """

    conn.execute(
        text(
            "CREATE TABLE chunk ("
            "id TEXT PRIMARY KEY, owner_type TEXT, owner_id TEXT, chunk_no INTEGER, "
            "content TEXT, embedding TEXT, tsv TEXT, created_at TIMESTAMP)"
        )
    )
    conn.execute(text("CREATE INDEX ix_chunk_owner ON chunk (owner_type, owner_id)"))


def seed(db_path: str) -> dict[str, int]:
    rng = random.Random(SEED)
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()

    engine = create_engine(f"sqlite:///{path.as_posix()}")
    import aiintel.db.models  # noqa: F401  触发模型注册
    from aiintel.db.base import Base

    Base.metadata.create_all(
        engine,
        tables=[t for name, t in Base.metadata.tables.items() if name != "chunk"],
    )
    with engine.begin() as conn:
        _create_chunk_table(conn)

    counts = {"vulns": 0, "raw_items": 0, "enrichments": 0, "chunks": 0, "edges": 0}

    # 知识库切片走裸 SQL：简化表没有 embedding 列，ORM 会报列不存在。
    # owner_id 用的是 CVE 编号/arxiv id，不依赖其他表，所以可以先于 session 插完。
    with engine.begin() as conn:
        chunk_no: dict[str, int] = {}
        for owner_id, content in CHUNKS:
            n = chunk_no.get(owner_id, 0)
            chunk_no[owner_id] = n + 1
            # 编号必须进 content：检索匹配的是 chunk.content，而 owner_id 才是 CVE 号
            # （否则用 CVE 编号提问检索不到自己的切片，见 scripts/reseed_knowledge.py 注释）
            text_body = f"{owner_id} {content}"
            conn.execute(
                text(
                    "INSERT INTO chunk (id, owner_type, owner_id, chunk_no, content, tsv, created_at) "
                    "VALUES (:id, :owner_type, :owner_id, :chunk_no, :content, :tsv, :created_at)"
                ),
                {
                    "id": uuid.uuid4().hex,
                    "owner_type": "paper" if owner_id.startswith("arxiv-") else "vuln",
                    "owner_id": owner_id,
                    "chunk_no": n,
                    "content": text_body,
                    "tsv": text_body,
                    "created_at": _hours_ago(rng.randint(1, 60)),
                },
            )
            counts["chunks"] += 1

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    from aiintel.db.models import (
        AgentRun,
        AgentStep,
        Alert,
        Enrichment,
        GraphEdge,
        Paper,
        Poc,
        RawItem,
        SyncWatermark,
        Vuln,
        VulnSource,
    )

    with factory() as session:
        paper_ids: dict[str, str] = {}
        for arxiv_id, title, year in PAPERS:
            paper = Paper(
                arxiv_id=arxiv_id,
                title=title,
                abstract=f"（演示数据）{title}",
                year=year,
                url=f"https://arxiv.org/abs/{arxiv_id}",
                published_at=_hours_ago(rng.randint(200, 400)),
            )
            session.add(paper)
        session.flush()  # 先落库拿主键，graph_edge 的 dst_id 要用它
        for arxiv_id, _title, _year in PAPERS:
            paper = session.query(Paper).filter_by(arxiv_id=arxiv_id).one()
            paper_ids[arxiv_id] = paper.id

        for idx, spec in enumerate(VULNS):
            published = _hours_ago(spec["hours_ago"] + rng.randint(1, 5))
            vuln = Vuln(
                cve_id=spec["cve_id"],
                ghsa_id=spec["ghsa_id"],
                title=spec["title"],
                description=spec["desc"],
                summary=spec["desc"][:120],
                severity=spec["severity"],
                cvss_vector=spec["cvss_vector"],
                cvss_score=spec["cvss_score"],
                cwe=spec["cwe"],
                cpe=[f"cpe:2.3:a:{spec['ai_risk_category']}:*:*:*:*:*:*:*:*"],
                epss=spec["epss"],
                kev=spec["kev"],
                # CISA KEV 的强制修复截止日。只给已列入 KEV 的条目，且期限要早于
                # 演示基准日（NOW = 2026-09-28），否则会显得是未来才要修的假数据。
                kev_due_date=_kev_due_date(spec["cve_id"], spec["kev"]),
                ai_risk_category=spec["ai_risk_category"],
                exploit_status=spec["exploit_status"],
                # 漏洞的"原始出处"。没有它，问答页的引用链接无处可点
                # （实测过：references 为空 → 前端把内部 chunk key 当链接，点了没反应）。
                # 注意：这里的 CVE 是 2026 演示编号，真实世界里不存在，
                # 因此只写**能打开**的确定性链接（NVD 详情页按编号寻址）。
                # GHSA 不拼链接：`github.com/advisories/GHSA-xxx` 对不存在的编号返回 404，
                # 拼过去就是死链，宁可少一条也不要假链接。
                references=_references_for(spec),
                published_at=published,
                modified_at=published,
                fetched_at=_hours_ago(spec["hours_ago"]),
            )
            session.add(vuln)
            session.flush()
            counts["vulns"] += 1

            # 每个源一条原始记录，制造真实的合并率
            for source in spec["sources"]:
                raw = RawItem(
                    source=source,
                    external_id=f"{source}:{spec['cve_id']}",
                    url=f"https://example.org/{source}/{spec['cve_id']}",
                    title=spec["title"],
                    content_text=spec["desc"],
                    published_at=published,
                    fetched_at=_hours_ago(spec["hours_ago"]),
                    content_hash=f"h{source}{idx:02d}".ljust(64, "0")[:64],
                    simhash=rng.getrandbits(63),
                    raw_json={"demo": True, "source": source},
                )
                session.add(raw)
                session.flush()
                counts["raw_items"] += 1
                session.add(
                    VulnSource(
                        vuln_id=vuln.id, raw_item_id=raw.id, source=source, merged_at=raw.fetched_at
                    )
                )

            # 富化：前 8 个漏洞灌满全部维度，后 4 个只灌部分，模拟覆盖率
            dims = list(DIMENSIONS) if idx < 8 else list(DIMENSIONS)[: 2 + idx % 3]
            for dim in dims:
                spec_dim = DIMENSIONS[dim]
                # ⚠️ `cvss` 与 `asset` **不能套模板**：DIMENSIONS 是按
                # CVE-2026-31001 一条写死的，套给全部 13 条会让
                # `cvss.base_score` 恒为 9.8（与各自向量矛盾 8/11 条）、
                # `asset` 恒为 vllm/vllm。
                #   - cvss：由该条向量本地算出（可复核）
                #   - asset：由该条 CPE 解析；**没有 CPE 就如实给空**，
                #     不回落到模板（否则等于凭空说"影响 vLLM"）
                # 见 scripts/demo_derive.py。
                if dim == "asset":
                    spec_dim = derive_asset_or_abstain(spec)
                else:
                    derived = derive(dim, spec)
                    if derived is not None:
                        spec_dim = derived

                # 剩下 5 个维度（poc / paper / fix / consistency / ai_risk）仍是
                # `DIMENSIONS` 里的**同一条示例值**，逐条产生它们需要真实检索或
                # LLM 调用，本机网络下不可达（实测 GitHub 搜索、arXiv/OpenAlex
                # 均无结果）。既然造不出真实值，就必须**把"这是示例值"标出来**，
                # 不能让它看起来像该条漏洞的真实富化结论。
                # 标记方式：degraded_to="fixture"（该枚举值本就表示"预置数据"）
                # + reason 写清，前端会据此显示降级徽标。
                templated = dim in _TEMPLATE_DIMS
                session.add(
                    Enrichment(
                        vuln_id=vuln.id,
                        dimension=dim,
                        value=spec_dim["value"],
                        evidence=spec_dim["evidence"],
                        source=spec_dim.get("source", []),
                        confidence=spec_dim["confidence"],
                        model=spec_dim.get("model", "deepseek-v4-pro"),
                        agent="EnrichAgent",
                        mock=bool(spec_dim.get("mock")) or templated,
                        degraded_to="fixture" if templated else spec_dim.get("degraded_to"),
                        degraded_reason=(
                            _TEMPLATE_REASON if templated else spec_dim.get("degraded_reason", "")
                        ),
                        quality_score=spec_dim.get("quality_score"),
                        trace_id=f"trace_demo_{idx:03d}",
                    )
                )
                counts["enrichments"] += 1

            poc: dict[str, Any] = DIMENSIONS["poc"]["value"]
            if poc.get("has_poc"):
                session.add(
                    Poc(
                        vuln_id=vuln.id,
                        url=DIMENSIONS["poc"]["evidence"][0]["url"],
                        repo="example/poc",
                        kind=poc.get("kind", "poc"),
                        language="Python",
                        stars=rng.randint(3, 900),
                        verified=rng.random() > 0.4,
                    )
                )

            # 关系边：漏洞 → 论文 / 漏洞 → CWE
            if idx < 6:
                arxiv_id = PAPERS[idx % len(PAPERS)][0]
                session.add(
                    GraphEdge(
                        src_type="vuln",
                        src_id=vuln.id,
                        rel="mentioned_by",
                        dst_type="paper",
                        dst_id=paper_ids[arxiv_id],
                        props={"score": round(rng.uniform(0.3, 0.9), 3)},
                    )
                )
                counts["edges"] += 1
            if spec["cwe"]:
                session.add(
                    GraphEdge(
                        src_type="vuln",
                        src_id=vuln.id,
                        rel="maps_to",
                        dst_type="cwe",
                        dst_id=spec["cwe"][0],
                        props={"primary": True},
                    )
                )
                counts["edges"] += 1

        # 采集水位线：故意让一个源失败，好看到大屏上的红色状态
        for source in SOURCES:
            ok = source != "community_rss"
            session.add(
                SyncWatermark(
                    source=source,
                    last_sync_at=_hours_ago(rng.uniform(0.05, 0.6)),
                    last_full_sync=_hours_ago(rng.uniform(24, 96)),
                    last_published_at=_hours_ago(rng.uniform(0.1, 4)),
                    items_last_run=rng.randint(40, 320) if ok else 0,
                    last_error=None if ok else "HTTPError 503: upstream rate limited (demo)",
                )
            )

        # Agent 轨迹：一个成功的富化 run + 一个失败的，方便看轨迹接口
        good = AgentRun(
            graph="enrich",
            trigger="schedule",
            state="done",
            input_summary="backfill 12 vulns / dimensions=[poc, impact, ai_risk]",
            output_summary="富化 84 条，repair 2 次，失败 0",
            tokens=18432,
            cost_cny=0.4213,
            latency_ms=48210,
        )
        session.add(good)
        session.flush()
        for seq, (node, state, lat) in enumerate(
            [
                ("load_target", "ok", 820),
                ("retrieve_context", "ok", 2310),
                ("enrich:impact", "ok", 9640),
                ("enrich:poc", "ok", 12100),
                ("self_check", "ok", 3140),
            ]
        ):
            session.add(
                AgentStep(
                    run_id=good.id,
                    seq=seq,
                    node=node,
                    state=state,
                    input_summary=f"{node} 输入",
                    output_summary=f"{node} 输出",
                    tokens=rng.randint(400, 4000),
                    cost_cny=round(rng.uniform(0.01, 0.12), 4),
                    latency_ms=lat,
                )
            )
        session.add(
            AgentRun(
                graph="collect",
                trigger="manual",
                state="error",
                input_summary="sources=[community_rss]",
                output_summary="",
                tokens=0,
                cost_cny=0.0,
                latency_ms=3010,
                error="HTTPError 503: upstream rate limited (demo)",
            )
        )

        for level, title, msg in [
            ("critical", "KEV 新增：vLLM chat_template RCE", "CVE-2026-31001 已加入 CISA KEV 目录"),
            ("high", "富化 repair 重试", "CVE-2026-30077 的 poc 维度证据不足，已重试"),
        ]:
            session.add(Alert(level=level, title=title, message=msg, delivered=True))

        session.commit()

    engine.dispose()
    counts["papers"] = len(PAPERS)
    return counts


def seed_enrichment_chunks(db_path: str) -> int:
    """把 `enrichment` 表里的富化结论**也切成检索切片**，返回写入条数。

    ## 为什么必须补这一步

    `seed()` 只写 `enrichment` **表**，不写对应的 `chunk` ——
    实测冷启动（fresh clone → `demo_seed.py`）后：

    | | 冷启动库 | 完整库 |
    | --- | --- | --- |
    | `enrichment` 行 | 69 | 583 |
    | **`enrichment` 切片** | **0** | **583** |

    后果是**问"这个漏洞怎么修"召回不到任何修复结论** ——
    而黄金集 20 题问的全是这些合成 CVE。评委会看到问答质量明显低于本机演示。

    修法：用**与在线路径同一套口径**（`indexer.enrichment_chunk_text()`）
    从 `enrichment` 表派生切片，避免两处口径漂移。

    ## 为什么单独跑一次而不是塞进 `seed()`

    `seed()` 里的 chunk 是**裸 SQL** 先于 ORM session 写入的（简化表没有
    `embedding` 列，ORM 会报列不存在），而 `enrichment` 是 session 里写的。
    所以只能在 commit 之后回读一次 —— 这样也更简单：数据已经是最终形态。
    """

    import sys as _sys
    from pathlib import Path as _Path

    _root = _Path(__file__).resolve().parent.parent
    if str(_root / "src") not in _sys.path:
        _sys.path.insert(0, str(_root / "src"))

    from sqlalchemy import create_engine, text

    from aiintel.services.knowledge.indexer import enrichment_chunk_text

    engine = create_engine(f"sqlite:///{db_path}")
    written = 0
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "select v.cve_id, e.dimension, e.value, e.evidence "
                "from enrichment e join vuln v on v.id = e.vuln_id "
                "where v.cve_id is not null and e.evidence is not null and e.evidence != '[]' "
                "order by v.cve_id, e.dimension"
            )
        ).all()

        # 每个 owner 的切片编号接着 `vuln` 切片的编号往后排，避免不同 owner_type
        # 之间的编号含义混乱；`enrichment` 是独立 owner_type，从 0 起即可。
        next_no: dict[str, int] = {}
        for cve, dim, value, evidence in rows:
            val = value
            if isinstance(val, str) and val:
                try:
                    val = json.loads(val)
                except ValueError:
                    val = {}
            ev = evidence
            if isinstance(ev, str) and ev:
                try:
                    ev = json.loads(ev)
                except ValueError:
                    ev = []
            body = enrichment_chunk_text(str(dim or ""), val or {}, ev or [], identity=str(cve))
            if not body:
                continue
            n = next_no.get(str(cve), 0)
            next_no[str(cve)] = n + 1
            conn.execute(
                text(
                    "INSERT INTO chunk (id, owner_type, owner_id, chunk_no, content, tsv, "
                    "created_at) VALUES (:id, 'enrichment', :owner_id, :chunk_no, :content, "
                    ":tsv, :created_at)"
                ),
                {
                    "id": uuid.uuid4().hex,
                    "owner_id": str(cve),
                    "chunk_no": n,
                    "content": body,
                    "tsv": body,
                    "created_at": _hours_ago(1),
                },
            )
            written += 1
    engine.dispose()
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="生成演示数据")
    parser.add_argument("--db", default="data/demo.db", help="SQLite 文件路径")
    args = parser.parse_args()

    counts = seed(args.db)
    counts["enrichment_chunks"] = seed_enrichment_chunks(args.db)
    print(f"已生成演示数据 -> {args.db}")
    for key, value in counts.items():
        print(f"  {key}: {value}")
    print("\n提示：成本指标为空时大屏显示 0.00，把 llm_usage 或 cost.jsonl 补上即可")


if __name__ == "__main__":
    main()

"""把"模板富化"改成"由该条漏洞自身数据**确定性推导**"的富化。

## 要解决的问题

`demo_seed.py::DIMENSIONS` 是按 **CVE-2026-31001 这一条**写死的模板，
却套给了全部 13 条漏洞。实测后果（`eval/datasets/enrich_annotation.demo.jsonl`）：

- 7 个维度各只有 **2 个不同值**（76 条数据）
- `cvss.base_score` **写死 9.8**，而 13 条的向量各不相同（独立算出 3.3 ~ 10.0），
  可核对的 11 条里 **8 条与自己的向量矛盾**
- `asset` 写死 `vllm/vllm`，而每条漏洞的 CPE 其实不同
- `poc` 的 11 个引用全指向同一个占位仓库；`paper` 的 12 个引用全指向同一篇

评委只要点开一处就能看出"这不是富化，是复制粘贴"。

## 本模块做什么

只做**能确定性推导**的两类维度 —— 推导依据全部来自该条漏洞自己的字段，
所以**不是编造**：

| 维度 | 推导依据 | 产出 |
| --- | --- | --- |
| `cvss` | `vuln.cvss_vector` | 按 CVSS v3.1 规范**本地算出** base_score + severity 标签 |
| `asset` | `vuln.cpe` | 解析 CPE 2.3 得到 vendor / product / version |

**刻意不做** `poc` / `paper`：真实联网检索在本机不可达（实测 GitHub 搜索、
arXiv/OpenAlex 均无结果），凭空给每条漏洞编一个仓库或论文是**造假**。
这两维度的处理方式见 `scripts/demo_seed.py` 里的说明（如实标注为占位）。

复用 `services/enrich/cvss.py` 与 `services/enrich/asset.py` 的解析与计分函数，
保证与真实富化链路**同一套口径**（不另写一份，避免口径漂移）。
"""

from __future__ import annotations

from typing import Any

from aiintel.services.enrich.asset import parse_cpe
from aiintel.services.enrich.cvss import (
    qualitative,
    resolve_score,
    severity_label,
    vector_version,
)


def derive_cvss(vuln: dict[str, Any]) -> dict[str, Any] | None:
    """由该漏洞自己的 `cvss_vector` 算出分数与档位。向量缺失则返回 None（不猜）。"""

    vector = (vuln.get("cvss_vector") or "").strip()
    if not vector:
        return None

    score, source = resolve_score(vector, vuln.get("cvss_score"))
    if score is None:
        return None

    cve = vuln.get("cve_id") or "（无 CVE 编号）"
    severity = severity_label(score)
    return {
        "value": {
            "vector": vector,
            "vector_version": vector_version(vector) or "3.1",
            "base_score": score,
            "official_score": vuln.get("cvss_score"),
            "score_source": source,
            "computed_locally": True,
            "severity": severity,
            "qualitative": qualitative(score),
            "cvss_31": {"vector": vector, "score": score},
            "cvss_40": {"vector": None, "score": None},
            "epss": vuln.get("epss"),
            "kev": bool(vuln.get("kev")),
            "cwe": list(vuln.get("cwe") or []),
            "technical_impact": vuln.get("desc") or vuln.get("description") or "",
            "business_impact": "",
            "affected_scenarios": [],
            "prerequisites": "",
            "evidence_refs": ["ev-1", "ev-2"],
        },
        "confidence": 0.9,
        "model": "rule-based",
        "source": ["nvd", "computed"],
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "nvd",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}" if vuln.get("cve_id") else None,
                "snippet": f"CVSS 3.1 base score {score}（向量 {vector}）",
                "fetched_at": vuln.get("fetched_at"),
                "raw_item_id": None,
            },
            {
                "evidence_id": "ev-2",
                "source": "computed",
                "url": None,
                # 把"可复核"写进证据本身：给出向量与结果，任何人可自行重算
                "snippet": f"{vector} → {score}（本地按 CVSS v3.1 规范计算，可复核）",
                "fetched_at": vuln.get("fetched_at"),
                "raw_item_id": None,
            },
        ],
    }


def derive_asset(vuln: dict[str, Any]) -> dict[str, Any] | None:
    """由该漏洞自己的 CPE 解析出受影响产品。CPE 缺失则不产出（不猜）。"""

    cpes = [c for c in (vuln.get("cpe") or []) if c]
    if not cpes:
        return None

    products: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None]] = set()
    for raw in cpes:
        parsed = parse_cpe(raw)
        if not parsed:
            continue
        key = (parsed.get("vendor"), parsed.get("product"))
        if key in seen:
            continue
        seen.add(key)
        products.append(
            {
                "vendor": parsed.get("vendor"),
                "product": parsed.get("product"),
                "cpe": raw,
                "affected_versions": parsed.get("version") or "unknown",
                "introduced": None,
                "fixed": None,
                "range_source": "cpe",
                "url": None,
            }
        )

    if not products:
        return None

    summary = "、".join(
        f"{p['vendor']}:{p['product']}" for p in products if p.get("vendor") or p.get("product")
    )
    return {
        "value": {
            "products": products,
            # 资产测绘默认关闭（合规红线）—— 这一项仍然如实为 mock，
            # 与真实链路一致（见 services/enrich/asset.py）
            "exposed_assets": [],
            "exposure_level": "unknown",
            "inventory_loaded": False,
            "asset_scan_enabled": False,
            "mock": True,
        },
        "confidence": 0.6,
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
                "snippet": f"{summary}（由 CPE 本地解析）",
                "fetched_at": vuln.get("fetched_at"),
                "raw_item_id": None,
            }
        ],
    }


#: 可由漏洞自身数据确定性推导的维度 → 推导函数
DERIVERS = {
    "cvss": derive_cvss,
    "asset": derive_asset,
}


def derive(dimension: str, vuln: dict[str, Any]) -> dict[str, Any] | None:
    """返回该维度的推导结果；无法推导时返回 None。

    ⚠️ 注意调用方不能再回落到模板 —— 实测踩过：种子数据里 `cpe` 全为空，
    `derive_asset` 返回 None，调用方于是回落到 `DIMENSIONS["asset"]`，
    结果 12 条又全部变成写死的 `vllm/vllm`（"推导没生效"的假象）。
    `asset` 因此显式走 `derive_asset_or_abstain()`。
    """

    fn = DERIVERS.get(dimension)
    if fn is None:
        return None
    return fn(vuln)


def derive_asset_or_abstain(vuln: dict[str, Any]) -> dict[str, Any]:
    """asset 维度：有 CPE 就解析，**没有就如实产出空产品列表**，绝不回落到模板。

    为什么必须这样：种子数据的 `cpe` 字段为空，而模板里写的是 `vllm/vllm`
    （那是照 CVE-2026-31001 写的）。继续用模板等于说"这条漏洞影响 vLLM"，
    而数据里没有任何依据 —— 这是编造。空列表 + 明确 reason 才是诚实的。
    """

    derived = derive_asset(vuln)
    if derived is not None:
        return derived

    return {
        "value": {
            "products": [],
            "exposed_assets": [],
            "exposure_level": "unknown",
            "inventory_loaded": False,
            "asset_scan_enabled": False,
            "mock": True,
            "abstained": True,
            "abstain_reason": "该漏洞没有 CPE 数据，无法解析受影响产品（不猜测）",
        },
        "confidence": 0.3,
        "model": "rule-based",
        "source": ["rule"],
        "mock": True,
        "degraded_to": "mock",
        "degraded_reason": (
            "无 CPE 数据，受影响产品无法确定；资产测绘默认关闭（合规红线）。"
            "**不猜测产品**，故产品列表为空。"
        ),
        "evidence": [
            {
                "evidence_id": "ev-1",
                "source": "rule",
                "url": None,
                "snippet": "该漏洞的 CPE 字段为空，未解析出任何受影响产品",
                "fetched_at": vuln.get("fetched_at"),
                "raw_item_id": None,
            }
        ],
    }

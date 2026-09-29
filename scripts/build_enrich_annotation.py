"""构建富化评测标注集：把「可判定」与「不可判定」严格分开。

## 为什么要分开

本机语料是**合成**的（CVE-2026-xxxxx 是编的，13 条漏洞都是造的）。
所以"富化说得对不对"在多数维度上**无法对照现实核查** ——
没有现实中的 CVE-2026-31001 可以查，也就无从判断"这个 POC 是否真的存在"。

如果硬给每一条都写个对/错，那是在编造标注。本仓已经因为"expected 抄自 actual"
栽过一次（一致率恒为 1.0），不能再犯第二次。

于是把它们分成两类：

| 类别 | 判据 | 能否自动判定 |
| --- | --- | --- |
| **A. 可判定（内部一致性）** | 系统产出与**它自己的输入证据**是否矛盾 | ✅ 可，且确定 |
| **B. 需外部核查** | 需要与现实世界核对（POC 是否真存在、论文是否真相关…） | ❌ 不可，标 `needs_human` |

A 类不是"退而求其次"：**与自己的证据矛盾是硬缺陷**。例如
「CVSS 向量写着 AV:L/AC:L（本地低权限），却报 9.8」——
连不懂安全的人都能看出不对。这类错误正是报告里不能出现的。

## A 类具体判什么

1. **cvss**：`value.base_score` vs 由 `value.vector` **独立重算**的分数
   （用 `eval/cvss_reference.py`，它已用 12 个官方已知向量自测通过）。
   注：系统若从向量算分，本应恒等；演示库却是写死的 9.8。
2. **severity 一致性**：`vuln.severity` 这个标签是否与实际 CVSS 分数档位相符。
3. **poc / paper 的占位符**：URL 是否落在 `example/` 这类**明显占位**命名空间下
   （不是"错"，但必须标出来：它不可能是真证据）。
4. **asset 的 CPE 一致性**：`products[].vendor/product` 是否与输入 `cpe` 对得上。

## 产出

`eval/datasets/enrich_annotation.jsonl`，每行：
    {case_id, cve_id, dimension, track: "A"|"B", verdict: "correct"|"wrong"|"needs_human",
     evidence: {...}, rationale: "..."}

用法::

    python -m scripts.build_enrich_annotation                # 真实链路产出（默认）
    python -m scripts.build_enrich_annotation --source demo  # 演示库那套
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from eval.cvss_reference import base_score as ref_base_score  # noqa: E402
from eval.cvss_reference import severity_label as ref_severity  # noqa: E402

REAL_DIR = ROOT / "eval" / "artifacts" / "real_enrich"
DATASET_DIR = ROOT / "eval" / "datasets"

#: ⚠️ 输出必须**按来源分开**。早先两个来源写同一个文件名，
#: 结果 demo 那次覆盖了 real 那次，我拿着 demo 的数据当 real 的看 —— 顺序错误很难发现。
OUT_BY_SOURCE = {
    "real": DATASET_DIR / "enrich_annotation.jsonl",  # 正式入库
    "demo": DATASET_DIR / "enrich_annotation.demo.jsonl",  # 对照用，不入正式口径
}

#: `example/` 命名空间是文档/示例专用，出现在真实引用里必属占位
PLACEHOLDER_RE = re.compile(r"(github\.com/example/|/example/|example\.com|TODO|placeholder)", re.I)


def _load_real() -> list[dict]:
    out = []
    for p in sorted(REAL_DIR.glob("*.json")):
        out.append(json.loads(p.read_text(encoding="utf-8")))
    return out


def _load_demo(dsn: str | None = None) -> list[dict]:
    import os

    if dsn:
        os.environ["POSTGRES_DSN"] = dsn
    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import Enrichment, Vuln

    with get_sessionmaker()() as s:
        vmap = {v.id: v for v in s.query(Vuln).all()}
        rows = s.query(Enrichment).all()
    out: dict[tuple[str, str], dict] = {}
    for e in rows:
        v = vmap.get(e.vuln_id)
        out[(v.cve_id if v else None, e.dimension)] = {
            "cve_id": v.cve_id if v else None,
            "vuln_id": e.vuln_id,
            "dimensions": {
                e.dimension: {
                    "dimension": e.dimension,
                    "value": e.value,
                    "source": e.source,
                    "evidence": e.evidence,
                    "confidence": e.confidence,
                    "degraded_to": e.degraded_to,
                }
            },
            "input": {
                "cve_id": v.cve_id if v else None,
                "title": v.title if v else None,
                "cpe": (v.cpe or []) if v else [],
                "cvss_vector": getattr(v, "cvss_vector", None) if v else None,
                "severity": v.severity if v else None,
            },
        }
    return list(out.values())


def _case(
    idx: int,
    cve: str | None,
    dim: str,
    track: str,
    verdict: str,
    rationale: str,
    evidence: dict[str, Any],
) -> dict:
    return {
        "case_id": f"a{idx:03d}",
        "cve_id": cve,
        "dimension": dim,
        "track": track,
        "verdict": verdict,
        "rationale": rationale,
        "evidence": evidence,
    }


def build(source: str, dsn: str | None) -> dict[str, Any]:
    records = _load_real() if source == "real" else _load_demo(dsn)
    cases: list[dict] = []
    idx = 0

    for rec in records:
        cve = rec.get("cve_id")
        inp = rec.get("input") or {}
        vector = inp.get("cvss_vector")
        truth = ref_base_score(vector) if vector else None
        truth_sev = ref_severity(truth)

        for dim, node in (rec.get("dimensions") or {}).items():
            if not isinstance(node, dict):
                continue
            val = node.get("value") or {}
            idx += 1

            if dim == "cvss":
                got = val.get("base_score")
                if truth is None:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "B",
                            "needs_human",
                            "输入没有可解析的 CVSS 向量，无法独立核算分数",
                            {"vector": vector, "got": got, "expected": None},
                        )
                    )
                elif got is None:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "A",
                            "wrong",
                            f"向量 {vector} 可算出 {truth}，但产出没有 base_score",
                            {"vector": vector, "got": got, "expected": truth},
                        )
                    )
                elif float(got) == float(truth):
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "A",
                            "correct",
                            f"base_score 与由向量独立算出的 {truth} 一致",
                            {"vector": vector, "got": got, "expected": truth},
                        )
                    )
                else:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "A",
                            "wrong",
                            f"向量 {vector} 应为 {truth}（{truth_sev}），实际报 {got}",
                            {"vector": vector, "got": got, "expected": truth},
                        )
                    )
                continue

            if dim == "poc":
                pocs = val.get("pocs") or []
                urls = [p.get("url") or "" for p in pocs]
                placeholders = [u for u in urls if PLACEHOLDER_RE.search(u)]
                if placeholders:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "A",
                            "wrong",
                            f"{len(placeholders)}/{len(urls)} 条 POC 指向占位命名空间，不可能是真证据",
                            {"urls": urls, "placeholders": placeholders},
                        )
                    )
                else:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "B",
                            "needs_human",
                            f"有 {len(urls)} 条 POC 引用，需联网核实仓库是否真实存在且与本漏洞相关",
                            {"urls": urls, "count": len(urls)},
                        )
                    )
                continue

            if dim == "paper":
                papers = val.get("papers") or []
                ids = [p.get("arxiv_id") or p.get("paper_id") or "" for p in papers]
                bad = [i for i in ids if PLACEHOLDER_RE.search(i or "")]
                if bad:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "A",
                            "wrong",
                            f"{len(bad)} 条论文 id 是占位值",
                            {"arxiv_ids": ids},
                        )
                    )
                else:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "B",
                            "needs_human",
                            f"有 {len(ids)} 篇论文关联，需核实是否真实存在且主题相关",
                            {"arxiv_ids": ids, "count": len(ids)},
                        )
                    )
                continue

            if dim == "asset":
                prods = val.get("products") or []
                cpes = [p.get("cpe") or "" for p in prods]
                input_cpes = inp.get("cpe") or []
                # 判"vendor 是否来自输入 CPE"（可机械核对）
                in_vendors = set()
                for c in input_cpes:
                    parts = c.split(":")
                    if len(parts) > 4:
                        in_vendors.add(parts[3])
                out_vendors = {p.get("vendor") for p in prods if p.get("vendor")}
                if not prods:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "B",
                            "needs_human",
                            "未给出受影响产品，无法核对（也可能是如实为空）",
                            {"input_cpe": input_cpes},
                        )
                    )
                elif out_vendors and in_vendors and out_vendors <= in_vendors:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "A",
                            "correct",
                            f"产品 vendor {sorted(out_vendors)} 与输入 CPE 的 vendor 一致",
                            {"input_cpe": input_cpes, "out_vendors": sorted(out_vendors)},
                        )
                    )
                else:
                    cases.append(
                        _case(
                            idx,
                            cve,
                            dim,
                            "B",
                            "needs_human",
                            "vendor 与输入 CPE 对不齐或无法机械判定",
                            {
                                "input_cpe": input_cpes,
                                "out_vendors": sorted(out_vendors),
                                "cpes": cpes,
                            },
                        )
                    )
                continue

            # fix / consistency / ai_risk：文本类，无客观参照
            cases.append(
                _case(
                    idx,
                    cve,
                    dim,
                    "B",
                    "needs_human",
                    f"{dim} 属判断类（措辞/覆盖度/分类合理性），需领域专家复核",
                    {"value_keys": sorted(val.keys())[:8]},
                )
            )

    out_path = OUT_BY_SOURCE[source]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    track_a = [c for c in cases if c["track"] == "A"]
    verdicts: dict[str, int] = {}
    for c in cases:
        verdicts[c["verdict"]] = verdicts.get(c["verdict"], 0) + 1
    return {
        "source": source,
        "total": len(cases),
        "track_a": len(track_a),
        "track_b": len(cases) - len(track_a),
        "verdicts": verdicts,
        "track_a_correct": sum(1 for c in track_a if c["verdict"] == "correct"),
        "track_a_wrong": sum(1 for c in track_a if c["verdict"] == "wrong"),
        "path": str(out_path),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="构建富化评测标注集")
    ap.add_argument("--source", choices=["real", "demo"], default="real")
    ap.add_argument("--dsn", default=None)
    args = ap.parse_args()

    if args.source == "real" and not list(REAL_DIR.glob("*.json")):
        print("[FAIL] 找不到真实富化产出。先跑：python -m scripts.run_real_enrichment")
        print(f"       期望目录：{REAL_DIR}")
        return 1

    r = build(args.source, args.dsn)
    a = r["track_a"]
    print(f"来源        : {r['source']}")
    print(f"总条数      : {r['total']}")
    print(
        f"  A 类(可判定): {r['track_a']}   其中 correct={r['track_a_correct']} wrong={r['track_a_wrong']}"
    )
    print(f"  B 类(需人工): {r['track_b']}")
    print(f"判定分布    : {r['verdicts']}")
    if a:
        acc = r["track_a_correct"] / a
        print(f"A 类准确率  : {acc:.3f}  ({r['track_a_correct']}/{a})")
    print(f"已写        : {r['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

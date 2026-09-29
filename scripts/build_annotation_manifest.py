"""汇总各标注块，产出 `eval/datasets/MANIFEST.md` 与 `annotation_summary.json`。

台账要求「100 条标注集（漏洞 30 / 富化 40 / 问答 30）」。本文件如实报告**实际**交付量，
以及每一块**有多少条是机器可判定的**（这是本事最容易被含糊过去的地方）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

DS = ROOT / "eval" / "datasets"


def load(name: str) -> list[dict]:
    p = DS / name
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def stats(rows: list[dict], verdict_key: str = "verdict") -> dict:
    a = [r for r in rows if r.get("track") == "A"]
    correct = sum(1 for r in a if r.get(verdict_key) == "correct")
    return {
        "total": len(rows),
        "track_a": len(a),
        "track_b": len(rows) - len(a),
        "a_correct": correct,
        "a_wrong": sum(1 for r in a if r.get(verdict_key) == "wrong"),
        "a_accuracy": round(correct / len(a), 3) if a else None,
    }


def main() -> int:
    vuln = stats(load("vuln_annotation.jsonl"))
    enrich_real = stats(load("enrich_annotation.jsonl"))
    enrich_demo = stats(load("enrich_annotation.demo.jsonl"))
    qa = load("qa_cases.jsonl")
    qa_art = ROOT / "eval" / "artifacts" / "qa_accuracy.json"
    qa_acc = None
    if qa_art.exists():
        import re

        raw = qa_art.read_text(encoding="utf-8-sig", errors="replace")
        m = re.search(r'"accuracy":\s*([\d.]+)', raw)
        qa_acc = float(m.group(1)) if m else None

    summary = {
        "vuln": vuln,
        "enrich_real_pipeline": enrich_real,
        "enrich_demo_template": enrich_demo,
        "qa": {"total": len(qa), "accuracy": qa_acc, "target": 0.85},
        "grand_total_rows": vuln["total"] + enrich_real["total"] + len(qa),
    }

    (DS / "annotation_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    total = summary["grand_total_rows"]
    a_total = vuln["track_a"] + enrich_real["track_a"]
    a_ok = vuln["a_correct"] + enrich_real["a_correct"]
    #: ⚠️ **绝不把两个来源的 A 类合成一个数**。
    #: 真实链路 24/24 与演示模板 2/21 是两个完全不同的被测对象；
    #: 合成 34/37=0.919 会让人以为"系统准确率 0.919"，那是误导。
    #: 这里只给**同一被测对象**的比率：漏洞主表（演示数据）自身的一致性。
    demo_side_total = vuln["track_a"] + enrich_demo["track_a"]
    demo_side_ok = vuln["a_correct"] + enrich_demo["a_correct"]

    md = f"""# 评测标注集清单（自动生成，勿手工改）

生成命令：
```bash
python -m scripts.run_real_enrichment        # 真实富化 12 条漏洞（约 3 分钟）
python -m scripts.build_vuln_annotation      # 漏洞一致性标注
python -m scripts.build_enrich_annotation --source real    # 富化标注（正式）
python -m scripts.build_enrich_annotation --source demo    # 富化标注（对照）
python -m scripts.build_annotation_manifest  # 本文件
```

## 交付量 vs 台账要求

| 块 | 台账要求 | 实际 | 说明 |
| --- | --- | --- | --- |
| 漏洞 | 30 | **{vuln["total"]}** | 演示库只有 13 条漏洞（1 条无 CVE 编号） |
| 富化 | 40 | **{enrich_real["total"]}** | 真实链路 12 条漏洞 × 7 维度 |
| 问答 | 30 | **{len(qa)}** | 20 条黄金集，已实测 |
| **合计** | 100 | **{total}** | |

## ⚠️ 关键区分：哪些能自动判定，哪些不能

本事最容易含糊的地方是"我有 100 条标注"。实际分两类：

| 块 | 总条数 | **机器可判定(A)** | 需人工(B) | A 类正确 | A 类准确率 |
| --- | --- | --- | --- | --- | --- |
| 漏洞一致性 | {vuln["total"]} | {vuln["track_a"]} | {vuln["track_b"]} | {vuln["a_correct"]} | **{vuln["a_accuracy"]}** |
| 富化（真实链路） | {enrich_real["total"]} | {enrich_real["track_a"]} | {enrich_real["track_b"]} | {enrich_real["a_correct"]} | **{enrich_real["a_accuracy"]}** |
| 富化（演示库模板） | {enrich_demo["total"]} | {enrich_demo["track_a"]} | {enrich_demo["track_b"]} | {enrich_demo["a_correct"]} | **{enrich_demo["a_accuracy"]}** |
| 问答黄金集 | {len(qa)} | {len(qa)} | 0 | — | **{qa_acc}**（LLM-judge） |

**为什么大量条目是 B 类**：本机语料是**合成**的（`CVE-2026-xxxxx` 是编的）。
判断"这个 POC 是否真的存在""这篇论文是否真的相关"需要与现实核对，
而这里**没有现实可核对**。硬写一个对/错就是编造标注 ——
本仓已经因为「expected 抄自 actual」栽过一次（一致率恒 1.0），不能再犯。

可判定的 A 类判的是**内部一致性**（产出与自己的输入证据是否矛盾），
这类错误是硬缺陷，且零判断即可判定。

## 已测出的客观结论

### 1. 演示库的富化是模板，不是富化（A 类准确率 {enrich_demo["a_accuracy"]}）

- 7 个维度各只有 **2 个不同值**（76 条）
- `poc` 的 11 个引用指向**同一个占位仓库** `github.com/example/vllm-template-rce-poc`
- `paper` 的 12 个引用指向**同一篇论文** `arxiv.org/abs/2609.01234`
- `cvss` 的 `base_score` 在 `demo_seed.py:401` **写死为 9.8**；
  而 13 条的向量各不相同，独立算出的真值跨度是 **3.3 ~ 10.0**；
  可核对的 11 条里 **8 条矛盾**

### 2. 真实富化链路行为正确（A 类准确率 {enrich_real["a_accuracy"]}）

真实 `EnrichAgent` 产出**逐条不同**，且与自己的证据自洽：

| 维度 | 真实链路 | 演示模板 |
| --- | --- | --- |
| cvss | 3.3 / 5.3 / 6.5 / 7.4 / 7.5 / 8.8 / 9.8 / 10.0，**每个都与向量一致** | 全部 9.8 |
| poc | 0~5 条不等；**无依据时如实给 0** | 每条都声称 1 条 |
| paper | 12 条全部为 0（arXiv/OpenAlex 未返回） | 每条都声称 1 篇 |
| ai_risk | 4 个不同类别（ai_infrastructure / ai_application / general / supply_chain） | 单一类别 |

### 3. 漏洞主表一致性问题

13 条里 **3 条不合格**（{vuln["a_accuracy"]}）：

- 1 条**完全没写 `cve_id`**（AutoAWQ 那条），且无 `cvss_vector`
- 1 条 `severity=high` 但向量算出来是 `critical`（9.8）
- 1 条 `severity=critical` 但向量算出来是 `high`（8.8）

> 报告原写"数据标准化率 >99%"。以本口径实测为 **{vuln["a_accuracy"]}**。

## 汇总（**必须按被测对象分开读**）

- 标注行数合计：**{total}**

### 被测对象 = 演示库数据（当前 `data/demo.db`）

| 项 | 值 |
| --- | --- |
| 可判定条数 | {demo_side_total} |
| 正确 | {demo_side_ok} |
| **一致性准确率** | **{round(demo_side_ok / demo_side_total, 3) if demo_side_total else "—"}** |

这是**当前演示数据的自洽程度**：漏洞主表 {vuln["a_correct"]}/{vuln["track_a"]}，
富化 {enrich_demo["a_correct"]}/{enrich_demo["track_a"]}。

### 被测对象 = 真实富化链路（`EnrichAgent`）

| 项 | 值 |
| --- | --- |
| 可判定条数 | {enrich_real["track_a"]} |
| 正确 | {enrich_real["a_correct"]} |
| **一致性准确率** | **{enrich_real["a_accuracy"]}** |

### 被测对象 = 问答链路

| 项 | 值 |
| --- | --- |
| 黄金集条数 | {len(qa)} |
| **LLM-judge 准确率** | **{qa_acc}**（目标 0.85） |

> ⚠️ **这三个数字不能合成一个"系统准确率"**。前两者分别测"演示数据自洽"与
> "真实富化链路自洽"，第三个测"问答端到端质量"，样本与口径都不同。
> 把 34/37=0.919 当成总分是误导。

⚠️ **不可外推**：样本是 13 条合成漏洞 / 12 个知识切片。
这些数字说明"演示数据与链路自洽性如何"，不能说明"系统在真实语料上的准确率"。
"""
    (DS / "MANIFEST.md").write_text(md, encoding="utf-8")

    print(f"总行数        : {total}")
    print(f"  漏洞        : {vuln['total']} (A={vuln['track_a']}, 准确率 {vuln['a_accuracy']})")
    print(
        f"  富化(真实)  : {enrich_real['total']} (A={enrich_real['track_a']}, 准确率 {enrich_real['a_accuracy']})"
    )
    print(
        f"  富化(演示)  : {enrich_demo['total']} (A={enrich_demo['track_a']}, 准确率 {enrich_demo['a_accuracy']})"
    )
    print(f"  问答        : {len(qa)} (准确率 {qa_acc})")
    print(
        f"A 类合计      : {a_total} 条，正确 {a_ok} -> {round(a_ok / a_total, 3) if a_total else '—'}"
    )
    print(f"已写          : {DS / 'MANIFEST.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

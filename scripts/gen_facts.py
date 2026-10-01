"""生成 `docs/FACTS.md` —— 全仓数字的**单一来源**。

## 为什么

这些数字（库有多少条、富化覆盖多少、切片多少）此前在
`docs/情况.md`、`docs/演示口径说明.md`、`docs/交接说明.md` 里**各写了一遍**。
重复必然漂移 —— 实测已经漂了：同一份 `演示口径说明.md` 里，
第 31 行写"94 / 1451"、第 142 行还写着"46 条"。

## 机制

- **唯一计算处**：`scripts/check_db_after_ingest.py::snapshot()`（实时查库）；
- **唯一数字文件**：`docs/FACTS.md`（本脚本生成，带时间戳）；
- **防漂移**：`tests/test_docs_facts.py` 断言其它文档里**不再手写**这些数字，
  只允许引用 `FACTS.md`。

改数据后跑一次：

    python -m scripts.gen_facts          # 刷新 docs/FACTS.md
    pytest tests/test_docs_facts.py      # 确认没有文档还在手写旧数字
"""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "FACTS.md"

#: 数字键 → (中文名, 说明)
LABELS: dict[str, tuple[str, str]] = {
    "vuln": ("漏洞总数", "`vuln` 表行数"),
    "vuln_from_raw": ("真实采集", "**判据**：`raw_item` 里有同 `external_id`"),
    "vuln_preset": ("演示预置", "无 `raw_item` 支撑（`demo_seed.py` 写入的样本）"),
    "raw_item": ("原始条目", "`raw_item` 表行数（证据链起点）"),
    "chunk": ("检索切片", "`chunk` 表行数"),
    "chunk_enrichment": ("富化结论切片", "`owner_type='enrichment'` 的切片数"),
    "vuln_chunk_with_own_id": ("切片含自身编号", "按 CVE 编号提问能检到该漏洞自己的前提"),
    "enrichment_rows": ("富化行数", "`enrichment` 表行数（一行 = 一维）"),
    "vuln_enriched": ("已富化漏洞", "至少有 1 维富化的漏洞数"),
    "vuln_enriched_real": ("其中真实采集", "已富化 ∩ 真实采集"),
    "enrichment_indexed": ("富化已进检索空间", "富化结论能被问答召回的漏洞数"),
    "enrichment_index_gap": ("富化索引缺口", "**必须为 0**：>0 说明有结论检不到"),
    "graph_edge": ("关系边", "`graph_edge` 表行数（按 CWE 自动连）"),
    "vuln_source": ("来源关联", "`vuln_source` 表行数"),
    "vuln_no_cve_id": ("缺 cve_id", "**必须为 0**（红线：脏数据不进底座）"),
    "vuln_no_severity": ("severity 缺失", "`null` 或 `unknown`"),
    "raw_no_external_id": ("raw 缺 external_id", "**必须为 0**（证据链断裂）"),
}


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ("git", *args), cwd=ROOT, capture_output=True, text=True, encoding="utf-8"
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def render(snap: dict[str, int]) -> str:
    now = datetime.now(UTC).astimezone().strftime("%Y-%m-%d %H:%M")
    head = _git("log", "-1", "--format=%h  %s") or "(unknown)"
    branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "(unknown)"

    pct = snap["vuln_enriched_pct_x10"] / 10
    lines = [
        "# FACTS —— 全仓数字的单一来源",
        "",
        "> ⚠️ **本文件由脚本生成，请勿手改。**",
        "> 刷新：`python -m scripts.gen_facts`",
        "> 校验：`pytest tests/test_docs_facts.py`",
        ">",
        "> **其它文档不要手写这些数字**，改为「见 `docs/FACTS.md`」。",
        "> 原因：同一组数字曾分散在 3 份文档里各写一遍，实测已经漂移",
        "> （`演示口径说明.md` 第 31 行写 94、第 142 行还写 46）。",
        "",
        f"- 生成时间：**{now}**",
        f"- 分支 / HEAD：`{branch}` · `{head}`",
        "- 库：`POSTGRES_DSN` 指向的演示库（`data/demo.db`）",
        "",
        "## 一、数据总量",
        "",
        "| 项 | 值 | 说明 |",
        "| --- | --- | --- |",
    ]

    def row(key: str) -> str:
        label, desc = LABELS[key]
        return f"| **{label}** | **{snap[key]}** | {desc} |"

    for key in (
        "vuln",
        "vuln_from_raw",
        "vuln_preset",
        "raw_item",
        "chunk",
        "chunk_enrichment",
        "vuln_chunk_with_own_id",
    ):
        lines.append(row(key))

    lines += [
        "",
        "## 二、富化覆盖",
        "",
        "| 项 | 值 | 说明 |",
        "| --- | --- | --- |",
        f"| 覆盖率 | **{pct}%**（{snap['vuln_enriched']} / {snap['vuln']}） | "
        "按演示价值抽样，非全量 |",
    ]
    for key in ("vuln_enriched", "vuln_enriched_real", "enrichment_rows"):
        lines.append(row(key))

    gap = snap["enrichment_index_gap"]
    lines += [
        "",
        "## 三、一致性红线（必须满足）",
        "",
        "| 检查 | 值 | 期望 |",
        "| --- | --- | --- |",
        f"| 富化索引缺口 | **{gap}** | `0`（>0 表示有结论检不到） |",
        f"| 缺 `cve_id` | **{snap['vuln_no_cve_id']}** | `0` |",
        f"| `raw_item` 缺 `external_id` | **{snap['raw_no_external_id']}** | `0` |",
        f"| 富化已进检索空间 | **{snap['enrichment_indexed']}** | 等于「已富化漏洞」 |",
        "",
        "## 四、其它",
        "",
        "| 项 | 值 | 说明 |",
        "| --- | --- | --- |",
        row("graph_edge"),
        row("vuln_source"),
        row("vuln_no_severity"),
        "",
        "## 五、判据说明（别用错）",
        "",
        "- **不能用 `cve_id like 'CVE-2026-%'` 判断\"这是合成数据\"** ——",
        "  真实 NVD 里也有大量 2026 年 CVE（实测 774 条中 763 条为真实采集）。",
        "  唯一可靠判据是**证据链**：`raw_item` 里有无同 `external_id`。",
        "- `published_at` 在 SQLite 上读回无 tzinfo 是**存储介质假象**",
        "  （`_iso_utc()` 读回时补 UTC），**不算脏数据**。",
        "",
        "## 六、不在本文件里的数字",
        "",
        "以下数字来自**评测实测**而非实时查库，因此由",
        "`eval/datasets/MANIFEST.md` 与 `docs/评测实测结果.md` 负责，",
        "本文件不重复（避免又一处漂移）：",
        "",
        "- 问答质量（QA 分数、单跳/多跳/拒答分解）",
        "- 引用覆盖率、`degraded_to` 比例",
        "- 延迟分位（P50/P95）",
        "- LLM 成本（¥）",
        "",
        '> ⚠️ **不要把这些加总成"系统准确率"** —— 它们是不同口径的独立指标。',
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    from scripts.check_db_after_ingest import snapshot

    snap = snapshot()
    text = render(snap)
    OUT.write_text(text, encoding="utf-8")

    print(f"✓ 已生成 {OUT.relative_to(ROOT)}")
    print(f"  vuln {snap['vuln']}（真实 {snap['vuln_from_raw']} + 预置 {snap['vuln_preset']}）")
    print(
        f"  富化 {snap['vuln_enriched']} / {snap['vuln']}"
        f"（{snap['vuln_enriched_pct_x10'] / 10}%），索引缺口 {snap['enrichment_index_gap']}"
    )
    if snap["enrichment_index_gap"] or snap["vuln_no_cve_id"] or snap["raw_no_external_id"]:
        print("  ⛔ 一致性红线未满足，请先修数据再引用本文件")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

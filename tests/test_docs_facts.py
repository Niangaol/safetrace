"""防文档漂移：数字必须来自 `docs/FACTS.md`，不许在别处手写。

## 这条测试守的是什么

同一组数字（库有多少条、富化覆盖多少、切片多少）此前在
`docs/情况.md`、`docs/演示口径说明.md`、`docs/交接说明.md` 里**各写了一遍**，
于是必然漂移 —— 实测已经漂了：同一份 `演示口径说明.md` 里，
第 31 行写"94 / 1451"、第 142 行还写着"已富化 46 条"。

**收敛后的规矩**：
- **唯一计算处** = `scripts/check_db_after_ingest.py::snapshot()`；
- **唯一数字文件** = `docs/FACTS.md`（由 `scripts/gen_facts.py` 生成）；
- 其它文档只说"见 `docs/FACTS.md`"，**不写具体数字**。

## 为什么用"下限阈值"而不是精确值

数字会随采集增长（1440 → 更多）。若测试断言"必须等于 1440"，
每次合法增长都要改测试 —— 那就又变成一处要维护的硬编码。

所以这里断言的是**量级红线**（防止把 94 写成 46、把 1440 写成 12 这类
数量级错误），而不是精确相等。精确值由 `docs/FACTS.md` 负责。

## 例外

`docs/交接说明.md` 是**审计轨迹**：它必须记住"当时是多少"
（否则复盘"46 → 94 怎么来的"就没了依据）。
所以只检查**自 §14.17 起**的新增小节 —— 那之后才立的规矩。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

#: 这些文档是"面向评委"的现行口径，**不得手写具体数字**
LIVE_DOCS = ("情况.md", "演示口径说明.md")

#: 必须引用单一来源的文件
FACTS = DOCS / "FACTS.md"

#: 审计轨迹：只检查自该小节起的内容
AUDIT_DOC = "交接说明.md"
AUDIT_FROM = "### 14.17"

#: 禁写的数量级阈值：文档里出现这些数字就是在手写库容（应改为见 FACTS.md）
#: 取"下限"而非精确值 —— 见模块 docstring 的说明。
FORBIDDEN_MIN = 1000

#: ⚠️ **假阳性防护**：CVE 编号里的流水号（`CVE-2026-102697` 的 `102697`）
#: 不是库容数字。实测第一次跑就把 3 条 CVE 编号误报成违规 —— 必须先剥掉再匹配。
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

_NUM = re.compile(r"(?<![\d.])(\d{4,})(?![\d.])")

#: 允许保留历史值的**显式**标注（审计轨迹要记住"当时是多少"）。
#: 必须显式标，不能靠猜 —— 否则迟早有人拿它当后门绕过检查。
#: 同时认可带 markdown 强调符的写法（`（**历史值**）`）——
#: 实现方式是先剥掉 `*` 再匹配，所以两种写法都命中。
_HISTORICAL = ("（历史值）", "(历史值)", "<!-- historical -->")

#: 反引号内容视为**代码/配置**，不是"库容数字"。
#: 实测假阳性来源：`` `max_tokens=2500` ``、`` `102697` ``。
_CODE_SPAN = re.compile(r"`[^`]*`")

#: 年份不算库容数字（`2023 年后`、`2026-10-01`）。
_YEAR_MIN, _YEAR_MAX = 1960, 2100


def _has_historical(line: str) -> bool:
    """是否带显式历史标注（容忍 markdown 强调符）。"""

    stripped = line.replace("**", "").replace("*", "")
    return any(mark in stripped for mark in _HISTORICAL)


def _facts_numbers() -> set[str]:
    assert FACTS.exists(), (
        "docs/FACTS.md 不存在 —— 先跑 `python -m scripts.gen_facts`（数字的唯一来源）"
    )
    return set(_NUM.findall(FACTS.read_text(encoding="utf-8")))


def _violations(path: Path, text: str, allowed: set[str]) -> list[tuple[int, str, str]]:
    """找出"手写的库容数字"：≥1000 且不在 FACTS.md 的当前值里。

    三类假阳性已显式排除（均为实测踩到）：
    1. **CVE 编号**里的流水号（`CVE-2026-102697`）；
    2. **反引号内的配置值**（`` `max_tokens=2500` ``）；
    3. **年份**（`2023 年后`）。
    """

    out: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        # 跳过代码块、引用块、带显式历史标注的行
        if line.lstrip().startswith(("#", ">", "```")):
            continue
        if _has_historical(line):
            continue
        haystack = _CODE_SPAN.sub(" ", line)
        haystack = _CVE_ID.sub("CVE", haystack)
        for num in _NUM.findall(haystack):
            value = int(num)
            if value < FORBIDDEN_MIN or _YEAR_MIN <= value <= _YEAR_MAX:
                continue
            if num in allowed:
                continue
            out.append((lineno, num, line.strip()[:96]))
    return out


@pytest.mark.parametrize("name", LIVE_DOCS)
def test_live_docs_have_no_handwritten_counts(name: str) -> None:
    """**核心**：面向评委的文档不许手写库容数字（只能引用 FACTS.md）。"""

    path = DOCS / name
    if not path.exists():
        pytest.skip(f"{name} 不存在")

    allowed = _facts_numbers()
    bad = _violations(path, path.read_text(encoding="utf-8"), allowed)
    # FACTS.md 的值是"当前真值"，允许出现；陈旧值（如 46、1709）必须报错
    assert not bad, (
        f"`docs/{name}` 里出现手写的库容数字，应改为「见 docs/FACTS.md」：\n"
        + "\n".join(f"  L{n}: {num}  ← {snippet}" for n, num, snippet in bad[:10])
    )


def test_live_docs_reference_facts() -> None:
    """既然不许手写，就必须**指向**单一来源（否则读者无从查证）。"""

    for name in LIVE_DOCS:
        path = DOCS / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        assert "FACTS.md" in text, f"`docs/{name}` 未引用 docs/FACTS.md"


def test_audit_doc_new_sections_reference_facts() -> None:
    """`交接说明.md` 是审计轨迹（保留历史值），但**自 §14.17 起**必须引用单一来源。"""

    path = DOCS / AUDIT_DOC
    if not path.exists():
        pytest.skip(f"{AUDIT_DOC} 不存在")
    text = path.read_text(encoding="utf-8")
    if AUDIT_FROM not in text:
        pytest.skip(f"{AUDIT_DOC} 里没有 {AUDIT_FROM}")

    tail = text.split(AUDIT_FROM, 1)[1]
    assert "FACTS.md" in tail, (
        f"`{AUDIT_FROM}` 之后的小节必须引用 docs/FACTS.md（新规矩自该节生效）"
    )
    allowed = _facts_numbers()
    bad = _violations(path, tail, allowed)
    assert not bad, f"`{AUDIT_DOC}` 自 {AUDIT_FROM} 起出现手写库容数字：\n" + "\n".join(
        f"  {num}  ← {snippet}" for _n, num, snippet in bad[:10]
    )


# ---------------------------------------------------------------- 一致性红线


def test_facts_consistency_redlines_hold() -> None:
    """FACTS.md 里的三项一致性红线必须满足（缺点 = 数据真有问题）。"""

    from scripts.check_db_after_ingest import snapshot

    snap = snapshot()
    assert snap["enrichment_index_gap"] == 0, (
        f'有 {snap["enrichment_index_gap"]} 个漏洞的富化结论进不了检索空间（问"怎么修"会召回不到）'
    )
    assert snap["vuln_no_cve_id"] == 0, (
        f"{snap['vuln_no_cve_id']} 条漏洞缺 cve_id（红线：脏数据不进底座）"
    )
    assert snap["raw_no_external_id"] == 0, "raw_item 缺 external_id，证据链断裂"
    assert snap["enrichment_indexed"] == snap["vuln_enriched"], (
        "「富化已进检索空间」应等于「已富化漏洞」"
    )


def test_facts_file_is_fresh() -> None:
    """FACTS.md 不能与实时库脱节（忘了跑 gen_facts 时给出可操作的报错）。"""

    from scripts.check_db_after_ingest import snapshot

    snap = snapshot()
    text = FACTS.read_text(encoding="utf-8")
    # 抽查几个关键值是否出现在文件里
    for key in ("vuln", "vuln_from_raw", "vuln_enriched", "chunk_enrichment"):
        assert str(snap[key]) in text, (
            f"`docs/FACTS.md` 里找不到最新值 {key}={snap[key]} —— "
            "数据变了但没刷新，请跑 `python -m scripts.gen_facts`"
        )

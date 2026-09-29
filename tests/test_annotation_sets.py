"""标注集完整性测试。

**重点不是"文件存在"，而是防止退化成"自证式标注"**：
本仓曾出现过 `enrich_cases.jsonl` 的 expected 抄自 actual，一致率恒为 1.0，
看起来像"准确率 100%"。所以这里明确断言：

1. 标注文件的 expected/verdict **不来自被测系统的产出**（用独立实现判定）；
2. 每条 A 类判定都必须带可复核的证据字段；
3. `eval/cvss_reference.py` 的独立实现要与 12 个官方已知向量吻合
   （否则"标准答案"本身不可信）；
4. 回归基线文件必须带 `caveat` 说明（防止被当成准确率）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DS = ROOT / "eval" / "datasets"


def _load(name: str) -> list[dict]:
    p = DS / name
    if not p.exists():
        pytest.skip(f"缺 {name}")
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_cvss_reference_matches_official_known_vectors() -> None:
    """独立实现的正确性是整个标注的可信度前提。"""

    from eval.cvss_reference import KNOWN_VECTORS, base_score

    bad = [(v, e, base_score(v)) for v, e in KNOWN_VECTORS if base_score(v) != e]
    assert not bad, f"独立 CVSS 实现与已知值不符: {bad}"


def test_cvss_reference_is_independent_of_system_module() -> None:
    """必须与被测模块是两个来源（否则等于自证）。

    判据看**实际 import**，不是看注释里有没有提到模块名
    （参考实现的 docstring 本来就会说明"不复用被测模块"）。
    """

    import ast
    import inspect

    import eval.cvss_reference as ref

    import aiintel.services.enrich.cvss as sysmod

    tree = ast.parse(inspect.getsource(ref))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    offenders = [m for m in imported if "aiintel" in m]
    assert not offenders, f"独立实现不应 import 被测模块，实际: {offenders}"

    # 两者对同一向量应给出一致结果（各自独立算，结果吻合才可信）
    vec = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert ref.base_score(vec) == sysmod.resolve_score(vec, None)[0]


def test_vuln_annotation_verdicts_are_traceable() -> None:
    rows = _load("vuln_annotation.jsonl")
    assert rows, "漏洞标注集为空"
    for r in rows:
        assert r["case_id"] and r["verdict"] in {"correct", "wrong", "needs_human"}
        assert r.get("checks"), f"{r['case_id']} 没有 checks，判定不可复核"
        if r["verdict"] == "wrong":
            failed = [c for c in r["checks"] if not c["ok"]]
            assert failed, f"{r['case_id']} 判为 wrong 但没有失败项"


def test_enrich_annotation_has_both_tracks_and_evidence() -> None:
    rows = _load("enrich_annotation.jsonl")
    assert rows, "富化标注集为空"
    tracks = {r["track"] for r in rows}
    assert tracks <= {"A", "B"}, f"未知轨道: {tracks}"
    for r in rows:
        assert r["verdict"] in {"correct", "wrong", "needs_human"}
        # A 类判定必须说明理由，且理由里要有具体数字/向量，能被人复核
        if r["track"] == "A" and r["verdict"] != "needs_human":
            assert r.get("rationale"), f"{r['case_id']} 缺 rationale"
            assert r.get("evidence"), f"{r['case_id']} 缺 evidence"


def test_enrich_annotation_is_not_self_referential() -> None:
    """A 类里判 correct 的 cvss 条目，其 expected 必须等于**独立实现**算出的值。

    如果将来有人把 expected 改成"抄系统输出"，这条会失败。
    """

    from eval.cvss_reference import base_score

    rows = [
        r
        for r in _load("enrich_annotation.jsonl")
        if r["dimension"] == "cvss" and r["track"] == "A"
    ]
    checked = 0
    for r in rows:
        ev = r["evidence"]
        vec, expect = ev.get("vector"), ev.get("expected")
        if not vec or expect is None:
            continue
        assert base_score(vec) == expect, (
            f"{r['case_id']}: evidence.expected={expect} 与独立实现算出的 {base_score(vec)} 不符"
        )
        checked += 1
    assert checked > 0, "没有任何可校验的 cvss 条目，测试形同虚设"


def test_regression_baseline_declares_its_caveat() -> None:
    """回归基线必须自带口径警告，防止被当成"富化准确率"。"""

    from eval.enrich_accuracy import score_cases

    cases = [{"case_id": "x", "dimension": "poc", "expected": {"poc": True}}]
    actuals = {"x": {"value": {"pocs": [{"url": "u"}]}}}
    result = score_cases(cases, actuals)
    assert "caveat" in result, "回归基线缺少口径警告"
    assert "回归基线" in result["caveat"]

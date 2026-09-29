"""独立的 CVSS v3.1 基础分实现 —— **刻意不复用 `aiintel.services.enrich.cvss`**。

为什么必须独立：如果标注的"正确答案"用被测系统自己的函数算出来，
那评测就变成"系统与自己一致"，永远 100%，毫无意义（本仓已栽过一次：
`enrich_cases.jsonl` 的 expected 抄自 actual，一致率恒为 1.0）。

本实现直接照 CVSS v3.1 规范写：
    ISS  = 1 - (1-C)(1-I)(1-A)
    Impact(Scope=U) = 6.42 * ISS
    Impact(Scope=C) = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15
    Exploitability  = 8.22 * AV * AC * PR * UI
    Base(Scope=U)   = roundup(min(Impact+Exploitability, 10))
    Base(Scope=C)   = roundup(min(1.08*(Impact+Exploitability), 10))
其中 roundup 是"向上进位到 1 位小数"（不是四舍五入）。

正确性由 `KNOWN_VECTORS` 里的官方已知值校验（见文件末尾自测）。
"""

from __future__ import annotations

import math

#: 各度量的数值权重（CVSS v3.1 规范 7.4 节）
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
#: PR 依赖 Scope
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(value: float) -> float:
    """CVSS 规范定义的 roundup：向上进位到 1 位小数。

    注意这与四舍五入不同：3.31 -> 3.4，而 round() 会给 3.3。
    规范原文用整数运算表达，这里用浮点等价写法。
    """

    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    """把 `CVSS:3.1/AV:N/AC:L/...` 解析成度量字典。"""

    out: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        # 第一段是 "CVSS:3.1"，会被解析成 {'CVSS': '3.1'}，无害
        out[key.strip().upper()] = val.strip().upper()
    return out


def base_score(vector: str) -> float | None:
    """从向量算基础分；向量不合法或字段缺失时返回 None（**不猜**）。"""

    m = parse(vector or "")
    need = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(k not in m for k in need):
        return None
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
        # 刻意写成 if/else 而非三元表达式：这两个分支直接对应 CVSS v3.1 规范里
        # Impact 的两个公式（Scope 不变 / 改变），分行写便于对着规范逐字核对。
        if scope_changed:  # noqa: SIM108
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (PR_C if scope_changed else PR_U)[m["PR"]]
        exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
        if impact <= 0:
            return 0.0
        raw = (impact + exploitability) * (1.08 if scope_changed else 1.0)
        return roundup(min(raw, 10.0))
    except KeyError:
        return None


def severity_label(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


#: 官方/广泛引用的已知向量 → 期望分（用于自测本实现是否正确）
KNOWN_VECTORS: list[tuple[str, float]] = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # 经典 critical
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # 仅机密性
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),  # 需交互
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),  # 高复杂度
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),  # 低机密性
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),  # 需低权限
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # 范围改变
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3),  # 本地低权限
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8),
]


def self_test() -> list[str]:
    """返回不一致的项；空列表表示实现与已知值全部吻合。"""

    bad = []
    for vec, expect in KNOWN_VECTORS:
        got = base_score(vec)
        if got != expect:
            bad.append(f"{vec}  期望 {expect} 实得 {got}")
    return bad


if __name__ == "__main__":
    problems = self_test()
    print(
        f"自测 {len(KNOWN_VECTORS)} 个已知向量：", "全部通过 ✅" if not problems else "有不一致 ⚠"
    )
    for p in problems:
        print("  ✗", p)
    print()
    print("演示库 13 条的 CVSS 向量 → 正确分数：")
    demo = [
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ]
    for v in demo:
        print(f"  {base_score(v)!s:>5}  {severity_label(base_score(v)):9} {v}")

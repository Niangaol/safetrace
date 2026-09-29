"""把本轮标注集测出的真实数字并进报告生成脚本。

原则：**有依据的就给数字，没依据的保持"未验证"**。
本轮新增的依据来自 `eval/datasets/MANIFEST.md` 与独立 CVSS 实现
（`eval/cvss_reference.py`，已用 12 个官方已知向量自测通过）。

最关键的一处：**数据标准化率**。原报告写 ">99%"，此前只能删掉；
现在实测为 **0.769**（13 条里 3 条不合格），有具体缺陷清单支撑，可以写进去。
"""

from pathlib import Path

DIR = Path(
    r'C:\Users\kkk97\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent'
    r'\work-mode-projects\6abb26ff17b11b4656d447f2'
)

#: (原文, 替换为, 说明)  —— 只替换能唯一匹配的整行
PAIRS = [
    # ── 数据标准化率：从"删掉的假数字"升级为"有依据的真数字" ──
    (
        "['带 cve_id 的漏洞占比', '92.3%（12/13 实测）', '1 条 AutoAWQ 无 CVE 编号（已知脏数据）'],",
        "['数据标准化一致性', '0.769（10/13 实测）', "
        "'含 cve_id 与 severity 两项：1 条缺 cve_id，2 条 severity 与 CVSS 向量档位不符'],",
        '标准化率 → 实测 0.769',
    ),
    # ── 各维度：把"未验证"细化为"部分可判定 + 已测结果" ──
    (
        "['cvss CVSS+影响', '未验证', '—', '—', '需与官方计算器逐条比对'],",
        "['cvss CVSS+影响', '1.000（24/24 可判定）', '—', '—', "
        "'由向量独立重算比对；已用 12 个官方已知向量校验实现正确性'],",
        'cvss → 真实链路 1.000',
    ),
    (
        "['poc POC搜集', '未验证', '—', '—', '需人工标注集'],",
        "['poc POC搜集', '占位符检出 11/11 命中', '—', '—', "
        "'真实链路 0~5 条不等且无依据时给 0；演示库 11 条全指向 example/ 占位仓库'],",
        'poc → 占位符检出',
    ),
    (
        "['paper 论文关联', '未验证', '—', '—', '需人工标注集；本机无嵌入模型'],",
        "['paper 论文关联', '待人工（60/84 条）', '—', '—', "
        "'本机 arXiv/OpenAlex 未返回；演示库 12 条全指向同一篇占位论文'],",
        'paper → 待人工',
    ),
    # ── 评分对照表的富化两行 ──
    (
        "['富化准确率', '≥95%', '未验证（缺人工标注集）', '待补测'],",
        "['富化准确率', '≥95%', '可判定部分 24/24（1.000）；其余 60/84 需人工', '部分可测'],",
        '评分表-富化准确率',
    ),
    (
        "['富化召回率', '≥95%', '未验证（缺人工标注集）', '待补测'],",
        "['富化召回率', '≥95%', '未验证（语料为合成，无现实可核对）', '待补测'],",
        '评分表-富化召回率',
    ),
]


def main() -> int:
    total_ok = total_miss = 0
    for name in ('generate_report.py', 'generate_word.py', 'generate_ppt.py'):
        p = DIR / name
        if not p.exists():
            print(f'（缺 {name}）')
            continue
        text = p.read_text(encoding='utf-8')
        ok = miss = 0
        print(f'===== {name} =====')
        for old, new, desc in PAIRS:
            if old in text:
                text = text.replace(old, new)
                ok += 1
                print(f'  ✓ {desc}')
            else:
                miss += 1
                print(f'  - {desc}：未命中')
        p.write_text(text, encoding='utf-8')
        print(f'  小计 {ok} 替换 / {miss} 未命中')
        total_ok += ok
        total_miss += miss
    print(f'\n合计 {total_ok} 替换，{total_miss} 未命中')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""客观审计 13 条漏洞主表：CVE 编号/严重度/CVSS 三者是否自洽。

这些都是**零判断**的检查（不需要专家、不需要外部核查），适合做"漏洞"块标注：
  - cve_id 是否存在、格式是否合法
  - severity 标签是否与 cvss_vector 独立算出的档位一致
  - 时间戳是否齐全（published_at <= fetched_at）
"""

import os
import re
import sys
from collections import Counter

sys.path.insert(0, "src")
sys.path.insert(0, ".")
os.environ.setdefault("POSTGRES_DSN", "sqlite:///E:/code/ai-threat-intel-demo-v1/data/demo.db")

from eval.cvss_reference import base_score as ref_score
from eval.cvss_reference import severity_label as ref_sev

from aiintel.db.base import get_sessionmaker
from aiintel.db.models import Vuln

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

with get_sessionmaker()() as s:
    rows = s.query(Vuln).all()

print(f"漏洞总数: {len(rows)}")
print()
print("=== 逐条审计 ===")
issues = Counter()
for v in sorted(rows, key=lambda x: x.cve_id or ""):
    probs = []
    if not v.cve_id:
        probs.append("缺 cve_id")
    elif not CVE_RE.match(v.cve_id):
        probs.append("cve_id 格式非法")
    truth = ref_score(v.cvss_vector) if v.cvss_vector else None
    if truth is None:
        probs.append("cvss_vector 缺失或不可解析")
    else:
        want = ref_sev(truth)
        if (v.severity or "").lower() != want:
            probs.append(f"severity={v.severity} 与向量档位 {want}({truth}) 不符")
    if v.published_at and v.fetched_at and v.published_at > v.fetched_at:
        probs.append("published_at > fetched_at")
    for p in probs:
        issues[p.split("=")[0].split(" ")[0]] += 1
    flag = "✗" if probs else "✓"
    sev_truth = f"{truth}/{ref_sev(truth)}" if truth is not None else "—"
    print(
        f"  {flag} {str(v.cve_id):20} severity={str(v.severity):9} 向量应={sev_truth:16} "
        f"{'; '.join(probs)[:60]}"
    )

print()
print("=== 问题汇总 ===")
for k, n in issues.most_common():
    print(f"  {n:2} 条：{k}")
print()
clean = sum(
    1
    for v in rows
    if CVE_RE.match(v.cve_id or "")
    and ref_score(v.cvss_vector or "") is not None
    and (v.severity or "").lower() == ref_sev(ref_score(v.cvss_vector or ""))
)
print(f"三项全对: {clean}/{len(rows)} = {clean / len(rows):.3f}")

"""富化线（F 线）对外出口。

模块分工（与 `docs/富化线详细设计.md` 一致）：

| 文件 | 职责 |
| --- | --- |
| `dimensions.py` | 维度注册表 + AI 风险专项维度 |
| `paper.py` / `asset.py` / `poc.py` / `cvss_impact.py` / `fix.py` / `consistency.py` | F1–F6 六个维度 |
| `cvss.py` / `nvd.py` | CVSS 计算与 NVD JSON 解析（纯函数） |
| `evidence.py` | 证据链构造 + 三条不变量 |
| `agent.py` | 并发编排与单维隔离 |
| `mg1.py` | 模型网关客户端（F 线唯一模型入口） |
| `s1_knowledge.py` | 知识底座客户端（F 线唯一出库入口） |
| `s2_events.py` | 事件总线客户端（只许发 enrich.* 三个 topic） |
"""

from aiintel.services.enrich.agent import EnrichAgent
from aiintel.services.enrich.cvss import score_vector_31, severity_label
from aiintel.services.enrich.dimensions import AI_RISK_CATEGORIES, DIMENSIONS
from aiintel.services.enrich.evidence import build_result, check_invariants

__all__ = [
    "AI_RISK_CATEGORIES",
    "DIMENSIONS",
    "EnrichAgent",
    "build_result",
    "check_invariants",
    "score_vector_31",
    "severity_label",
]

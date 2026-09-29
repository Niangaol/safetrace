"""结构化日志 + Prometheus 指标。"""

from __future__ import annotations

import logging
import sys

from prometheus_client import Counter, Gauge, Histogram

# ---- 业务指标（对应 /api/v1/metrics/overview 与 Grafana 面板）----
collect_latency = Histogram(
    "intel_collect_latency_seconds",
    "漏洞信息从发布到入库的延迟",
    labelnames=("source",),
    buckets=(600, 1800, 3600, 7200, 21600, 43200, 86400, float("inf")),
)
collect_items = Counter("intel_collect_items_total", "采集条目数", labelnames=("source", "stage"))
enrich_success = Counter("intel_enrich_success_total", "富化成功次数", labelnames=("dimension",))
enrich_failed = Counter("intel_enrich_failed_total", "富化失败次数", labelnames=("dimension",))
enrich_coverage = Gauge("intel_enrich_coverage_ratio", "富化覆盖率")
qa_latency = Histogram(
    "intel_qa_latency_seconds",
    "问答端到端时延",
    buckets=(0.5, 1, 2, 3, 5, 8, float("inf")),
)
agent_runs = Counter("intel_agent_runs_total", "Agent 执行次数", labelnames=("agent", "result"))
llm_cost = Counter(
    "intel_llm_cost_cny_total", "LLM 花费（元）", labelnames=("agent", "node", "model")
)
llm_tokens = Counter("intel_llm_tokens_total", "LLM token 用量", labelnames=("tier", "kind"))
selfheal = Counter("intel_selfheal_actions_total", "自愈动作", labelnames=("action",))


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        stream=sys.stdout,
        force=True,
    )
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

"""EnrichAgent：多维度富化并行执行，单维失败降级不影响其他维度。

边界（写进测试）：本模块**不直接落库、不发原始事件**——出库走 `s1_knowledge`，
事件走 `s2_events`，模型调用走 `mg1`。这样 F 线可以在没有 PostgreSQL / Redis / LLM 的
机器上把一个漏洞的 7 个维度全部跑完（这正是"fixture 优先"的意义）。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aiintel.core.contracts import to_enrich_input
from aiintel.core.metrics import enrich_failed
from aiintel.services.enrich import s1_knowledge, s2_events
from aiintel.services.enrich.dimensions import CORE_DIMENSIONS, DIMENSIONS, dimensions_for_quality
from aiintel.services.enrich.evidence import check_invariants

logger = logging.getLogger(__name__)

MAX_CONCURRENCY = 4
TIMEOUT_PER_DIMENSION = 180.0

# F6 依赖其他维度的产出，必须最后跑（见 `run` 的两波执行）
CONSISTENCY_DIMENSION = "consistency"


class EnrichAgent:
    def __init__(self, bus: Any | None = None) -> None:
        self.bus = bus

    async def run(
        self,
        vuln: dict[str, Any],
        dimensions: list[str] | None = None,
        trace_id: str | None = None,
    ) -> list[dict]:
        """并行跑指定维度。显式传 `dimensions` 时不受质量闸门约束（回填场景）。

        入口处做一次契约归一：接受权威 `IntelItem`（`intel_id`/`cve_ids`/`entities`）
        或 Y 线内部视图，投影成维度引擎习惯的形状（`docs/契约对齐-SafeTrace.md` §5）。
        归一是幂等的，旧调用方无需改造。
        """

        vuln = to_enrich_input(vuln)
        vuln_id = str(vuln.get("id") or vuln.get("vuln_id") or "")
        effective_trace = trace_id or str(vuln.get("trace_id") or "") or None

        if dimensions:
            targets = list(dimensions)
        else:
            allowed = dimensions_for_quality(vuln)
            if allowed is None:
                logger.info(
                    "vuln=%s quality_score=%s 低于阈值，跳过富化（DQ1 质量闸门）",
                    vuln_id,
                    vuln.get("quality_score"),
                )
                return []
            targets = allowed

        await s2_events.publish_requested(self.bus, vuln_id, targets)
        semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

        async def run_one(name: str, prior: list[dict] | None = None) -> dict | None:
            fn = DIMENSIONS.get(name)
            if fn is None:
                return None
            async with semaphore:
                try:
                    # F6 需要"其他维度的产出"作为输入，所以单独走 prior 参数（见下方两波执行）
                    if name == CONSISTENCY_DIMENSION:
                        coro = fn(vuln, prior or [], effective_trace)
                    else:
                        coro = fn(vuln, effective_trace)
                    result = await asyncio.wait_for(coro, timeout=TIMEOUT_PER_DIMENSION)
                    problems = check_invariants(result)
                    if problems:
                        logger.warning("维度 %s 违反不变量: %s", name, problems)
                        enrich_failed.labels(dimension=name).inc()
                        return {
                            "dimension": name,
                            "value": {},
                            "source": [],
                            "evidence": [],
                            "confidence": 0.0,
                            "mock": False,
                            "degraded_to": "rule",
                            "degraded_reason": "结果违反富化契约不变量",
                            "error": "; ".join(problems)[:300],
                            "agent": "EnrichAgent",
                            "trace_id": effective_trace,
                        }
                    return {**result, "dimension": name}
                except Exception as exc:  # noqa: BLE001 - 单维失败不阻断
                    # 必须带 exc_info：只打 str(exc) 的话，"维度失败"根本没法定位
                    logger.warning(
                        "富化维度 %s 失败 vuln=%s: %s", name, vuln_id, exc, exc_info=True
                    )
                    enrich_failed.labels(dimension=name).inc()
                    return {
                        "dimension": name,
                        "value": {},
                        "source": [],
                        "evidence": [],
                        "confidence": 0.0,
                        "mock": False,
                        "degraded_to": "rule",
                        "degraded_reason": f"维度执行异常：{type(exc).__name__}",
                        "error": str(exc)[:300],
                        "agent": "EnrichAgent",
                        "trace_id": effective_trace,
                    }

        # 两波执行：先并行跑"取数类"维度，最后跑 F6（它要拿其他维度的结论做跨源比对）。
        # 代价是 F6 不再与其他维度并发，收益是冲突检测真的能看到多源声明。
        parallel_targets = [name for name in targets if name != CONSISTENCY_DIMENSION]
        results = await asyncio.gather(*(run_one(name) for name in parallel_targets))
        kept = [r for r in results if r is not None]
        if CONSISTENCY_DIMENSION in targets:
            prior = [r for r in kept if not r.get("error")]
            consistency_result = await run_one(CONSISTENCY_DIMENSION, prior)
            if consistency_result is not None:
                kept = [*kept, consistency_result]

        # 成功（无 error）的维度才发 completed；降级的额外发 degraded（FB1 可见性）
        ok_results = [r for r in kept if not r.get("error")]
        await s2_events.publish_all(self.bus, vuln_id, ok_results)
        return kept

    async def backfill(
        self,
        vuln_ids: list[str],
        dimensions: list[str] | None = None,
        trace_id: str | None = None,
    ) -> int:
        """离线批量补富化，建议钉在闲时时段执行（成本治理）。

        出库走 S1 客户端（默认桩模式不写库），因此可在无 PostgreSQL 环境做端到端演练。
        """

        from aiintel.services.ingest.pipeline import load_intel_item

        done = 0
        for vuln_id in vuln_ids:
            payload = load_intel_item(vuln_id)
            if not payload:
                logger.warning("backfill 跳过：找不到 vuln=%s", vuln_id)
                continue
            results = await self.run(payload, dimensions, trace_id=trace_id)
            await s1_knowledge.store_enrichment(payload, results)
            done += 1
        logger.info("backfill 完成 %d 个漏洞（维度 %s）", done, dimensions or "全部")
        return done


__all__ = ["CORE_DIMENSIONS", "EnrichAgent", "MAX_CONCURRENCY", "TIMEOUT_PER_DIMENSION"]

"""MonitorGraph 节点实现。每个节点保持"薄"，把业务逻辑放在 services/，便于并行开发与测试。

**载荷必须过契约**：本模块发布的每条事件，payload 由 `core/contracts.py` 的投影函数生成
（`to_raw_doc` / `to_intel_item` / `to_enrichment_result` / `to_dimension_evidence`），
不允许在这里手写短字典 —— 手写字典正是 P0-A 那个"346 个测试全绿但载荷 0/7 匹配"的根因。
`tests/test_event_payloads.py` 直接从本模块的发布函数取载荷过 Schema，防止再退化。
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from aiintel.agents.state import IntelState
from aiintel.core.contracts import (
    source_type_of,
    to_dimension_evidence,
    to_enrichment_result,
    to_intel_item,
    to_raw_doc,
)
from aiintel.core.events import (
    TOPIC_DQ_VERDICTS,
    TOPIC_ENRICH_EVIDENCE,
    TOPIC_ENRICH_ITEMS,
    TOPIC_ENRICH_PAPERS,
    TOPIC_ENRICH_TRIAGE,
    TOPIC_INTEL_ITEMS,
    TOPIC_RAW_DOCS,
    TOPIC_REPORT_DAILY,
    EventBus,
)
from aiintel.core.metrics import enrich_success

logger = logging.getLogger(__name__)
bus = EventBus()

# 分级调度：webhook 实时 / 轮询增量 / 每周全量
MAX_REPAIR_ATTEMPTS = 3
SEVERITY_PRIORITY = {"critical": "urgent", "high": "high", "medium": "normal", "low": "normal"}


def payload_ref_of(source: str, external_id: str) -> str:
    """权威 `payload_ref` 约定：`payload://{source}/{external_id}`。

    它与 `IntelItem.raw_refs` 用同一约定，F 线才能按 ref 回读原始 payload。
    """

    return f"payload://{source}/{external_id or 'unknown'}"


def source_map_of(raw_items: list[dict[str, Any]]) -> dict[str, str]:
    """`raw_item_id` → 源名。归并后仍能说清"这条情报来自哪几个源"。"""

    return {
        str(item.get("id")): str(item.get("source") or "unknown")
        for item in raw_items
        if item.get("id")
    }


def source_ids_for(merged: dict[str, Any], source_map: dict[str, str]) -> list[str]:
    """归并条目的来源清单（按 `merged_raw_ids` 回查，保序去重）。"""

    ids: list[str] = []
    for raw_id in [merged.get("id"), *(merged.get("merged_raw_ids") or [])]:
        name = source_map.get(str(raw_id))
        if name and name not in ids:
            ids.append(name)
    if not ids:
        fallback = merged.get("source")
        ids = [str(fallback)] if fallback else ["unknown"]
    return ids


def intel_id_of(vuln: dict[str, Any]) -> str:
    """内部条目 → 权威 `intel_id`（与 `to_intel_item` 的派生规则保持一致）。"""

    cve_id = str(vuln.get("cve_id") or "")
    return str(
        vuln.get("intel_id") or f"intel_{cve_id or vuln.get('id') or 'unknown'}".replace("-", "_")
    )


async def node_collect(state: IntelState) -> IntelState:
    """M1：多源采集。失败时由 supervisor 路由到 repair。"""

    from aiintel.services.ingest.pipeline import persist_raw_items, poll_sources

    started = time.perf_counter()
    items = await poll_sources(state.get("sources") or None, state.get("mode", "incremental"))

    # 原始条目先落库：证据链的起点，也是采集延迟指标（fetched_at - published_at）的数据源
    persisted = await persist_raw_items(items)
    logger.info(
        "collect: 采集 %d 条，入库 %d 条，耗时 %dms",
        len(items),
        persisted,
        int((time.perf_counter() - started) * 1000),
    )

    causality: dict[str, str] = {}
    for item in items:
        source = str(item.get("source") or "unknown")
        external_id = str(item.get("external_id") or item.get("id") or "")
        # 采集是因果链的根：没有上游，所以不带 causation_id。
        # dedup_key 用 source:external_id，重放同一条原始抓取得同一个 event_id。
        event_id = await bus.try_publish(
            TOPIC_RAW_DOCS,
            to_raw_doc(
                item,
                source_id=source,
                source_type=source_type_of(source),
                external_id=external_id,
                url=str(item.get("url") or f"https://unknown.invalid/{external_id}"),
                payload_ref=payload_ref_of(source, external_id),
            ),
            state.get("trace_id"),
            dedup_key=f"{source}:{external_id}",
        )
        if event_id:
            causality.setdefault("raw", event_id)
    return {
        **state,
        "raw_items": items,
        "collected": len(items),
        "raw_persisted": persisted,
        "causality": {**(state.get("causality") or {}), **causality},
    }


async def node_normalize(state: IntelState) -> IntelState:
    """M2：LLM 字段抽取 + CVE Schema 归一。"""

    from aiintel.services.ingest.pipeline import normalize_items

    merged = await normalize_items(state.get("raw_items", []))
    return {**state, "merged": merged, "merged_count": len(merged)}


async def node_dedup(state: IntelState) -> IntelState:
    """M3：精确 hash + SimHash 近似去重 + 跨源事件合并。"""

    from aiintel.services.ingest.dedup import merge_items

    merged = merge_items(state.get("merged", []))
    source_map = source_map_of(state.get("raw_items") or [])
    causality = dict(state.get("causality") or {})
    # 逐条记录 parent event：一轮可能有多个条目，全部挂在"最后一条"上是错的因果链
    cause_by_item: dict[str, str] = {}
    for item in merged:
        # 多源来源清单从 raw_items 回查（归并后仍要说得清"来自哪几个源"）
        intel_item = to_intel_item({**item, "sources": source_ids_for(item, source_map)})
        # intel.items 由 raw.docs 归并而来，causation_id 指向采集事件。
        event_id = await bus.try_publish(
            TOPIC_INTEL_ITEMS,
            intel_item,
            state.get("trace_id"),
            causation_id=causality.get("raw"),
            dedup_key=str(intel_item["intel_id"]),
        )
        if event_id:
            causality["intel"] = event_id
            cause_by_item[str(item.get("cve_id") or item.get("id") or "unknown")] = event_id
    return {
        **state,
        "merged": merged,
        "merged_count": len(merged),
        "causality": causality,
        # 逐条 intel.items event_id：dq1 才能把每条判定挂到**它自己**的上游
        "intel_causation": cause_by_item,
    }


async def node_dq1(state: IntelState) -> IntelState:
    """DQ1 数据质量闸门（插在 `dedup` 与 `triage` 之间）。

    为什么在这个位置：质量判定必须在**富化之前**生效，才能真正替代
    `dimensions_for_quality()` 的筛选作用 —— 否则脏数据已经花掉 LLM 预算了。

    产出：
    - `merged[i]["quality_score"]`：写入 `Vuln.quality_score` 的值（由 `node_persist` 落库）；
    - `state["quality_verdicts"]`：`item_id -> QualityVerdict` 载荷；
    - `dq.verdicts` 事件：每条一条，因果链挂在上游 `intel.items` 上。
    """

    from aiintel.config import get_settings
    from aiintel.services.dq1 import evaluate

    settings = get_settings()
    if not settings.dq1_enabled:
        logger.info("DQ1 已关闭（DQ1_ENABLED=false），跳过质量闸门")
        return state

    merged = state.get("merged", [])
    verdicts: dict[str, dict[str, Any]] = {}
    causality = dict(state.get("causality") or {})
    # 逐条挂到自己的 intel.items 上（由 dedup 提供），而不是全挂最后一条
    cause_by_item: dict[str, str] = dict(state.get("intel_causation") or {})
    scored: list[dict[str, Any]] = []
    quarantined = 0

    for item in merged:
        verdict = evaluate(item, gate_version=settings.dq1_gate_version)
        payload = verdict.to_payload()
        verdicts[verdict.item_id] = payload
        if verdict.verdict == "quarantine":
            quarantined += 1
            logger.warning(
                "DQ1 隔离 item=%s 命中 flag=%s（分数 %.3f）",
                verdict.item_id,
                payload["flags"],
                verdict.quality_score,
            )
        # 分数写回条目：富化闸门与落库都读它，避免同一判定算两遍
        scored.append({**item, "quality_score": verdict.quality_score})

        event_id = await bus.try_publish(
            TOPIC_DQ_VERDICTS,
            payload,
            state.get("trace_id"),
            causation_id=cause_by_item.get(verdict.item_id) or causality.get("intel"),
            dedup_key=f"{verdict.item_id}|{settings.dq1_gate_version}",
        )
        if event_id:
            causality["dq"] = event_id

    logger.info(
        "DQ1 判定 %d 条，隔离 %d 条（gate_version=%s）",
        len(merged),
        quarantined,
        settings.dq1_gate_version,
    )
    return {
        **state,
        "merged": scored,
        "quality_verdicts": verdicts,
        "causality": causality,
    }


def _item_key(item: dict[str, Any]) -> str:
    """DQ1 的 `item_id` 派生规则（与 `services/dq1.evaluate` 保持一致）。"""

    return str(item.get("cve_id") or item.get("id") or item.get("vuln_id") or "unknown")


async def node_triage(state: IntelState) -> IntelState:
    """TriageAgent：动态优先级排序与派单（Y5）。

    排序用 **EPSS / KEV / CVSS** 三项加权（`services/triage.py`，权重版本化且可复算），
    不再是"只看 CVSS 挑一条"。同时产出 **Top-N 队列**（`triage_queue`），
    队首进 `vuln` 走详细富化，队尾条目按 `route=template_enrich` 走通用模板 ——
    这是 F 线"富化完整性"分数上不去的根因（一次只处理一条）。

    只对**未被 DQ1 隔离**的条目排序；全部被隔离时退回"隔离批里最高分者"并标记降级，
    由下游（富化闸门 / 隔离区）而不是本节点决定怎么处理。

    ⚠️ 诚实边界：`asset_scan_enabled=False` 时没有"业务暴露面"这一维，
    所以本节点算的是"**被利用概率优先**"，**不是"对我们最危险"**。
    """

    from aiintel.config import get_settings
    from aiintel.services.triage import rank_items

    settings = get_settings()
    items = state.get("merged", [])
    verdicts = state.get("quality_verdicts") or {}
    healthy = [
        item
        for item in items
        if (verdicts.get(_item_key(item)) or {}).get("verdict") != "quarantine"
    ]
    if items and not healthy:
        logger.warning("本批 %d 条全部被 DQ1 隔离，退回隔离批排序并标记降级", len(items))
    pool = healthy or items

    ranked = rank_items(
        pool,
        limit=settings.triage_detail_top_n,
        policy_version=settings.triage_policy_version,
    )
    # 队首是"最该先修的那条"；按 vuln_id 回查原条目（排名里只有评分，不带原始 payload）
    by_id = {_item_key(item): item for item in pool}
    target = by_id.get(ranked[0].vuln_id, pool[0]) if ranked else {}
    severity = (target.get("severity") or "low").lower()
    top = ranked[0] if ranked else None

    if top is not None:
        logger.info(
            "triage 排序 %d 条（策略 %s）：首位 %s score=%.3f priority=%s route=%s",
            len(ranked),
            settings.triage_policy_version,
            top.vuln_id,
            top.score,
            top.priority,
            top.route,
        )

    return {
        **state,
        "vuln": target,
        "vuln_id": target.get("id", ""),
        "severity": severity,
        # `priority` 现在来自动态策略，而不是 severity 的静态映射
        "priority": top.priority if top is not None else "normal",
        "triage_queue": [c.to_order_payload() for c in ranked],
        "ai_risk_category": target.get("ai_risk_category") or "",
        "degraded": bool(state.get("degraded")) or (bool(items) and not healthy),
    }


async def node_enrich(state: IntelState) -> IntelState:
    """EnrichAgent：7 维富化并行，单维失败不影响其他维度。

    发两类事件：

    - `enrich.items`：权威 `EnrichmentResult` 交接口，**一次富化一条**（不是一维一条）；
    - `enrich.evidence`：本仓扩展契约 `DimensionEvidence`，**一维一条**，承载 7 维明细证据链。
      权威交接口因 `additionalProperties: false` 装不下明细，这是唯一的明细出口。
    """

    from aiintel.services.enrich.agent import EnrichAgent

    vuln = state.get("vuln") or {}
    if not vuln:
        return {**state, "enrichments": []}
    enrichments = await EnrichAgent().run(vuln)
    causality = dict(state.get("causality") or {})
    intel_id = intel_id_of(vuln)
    trace_id = state.get("trace_id")

    for item in enrichments:
        enrich_success.labels(dimension=item.get("dimension", "?")).inc()

    # 明细出口：一维一条（权威交接口装不下，明细必须走扩展契约）
    for item in enrichments:
        event_id = await bus.try_publish(
            TOPIC_ENRICH_EVIDENCE,
            to_dimension_evidence(
                item,
                intel_id=intel_id,
                cve_id=vuln.get("cve_id"),
            ),
            trace_id,
            causation_id=causality.get("intel"),
            dedup_key=f"{intel_id}|{item.get('dimension')}",
        )
        if event_id:
            causality["enrich_evidence"] = event_id

    # 交接口：一次富化一条 EnrichmentResult
    completed = [i for i in enrichments if not i.get("error")]
    failed = [i for i in enrichments if i.get("error")]
    event_id = await bus.try_publish(
        TOPIC_ENRICH_ITEMS,
        to_enrichment_result(intel_id, completed, failed=failed),
        trace_id,
        causation_id=causality.get("intel"),
        dedup_key=intel_id,
    )
    if event_id:
        causality["enrich"] = event_id

    # F1 论文关联专用出口（消费方是 F6 一致性校验与 S1 知识底座）
    papers_payload = publish_papers_payload(intel_id, completed)
    if papers_payload is not None:
        papers_event_id = await bus.try_publish(
            TOPIC_ENRICH_PAPERS,
            papers_payload,
            trace_id,
            causation_id=causality.get("intel"),
            dedup_key=f"{intel_id}|papers",
        )
        if papers_event_id:
            causality["enrich_papers"] = papers_event_id

    return {
        **state,
        "enrichments": enrichments,
        "enriched_count": len(enrichments),
        "causality": causality,
    }


def publish_papers_payload(intel_id: str, enrichments: list[dict[str, Any]]) -> dict | None:
    """`enrich.papers` 的载荷：`EnrichmentResult` 只带 `artifacts.papers`。

    返回 `None` 表示本轮没有论文结论 —— 那就**不发**这条事件，
    而不是发一条空的装样子（空载荷会让下游以为"查过了，没有论文"）。
    """

    for item in enrichments:
        if str(item.get("dimension")) != "paper":
            continue
        payload = to_enrichment_result(intel_id, [item])
        if payload["artifacts"].get("papers"):
            return payload
    return None


async def node_verify(state: IntelState) -> IntelState:
    """证据校验：evidence 缺失或置信度过低的字段重新标记，交给前端提示"待人工确认"。"""

    checked: list[dict] = []
    for item in state.get("enrichments", []):
        evidence = item.get("evidence") or []
        if not evidence:
            item = {**item, "verified": False, "flag": "no_evidence"}
        else:
            item = {**item, "verified": True}
        checked.append(item)
    return {**state, "enrichments": checked}


async def node_persist(state: IntelState) -> IntelState:
    """M5：写入 PG + 向量 + 关系边表。

    `quality_score` 由 DQ1 在 `node_dq1` 写进条目（`vuln` 就是 triage 选中的那条），
    这里随其他字段一起落库 —— 修复"列存在但无运行时写入方"的问题。
    """

    from aiintel.services.knowledge.indexer import persist_vuln

    vuln = state.get("vuln") or {}
    if vuln.get("id"):
        await persist_vuln(vuln, state.get("enrichments", []))
    return state


async def node_alert(state: IntelState) -> IntelState:
    """告警：仅高危及以上推送，避免噪声。

    `enrich.triage` 的载荷是**权威内联契约 `TriageOrder`**：它由 triage 阶段算出的
    动态优先级排名提供（`state["triage_queue"]` 的队首），因此下游（F 线 / Q 线）
    拿到的是"为什么排第一"的完整依据，而不是一句 priority 字符串。
    """

    from aiintel.core.alerts import AlertManager

    severity = state.get("severity", "low")
    vuln = state.get("vuln") or {}
    raised = 0
    causality = dict(state.get("causality") or {})
    if severity in {"critical", "high"}:
        await AlertManager(bus).raise_alert(
            level=severity.upper(),
            title=vuln.get("cve_id") or vuln.get("title", "未知漏洞"),
            message=f"{vuln.get('title', '')}（CVSS {vuln.get('cvss_score')}）",
            vuln_id=vuln.get("id"),
            trace_id=state.get("trace_id"),
            causation_id=causality.get("intel"),
            dedup_key=f"{vuln.get('id', '')}:alert:{severity}",
        )
        raised = 1
        order = triage_order_payload(state, vuln)
        event_id = await bus.try_publish(
            TOPIC_ENRICH_TRIAGE,
            order,
            state.get("trace_id"),
            causation_id=causality.get("enrich") or causality.get("intel"),
            dedup_key=f"{order['vuln_id']}:triage:{order['policy_version']}",
        )
        if event_id:
            causality["triage"] = event_id
    return {**state, "alerts": raised, "causality": causality}


def triage_order_payload(state: IntelState, vuln: dict[str, Any]) -> dict[str, Any]:
    """取队首的 `TriageOrder`；队列缺失时按当前 state 兜底构造一条。

    兜底路径也要过契约（不能因为"排名没算"就发一个缺字段的载荷）。
    """

    from aiintel.config import get_settings

    queue = state.get("triage_queue") or []
    if queue:
        return queue[0]

    settings = get_settings()
    severity = str(state.get("severity") or "low").lower()
    return {
        "vuln_id": str(vuln.get("cve_id") or vuln.get("id") or "unknown"),
        "priority": str(state.get("priority") or "normal"),
        "severity": severity,
        "cvss_score": vuln.get("cvss_score"),
        "epss": vuln.get("epss"),
        "kev": bool(vuln.get("kev")),
        "score": 0.0,
        "rank": 1,
        "route": "detail_enrich",
        "reasons": ["triage 队列缺失，按当前 state 兜底（未做动态排序）"],
        "policy_version": settings.triage_policy_version,
    }


async def node_report(state: IntelState) -> IntelState:
    """生成日报并广播。"""

    from aiintel.agents.report import build_daily_report

    report = await build_daily_report(state)
    causality = state.get("causality") or {}
    await bus.publish(
        TOPIC_REPORT_DAILY,
        {"markdown": report},
        state.get("trace_id"),
        causation_id=causality.get("triage") or causality.get("enrich"),
    )
    return {**state, "report": report}


async def node_repair(state: IntelState) -> IntelState:
    """自愈分支：记录错误并退回采集节点重试，超过上限则降级。"""

    retry_map = dict(state.get("retry_map", {}))
    node = state.get("failed_node", "collect")
    retry_map[node] = retry_map.get(node, 0) + 1
    if retry_map[node] > MAX_REPAIR_ATTEMPTS:
        logger.error("节点 %s 重试超限，标记降级", node)
        from aiintel.agents.watchdog import record_selfheal

        await record_selfheal("give_up", target=node, reason="retry_limit_exceeded")
        return {**state, "retry_map": retry_map, "degraded": True}
    return {**state, "retry_map": retry_map}


Node = Callable[[IntelState], Awaitable[IntelState]]

# 节点注册表：graph.py 按此顺序连边，report 中也用它生成执行轨迹
NODES: dict[str, Node] = {
    "collect": node_collect,
    "normalize": node_normalize,
    "dedup": node_dedup,
    "dq1": node_dq1,
    "triage": node_triage,
    "enrich": node_enrich,
    "verify": node_verify,
    "persist": node_persist,
    "alert": node_alert,
    "report": node_report,
    "repair": node_repair,
}

__all__ = [
    "MAX_REPAIR_ATTEMPTS",
    "NODES",
    "SEVERITY_PRIORITY",
    "intel_id_of",
    "node_alert",
    "node_collect",
    "node_dedup",
    "node_dq1",
    "node_enrich",
    "node_normalize",
    "node_persist",
    "node_repair",
    "node_report",
    "node_triage",
    "node_verify",
    "payload_ref_of",
    "publish_papers_payload",
    "source_ids_for",
    "source_map_of",
    "triage_order_payload",
]

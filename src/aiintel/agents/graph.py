"""LangGraph 编排：MonitorGraph + 问答图。

Supervisor 用条件边按"数据成熟度"路由：
  collect → normalize → dedup → dq1 → triage → enrich → verify → persist → alert → report
任一节点异常 → repair → 回到 collect（带重试计数），超限则降级结束。

`dq1` 插在 `dedup` 与 `triage` 之间：脏数据必须在**富化之前**被拦下，
否则隔离判定只是事后记录，LLM 预算已经花掉了（见 `services/dq1.py`）。
"""

from __future__ import annotations

import logging
import time
from typing import Any

from aiintel.agents.nodes import NODES
from aiintel.agents.state import IntelState, new_state
from aiintel.core.metrics import agent_runs

logger = logging.getLogger(__name__)

PIPELINE = (
    "collect",
    "normalize",
    "dedup",
    "dq1",
    "triage",
    "enrich",
    "verify",
    "persist",
    "alert",
    "report",
)


class StepFailure(RuntimeError):
    pass


def _wrap(name: str):
    node = NODES[name]

    async def runner(state: IntelState) -> IntelState:
        started = time.perf_counter()
        try:
            result = await node(state)
        except Exception as exc:  # noqa: BLE001 - 图边界统一转为状态，交给 supervisor
            logger.exception("节点 %s 失败", name)
            agent_runs.labels(agent="MonitorAgent", result="error").inc()
            return {
                **state,
                "failed_node": name,
                "errors": [*state.get("errors", []), f"{name}: {exc}"],
            }
        # 成功即清除失败标记，避免 supervisor 误判
        result.pop("failed_node", None)
        latency = int((time.perf_counter() - started) * 1000)
        logger.info("node=%s ok latency=%dms", name, latency)
        agent_runs.labels(agent="MonitorAgent", result="ok").inc()
        return result

    runner.__name__ = f"node_{name}"
    return runner


def build_monitor_graph() -> Any:
    """构建状态机（延迟导入 langgraph，未安装依赖时也能 import 本模块）。"""

    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(IntelState)
    for name in PIPELINE:
        builder.add_node(name, _wrap(name))
    builder.add_node("repair", _wrap("repair"))

    builder.add_edge(START, "collect")
    for current, nxt in zip(PIPELINE, PIPELINE[1:], strict=False):
        # current/nxt 必须用默认参数绑定：否则所有条件边都指向最后一个 nxt
        builder.add_conditional_edges(
            current,
            lambda s, _cur=current, _nxt=nxt: "repair" if s.get("failed_node") else _nxt,
            {nxt: nxt, "repair": "repair"},
        )
    # repair 后回到 collect；超限则结束（降级）
    builder.add_conditional_edges(
        "repair",
        lambda s: (
            "collect" if s.get("retry_map", {}).get(s.get("failed_node", ""), 0) <= 3 else "report"
        ),
        {"collect": "collect", "report": "report"},
    )
    builder.add_edge("report", END)
    return builder.compile()


_monitor_graph: Any | None = None


def get_monitor_graph() -> Any:
    global _monitor_graph
    if _monitor_graph is None:
        _monitor_graph = build_monitor_graph()
    return _monitor_graph


async def run_monitor_cycle(
    sources: list[str] | None = None, mode: str = "incremental", trace_id: str | None = None
) -> IntelState:
    """执行一轮完整链路，供 API / CLI / 定时任务调用。"""

    import uuid

    state = new_state(trace_id or uuid.uuid4().hex, sources=sources or [], mode=mode)
    started = time.perf_counter()
    try:
        final = await get_monitor_graph().ainvoke(state)
    except Exception as exc:  # noqa: BLE001
        logger.exception("monitor cycle 失败")
        final = {**state, "errors": [*state.get("errors", []), str(exc)], "degraded": True}
    logger.info(
        "monitor cycle done collected=%s merged=%s enriched=%s elapsed=%dms",
        final.get("collected"),
        final.get("merged_count"),
        final.get("enriched_count"),
        int((time.perf_counter() - started) * 1000),
    )
    return final

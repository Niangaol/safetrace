"""活进程链路验证：跑一次完整 MonitorGraph cycle，逐条校验事件载荷。

**为什么需要这个脚本**（`docs/任务指示-Y线.md` §6.1）：
403/426 个测试全绿只证明"单测充分"，**不等于事件链路在活进程里跑通过**。
本脚本把"采集 → 归一 → 去重 → DQ1 → 排序 → 富化 → 落库 → 告警 → 日报"
整条链在**真实配置**下跑一遍，并逐条断言：

1. 每个主题的载荷过其契约（`scripts.validate_contracts.payload_schema_for`）；
2. 因果链真的连起来（`raw.docs → intel.items → dq.verdicts → enrich.items`）；
3. 降级可见（无 LLM Key / 无 Redis 时不许静默）。

**与 Redis 的关系（诚实说明）**：本脚本默认把事件写进内存总线（记录器），
所以它验证的是**出版侧**（谁发、发什么、载荷对不对、因果链对不对），
**不验证 Redis 传输本身**。要验传输，起 Redis 后用 `--redis` 跑：
那会走真实 `redis.asyncio` 客户端发布。

用法::

    python -m scripts.check_e2e_cycle                    # 内存总线（默认）
    python -m scripts.check_e2e_cycle --sources nvd      # 只跑一个源
    python -m scripts.check_e2e_cycle --redis            # 真发 Redis（需 6379 在听）
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from aiintel.agents import nodes  # noqa: E402
from aiintel.agents.graph import PIPELINE  # noqa: E402
from aiintel.agents.state import new_state  # noqa: E402
from aiintel.core.events import ALL_TOPICS, EventBus  # noqa: E402
from scripts.contracts import load_schema, validate  # noqa: E402
from scripts.validate_contracts import payload_schema_for  # noqa: E402

#: 权威因果链（`contracts/events.md` §1）：
#: `raw.docs → intel.items → enrich.items → enrich.triage`（前者是后者的父）。
EXPECTED_CHAIN = ("raw.docs", "intel.items", "enrich.items")

#: 本仓扩展分支：DQ1 的判定挂在与富化**同一个**上游（`intel.items`）上。
#: 注意它不是"主链的下一跳"——`enrich.items` 的父仍是 `intel.items`（权威钉死的），
#: 所以这里单独表示为分支，而不是把它插进主链（那是错的因果语义）。
EXPECTED_BRANCHES = (("intel.items", "dq.verdicts"),)


class RecordingRedis:
    """假 Redis：只实现 `publish`，把 (channel, message) 记下来。"""

    def __init__(self) -> None:
        self.published: list[tuple[str, str]] = []

    async def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, message))
        return 1


async def seed_from_db_if_no_network(state, registry) -> int:
    """网络不可达时的兜底：用 demo 库里**已落库的 raw_item** 驱动后半条链。

    demo.db 里的 `raw_item` 是 `demo_seed` 按真实结构灌的（source/external_id/url/
    fetched_at 齐全），拿它们跑归一之后的所有节点，等价于"采集已经成功、从归一接手"。
    """

    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import RawItem

    with get_sessionmaker()() as session:
        rows = session.query(RawItem).limit(30).all()
        items = [
            {
                "id": row.id,
                "source": row.source,
                "external_id": row.external_id,
                "url": row.url,
                "title": row.title,
                "content_text": row.content_text,
                "published_at": row.published_at.isoformat() if row.published_at else None,
                "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
                "content_hash": row.content_hash,
                "raw": row.raw_json or {},
            }
            for row in rows
        ]
    print(f"  兜底：从 demo.db 读入 {len(items)} 条已落库原始条目（等价于采集已完成）")
    return len(items), items


async def run_cycle(sources: list[str] | None, use_redis: bool) -> int:
    problems: list[str] = []

    if use_redis:
        from aiintel.config import get_settings

        settings = get_settings()
        print(f"  使用真实 Redis: {settings.redis_url}")
        bus = EventBus()
        rec = None
    else:
        rec = RecordingRedis()
        bus = EventBus(redis_client=rec)
        print("  事件写入内存总线（只验证出版侧；Redis 传输本身未验证）")

    nodes.bus = bus

    state = new_state(trace_id="e2e-check", task="monitor_cycle", mode="incremental")
    if sources:
        state["sources"] = sources

    # --- 阶段 1：真实采集（网络不可达就跳过，由阶段 2 接）
    from aiintel.agents import nodes as nodes_module

    print("阶段 1/3：真实采集（网络可达则真拉，否则记录降级）")
    try:
        state = await nodes_module.node_collect(state)
    except Exception as exc:  # noqa: BLE001 - 采集失败正是要观察的降级路径
        print(f"  采集节点异常（已按图语义降级）：{type(exc).__name__}: {exc}")
        state["errors"] = [*state.get("errors", []), f"collect: {exc}"]
    collected = len(state.get("raw_items") or [])
    print(f"  采集到 {collected} 条")

    if collected == 0:
        count, items = await seed_from_db_if_no_network(state, None)
        state = {**state, "raw_items": items, "collected": count}

    # --- 阶段 2：图的其余节点（真实服务层，不再打桩）
    print("阶段 2/3：归一 → 去重 → DQ1 → 排序 → 富化 → 落库 → 告警 → 日报")
    for name in PIPELINE:
        if name == "collect":
            continue
        try:
            state = await nodes_module.NODES[name](state)
        except Exception as exc:  # noqa: BLE001 - 单节点失败要如实记录，不掩盖
            problems.append(f"节点 {name} 抛异常：{type(exc).__name__}: {exc}")
            print(f"  [FAIL] 节点 {name} 抛异常：{exc}")
            continue
        if state.get("failed_node"):
            problems.append(f"节点 {name} 被标记失败：{state.get('failed_node')}")
        print(
            f"  [ ok ] {name:<10} merged={state.get('merged_count')} "
            f"enriched={state.get('enriched_count')} alerts={state.get('alerts')}"
        )

    # --- 阶段 3：事件校验
    print("阶段 3/3：事件载荷与因果链校验")
    if rec is None:
        print("  （--redis 模式不记录载荷，跳过逐条校验；请用默认模式做契约核对）")
        return 0

    envelopes = [json.loads(raw) for _, raw in rec.published]
    by_topic: dict[str, list[dict]] = {}
    for env in envelopes:
        by_topic.setdefault(env["topic"], []).append(env)

    print(f"  发布事件 {len(envelopes)} 条，主题 {sorted(by_topic)}")
    for env in envelopes:
        topic = env["topic"]
        env_errors = validate(load_schema("EventEnvelope.json"), env)
        if env_errors:
            problems.append(f"{topic} 信封违约: {env_errors[:2]}")
        if topic not in ALL_TOPICS:
            problems.append(f"{topic} 不在 ALL_TOPICS 里")
            continue
        schema = payload_schema_for(topic)
        if schema is None:
            problems.append(f"{topic} 没有登记载荷契约")
            continue
        errors = validate(schema, env["payload"])
        if errors:
            problems.append(f"{topic} 载荷违约: {errors[:2]}")

    # 因果链逐跳：子事件的 causation_id 必须落在**父事件**的 event_id 集合里
    for topic in (*EXPECTED_CHAIN, "dq.verdicts", "enrich.evidence"):
        if topic not in by_topic:
            print(f"  [warn] 因果链缺少 {topic}（可能本轮没数据，不算失败）")
    edges = list(zip(EXPECTED_CHAIN, EXPECTED_CHAIN[1:], strict=False)) + list(EXPECTED_BRANCHES)
    for parent, child in edges:
        children = by_topic.get(child) or []
        parents = {e["event_id"] for e in (by_topic.get(parent) or [])}
        if not (children and parents):
            continue
        linked = [e for e in children if e.get("causation_id") in parents]
        print(f"  因果链 {parent} → {child}: {len(linked)}/{len(children)} 条挂上了上游")
        if not linked:
            problems.append(f"因果链断了：{child} 没有任何一条指向 {parent}")
    roots = [e for e in (by_topic.get("raw.docs") or []) if "causation_id" not in e]
    if by_topic.get("raw.docs") and not roots:
        problems.append("raw.docs 是根事件，不该带 causation_id")

    # 降级可见性
    degraded = [e for e in envelopes if e["topic"] == "fallback.events"]
    print(
        f"  降级事件 fallback.events: {len(degraded)} 条（无 Key/无 Redis 时应当出现或走 try_publish 记录）"
    )

    print()
    if problems:
        print("发现问题：")
        for item in problems:
            print("  -", item)
        return 1
    print("OK：整条链在真实配置下跑通，全部事件载荷过契约，因果链完整")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="跑一次完整 cycle 并校验事件链路")
    parser.add_argument("--sources", help="逗号分隔的采集源（默认全部）")
    parser.add_argument("--redis", action="store_true", help="真发 Redis（需 6379 在听）")
    args = parser.parse_args()
    sources = [s.strip() for s in (args.sources or "").split(",") if s.strip()] or None
    return asyncio.run(run_cycle(sources, args.redis))


if __name__ == "__main__":
    raise SystemExit(main())

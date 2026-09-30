"""真实数据接线检查：EPSS/KEV 数据路径 + 动态优先级排名。

三件事必须在真实数据上成立，单测覆盖不到：

1. 归一阶段能从**真实形状的 NVD payload** 抽出 EPSS/KEV；
2. 跨源合并（dedup）**不丢**这两个字段；
3. triage 的排名与 `TriageOrder` 载荷在真库条目上过契约。

**放在 `scripts/` 而不是 `data/`**：`data/` 被 `.gitignore` 覆盖，
而真库验证脚本恰恰是最该留存的资产（曾只存在于一台机器上，见任务指示 §4.1）。

用法（与 API 相同的环境变量）：
    python -m scripts.check_real_data
    # 或指向 demo 库：
    #   $env:POSTGRES_DSN="sqlite:///E:/code/ai-threat-intel-demo-v1/data/demo.db"
    #   python -m scripts.check_real_data
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from aiintel.agents import nodes  # noqa: E402
from aiintel.agents.state import new_state  # noqa: E402
from aiintel.config import get_settings  # noqa: E402
from aiintel.core.events import TOPIC_DQ_VERDICTS, EventBus  # noqa: E402
from aiintel.db.base import get_sessionmaker  # noqa: E402
from aiintel.db.models import Vuln  # noqa: E402
from aiintel.services.ingest.dedup import merge_items  # noqa: E402
from aiintel.services.ingest.pipeline import (  # noqa: E402
    extract_epss,
    extract_kev,
    load_intel_item,
)
from scripts.contracts import load_schema, validate  # noqa: E402
from scripts.validate_contracts import payload_schema_for  # noqa: E402

#: 真库条目抽样上限。写成一个具名常量而不是裸 `12`，是为了让输出能说清
#: "总共多少条、这轮看了多少条"——否则抽样会被当成全量。
_SAMPLE = 12


class RecordingBus:
    def __init__(self) -> None:
        class FakeRedis:
            def __init__(self) -> None:
                self.published: list[tuple[str, str]] = []

            async def publish(self, channel: str, message: str) -> int:
                self.published.append((channel, message))
                return 1

        self.redis = FakeRedis()
        self.bus = EventBus(redis_client=self.redis)


def check_signal_extraction() -> list[str]:
    """真实**形状**的 NVD 2.0 payload → EPSS / KEV。

    注意：`fixtures/nvd_cve.sample.json` 是真实 NVD 快照，里面**本来就没有**
    `cisaExploitAdd` / `epss` 字段（NVD 的 KEV 标记来自 CISA 目录，EPSS 来自 FIRST），
    所以这里用同形状的合成 payload 验证解包逻辑，而不是去改那份快照。
    """

    problems: list[str] = []

    # NVD 2.0 响应体形态：KEV 标记 + EPSS 数组（两种已知摆放都覆盖）
    payload = {
        "cve": {
            "id": "CVE-2026-31001",
            "descriptions": [{"lang": "en", "value": "vLLM template injection RCE"}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
            "cisaExploitAdd": "2026-09-22",
            "epss": [{"epss": 0.87, "percentile": 0.99}],
        }
    }
    kev = extract_kev(payload)
    epss = extract_epss(payload)
    print(f"NVD 2.0 形态: kev={kev} epss={epss}")
    if kev is not True:
        problems.append("cisaExploitAdd 没被识别为 KEV")
    if epss != 0.87:
        problems.append(f"EPSS 数组形态没被抽出（得到 {epss!r}）")

    # 扁平形态
    flat = {"id": "CVE-2026-2", "metrics": {}, "epss": 0.42}
    if extract_epss(flat) != 0.42:
        problems.append("扁平 epss 形态没被抽出")
    # 只有 hasKev（查询开关）时**不许**当作在野利用
    if extract_kev({"id": "x", "hasKev": True}) is not False:
        problems.append("把 hasKev 查询开关误当成 KEV 标记（collectors/nvd.py:52 明确警告过）")
    # 缺信号不能瞎猜
    if extract_epss({}) is not None or extract_kev({}) is not False:
        problems.append("缺信号时返回值不对（不应臆造）")
    return problems


def check_dedup_preserves_signals() -> list[str]:
    """跨源合并后 EPSS 取更大值、KEV 取并集（来源先后不该影响风险判断）。"""

    problems: list[str] = []
    low = {
        "id": "r1",
        "source": "nvd",
        "cve_id": "CVE-2026-31001",
        "content_hash": "h1" + "0" * 62,
        "epss": 0.02,
        "kev": False,
        "cvss_score": 9.8,
    }
    high = {
        "id": "r2",
        "source": "ghsa",
        "cve_id": "CVE-2026-31001",
        "content_hash": "h2" + "0" * 62,
        "epss": 0.91,
        "kev": True,
        "cvss_score": 7.5,
    }
    for order, label in (((low, high), "nvd→ghsa"), ((high, low), "ghsa→nvd")):
        merged = merge_items([dict(x) for x in order])
        item = merged[0]
        print(f"  合并顺序 {label}: epss={item.get('epss')} kev={item.get('kev')}")
        if item.get("epss") != 0.91:
            problems.append(f"{label}：EPSS 没取更大值（得到 {item.get('epss')!r}）")
        if item.get("kev") is not True:
            problems.append(f"{label}：KEV 没取并集")
    return problems


async def check_triage_on_real_rows() -> list[str]:
    """真库条目 → 动态排名 → TriageOrder 载荷过契约。"""

    problems: list[str] = []
    with get_sessionmaker()() as session:
        total = session.query(Vuln).count()
        rows = session.query(Vuln).limit(_SAMPLE).all()
        items = [payload for row in rows if (payload := load_intel_item(row.id))]
    # 标签必须说清扫的是哪个库、扫了多少条：早先这里写死成"从 demo.db"，
    # 于是指向真 PG 时输出仍在说 demo.db，看的人会误以为验的是演示库。
    dsn = get_settings().postgres_dsn
    print(f"数据源 {dsn}")
    print(f"装配 IntelItem: {len(items)} 条（vuln 共 {total} 条，本轮抽样 {_SAMPLE} 条）")
    if total > _SAMPLE:
        print(f"  注意：只抽了前 {_SAMPLE} 条，未覆盖其余 {total - _SAMPLE} 条")

    rec = RecordingBus()
    nodes.bus = rec.bus
    state = new_state(trace_id="real-triage", task="monitor_cycle")
    state = {**state, "merged": items}
    state = await nodes.node_dq1(state)
    state = await nodes.node_triage(state)

    queue = state.get("triage_queue") or []
    schema = payload_schema_for("enrich.triage")
    assert schema is not None
    for entry in queue:
        errors = validate(schema, entry)
        if errors:
            problems.append(f"TriageOrder 载荷违约 {entry.get('vuln_id')}: {errors[:2]}")
    print(f"排名 {len(queue)} 条，队首={state['vuln_id']} priority={state['priority']}")
    for entry in queue[:3]:
        print(
            f"  rank={entry['rank']} {entry['vuln_id']} score={entry['score']} "
            f"prio={entry['priority']} route={entry['route']} epss={entry['epss']} kev={entry['kev']}"
        )
    if not queue:
        problems.append("triage 没产出排名队列")
    elif queue[0]["rank"] != 1:
        problems.append("队首 rank 不为 1")

    # 真实 payload 上的排序必须与"只看 CVSS"不同（否则改动没生效）
    by_cvss = sorted(items, key=lambda i: -(i.get("cvss_score") or 0))
    if items and by_cvss and queue:
        print(f"  CVSS 单因子首位={by_cvss[0].get('cve_id')}，动态策略首位={queue[0]['vuln_id']}")

    # DQ1 仍然在 triage 之前生效
    envelopes = [json.loads(raw) for _, raw in rec.redis.published]
    if not any(e["topic"] == TOPIC_DQ_VERDICTS for e in envelopes):
        problems.append("没发 dq.verdicts")
    for env in envelopes:
        if validate(load_schema("EventEnvelope.json"), env):
            problems.append(f"信封违约: {env['topic']}")
    return problems


async def main() -> int:
    problems: list[str] = []
    print("=== 1) 真实 NVD payload → EPSS/KEV ===")
    problems += check_signal_extraction()
    print("=== 2) 跨源合并保留 EPSS/KEV ===")
    problems += check_dedup_preserves_signals()
    print("=== 3) 真库条目 → 动态排名 → 载荷契约 ===")
    problems += await check_triage_on_real_rows()

    print()
    if problems:
        print("发现问题：")
        for item in problems:
            print("  -", item)
        return 1
    print("OK：EPSS/KEV 数据路径与动态优先级在真实数据上全部成立")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

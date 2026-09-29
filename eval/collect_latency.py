"""采集时效指标：fetched_at - published_at 的分位数与 SLA 达成率。

评分目标：P95 ≤ 6h 为优秀档，≤12h 为良好档，≤24h 为合格档。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SLA_TIERS = {"excellent": 6 * 3600, "good": 12 * 3600, "pass": 24 * 3600, "fail": None}


def collect_latency_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """rows: [{"source": str, "latency_seconds": float}]"""

    by_source: dict[str, list[float]] = {}
    for row in rows:
        seconds = row.get("latency_seconds")
        if seconds is None or seconds < 0:
            continue
        by_source.setdefault(row.get("source", "unknown"), []).append(float(seconds))

    def percentile(values: list[float], p: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        idx = min(int(len(ordered) * p), len(ordered) - 1)
        return round(ordered[idx], 1)

    overall: list[float] = [v for values in by_source.values() for v in values]
    p50, p95 = percentile(overall, 0.5), percentile(overall, 0.95)
    tier = next(
        (name for name, limit in SLA_TIERS.items() if limit and p95 is not None and p95 <= limit),
        "fail",
    )
    return {
        "samples": len(overall),
        "p50_seconds": p50,
        "p95_seconds": p95,
        "sla_tier": tier,
        "sla_6h_ratio": round(sum(1 for v in overall if v <= 6 * 3600) / len(overall), 4)
        if overall
        else None,
        "by_source": {
            source: {
                "samples": len(values),
                "p50_seconds": percentile(values, 0.5),
                "p95_seconds": percentile(values, 0.95),
            }
            for source, values in by_source.items()
        },
    }


def derive_latency_seconds(stored: float | None, published: Any, fetched: Any) -> float | None:
    """算单条采集延迟：优先用落库值，为空则由两个时间戳推导。

    **为什么要有这个函数**：原实现只读 `RawItem.latency_seconds`，
    而该列在演示库里恒为 NULL —— 于是评测报 `samples: 0`、`p50/p95 = null`、
    `sla_tier = "fail"`。但 `published_at` / `fetched_at` 明明都有真值，
    时效是**算得出来**的。这不是"没有数据"，是"没去算"，
    会让报告里的时效指标无端变成 fail（实测踩过）。

    抽成独立函数是为了能单测（`load_from_db` 依赖数据库，不好测）。
    """

    if stored is not None:
        return float(stored)
    if not published or not fetched:
        return None
    return (fetched - published).total_seconds()


def load_from_db() -> list[dict[str, Any]]:
    from aiintel.db.base import get_sessionmaker
    from aiintel.db.models import RawItem

    with get_sessionmaker()() as session:
        rows = session.query(RawItem).all()
        return [
            {
                "source": r.source,
                "published_at": r.published_at.isoformat() if r.published_at else None,
                "fetched_at": r.fetched_at.isoformat() if r.fetched_at else None,
                "latency_seconds": derive_latency_seconds(
                    r.latency_seconds, r.published_at, r.fetched_at
                ),
            }
            for r in rows
        ]


def main() -> dict[str, Any]:
    try:
        rows = load_from_db()
    except Exception as exc:  # noqa: BLE001 - 无库时用样本文件
        print(f"[warn] 数据库不可用({exc})，改用 eval/datasets/collect_latency.sample.json")
        sample = Path(__file__).parent / "datasets" / "collect_latency.sample.json"
        if not sample.exists():
            return {"error": "no data source available"}
        rows = json.loads(sample.read_text(encoding="utf-8"))
    stats = collect_latency_stats(rows)
    print("[collect] ", json.dumps(stats, ensure_ascii=False))
    return stats


if __name__ == "__main__":
    print(json.dumps(main(), ensure_ascii=False, indent=2))

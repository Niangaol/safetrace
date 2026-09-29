"""采集时效指标的回归测试。

`load_from_db` 只读 `RawItem.latency_seconds`，而该列在演示库里恒为 NULL，
导致评测报 `samples: 0` / `sla_tier: "fail"` —— 但 `published_at` 与 `fetched_at`
都有真值，时效算得出来。这是"没去算"，不是"没数据"，会把报告的时效指标误判成不合格。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from eval.collect_latency import (
    collect_latency_stats,
    derive_latency_seconds,
)

T0 = datetime(2026, 9, 28, 7, 0, tzinfo=UTC)


def test_derive_prefers_stored_value() -> None:
    """落库值优先（它可能是采集端实测的，比事后相减更准）。"""

    assert derive_latency_seconds(123.0, T0, T0 + timedelta(hours=9)) == 123.0


def test_derive_falls_back_to_timestamps() -> None:
    """回归：stored 为 None 时必须由时间戳推导，否则 samples 恒为 0。"""

    fetched = T0 + timedelta(hours=3)
    assert derive_latency_seconds(None, T0, fetched) == 3 * 3600.0


def test_derive_returns_none_when_insufficient() -> None:
    assert derive_latency_seconds(None, None, T0) is None
    assert derive_latency_seconds(None, T0, None) is None


def test_negative_latency_is_skipped_not_counted() -> None:
    """fetched 早于 published（时钟问题）算负值，应被跳过而不是污染分位数。"""

    rows = [
        {"source": "nvd", "latency_seconds": 7200.0},
        {"source": "nvd", "latency_seconds": -60.0},  # 脏数据
        {"source": "ghsa", "latency_seconds": None},  # 无值
    ]
    stats = collect_latency_stats(rows)
    assert stats["samples"] == 1, "负值与空值都不该计入样本"
    assert stats["p50_seconds"] == 7200.0
    assert stats["sla_6h_ratio"] == 1.0


def test_real_derived_data_hits_excellent_tier() -> None:
    """用演示库真实的 (published, fetched) 形状算一遍，确认档位判定可用。

    演示数据里 nvd 是 published 07:00 / fetched 09:00（2h）这类分布，
    只要推导生效就不该再是 fail。
    """

    rows = [
        {"source": s, "latency_seconds": derive_latency_seconds(None, T0, T0 + timedelta(hours=h))}
        for s, h in (("nvd", 3), ("ghsa", 3), ("community_rss", 2), ("arxiv", 2))
    ]
    stats = collect_latency_stats(rows)
    assert stats["samples"] == 4
    assert stats["sla_tier"] in ("excellent", "good"), stats
    assert stats["sla_6h_ratio"] == 1.0
    assert set(stats["by_source"]) == {"nvd", "ghsa", "community_rss", "arxiv"}

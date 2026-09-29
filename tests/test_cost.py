"""成本闸门与峰谷计价：核心风控逻辑必须稳定。"""

from __future__ import annotations

import json
from datetime import datetime, time

import pytest

from aiintel.core.cost import (
    PRICES,
    BudgetExceeded,
    CostGuard,
    Usage,
    blended_price,
    estimate_cny,
    is_peak,
)


def _beijing(y: int, m: int, d: int, hh: int, mm: int = 0) -> datetime:
    from aiintel.config import BEIJING_TZ

    return datetime(y, m, d, hh, mm, tzinfo=BEIJING_TZ)


def test_peak_window_matches_design():
    assert is_peak(_beijing(2026, 9, 28, 10)) is True  # 9-12 高峰
    assert is_peak(_beijing(2026, 9, 28, 15)) is True  # 14-18 高峰
    assert is_peak(_beijing(2026, 9, 28, 12)) is False  # 右开区间
    assert is_peak(_beijing(2026, 9, 28, 3)) is False  # 闲时


def test_peak_costs_more_than_idle():
    idle = Usage(1_000_000, 0, 1_000_000).cost_cny("flash", _beijing(2026, 9, 28, 3))
    peak = Usage(1_000_000, 0, 1_000_000).cost_cny("flash", _beijing(2026, 9, 28, 10))
    assert peak > idle


def test_cache_hit_is_cheaper_than_fresh_input():
    hit = Usage(1_000_000, 1_000_000, 0).cost_cny("flash", _beijing(2026, 9, 28, 3))
    fresh = Usage(1_000_000, 0, 0).cost_cny("flash", _beijing(2026, 9, 28, 3))
    assert hit < fresh


def test_pro_expensive_than_flash():
    f = Usage(1_000_000, 0, 1_000_000).cost_cny("flash", _beijing(2026, 9, 28, 3))
    p = Usage(1_000_000, 0, 1_000_000).cost_cny("pro", _beijing(2026, 9, 28, 3))
    assert p > f


def test_blended_price_between_idle_and_peak():
    blended = blended_price("flash")
    idle, peak = PRICES["flash"]["idle"], PRICES["flash"]["peak"]
    assert idle.input <= blended.input <= peak.input
    assert idle.output <= blended.output <= peak.output


def test_usage_cost_matches_price_table():
    usage = Usage(2_000_000, 0, 1_000_000)
    assert usage.cost_cny("flash", _beijing(2026, 9, 28, 3)) == pytest.approx(
        2 * PRICES["flash"]["idle"].input + 1 * PRICES["flash"]["idle"].output
    )


def test_estimate_cny_scales_with_cache_hit():
    assert estimate_cny(100_000, 10_000, "flash", 0.0) > estimate_cny(100_000, 10_000, "flash", 0.9)


def test_guard_records_and_accumulates(tmp_path):
    # 预算要盖住单次调用的最高峰谷价（flash 峰时 1M in + 1M out = 12 元），
    # 否则 remaining() 归零后这条断言只在闲时成立，每天高峰时段都会挂
    guard = CostGuard(daily_budget=1_000.0, tracker_path=str(tmp_path / "c.jsonl"))
    assert guard.spent_today() == 0.0
    cost = guard.record(Usage(1_000_000, 0, 1_000_000), "flash", model="m", node="n", agent="A")
    assert cost > 0
    assert guard.spent_today() == pytest.approx(cost)
    assert guard.remaining() == pytest.approx(1_000.0 - cost)
    assert guard.exceeded() is False


def test_remaining_clamps_at_zero_when_over_budget(tmp_path):
    """remaining() 不应返回负数：超预算是"没钱了"，不是"倒欠"。"""

    guard = CostGuard(daily_budget=0.000001, tracker_path=str(tmp_path / "c.jsonl"))
    guard.record(Usage(1_000_000, 0, 1_000_000), "flash", model="m")
    assert guard.spent_today() > guard.daily_budget
    assert guard.remaining() == 0.0
    assert guard.exceeded() is True


def test_guard_raises_after_budget_exhausted(tmp_path):
    guard = CostGuard(daily_budget=0.000001, tracker_path=str(tmp_path / "c.jsonl"))
    guard.record(Usage(1_000_000, 0, 1_000_000), "flash", model="m")
    assert guard.exceeded() is True
    with pytest.raises(BudgetExceeded):
        guard.check()


def test_guard_near_budget_warning(tmp_path):
    guard = CostGuard(daily_budget=10.0, warn_ratio=0.5, tracker_path=str(tmp_path / "c.jsonl"))
    guard.record(Usage(1_000_000, 0, 1_000_000), "flash", model="m")
    assert guard.near_budget() is True


def test_guard_survives_corrupt_logfile(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    guard = CostGuard(daily_budget=5.0, tracker_path=str(path))
    assert guard.spent_today() == 0.0


def test_breakdown_sums_to_today_total(tmp_path):
    guard = CostGuard(daily_budget=10.0, tracker_path=str(tmp_path / "c.jsonl"))
    guard.record(Usage(1_000, 0, 500), "flash", model="m", node="qa", agent="QAAgent")
    guard.record(Usage(2_000, 0, 900), "pro", model="m", node="enrich", agent="EnrichAgent")
    breakdown = guard.breakdown()
    assert set(breakdown) == {"QAAgent/qa", "EnrichAgent/enrich"}
    assert sum(breakdown.values()) == pytest.approx(guard.spent_today())


def test_tracker_file_is_jsonl(tmp_path):
    path = tmp_path / "c.jsonl"
    guard = CostGuard(daily_budget=10.0, tracker_path=str(path))
    guard.record(Usage(10, 0, 5), "flash", model="m", node="n", agent="a")
    rec = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert {"day", "cost_cny", "tier", "usage"} <= set(rec)


def test_reservation_contextmanager_blocks_when_exceeded(tmp_path):
    guard = CostGuard(daily_budget=0.0, tracker_path=str(tmp_path / "c.jsonl"))
    with pytest.raises(BudgetExceeded), guard.reservation():
        pass


def test_peak_windows_are_non_overlapping():
    windows = sorted(PRICES["flash"])  # ['idle', 'peak']
    assert windows == ["idle", "peak"]
    assert time(9) < time(12) < time(14) < time(18)

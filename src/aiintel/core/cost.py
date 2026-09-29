"""成本治理：DeepSeek 峰谷计价模型 + 日预算熔断。

参考 docs/设计文档.md 第 10 章。单价为 2026-08-17 起的官方人民币计价，
价格会变，充值/预算复核以 api-docs.deepseek.com 为准。
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import Path
from typing import Literal

from aiintel.config import BEIJING_TZ, get_settings

ModelTier = Literal["flash", "pro"]
Cny = float


@dataclass(frozen=True, slots=True)
class Price:
    """元 / 百万 tokens。"""

    cache_hit_input: Cny
    input: Cny
    output: Cny


# 峰谷分时：高峰 9:00-12:00、14:00-18:00，其余为闲时（闲时价为高峰的一半）
PEAK_WINDOWS: tuple[tuple[time, time], ...] = (
    (time(9), time(12)),
    (time(14), time(18)),
)

PRICES: dict[ModelTier, dict[str, Price]] = {
    "flash": {
        "idle": Price(cache_hit_input=0.05, input=1.5, output=4.5),
        "peak": Price(cache_hit_input=0.10, input=3.0, output=9.0),
    },
    "pro": {
        "idle": Price(cache_hit_input=0.15, input=4.5, output=13.5),
        "peak": Price(cache_hit_input=0.30, input=9.0, output=27.0),
    },
}

# 闲时 17h / 高峰 7h，按天加权后的平均价，用于预算预判
IDLE_SHARE = 17 / 24
PEAK_SHARE = 1 - IDLE_SHARE


def is_peak(moment: datetime | None = None) -> bool:
    now = (moment or datetime.now(BEIJING_TZ)).astimezone(BEIJING_TZ)
    t = now.time()
    return any(start <= t < end for start, end in PEAK_WINDOWS)


def blended_price(tier: ModelTier) -> Price:
    """峰谷加权平均价，用于成本预估与日预算判断。"""

    idle, peak = PRICES[tier]["idle"], PRICES[tier]["peak"]
    return Price(
        cache_hit_input=idle.cache_hit_input * IDLE_SHARE + peak.cache_hit_input * PEAK_SHARE,
        input=idle.input * IDLE_SHARE + peak.input * PEAK_SHARE,
        output=idle.output * IDLE_SHARE + peak.output * PEAK_SHARE,
    )


@dataclass(slots=True)
class Usage:
    prompt_tokens: int = 0
    cache_hit_tokens: int = 0
    completion_tokens: int = 0

    def cost_cny(self, tier: ModelTier, at: datetime | None = None) -> Cny:
        period = "peak" if is_peak(at) else "idle"
        price = PRICES[tier][period]
        miss = max(self.prompt_tokens - self.cache_hit_tokens, 0)
        return (
            miss / 1e6 * price.input
            + self.cache_hit_tokens / 1e6 * price.cache_hit_input
            + self.completion_tokens / 1e6 * price.output
        )


class BudgetExceeded(RuntimeError):
    """日预算耗尽。调用方应降级到本地模型而不是直接失败。"""


class CostGuard:
    """按天累计 API 花费，超阈值抛 BudgetExceeded（不阻断业务流程）。"""

    def __init__(
        self,
        daily_budget: float,
        warn_ratio: float = 0.8,
        tracker_path: str = "./data/cost.jsonl",
    ) -> None:
        self.daily_budget = daily_budget
        self.warn_ratio = warn_ratio
        self.tracker_path = Path(tracker_path)
        self._lock = threading.Lock()
        self._records: dict[date, float] = {}
        self._load()

    def _load(self) -> None:
        if not self.tracker_path.exists():
            return
        for line in self.tracker_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            day = date.fromisoformat(rec["day"])
            self._records[day] = self._records.get(day, 0.0) + rec["cost_cny"]

    def _append(self, rec: dict) -> None:
        self.tracker_path.parent.mkdir(parents=True, exist_ok=True)
        with self.tracker_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def spent_today(self) -> Cny:
        with self._lock:
            return self._records.get(datetime.now(BEIJING_TZ).date(), 0.0)

    def remaining(self) -> Cny:
        return max(self.daily_budget - self.spent_today(), 0.0)

    def exceeded(self) -> bool:
        return self.spent_today() >= self.daily_budget

    def near_budget(self) -> bool:
        return self.spent_today() >= self.daily_budget * self.warn_ratio

    def check(self) -> None:
        if self.exceeded():
            raise BudgetExceeded(
                f"当日 LLM 预算已用尽（{self.spent_today():.2f}/{self.daily_budget:.2f} 元），应降级本地模型"
            )

    def record(
        self,
        usage: Usage,
        tier: ModelTier,
        *,
        model: str,
        node: str = "unknown",
        agent: str = "unknown",
    ) -> Cny:
        cost = usage.cost_cny(tier)
        now = datetime.now(BEIJING_TZ)
        rec = {
            "ts": now.isoformat(),
            "day": now.date().isoformat(),
            "period": "peak" if is_peak(now) else "idle",
            "tier": tier,
            "model": model,
            "node": node,
            "agent": agent,
            "usage": {
                "prompt": usage.prompt_tokens,
                "cache_hit": usage.cache_hit_tokens,
                "completion": usage.completion_tokens,
            },
            "cost_cny": round(cost, 6),
        }
        with self._lock:
            self._records[now.date()] = self._records.get(now.date(), 0.0) + cost
            self._append(rec)
        return cost

    def breakdown(self) -> dict[str, float]:
        """按 node/agent 聚合今日花费，用于回答"钱花在哪了"。"""

        if not self.tracker_path.exists():
            return {}
        today = datetime.now(BEIJING_TZ).date().isoformat()
        agg: dict[str, float] = {}
        for line in self.tracker_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("day") == today:
                key = f"{rec.get('agent', '?')}/{rec.get('node', '?')}"
                agg[key] = agg.get(key, 0.0) + rec["cost_cny"]
        return dict(sorted(agg.items(), key=lambda kv: -kv[1]))

    @contextmanager
    def reservation(self) -> Iterator[None]:
        """进入前检查预算，退出后强制落账（用于无法提前知道 token 数的调用）。"""

        self.check()
        yield


_guard: CostGuard | None = None


def get_cost_guard() -> CostGuard:
    global _guard
    if _guard is None:
        s = get_settings()
        _guard = CostGuard(
            daily_budget=s.cost_daily_budget_cny,
            warn_ratio=s.cost_warn_ratio,
            tracker_path=s.cost_tracker_path,
        )
    return _guard


def estimate_cny(
    prompt_tokens: int,
    completion_tokens: int,
    tier: ModelTier = "flash",
    cache_hit_ratio: float = 0.4,
) -> Cny:
    """离线预估单次调用成本（报告与预算编制用）。"""

    hit = int(prompt_tokens * cache_hit_ratio)
    return Usage(prompt_tokens, hit, completion_tokens).cost_cny(tier)

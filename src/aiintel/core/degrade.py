"""统一降级出口（FB1 红线：禁止静默兜底）。

对标 SafeTrace `src/shared/src/degrade.ts`：所有降级必须经本模块，
产出权威 `degraded_to`（6 值枚举）+ `degraded_state{label, since, detail_ref}`，
并可发 `fallback.events` 事件 —— 缺标记视为缺陷，而不是风格问题。

三条不变式（与 `evidence.build_result()` 同源，此处对**非富化**通道生效）：

1. 降级必须留痕：有 `degraded_to` 就必须有 `label` 与 `since`；
2. 降级必须可回溯：`detail_ref` 指向 `trace_id`；
3. 降级必须可恢复：尽量给出 `recovery_hint`。
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from aiintel.core.contracts import (
    DEGRADE_LABELS,
    RECOVERY_HINTS,
    ContractProjectionError,
    to_contract_degrade,
)

#: 权威 `fallback.events` 的 layer 枚举
LAYERS = ("L1", "L2", "L3", "L4")

#: 权威 `fallback.events` 主题名
FALLBACK_TOPIC = "fallback.events"


@dataclass(slots=True)
class DegradeMarker:
    """一次降级的显式标记。序列化为权威降级三件套。"""

    degraded_to: str
    label: str
    since: str = field(default_factory=lambda: dt.datetime.now(dt.UTC).isoformat())
    detail_ref: str = "trace_unavailable"
    recovery_hint: str = ""
    detail: str = ""
    trigger: str = ""
    layer: str = "L3"
    user_visible: bool = True

    @property
    def contract_value(self) -> str:
        """权威 6 值枚举。内部细名保留在 `detail`。

        映射口径**只有一份**，在 `core/contracts.py::DEGRADE_TO_CONTRACT`；
        这里不再自带一份表（两份表就是"降级口径有两处定义"的老毛病）。
        """

        try:
            return to_contract_degrade(self.degraded_to) or ""
        except ContractProjectionError as exc:
            raise ContractProjectionError(str(exc)) from None

    def state(self) -> dict[str, str]:
        """权威 `degraded_state` 固定形状。"""

        return {"label": self.label, "since": self.since, "detail_ref": self.detail_ref}

    def to_contract(self) -> dict[str, Any]:
        """权威降级标记：`degraded_to` + `degraded_state` + `recovery_hint`（可空）。"""

        out: dict[str, Any] = {
            "degraded_to": self.contract_value,
            "degraded_state": self.state(),
        }
        hint = self.recovery_hint or RECOVERY_HINTS.get(self.degraded_to, "")
        if hint:
            out["recovery_hint"] = hint
        return out

    def to_fallback_event(self, *, event_id: str, trace_id: str) -> dict[str, Any]:
        """权威内联契约 `FallbackEvent`（`fallback.events` 主题 payload）。"""

        if self.layer not in LAYERS:
            raise ContractProjectionError(f"layer {self.layer!r} 不在权威枚举 {LAYERS} 内")
        return {
            "event_id": event_id,
            "layer": self.layer,
            "trigger": self.trigger or self.degraded_to,
            "action_taken": f"切换到 {self.degraded_to} 通道继续服务",
            "degraded_of": self.detail or "unknown",
            "user_visible": self.user_visible,
            "degraded_state": self.state(),
            **({"recovery_hint": self.recovery_hint} if self.recovery_hint else {}),
            "trace_id": trace_id,
        }


def degrade(
    degraded_to: str,
    *,
    detail: str = "",
    trace_id: str | None = None,
    trigger: str = "",
    layer: str = "L3",
    label: str = "",
    recovery_hint: str = "",
    user_visible: bool = True,
) -> DegradeMarker:
    """构造降级标记。

    `label` 省略时取 `DEGRADE_LABELS` 里的用户可见文案；`trace_id` 缺失时用
    `trace_unavailable` 占位而不是静默丢弃 —— 缺 `detail_ref` 才是缺陷。
    """

    return DegradeMarker(
        degraded_to=degraded_to,
        label=label or DEGRADE_LABELS.get(degraded_to, f"已降级：{degraded_to}"),
        detail_ref=trace_id or "trace_unavailable",
        recovery_hint=recovery_hint or RECOVERY_HINTS.get(degraded_to, ""),
        detail=detail,
        trigger=trigger,
        layer=layer,
        user_visible=user_visible,
    )


def is_degraded(payload: dict[str, Any]) -> bool:
    """是否处于降级状态。非空 `degraded_to` 即为降级（权威红线）。"""

    return bool(payload.get("degraded_to"))


def visible_banner(payload: dict[str, Any]) -> str:
    """用户可见降级横幅文案。`events.md`：界面必须看到降级横幅或答案尾部标注。"""

    if not is_degraded(payload):
        return ""
    state = payload.get("degraded_state")
    if isinstance(state, dict) and state.get("label"):
        label = str(state["label"])
    else:
        label = DEGRADE_LABELS.get(str(payload.get("degraded_detail") or ""), "已降级")
    hint = payload.get("recovery_hint") or payload.get("degraded_state", {}).get("label", "")
    return f"[降级] {label}" + (f"（{hint}）" if hint and hint != label else "")

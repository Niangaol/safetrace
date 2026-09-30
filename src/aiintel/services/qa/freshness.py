"""答案的可信状态：**时效**与**注入筛查**。

## 为什么要有这个模块

上游契约 v1.1.3（C-04）给 `Answer` 追加了两个可选对象字段：

- `stale_warning`：证据是否**过龄**或**时效未知**
- `injection_guard`：证据是否经过**注入筛查**

本仓同步了这两个字段（见 `contracts/schemas/FROZEN_MANIFEST.json`），
但**只同步 schema 不改代码 = 字段永远为空**，用户仍然不知道手上的答案
"是不是拿一年前的证据答的""引用的外部网页有没有被人塞过指令"。

## 两个状态的设计原则（沿用了上游的硬要求，本仓认同并照做）

契约原文：

> `stale_warning` 缺省 = 未做时效评估，禁止当作证据新鲜
> `injection_guard.screened=false` **必须显式出现**，禁止把未筛查读成已筛查干净

所以本模块的两条铁律：

1. **"未知"必须说出来**，不能因为"没有证据说明它过时"就当作新鲜。
   只要有任意一条引用缺 `published_at`，就必须在 `note` 里点出条数。
2. **`screened=False` 永远是显式的**。本仓当前没有注入检测器，
   所以恒为 `False` —— 这不是缺陷，而是**如实**；把没做的筛查说成"干净"
   才是缺陷（红线 3：禁止静默兜底）。
"""

from __future__ import annotations

import datetime as dt
from typing import Any

#: 默认时效阈值（天）。与上游 `DEFAULT_STALE_THRESHOLD_DAYS` 一致。
#: 上游注明「A-05 将按意图细化」，本仓同样先取一个保守的统一值。
DEFAULT_STALE_THRESHOLD_DAYS = 365


def _parse_loose(value: Any) -> dt.datetime | None:
    """尽量解析时间；解析不出返回 None（**不猜**）。

    为什么要"loose"：上游 `published_at` 来自各采集源，格式并不统一
    （有的带时区、有的是 naive、有的可能是日期串）。契约对缺省的要求是
    「按未知处理」，所以解析失败必须归入"未知"，而不是当成"很新"。
    """

    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=dt.UTC)
    text = str(value).strip()
    if not text:
        return None
    # 允许末尾 Z（ISO 8601 的 UTC 写法）
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        # 只到"日"的写法
        try:
            parsed = dt.datetime.fromisoformat(candidate[:10])
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def assess_staleness(
    citations: list[dict[str, Any]],
    *,
    now: dt.datetime | None = None,
    threshold_days: int = DEFAULT_STALE_THRESHOLD_DAYS,
) -> dict[str, Any] | None:
    """判断引用证据是否**过龄**或**时效未知**。

    返回 `None` 表示"证据都是新鲜的、且时效全部已知"—— 这是**唯一**
    可以不提示的情况。其余任何情形（过龄 / 有未知 / 全都未知）都必须给提示。

    语义与上游 `assessStaleness()` 对齐（本仓独立实现，未照搬代码）：
    - 取**最早**的一条作为证据年龄（最保守：最旧的那条决定结论有多可能过时）；
    - 只要有一条缺 `published_at` 就计入 `unknown_published_at` 并提示；
    - 全部缺 `published_at` 时单独给一条措辞更重的提示。
    """

    if not citations:
        return None

    moment = now or dt.datetime.now(dt.UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.UTC)

    parsed = [_parse_loose(c.get("published_at")) for c in citations]
    unknown = sum(1 for t in parsed if t is None)
    known = [t for t in parsed if t is not None]

    if not known:
        return {
            "threshold_days": threshold_days,
            "unknown_published_at": unknown,
            "note": (
                "⚠️ 证据时效提示：引用证据均无上游发布时间（published_at 缺失），"
                "时效未知、无法确认新鲜度，请谨慎采用。"
            ),
        }

    oldest = min(known)
    age_days = int((moment - oldest).total_seconds() // 86400)
    if age_days <= threshold_days and unknown == 0:
        return None

    parts: list[str] = []
    if age_days > threshold_days:
        parts.append(f"最早证据发布于 {age_days} 天前（阈值 {threshold_days} 天）")
    if unknown > 0:
        parts.append(f"{unknown} 条证据缺上游发布时间，时效未知")

    return {
        "threshold_days": threshold_days,
        "oldest_published_at": oldest.isoformat(),
        "unknown_published_at": unknown,
        "note": f"⚠️ 证据时效提示：{'；'.join(parts)}。结论请结合最新通告核对。",
    }


def assess_injection_guard(citations: list[dict[str, Any]]) -> dict[str, Any]:
    """注入筛查状态。

    **本仓当前没有注入检测器**（上游同样只落了契约位，检测实现归 A-04）。
    因此这里如实返回 `screened=False`，并统计引用了多少条 **untrusted** 证据
    —— 那是"可能被外部文本影响"的暴露面，是此刻能给出的最有价值信息。

    绝不返回 `screened=True`：那等于宣称做过一件没做的事。
    """

    untrusted = sum(1 for c in citations if c.get("trust") == "untrusted")
    total = len(citations)
    if total == 0:
        note = "本轮无引用证据，注入筛查不适用。"
    elif untrusted:
        note = (
            f"⚠️ 未做注入筛查（screened=false）：本轮引用了 {untrusted}/{total} 条"
            f"外部文本（trust=untrusted）证据，其内容可能含误导性指令，请勿当作操作依据。"
        )
    else:
        note = (
            f"未做注入筛查（screened=false）：本轮 {total} 条引用均来自权威源，"
            f"未发现外部文本；但这不代表已做过注入检测。"
        )
    return {
        "screened": False,
        "untrusted_evidence": untrusted,
        "note": note,
    }

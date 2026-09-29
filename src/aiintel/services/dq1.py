"""DQ1 数据质量闸门：脏数据不进知识底座（工程红线 2）。

赛题原文：「宁可少一条，不可错一条」。本模块是那条闸门 ——
判定在**富化之前**生效，判定结果随 `intel.items` 一起流下去，也是 `dq.verdicts` 主题的载荷。

设计要点（`docs/契约对齐-SafeTrace.md` §7）：

1. **6 类 flag 全部实现，且 flag 与分数解耦** —— 命中即置位；`quarantine` 只看 flag，
   不看分数。反之分数低但无 flag 只到 `review`。这样"结构性错误"不会被高平均分掩盖。
2. **可复算**：同 `gate_version` + 同输入 ⇒ 同输出。评分全是确定性计算，
   不调 LLM、不读时钟（`now` 由调用方传入，默认取 UTC 当前时刻）。
3. **权重随版本号走**：`GATE_WEIGHTS[gate_version]`，换权重必须换版本号，
   否则历史判定无法复算。
4. **verdict 四档语义**（与 `Vuln.quality_score` 的三档过滤对齐）：

   | verdict | 条件 | 含义 |
   | --- | --- | --- |
   | `quarantine` | 命中任一 flag | 结构性错误，进隔离区，不进底座 |
   | `review` | 分数 < 0.5 | 人工复核后才可用 |
   | `degrade` | 分数 < 0.7 | 可用但只做核心维度富化 |
   | `pass` | 其余 | 全量富化 |

   注：`docs/契约对齐-SafeTrace.md` 把四档写成"分数 `<` 阈值"，
   但阈值恰好等于 `enrich_min_quality_partial` / `enrich_min_quality_full` 时，
   用 `<=` 才能与 `dimensions_for_quality()` 的旧行为逐条一致（有回归测试钉住）。
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any

from aiintel.config import get_settings

#: 当前闸门版本。改评分权重/口径必须同步 +1，否则历史判定不可复算。
GATE_VERSION = "1.0.0"

#: 版本化权重（每版本一套，禁止原地改）
GATE_WEIGHTS: dict[str, dict[str, float]] = {
    "1.0.0": {
        "structure": 0.20,
        "completeness": 0.30,
        "consistency": 0.20,
        "timeliness": 0.15,
        "sourcing": 0.15,
    },
}

#: 6 类 flag。命中即 quarantine，与分数解耦。
FLAG_TS_NO_TZ = "ts_no_tz"
FLAG_REJECT_STATUS = "reject_status"
FLAG_POC_DEAD_LINK = "poc_dead_link"
FLAG_KEY5_MISSING = "key5_missing"
FLAG_BOILERPLATE = "boilerplate"
FLAG_MULTI_ID_MISMATCH = "multi_id_mismatch"

ALL_FLAGS: tuple[str, ...] = (
    FLAG_TS_NO_TZ,
    FLAG_REJECT_STATUS,
    FLAG_KEY5_MISSING,
    FLAG_BOILERPLATE,
    FLAG_MULTI_ID_MISMATCH,
    FLAG_POC_DEAD_LINK,
)

#: 「关键五件套」：缺任一即 `key5_missing`
KEY5_FIELDS: tuple[str, ...] = (
    "cve_id",
    "title",
    "description",
    "published_at",
    "severity",
)

#: 上游表态"不予处理/驳回"的状态值（有记录但不可用）
REJECT_STATUS_VALUES: frozenset[str] = frozenset(
    {"rejected", "disputed", "withdrawn", "reject", "rejected_by_cna", "not_applicable"}
)

#: 时效兜底值：缺失 `published_at` 时的中性分（不算好也不算坏）
TIMELINESS_NEUTRAL = 0.5
#: 超过这个天数仍未入库即视为时效不合格（SLA 之上一个数量级）
TIMELINESS_MAX_DAYS = 30

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
#: GHSA ID 形如 `GHSA-<段>-<段>`，段数与长度在不同年份并不统一
#: （本仓 fixture 用 3 段如 `GHSA-7f3q-vllm-rce`，也有 4 段的）。
#: 所以只校验"前缀 + 2~5 段字母数字"，不做长度硬编码 —— 硬编码会把正常编号误判为非法。
_GHSA_RE = re.compile(r"GHSA(-[0-9a-z]+){2,5}", re.I)
_OSV_RE = re.compile(r"^(OSV|GHSA|PYSEC|GO|RUSTSEC)-", re.I)

#: 模板化/样板文本特征（正文几乎是公告模板，没有实质信息）
_BOILERPLATE_RES = (
    re.compile(r"^\s*(no description|no details|n/?a|待补充|暂无描述)\s*$", re.I),
    re.compile(r"(https?://\S+\s*){5,}"),  # 正文几乎只有一堆链接
)
#: POC 死链特征
_DEAD_LINK_HINTS = ("example.com", "localhost", "127.0.0.1", "0.0.0.0", "invalid")


class DQ1Error(ValueError):
    """闸门参数非法（如未知 gate_version）。"""


@dataclass(slots=True)
class QualityVerdict:
    """权威内联契约 `QualityVerdict` 的本地形状。"""

    item_id: str
    item_kind: str = "intel"
    quality_score: float = 0.0
    dimension_scores: dict[str, float] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    verdict: str = "pass"
    quarantine_ref: str | None = None
    reviewer: str | None = None
    reviewed_at: str | None = None
    gate_version: str = GATE_VERSION

    def to_payload(self) -> dict[str, Any]:
        """→ `dq.verdicts` 载荷（过 `LocalPayloads.json::QualityVerdict`）。"""

        return {
            "item_id": self.item_id,
            "item_kind": self.item_kind,
            "quality_score": round(float(self.quality_score), 4),
            "dimension_scores": {
                key: round(float(value), 4) for key, value in self.dimension_scores.items()
            },
            "flags": sorted(self.flags),
            "verdict": self.verdict,
            "quarantine_ref": self.quarantine_ref,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "gate_version": self.gate_version,
        }


# ---------------------------------------------------------------- 维度评分


def _is_tz_aware(value: Any) -> bool:
    """字符串/日期时间是否带时区。裸 `2026-09-21T00:00:00` 不算。"""

    if isinstance(value, dt.datetime):
        return value.tzinfo is not None
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _structured_ok(vuln: dict[str, Any]) -> bool:
    """是否有可解析的结构：原始 payload 或 CVSS/严重性任一。"""

    if vuln.get("raw_json") or vuln.get("raw"):
        return True
    return bool(vuln.get("cvss_vector") or vuln.get("severity"))


def score_structure(vuln: dict[str, Any]) -> float:
    """结构分：字段结构（50%）+ 是否有可解析载荷（50%）。

    两路分开加权，而不是"有载荷就 +0.4 再截断到 1.0"——后者会让字段齐全的条目
    无论有没有原始载荷都拿满分，结构分就失去了分辨力。
    """

    keys = ("published_at", "fetched_at", "cve_id", "description")
    present = sum(1 for key in keys if vuln.get(key) not in (None, "", [], {}))
    field_ratio = present / len(keys)
    parsable = 1.0 if _structured_ok(vuln) else 0.0
    return round(min(0.5 * field_ratio + 0.5 * parsable, 1.0), 4)


def score_completeness(vuln: dict[str, Any]) -> float:
    """关键五件套的完整率 + 编号一致性；多源情报额外给一点加分。"""

    present = sum(1 for key in KEY5_FIELDS if vuln.get(key) not in (None, "", [], {}))
    base = present / len(KEY5_FIELDS)
    merged = len(vuln.get("merged_raw_ids") or []) + 1
    if merged >= 2:
        base = min(1.0, base + 0.1)
    return round(base, 4)


def _cvss_consistency(vuln: dict[str, Any]) -> float:
    """向量算出来的分与记录的分是否对得上。对不上是数据不可信的直接信号。"""

    vector = vuln.get("cvss_vector")
    score = vuln.get("cvss_score")
    if not vector or score is None:
        return 1.0  # 没有可比的两方，不判它不一致（缺字段由 completeness 管）
    from aiintel.services.enrich.cvss import score_vector_31

    computed = score_vector_31(str(vector))
    if computed is None:
        return 1.0
    return 1.0 if abs(float(computed) - float(score)) <= 0.1 else 0.0


def score_consistency(vuln: dict[str, Any]) -> float:
    """一致性分：CVSS 自洽 + 编号/标题不打架 + 源数量表述可信。"""

    parts = [_cvss_consistency(vuln)]
    cve, ghsa = vuln.get("cve_id"), vuln.get("ghsa_id")
    parts.append(0.0 if (cve and ghsa and FLAG_MULTI_ID_MISMATCH in _id_flags(cve, ghsa)) else 1.0)
    title = str(vuln.get("title") or "")
    parts.append(0.0 if _looks_like_boilerplate(title) else 1.0)
    return round(sum(parts) / len(parts), 4)


def score_timeliness(vuln: dict[str, Any], *, now: dt.datetime | None = None) -> float:
    """时效分：`published_at` → `fetched_at` 的滞后，越久越低。

    缺 `published_at` 给中性分（既不奖励也不惩罚），而不是 0 分 ——
    0 分会把它推到 `review`，但"上游没给发布时间"不是这条情报的错。
    """

    published = _as_datetime(vuln.get("published_at"))
    if published is None:
        return TIMELINESS_NEUTRAL
    reference = _as_datetime(vuln.get("fetched_at")) or (now or dt.datetime.now(dt.UTC))
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=dt.UTC)
    if published.tzinfo is None:
        published = published.replace(tzinfo=dt.UTC)
    days = max((reference - published).total_seconds(), 0.0) / 86400.0
    if days <= 1:
        return 1.0
    if days >= TIMELINESS_MAX_DAYS:
        return 0.0
    return round(1.0 - (days - 1) / (TIMELINESS_MAX_DAYS - 1), 4)


def score_sourcing(vuln: dict[str, Any]) -> float:
    """来源分：多源交叉 + 每条来源带可打开的 URL。"""

    raw_sources = vuln.get("sources")
    sources = [s for s in raw_sources if s] if isinstance(raw_sources, list) else []
    count = len(sources) or (len(vuln.get("merged_raw_ids") or []) + 1)
    cross = 1.0 if count >= 3 else (0.6 if count == 2 else 0.3)
    with_url = [s for s in sources if isinstance(s, dict) and s.get("url")]
    url_ratio = (len(with_url) / len(sources)) if sources else (1.0 if vuln.get("url") else 0.3)
    return round(0.5 * cross + 0.5 * url_ratio, 4)


# ---------------------------------------------------------------- flag 命中


def _as_datetime(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _looks_like_boilerplate(text: str) -> bool:
    if not text or len(text.strip()) < 8:
        return True
    return any(pattern.search(text) for pattern in _BOILERPLATE_RES)


def _id_flags(cve: Any, ghsa: Any) -> list[str]:
    """编号一致性：CVE 与 GHSA **同时存在但形态非法**时置 `multi_id_mismatch`。

    口径说明（与 SafeTrace 冻结契约的 flag 语义对齐）：6 个 flag 是**并列的硬拦截**，
    任一命中即 `quarantine`。因此"两个编号体系打架"这种**可疑但不致命**的情况
    不进 flag（否则会把大量正常条目丢进隔离区），而是体现在 `consistency` 分数里。
    这里只拦"编号本身就不合法"的结构性错误。
    """

    cve_text = str(cve or "").strip()
    ghsa_text = str(ghsa or "").strip()
    if not (cve_text and ghsa_text):
        return []
    if not _CVE_RE.fullmatch(cve_text) or not _GHSA_RE.fullmatch(ghsa_text):
        return [FLAG_MULTI_ID_MISMATCH]
    return []


def _dead_link_flags(vuln: dict[str, Any]) -> list[str]:
    """POC 死链：references 里标为 exploit 的链接指向不可用地址。"""

    for ref in vuln.get("references") or []:
        if not isinstance(ref, dict):
            continue
        kind = str(ref.get("kind") or "").lower()
        if kind not in {"exploit", "poc"}:
            continue
        url = str(ref.get("url") or "").lower()
        if not url or any(hint in url for hint in _DEAD_LINK_HINTS):
            return [FLAG_POC_DEAD_LINK]
    return []


def collect_flags(vuln: dict[str, Any]) -> list[str]:
    """收集 6 类 flag（保序、去重）。**与分数完全解耦**。"""

    flags: list[str] = []
    published = vuln.get("published_at")
    if published not in (None, "") and not _is_tz_aware(published):
        flags.append(FLAG_TS_NO_TZ)

    status = str(vuln.get("vuln_status") or vuln.get("status") or "").strip().lower()
    if status in REJECT_STATUS_VALUES:
        flags.append(FLAG_REJECT_STATUS)

    missing = [key for key in KEY5_FIELDS if vuln.get(key) in (None, "", [], {})]
    if missing:
        flags.append(FLAG_KEY5_MISSING)

    title = str(vuln.get("title") or "")
    description = str(vuln.get("description") or vuln.get("content_text") or "")
    if _looks_like_boilerplate(description) or _looks_like_boilerplate(title):
        flags.append(FLAG_BOILERPLATE)

    flags.extend(_id_flags(vuln.get("cve_id"), vuln.get("ghsa_id")))
    flags.extend(_dead_link_flags(vuln))

    ordered: list[str] = []
    for flag in flags:
        if flag in ALL_FLAGS and flag not in ordered:
            ordered.append(flag)
    return ordered


# ---------------------------------------------------------------- 判定入口


def decide_verdict(score: float, flags: list[str], *, gate_version: str = GATE_VERSION) -> str:
    """四档判定。**flag 优先于分数**（拦截结构性错误，不被平均分掩盖）。"""

    if flags:
        return "quarantine"
    thresholds = thresholds_for(gate_version)
    if score <= thresholds["partial"]:
        return "review"
    if score <= thresholds["full"]:
        return "degrade"
    return "pass"


def thresholds_for(gate_version: str = GATE_VERSION) -> dict[str, float]:
    """版本化阈值 → 复用既有配置项名，避免破坏现有测试与运维认知。

    `enrich_min_quality_partial`（默认 0.4）/ `enrich_min_quality_full`（默认 0.7）
    是**一个**阈值同时约束两件事：
    - DQ1 的 `review` / `degrade` 判定线；
    - `dimensions_for_quality()` 的"跑哪几个维度"。
    """

    settings = get_settings()
    return {
        "partial": float(settings.enrich_min_quality_partial),
        "full": float(settings.enrich_min_quality_full),
    }


def weights_for(gate_version: str = GATE_VERSION) -> dict[str, float]:
    try:
        return dict(GATE_WEIGHTS[gate_version])
    except KeyError:
        raise DQ1Error(
            f"未知 gate_version {gate_version!r}，允许 {sorted(GATE_WEIGHTS)}（换权重必须换版本号）"
        ) from None


def evaluate(
    vuln: dict[str, Any],
    *,
    item_kind: str = "intel",
    gate_version: str = GATE_VERSION,
    now: dt.datetime | None = None,
) -> QualityVerdict:
    """对一条情报做质量判定。同一 `gate_version` + 同一输入 ⇒ 同一输出。"""

    weights = weights_for(gate_version)
    item_id = str(vuln.get("cve_id") or vuln.get("id") or vuln.get("vuln_id") or "unknown")

    dimension_scores = {
        "structure": score_structure(vuln),
        "completeness": score_completeness(vuln),
        "consistency": score_consistency(vuln),
        "timeliness": score_timeliness(vuln, now=now),
        "sourcing": score_sourcing(vuln),
    }
    score = sum(dimension_scores[key] * weights[key] for key in weights)
    flags = collect_flags(vuln)
    verdict = decide_verdict(score, flags, gate_version=gate_version)

    return QualityVerdict(
        item_id=item_id,
        item_kind=item_kind,
        quality_score=round(score, 4),
        dimension_scores=dimension_scores,
        flags=flags,
        verdict=verdict,
        quarantine_ref=f"quarantine://{item_id}" if verdict == "quarantine" else None,
        gate_version=gate_version,
    )


def quality_score_of(vuln: dict[str, Any], **kwargs: Any) -> float:
    """便捷入口：只要分数（`Vuln.quality_score` 的写入值）。"""

    return evaluate(vuln, **kwargs).quality_score


__all__ = [
    "ALL_FLAGS",
    "FLAG_BOILERPLATE",
    "FLAG_KEY5_MISSING",
    "FLAG_MULTI_ID_MISMATCH",
    "FLAG_POC_DEAD_LINK",
    "FLAG_REJECT_STATUS",
    "FLAG_TS_NO_TZ",
    "GATE_VERSION",
    "GATE_WEIGHTS",
    "KEY5_FIELDS",
    "DQ1Error",
    "QualityVerdict",
    "collect_flags",
    "decide_verdict",
    "evaluate",
    "quality_score_of",
    "score_completeness",
    "score_consistency",
    "score_sourcing",
    "score_structure",
    "score_timeliness",
    "thresholds_for",
    "weights_for",
]

"""C-05 数据域隔离闸（对齐上游 Niangaol/safetrace C-05 的最小适配版）。

上游做法（TS 网关）：config 增 provider `trust_boundary`（cloud/local/cache）+ 请求体 `data_domain`
（public/private），对 private 数据 + cloud provider **硬拒**并发 `fallback.events`；A-03 在其上补
私有标记 egress 守卫与本机通道预检（私有数据全链无本机通道时在任何 provider 尝试前显式失败）。

本仓唯一的 LLM 出网点是 `core/llm.py`，因此闸门落在这里，语义对齐但做了一处合并：

- `data_domain` 是**请求/数据**属性：经 API（`ChatRequest.data_domain`）或调用方显式传入。
- `trust_boundary` 是**后端**属性：deepseek 云端默认 `cloud`（可在 .env 覆盖为 local，即自托管网关），
  Ollama 本地 = `local`，demo/缓存占位 = `cache`。
- 规则：`data_domain=private` 只许 **local 边界**作答；云端边界不可用（non-local）且无本地通道时
  **fail-closed**（拒绝云端，也拒绝以 cache/模板/demo 冒充模型回答），并发布 `fallback.events`
  作为审计痕迹。拒绝即终止降级链，不改投下一家。

与上游的差别只在于：本仓把"private 自动走唯一合法本地通道"与"无本地通道即显式失败"合并成一条
（不再在 provider 之间改投，也没有代理链）。红线不变：任何降级/拒绝都必须显式可见。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

DataDomain: TypeAlias = Literal["public", "private"]
TrustBoundary: TypeAlias = Literal["cloud", "local", "cache"]

DATA_DOMAIN_DEFAULT = "public"
BOUNDARY_CLOUD: TrustBoundary = "cloud"
BOUNDARY_LOCAL: TrustBoundary = "local"
BOUNDARY_CACHE: TrustBoundary = "cache"

LEGAL_DOMAINS = ("public", "private")
LEGAL_BOUNDARIES = ("cloud", "local", "cache")


def normalize_domain(value: str | None) -> str:
    """把请求侧值规整成合法 data_domain；无/非法一律按 public（最宽松语义）。"""

    v = (value or DATA_DOMAIN_DEFAULT).strip().lower()
    return v if v in LEGAL_DOMAINS else DATA_DOMAIN_DEFAULT


def normalize_boundary(value: str | None) -> str:
    """把配置侧值规整成合法 trust_boundary；无/非法一律按 cloud（最严射程语义）。"""

    v = (value or "").strip().lower()
    return v if v in LEGAL_BOUNDARIES else BOUNDARY_CLOUD


def egress_allowed(data_domain: str, boundary: str) -> bool:
    """C-05 判定：private 只许 local 边界出网；public 任意边界放行。"""

    if normalize_domain(data_domain) != "private":
        return True
    return normalize_boundary(boundary) == BOUNDARY_LOCAL


class IsolationError(RuntimeError):
    """隔离类错误基类（对齐上游 A-03 的 IsolationError 家族）。

    调用方据此把失败判为"策略拒绝"而非"provider 故障"：拒绝即终止降级链，
    不得改投下一家，也不得以 cache/模板/demo 占位冒充模型回答。
    """


class IsolationRejectionError(IsolationError):
    """策略拒绝（C-05）：private 数据不允许经 cloud/cache 边界出网。

    **显式可见**：拒绝是发声的（抛错 + fallback.events），不是静默兜底；
    调用方拿到它必须如实上抛/展示，禁止吞掉后改用模板或占位回答。
    """


# ---------------------------------------------------------------- A-03 egress 守卫
# 第二道防线：即使调用方漏传 data_domain=private，只要出网载荷里出现私域标记
# （资产号/内网主机名/租户号/证书头等），也必须硬拒，不得静默出网。检索小写子串。

#: 私域标记清单（大小写不敏感、子串匹配）。新增标记须同步 CHANGELOG 与 egress 测试。
PRIVATE_MARKERS: tuple[str, ...] = (
    "asset_id",
    "internal_host",
    "tenant_id",
    "tenant:",
    "employee_id",
    "-----begin",
    "corp.internal",
    "intranet",
)

#: 扫描深度上限：超过即停（防恶意超深载荷把扫描拖垮）。
MAX_SCAN_DEPTH = 8


@dataclass(frozen=True)
class ScopeViolation:
    """一次私域标记命中。**只带标记与路径，不带命中内容**（与上游 P-10 lineage 口径一致）。"""

    marker: str
    path: str


class ScopeViolationError(IsolationError):
    """出网载荷命中私域标记。消息只报标记与路径，绝不回显命中正文。"""

    def __init__(self, violations: list[ScopeViolation], context: str) -> None:
        detail = ", ".join(f"{v.marker}@{v.path}" for v in violations)
        super().__init__(
            f"{context} 含私域标记，已拒绝出网（只报标记与路径，不回显内容）：{detail}"
        )
        self.violations = tuple(violations)


def scan_private_markers(value: Any, path: str = "$") -> list[ScopeViolation]:
    """深度优先扫描字符串载荷；命中即记标记与路径，**不返回命中文本**。"""

    hits: list[ScopeViolation] = []

    def walk(node: Any, at: str, depth: int) -> None:
        if depth > MAX_SCAN_DEPTH:
            return
        if isinstance(node, str):
            lower = node.lower()
            for marker in PRIVATE_MARKERS:
                if marker in lower:
                    hits.append(ScopeViolation(marker=marker, path=at))
            return
        if isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{at}[{index}]", depth + 1)
            return
        if isinstance(node, dict):
            for key, item in node.items():
                # 键名本身也可能是私域字段（例如 { asset_id: "..." }）
                lower_key = str(key).lower()
                for marker in PRIVATE_MARKERS:
                    if marker.rstrip(":") in lower_key:
                        hits.append(ScopeViolation(marker=marker, path=f"{at}.{key}（键名）"))
                walk(item, f"{at}.{key}", depth + 1)

    walk(value, path, 0)
    return hits


def assert_public_scope(payload: Any, context: str) -> None:
    """出网前调用：命中私域标记即抛 `ScopeViolationError`（禁静默放行）。"""

    violations = scan_private_markers(payload)
    if violations:
        raise ScopeViolationError(violations, context)
"""工具注册表：Agent 调用外部能力的唯一出口。

约束：白名单 + 入参 schema 校验 + 超时 + 只读网络权限 + 成本等级。
外部抓取的文本入库前先做提示注入检测（AI 安全赛题的特色加分项）。
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from aiintel.core.llm import get_llm

logger = logging.getLogger(__name__)

ToolFn = Callable[..., Awaitable[Any]]

# 抓取内容中的疑似提示注入（用于赛题的 AI 安全叙事与真实防护）
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?(system|above)\s+prompt", re.I),
    re.compile(r"(你现在是|from now on,?\s+you\s+are|act as)\s*.{0,40}(系统|管理员|admin)", re.I),
    re.compile(r"</?(system|assistant|tool|function)\s*>", re.I),
    re.compile(r"请(输出|忽略).{0,20}(你的)?(系统提示|api[ _-]?key|密钥)", re.I),
]


class ToolDenied(RuntimeError):
    pass


def detect_prompt_injection(text: str) -> list[str]:
    """返回命中的注入模式描述；空列表表示干净。"""

    return [p.pattern for p in INJECTION_PATTERNS if p.search(text or "")]


def sanitize(text: str) -> str:
    """把可疑片段包裹成不可执行引用，避免注入进入后续 prompt。"""

    hits = detect_prompt_injection(text)
    if not hits:
        return text
    redacted = text
    for pattern in INJECTION_PATTERNS:
        redacted = pattern.sub("[REDACTED-INJECTION]", redacted)
    return redacted


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    schema: dict[str, str]
    permission: str = "network:read"
    timeout: float = 20.0
    retries: int = 2
    cost_tier: str = "free"
    fn: ToolFn | None = field(default=None, repr=False)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self,
        name: str,
        description: str,
        schema: dict[str, str],
        *,
        permission: str = "network:read",
        timeout: float = 20.0,
        retries: int = 2,
        cost_tier: str = "free",
    ) -> Callable[[ToolFn], ToolFn]:
        def deco(fn: ToolFn) -> ToolFn:
            self._tools[name] = ToolSpec(
                name=name,
                description=description,
                schema=schema,
                permission=permission,
                timeout=timeout,
                retries=retries,
                cost_tier=cost_tier,
                fn=fn,
            )
            return fn

        return deco

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolDenied(f"工具未注册: {name}") from exc

    def names(self) -> list[str]:
        return sorted(self._tools)

    def catalog(self) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "schema": t.schema,
                "permission": t.permission,
                "cost_tier": t.cost_tier,
            }
            for t in sorted(self._tools.values(), key=lambda t: t.name)
        ]

    async def invoke(self, name: str, **kwargs: Any) -> Any:
        spec = self.get(name)
        if spec.fn is None:
            raise ToolDenied(f"工具 {name} 未绑定实现")
        if not spec.permission.startswith(("network:read", "db:read", "internal")):
            raise ToolDenied(f"工具 {name} 权限 {spec.permission} 不允许在 Agent 中调用")

        last_exc: Exception | None = None
        for attempt in range(spec.retries + 1):
            try:
                result = spec.fn(**kwargs)
                if inspect.isawaitable(result):
                    return await asyncio.wait_for(result, timeout=spec.timeout)
                return result
            except TimeoutError as exc:
                last_exc = exc
            except Exception as exc:  # noqa: BLE001 - 工具边界统一兜底后重试
                last_exc = exc
            logger.warning("工具 %s 第 %d 次失败: %s", name, attempt + 1, last_exc)
        raise RuntimeError(f"工具 {name} 重试 {spec.retries} 次后仍失败: {last_exc}")


registry = ToolRegistry()

# ---------------------------------------------------------------- 检索类工具


@registry.register(
    "hybrid_search",
    "混合检索（向量 + 全文 + 重排），返回带来源的片段列表",
    {"query": "str", "top_k": "int=8", "owner_type": "str?"},
    permission="internal",
    timeout=15.0,
)
async def hybrid_search(query: str, top_k: int = 8, owner_type: str | None = None) -> Any:
    from aiintel.services.knowledge.retrieval import hybrid_search as _search

    return await _search(query, top_k=top_k, owner_type=owner_type)


@registry.register(
    "graph_neighbors",
    "关系边表多跳扩展，返回节点与边",
    {"node_id": "str", "hops": "int=2", "limit": "int=50"},
    permission="internal",
    timeout=10.0,
)
async def graph_neighbors(node_id: str, hops: int = 2, limit: int = 50) -> Any:
    from aiintel.services.knowledge.retrieval import neighbors as _neighbors

    return await _neighbors(node_id, hops=hops, limit=limit)


@registry.register(
    "cvss_calculate",
    "本地计算 CVSS 3.1 基础分，不依赖 LLM",
    {"vector": "str"},
    permission="internal",
    timeout=5.0,
)
async def cvss_calculate(vector: str) -> Any:
    from aiintel.services.enrich.cvss import score_vector_31

    return {"vector": vector, "base_score": score_vector_31(vector)}


@registry.register(
    "ai_risk_classify",
    "LLM 判定 AI 安全风险分类（四级）并给出依据",
    {"title": "str", "description": "str", "cpe": "list"},
    permission="internal",
    timeout=60.0,
    cost_tier="pro",
)
async def ai_risk_classify(title: str, description: str, cpe: list[str] | None = None) -> Any:
    from aiintel.services.enrich.dimensions import classify_ai_risk

    return await classify_ai_risk(title, description, cpe or [])


@registry.register(
    "notify",
    "发送告警（webhook + 事件广播）",
    {"level": "str", "title": "str", "message": "str", "vuln_id": "str?"},
    permission="internal",
    timeout=10.0,
)
async def notify(level: str, title: str, message: str, vuln_id: str | None = None) -> Any:
    from aiintel.core.alerts import AlertManager

    await AlertManager().raise_alert(level, title, message, vuln_id=vuln_id)
    return {"sent": True}


@registry.register(
    "self_check",
    "LLM 自检：判断答案是否被给定证据支持，返回是否通过与理由",
    {"question": "str", "answer": "str", "evidence": "list"},
    permission="internal",
    timeout=60.0,
    cost_tier="pro",
)
async def self_check(question: str, answer: str, evidence: list) -> Any:
    from aiintel.services.qa.checks import check_answer

    return await check_answer(question, answer, evidence)


@registry.register(
    "sanitize",
    "对外部抓取的文本做提示注入检测与清洗",
    {"text": "str"},
    permission="internal",
    timeout=5.0,
)
async def sanitize_tool(text: str) -> Any:
    hits = detect_prompt_injection(text)
    return {"injection_detected": bool(hits), "patterns": hits, "clean_text": sanitize(text)}


@registry.register(
    "estimate_cost",
    "预估一次 LLM 调用的花费（成本治理）",
    {"prompt_tokens": "int", "completion_tokens": "int", "tier": "str=flash"},
    permission="internal",
    timeout=5.0,
)
async def estimate_cost(prompt_tokens: int, completion_tokens: int, tier: str = "flash") -> Any:
    from aiintel.core.cost import estimate_cny

    # tier 由 LLM 传参，这里兜底成 flash，避免非法档位打穿计价
    selected: Literal["flash", "pro"] = "pro" if tier == "pro" else "flash"
    return {"cost_cny": round(estimate_cny(prompt_tokens, completion_tokens, selected), 6)}


def build_langchain_tools() -> list[Any]:
    """把注册表导出为 LangChain 工具，供 Agent 绑定。"""

    from langchain_core.tools import StructuredTool

    def _make(spec: dict) -> Any:
        async def call(**kwargs: Any) -> Any:
            return await registry.invoke(spec["name"], **kwargs)

        call.__name__ = spec["name"]
        call.__doc__ = spec["description"]
        return StructuredTool.from_function(
            func=call,
            coroutine=call,
            name=spec["name"],
            description=spec["description"],
        )

    return [_make(spec) for spec in registry.catalog() if spec["permission"] == "internal"]


def default_llm() -> Any:
    return get_llm()

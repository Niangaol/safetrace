"""MG1 · 模型网关客户端（F 线的**唯一**模型出入口）。

计划红线 1：「模型接入标准化解耦——任何模型调用经 MG1，本地/云端切换只改配置不改代码」。
因此 `services/enrich/` 下**禁止直接 import provider SDK**（openai/anthropic/ollama/…），
也禁止直接 import `aiintel.core.llm`——`tests/test_enrich_boundaries.py` 会检查这一点。

MG1 职责：调用 + 降级标记 + 成本归集（成本归集在 `core.cost`，MG1 只透传 node/agent 标签）。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from aiintel.config import get_settings

logger = logging.getLogger(__name__)


class MG1Error(RuntimeError):
    """网关不可用且不允许静默兜底时抛出。"""


@dataclass(slots=True)
class MG1Result:
    """MG1 返回：文本 + 降级标记。`degraded` 非空表示结果来自兜底通道。"""

    text: str
    model: str = "unknown"
    degraded: str | None = None  # None | "local"
    cost_cny: float = 0.0
    ok: bool = True
    error: str = ""

    def json(self) -> Any:
        """解析结构化输出，容忍 ```json 包裹（与 `LLMResult.json` 同语义）。"""

        text = (self.text or "").strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < 0:
            raise MG1Error(f"模型未返回 JSON: {text[:200]}")
        return json.loads(text[start : end + 1])


def mg1_available() -> bool:
    return not get_settings().mg1_stub_mode


async def complete(
    messages: list[dict],
    *,
    task: str = "classify",
    max_tokens: int = 512,
    temperature: float = 0.2,
    node: str = "enrich",
    agent: str = "EnrichAgent",
) -> MG1Result:
    """经 MG1 调用模型。**永不抛异常**：失败返回 `ok=False` 让调用方走规则降级。

    这是刻意的设计——F 线任何一维都不该因为模型不可用而整体失败（FB1 多层兜底）。
    """

    from aiintel.core.llm import get_llm

    if get_settings().mg1_stub_mode:
        logger.info("MG1 桩模式：跳过真实模型调用 node=%s", node)
        return MG1Result(
            text="", model="mg1-stub", degraded="local", ok=False, error="mg1_stub_mode"
        )

    try:
        result = await get_llm().complete(
            messages,
            task=task,  # type: ignore[arg-type]
            max_tokens=max_tokens,
            temperature=temperature,
            node=node,
            agent=agent,
        )
    except Exception as exc:  # noqa: BLE001 - 网关是边界，统一转成降级信号
        logger.warning("MG1 调用失败 node=%s: %s", node, exc)
        return MG1Result(text="", model="unavailable", ok=False, error=str(exc)[:200])

    return MG1Result(
        text=result.text,
        model=result.model,
        degraded="local" if result.degraded else None,
        cost_cny=result.cost_cny,
    )


async def json_complete(
    messages: list[dict],
    *,
    task: str = "classify",
    max_tokens: int = 512,
    node: str = "enrich",
    agent: str = "EnrichAgent",
) -> tuple[dict[str, Any] | None, MG1Result]:
    """调用并解析 JSON；解析失败返回 (None, result)，由调用方走规则降级。"""

    result = await complete(messages, task=task, max_tokens=max_tokens, node=node, agent=agent)
    if not result.ok:
        return None, result
    try:
        payload = result.json()
    except Exception as exc:  # noqa: BLE001 - 模型没吐 JSON 是常态，不算异常
        logger.info("MG1 返回非 JSON node=%s: %s", node, exc)
        return None, result
    return (payload if isinstance(payload, dict) else None), result

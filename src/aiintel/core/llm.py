"""LLM 统一出口：分级路由 + 前缀缓存 + 思考模式开关 + 预算熔断 + 本地兜底。

设计要点见 docs/设计文档.md 第 10 章：
- 简单任务（抽取/分类/去重）走 flash 且关闭思考模式；
- 复杂任务（富化解释/问答推理链）走 pro 并开启思考模式；
- 预算或网络异常自动降级到本地 Ollama，并标记 degraded。
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from aiintel.config import get_settings
from aiintel.core.cost import BudgetExceeded, CostGuard, ModelTier, Usage, get_cost_guard

logger = logging.getLogger(__name__)

TaskKind = Literal["extract", "classify", "dedup", "enrich", "reason", "chat", "judge"]
# 需要更强推理能力的任务路由到 pro
PRO_TASKS: frozenset[TaskKind] = frozenset({"enrich", "reason"})
# 思考模式会按输出计费，只有推理类任务才打开
THINKING_TASKS: frozenset[TaskKind] = frozenset({"enrich", "reason", "chat"})


class LLMError(RuntimeError):
    pass


@dataclass(slots=True)
class LLMResult:
    text: str
    usage: Usage
    model: str
    cost_cny: float
    degraded: bool = False
    latency_ms: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    def json(self) -> Any:
        """解析结构化输出，容忍 ```json 包裹。"""

        text = self.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < 0:
            raise LLMError(f"模型未返回 JSON: {text[:200]}")
        return json.loads(text[start : end + 1])


class LLMRouter:
    def __init__(self, guard: CostGuard | None = None) -> None:
        self.settings = get_settings()
        self.guard = guard or get_cost_guard()
        self._client: httpx.AsyncClient | None = None

    # ---------- 内部工具 ----------

    @property
    def has_cloud_key(self) -> bool:
        return bool((self.settings.llm_api_key or "").strip())

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers: dict[str, str] = {}
            if self.has_cloud_key:
                headers["Authorization"] = f"Bearer {self.settings.llm_api_key.strip()}"
            # 没配 key 时绝不能发 "Bearer "：httpx 会直接抛
            # LocalProtocolError: Illegal header value b'Bearer '
            self._client = httpx.AsyncClient(
                base_url=self.settings.llm_base_url,
                timeout=httpx.Timeout(60.0, connect=10.0),
                headers=headers,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _pick(self, task: TaskKind) -> tuple[ModelTier, str, bool]:
        s = self.settings
        if task in PRO_TASKS:
            return "pro", s.llm_pro_model, True
        return "flash", s.llm_flash_model, False

    def route(self, task: TaskKind) -> tuple[ModelTier, str, bool]:
        """公开的路由查询：(tier, model, thinking)。供上层记录实际使用的模型。"""

        return self._pick(task)

    def _local_payload(
        self, model: str, messages: list[dict], thinking: bool, max_tokens: int
    ) -> dict:
        text = "\n\n".join(
            f"{m['role']}: {m['content']}"
            if isinstance(m.get("content"), str)
            else f"{m['role']}: {m['content']}"
            for m in messages
        )
        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": text}],
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": max_tokens},
        }
        if thinking:
            payload["think"] = True
        return payload

    async def _call_local(
        self, model: str, messages: list[dict], thinking: bool, max_tokens: int
    ) -> tuple[str, Usage]:
        s = self.settings
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=5.0)) as client:
            resp = await client.post(
                f"{s.llm_local_base_url}/api/chat",
                json=self._local_payload(model, messages, thinking, max_tokens),
            )
            resp.raise_for_status()
            data = resp.json()
        prompt_tokens = int(data.get("prompt_eval_count") or 0)
        completion_tokens = int(data.get("eval_count") or 0)
        return data.get("message", {}).get("content", ""), Usage(
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens
        )

    # ---------- 对外接口 ----------

    async def complete(
        self,
        messages: list[dict],
        *,
        task: TaskKind = "extract",
        max_tokens: int = 2048,
        temperature: float = 0.2,
        node: str = "unknown",
        agent: str = "unknown",
        response_format: dict | None = None,
    ) -> LLMResult:
        import time as _time

        tier, model, thinking = self._pick(task)
        if task not in THINKING_TASKS:
            # 抽取/分类类任务强制关闭思考模式：思考 token 按输出计费，会放大 2~3 倍成本
            thinking = False

        if self.guard.exceeded():
            logger.warning("日预算耗尽，降级本地模型: node=%s", node)
            return await self._local_result(model, messages, thinking, max_tokens, node, agent)

        if not self.has_cloud_key:
            # 没有云端凭据就别去请求了：省一次往返，也省掉对端 401 的噪音
            logger.warning("未配置 LLM_API_KEY，跳过云端调用: node=%s", node)
            return await self._local_result(model, messages, thinking, max_tokens, node, agent)

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if thinking:
            payload["enable_thinking"] = True
        if response_format is not None:
            payload["response_format"] = response_format

        started = _time.perf_counter()
        try:
            resp = await self.client.post("/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, BudgetExceeded) as exc:
            logger.warning("云端 LLM 失败(%s)，降级本地: %s", type(exc).__name__, exc)
            # 统一交给 _local_result 决定降级/兜底，别在这里直接 raise：
            # 早返回会漏掉 demo 兜底，并把 httpx 原始报文透给用户
            return await self._local_result(model, messages, thinking, max_tokens, node, agent)

        usage = self._parse_usage(data)
        cost = self.guard.record(usage, tier, model=model, node=node, agent=agent)
        content = data["choices"][0]["message"].get("content") or ""
        return LLMResult(
            text=content,
            usage=usage,
            model=model,
            cost_cny=cost,
            latency_ms=int((_time.perf_counter() - started) * 1000),
            raw=data,
        )

    async def _local_result(
        self,
        model: str,
        messages: list[dict],
        thinking: bool,
        max_tokens: int,
        node: str,
        agent: str,
    ) -> LLMResult:
        s = self.settings
        if not s.llm_local_enabled:
            if s.demo_mode:
                return _demo_result(messages, max_tokens)
            raise LLMError(
                "没有可用的 LLM 后端：未配置 LLM_API_KEY，且 LLM_LOCAL_ENABLED=false。"
                "请设置 LLM_API_KEY，或启用本地模型，或用 DEMO_MODE=true 查看占位回答"
            )
        try:
            text, usage = await self._call_local(s.llm_local_model, messages, thinking, max_tokens)
        except httpx.HTTPError as exc:
            if s.demo_mode:
                return _demo_result(messages, max_tokens)
            raise LLMError(f"本地模型不可用: {exc}") from exc
        return LLMResult(
            text=text,
            usage=usage,
            model=s.llm_local_model,
            cost_cny=0.0,
            degraded=True,
        )

    async def stream(
        self,
        messages: list[dict],
        *,
        task: TaskKind = "chat",
        max_tokens: int = 2048,
        temperature: float = 0.3,
        node: str = "qa",
        agent: str = "QAAgent",
    ) -> AsyncIterator[str]:
        """流式生成。降级时退化为一次性返回。"""

        tier, model, thinking = self._pick(task)
        if self.guard.exceeded() or not self.has_cloud_key:
            if self.guard.exceeded():
                logger.warning("日预算耗尽，降级本地模型: node=%s", node)
            else:
                logger.warning("未配置 LLM_API_KEY，跳过云端调用: node=%s", node)
            result = await self._local_result(
                self.settings.llm_local_model, messages, thinking, max_tokens, node, agent
            )
            yield result.text
            return

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }
        if thinking:
            payload["enable_thinking"] = True

        usage = Usage()
        try:
            async with self.client.stream("POST", "/chat/completions", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data = line[6:]
                    if data.strip() == "[DONE]":
                        break
                    chunk = json.loads(data)
                    if chunk.get("usage"):
                        usage = self._parse_usage(chunk)
                    for choice in chunk.get("choices", []):
                        piece = choice.get("delta", {}).get("content")
                        if piece:
                            yield piece
        except (httpx.HTTPError, BudgetExceeded) as exc:
            logger.warning("流式调用失败(%s)，降级本地: %s", type(exc).__name__, exc)
            result = await self._local_result(
                self.settings.llm_local_model, messages, thinking, max_tokens, node, agent
            )
            yield result.text
            return
        finally:
            if usage.completion_tokens:
                self.guard.record(usage, tier, model=model, node=node, agent=agent)

    @staticmethod
    def _parse_usage(data: dict) -> Usage:
        raw = data.get("usage") or {}
        details = raw.get("prompt_cache_hit_tokens") or 0
        return Usage(
            prompt_tokens=int(raw.get("prompt_tokens") or 0),
            cache_hit_tokens=int(details),
            completion_tokens=int(raw.get("completion_tokens") or 0),
        )


DEMO_BANNER = "【演示模式】未配置 LLM 凭据，以下为占位回答，用于验证前端渲染与 SSE 流式链路。"

DEMO_PLAN: dict[str, Any] = {
    "sub_questions": ["识别与提问相关的漏洞", "汇总其可利用性与影响面"],
    "queries": [],
    "intent": "demo",
}


def _demo_answer(messages: list[dict]) -> str:
    """从传入的证据里摘出引用编号，编一段结构完整的占位回答。"""

    refs: list[str] = []
    for message in messages:
        content = message.get("content")
        if not isinstance(content, str):
            continue
        for match in re.findall(r"\[(S\d+)\]", content):
            if match not in refs:
                refs.append(match)
    if not refs:
        return f"{DEMO_BANNER}\n\n未检索到可用证据，配置 LLM 凭据后重试即可获得真实回答。"

    cited = "、".join(refs[:4])
    return (
        f"{DEMO_BANNER}\n\n"
        f"结论：本次检索命中 {len(refs)} 条证据，主要来源为 {cited}。\n\n"
        f"依据：上述证据来自知识库切片，内容见引用列表。\n\n"
        f"推理链：意图改写 → 混合检索（RRF 融合）→ 关系扩展 → 生成 → 自检。\n\n"
        f"建议动作：配置 LLM_API_KEY 后重跑本问题，才能得到有实质内容的分析结论。"
    )


def _demo_result(messages: list[dict], max_tokens: int) -> LLMResult:
    """演示模式的占位返回。标记 degraded 以免被误当成真实模型输出。"""

    system = next((m.get("content") for m in messages if m.get("role") == "system"), "")
    wants_json = isinstance(system, str) and "只输出 JSON" in system
    text = json.dumps(DEMO_PLAN, ensure_ascii=False) if wants_json else _demo_answer(messages)
    return LLMResult(
        text=text[:max_tokens] if max_tokens else text,
        usage=Usage(prompt_tokens=0, completion_tokens=0),
        model="demo-stub",
        cost_cny=0.0,
        degraded=True,
    )


_router: LLMRouter | None = None


def get_llm() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router

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

from aiintel.config import BEIJING_TZ, get_settings
from aiintel.core.cost import BudgetExceeded, CostGuard, ModelTier, Usage, get_cost_guard
from aiintel.core.isolation import (
    IsolationRejectionError,
    ScopeViolationError,
    assert_public_scope,
    egress_allowed,
    normalize_domain,
)

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

    @property
    def truncated(self) -> bool:
        """是否因 `max_tokens` 用尽被截断。

        **必须能看出来**：本仓用的 deepseek-v4-pro / deepseek-flash 会**强制输出思维链**，
        思维 token 计入 completion。预算给小了，推理会把额度吃满、`content` 直接是空串，
        而 HTTP 状态仍是 200 —— 于是表现为"模型没报错，但什么都没返回"，
        上游只能看到一句 `模型未返回 JSON: `，极难定位（实测踩过）。
        """

        choices = self.raw.get("choices") or []
        if not choices:
            return False
        return choices[0].get("finish_reason") == "length"

    @property
    def reasoning_tokens(self) -> int:
        """思维 token 数（计入 completion，按输出计费）。"""

        details = (self.raw.get("usage") or {}).get("completion_tokens_details") or {}
        return int(details.get("reasoning_tokens") or 0)

    def json(self) -> Any:
        """解析结构化输出，容忍 ```json 包裹。"""

        text = self.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end < 0:
            if self.truncated:
                raise LLMError(
                    f"模型输出被 max_tokens 截断，正文为空（思维 token 已用 {self.reasoning_tokens}，"
                    f"model={self.model}）。请调大 max_tokens，而不是重试。"
                )
            raise LLMError(f"模型未返回 JSON: {text[:200]}")
        return json.loads(text[start : end + 1])


class LLMRouter:
    def __init__(self, guard: CostGuard | None = None) -> None:
        self.settings = get_settings()
        self.guard = guard or get_cost_guard()
        self._client: httpx.AsyncClient | None = None
        #: 单调递增的"降级发生次数"。**为什么要这个**：
        #: `stream()` 的契约是 `AsyncIterator[str]`（只 yield 文本），
        #: 于是流式路径上"本次调用是否降级"的信息拿不到 ——
        #: 而项目红线第 3 条要求降级必须**显式可见**，不能静默兜底。
        #: 调用方在 before/after 比较该计数来判断自己这次是否被降级：
        #:     before = get_llm().degrade_count
        #:     async for piece in get_llm().stream(...): ...
        #:     degraded = get_llm().degrade_count > before
        #: 用计数而非布尔：并发场景下不会被互相覆盖成"没降级"。
        self.degrade_count: int = 0

    def note_degraded(self, *, node: str, reason: str) -> None:
        """记录一次降级（流式与非流式路径都调用），并打日志。"""

        self.degrade_count += 1
        logger.warning("LLM 降级 node=%s 累计=%d 原因: %s", node, self.degrade_count, reason)

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
        data_domain: str = "public",
    ) -> LLMResult:
        import time as _time

        tier, model, thinking = self._pick(task)
        if task not in THINKING_TASKS:
            # 抽取/分类类任务强制关闭思考模式：思考 token 按输出计费，会放大 2~3 倍成本
            thinking = False

        if normalize_domain(data_domain) == "private":
            # C-05：private 只许 local 边界出网。云端边界若被显式标为 local（自托管
            # 网关）也统一由本地通道承载；无本地通道时 fail-closed（不云端作答、不
            # 以 cache/模板/demo 占位冒充模型回答）。
            if not egress_allowed("private", self.settings.llm_cloud_trust_boundary) and (
                not self.settings.llm_local_enabled
            ):
                await self._isolation_reject(
                    node, "private 数据无合法本地通道（cloud 边界不可用且本地未启用）"
                )
                raise IsolationRejectionError(
                    "私有数据要求本地/隔离边界：云端边界不可用（provider non-local）且"
                    "本地通道未启用（LLM_LOCAL_ENABLED=false），fail-closed"
                )
            return await self._private_local_result(
                model, messages, thinking, max_tokens, node, agent
            )

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

        # A-03：非本地目的地出网前扫私域标记。命中=策略拒绝（不是 provider 故障），
        # 立即终止降级链——不本地兜底、不改投别家、不回显命中内容。
        try:
            assert_public_scope(payload, "LLM complete 出网载荷")
        except ScopeViolationError as exc:
            await self._isolation_reject(node, str(exc), action="egress_guard_rejection")
            raise

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
                self.note_degraded(node=node, reason="DEMO_MODE 占位回答（无可用 LLM 后端）")
                return _demo_result(messages, max_tokens)
            raise LLMError(
                "没有可用的 LLM 后端：未配置 LLM_API_KEY，且 LLM_LOCAL_ENABLED=false。"
                "请设置 LLM_API_KEY，或启用本地模型，或用 DEMO_MODE=true 查看占位回答"
            )
        try:
            text, usage = await self._call_local(s.llm_local_model, messages, thinking, max_tokens)
        except httpx.HTTPError as exc:
            if s.demo_mode:
                self.note_degraded(node=node, reason=f"本地模型不可用且 DEMO_MODE 兜底: {exc}")
                return _demo_result(messages, max_tokens)
            raise LLMError(f"本地模型不可用: {exc}") from exc
        self.note_degraded(node=node, reason=f"降级本地模型 {s.llm_local_model}")
        return LLMResult(
            text=text,
            usage=usage,
            model=s.llm_local_model,
            cost_cny=0.0,
            degraded=True,
        )

    async def _private_local_result(
        self, model: str, messages: list[dict], thinking: bool, max_tokens: int,
        node: str, agent: str,
    ) -> LLMResult:
        """C-05：private 数据只经本地边界。本地不可用（未启用或调用失败）→ 硬拒。

        故意**不做** demo/模板/缓存兜底：那等于用占位冒充模型回答私有数据，
        正是上游 A-03 明令禁止的（"不再以 cache 模板冒充模型回答"）。
        """

        s = self.settings
        try:
            text, usage = await self._call_local(s.llm_local_model, messages, thinking, max_tokens)
        except httpx.HTTPError as exc:
            await self._isolation_reject(node, f"私有数据本地通道调用失败: {exc}")
            raise IsolationRejectionError(
                f"私有数据要求本地/隔离边界，但本地通道不可用: {exc}"
            ) from exc
        self.note_degraded(node=node, reason=f"data_domain=private 经本地模型 {s.llm_local_model}")
        return LLMResult(
            text=text,
            usage=usage,
            model=s.llm_local_model,
            cost_cny=0.0,
            degraded=True,
        )

    async def _isolation_reject(
        self, node: str, reason: str, action: str = "isolation_policy_rejection"
    ) -> None:
        """C-05/A-03：策略拒绝的审计事件（fallback.events）。尽力而为，绝不让主链路挂掉。"""

        logger.warning("隔离闸策略拒绝 node=%s 原因: %s", node, reason)
        try:
            from datetime import datetime

            from aiintel.core.events import TOPIC_FALLBACK_EVENTS, EventBus

            bus = EventBus()
            env = bus.envelope(
                TOPIC_FALLBACK_EVENTS,
                {
                    "layer": "L3",
                    "trigger": f"isolation:{node}",
                    "action_taken": action,
                    "degraded_of": "llm",
                    "user_visible": True,
                    "degraded_state": {
                        "label": "私有数据被隔离闸拒绝出网",
                        "since": datetime.now(BEIJING_TZ).isoformat(),
                        "detail_ref": reason[:200],
                    },
                    "recovery_hint": "为私有数据配置本地/隔离通道（LLM_LOCAL_ENABLED=true），或改用 data_domain=public",
                    "trace_id": node,
                },
                dedup_key=f"isolation:{node}:{reason[:80]}",
                trace_id=node,
            )
            env["payload"]["event_id"] = env["event_id"]
            await bus.publish_envelope(env)
        except Exception as exc:  # noqa: BLE001 - 审计事件失败不影响策略拒绝本身
            logger.warning("隔离策略拒绝事件发布失败: %s", exc)

    async def stream(
        self,
        messages: list[dict],
        *,
        task: TaskKind = "chat",
        max_tokens: int = 2048,
        temperature: float = 0.3,
        node: str = "qa",
        agent: str = "QAAgent",
        data_domain: str = "public",
    ) -> AsyncIterator[str]:
        """流式生成。降级时退化为一次性返回。"""

        tier, model, thinking = self._pick(task)

        if normalize_domain(data_domain) == "private":
            if not egress_allowed("private", self.settings.llm_cloud_trust_boundary) and (
                not self.settings.llm_local_enabled
            ):
                await self._isolation_reject(
                    node, "private 数据无合法本地通道（cloud 边界不可用且本地未启用）"
                )
                raise IsolationRejectionError(
                    "私有数据要求本地/隔离边界：云端边界不可用且本地通道未启用，fail-closed"
                )
            result = await self._private_local_result(
                model, messages, thinking, max_tokens, node, agent
            )
            yield result.text
            return

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

        # A-03：非本地目的地出网前扫私域标记（同 complete）。
        try:
            assert_public_scope(payload, "LLM stream 出网载荷")
        except ScopeViolationError as exc:
            await self._isolation_reject(node, str(exc), action="egress_guard_rejection")
            raise

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

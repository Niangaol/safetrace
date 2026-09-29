"""告警：webhook 推送 + 事件广播。"""

from __future__ import annotations

import logging

import httpx

from aiintel.core.events import TOPIC_ALERT_RAISED, EventBus

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, bus: EventBus | None = None) -> None:
        from aiintel.config import get_settings

        self.settings = get_settings()
        self.bus = bus or EventBus()

    async def raise_alert(
        self,
        level: str,
        title: str,
        message: str,
        *,
        vuln_id: str | None = None,
        trace_id: str | None = None,
        causation_id: str | None = None,
        dedup_key: str | None = None,
    ) -> None:
        payload = {"level": level, "title": title, "message": message, "vuln_id": vuln_id}
        await self.bus.try_publish(
            TOPIC_ALERT_RAISED,
            payload,
            trace_id,
            causation_id=causation_id,
            dedup_key=dedup_key,
        )
        await self._push_webhook(payload)

    async def _push_webhook(self, payload: dict) -> None:
        url = self.settings.alert_webhook_url
        if not url:
            logger.info("未配置 alert_webhook_url，跳过推送: %s", payload)
            return
        text = f"[{payload['level']}] {payload['title']}\n{payload['message']}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(url, json={"msgtype": "text", "text": {"content": text}})
        except httpx.HTTPError as exc:
            logger.warning("告警推送失败: %s", exc)

    async def test(self) -> dict:
        await self._push_webhook(
            {"level": "INFO", "title": "通道自检", "message": "来自 AI 安全情报系统的测试告警"}
        )
        return {"delivered": bool(self.settings.alert_webhook_url)}

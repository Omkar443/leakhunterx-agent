import asyncio
import time
import json
import logging
import uuid
from typing import Union, List, Dict, Any, Optional

import aiohttp

from .event_emitter import BaseEventEmitter, Event


class RealtimeEmitter(BaseEventEmitter):
    """
    Sends events immediately (no buffering).
    Uses same API format as batch emitter → backend safe.
    """

    def __init__(
        self,
        endpoint: str,
        agent_id: str,
        api_key: Optional[str] = None,
    ):
        super().__init__(name=f"realtime.{agent_id}")

        self.endpoint = endpoint
        self.agent_id = agent_id
        self.api_key = api_key

        self._session: Optional[aiohttp.ClientSession] = None
        self._send_tasks: List[asyncio.Task] = []

    async def _start_impl(self):
        await self._ensure_session()

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)

            headers = {
                "User-Agent": f"LeakHunterX-Agent/{self.agent_id}",
                "X-Agent-Id": self.agent_id,
                "Content-Type": "application/json",
                "X-Agent-Version": "1.0.0",
            }

            if self.api_key:
                headers["X-Agent-Secret"] = self.api_key

            connector = aiohttp.TCPConnector(limit=100)

            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector,
            )

    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        if self._is_closing:
            return

        try:
            event_obj = Event.normalize(event)

            task = asyncio.create_task(self._send_single(event_obj))
            self._send_tasks.append(task)

        except Exception as e:
            self.logger.error(f"Realtime emit error: {e}")

    async def _send_single(self, event: Event):
        await self._ensure_session()

        batch_id = str(uuid.uuid4())[:8]

        payload = {
            "events": [{"event": event.to_dict()}],
            "batch_size": 1,
            "timestamp": int(time.time()),
            "agent_id": self.agent_id,
            "batch_id": batch_id,
        }

        try:
            async with self._session.post(self.endpoint, json=payload) as response:
                if response.status not in (200, 202):
                    self.logger.warning(
                        f"Realtime send failed ({response.status}) for {event.event_type}"
                    )
        except Exception as e:
            self.logger.error(f"Realtime HTTP error: {e}")

    async def flush(self):
        return

    async def _close_impl(self):
        if self._send_tasks:
            for t in self._send_tasks:
                if not t.done():
                    t.cancel()

        if self._session and not self._session.closed:
            await self._session.close()
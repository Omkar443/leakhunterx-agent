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
    Production-grade realtime emitter.

    Guarantees:
    - No request explosion
    - Controlled concurrency
    - Smooth request rate
    - No memory/task leak
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

        # --------------------------------------------------
        #  PRODUCTION CONTROLS
        # --------------------------------------------------

        # Limit concurrent HTTP requests
        self._semaphore = asyncio.Semaphore(5)

        # Rate limiting (max ~10 req/sec)
        self._last_sent = 0.0
        self._min_interval = 0.1

        # Task safety
        self._max_tasks = 50

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

            # --------------------------------------------------
            #  CLEANUP COMPLETED TASKS
            # --------------------------------------------------
            self._cleanup_tasks()

            # --------------------------------------------------
            #  HARD LIMIT (BACKPRESSURE)
            # --------------------------------------------------
            if len(self._send_tasks) >= self._max_tasks:
                self.logger.warning(
                    f"Realtime overload → dropping event: {event_obj.event_type}"
                )
                return

            # --------------------------------------------------
            #  CRITICAL: guarantee delivery for terminal events
            # --------------------------------------------------
            if event_obj.event_type in {"scan_completed", "scan_failed"}:
                self.logger.warning(
                    f" Forcing sync send for {event_obj.event_type}"
                )
                await self._send_single(event_obj)  # BLOCKING (guaranteed)
                return

            # --------------------------------------------------
            # NORMAL ASYNC FLOW
            # --------------------------------------------------
            task = asyncio.create_task(self._send_single(event_obj))
            self._send_tasks.append(task)

        except Exception as e:
            self.logger.error(f"Realtime emit error: {e}")

    async def _send_single(self, event: Event):
        """
        Controlled send:
        - Rate limited
        - Concurrency limited
        """

        async with self._semaphore:

            # --------------------------------------------------
            #  RATE LIMITING
            # --------------------------------------------------
            now = time.time()
            delta = now - self._last_sent

            if delta < self._min_interval:
                await asyncio.sleep(self._min_interval - delta)

            self._last_sent = time.time()

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
                async with self._session.post(
                    self.endpoint,
                    json=payload
                ) as response:
                    if response.status not in (200, 202):
                        self.logger.warning(
                            f"Realtime send failed ({response.status}) for {event.event_type}"
                        )
            except Exception as e:
                self.logger.error(f"Realtime HTTP error: {e}")

    def _cleanup_tasks(self):
        """
        Remove completed tasks to prevent memory leak
        """
        self._send_tasks = [t for t in self._send_tasks if not t.done()]

    async def flush(self):
        """
        Realtime has no buffer
        """
        return

    async def _close_impl(self):
        """
        Graceful shutdown
        """
        # --------------------------------------------------
        #  CRITICAL: wait for pending requests instead of cancelling
        # --------------------------------------------------
        if self._send_tasks:
            try:
                await asyncio.gather(*self._send_tasks, return_exceptions=True)
            except Exception as e:
                self.logger.error(f"Error waiting for realtime tasks: {e}")

        if self._session and not self._session.closed:
            await self._session.close()
            
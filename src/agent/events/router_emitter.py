from typing import Union, Dict, Any
import logging

from .realtime_emitter import RealtimeEmitter
from .event_emitter import HTTPBatchEmitter, Event

logger = logging.getLogger(__name__)

# Events that MUST go to realtime immediately
REALTIME_EVENTS = {
    "scan_started",
    "scan_progress",
    "scan_completed",
    "scan_failed",
}

# Events that MUST ALWAYS be persisted (critical lifecycle)
CRITICAL_EVENTS = {
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_error",
    "scan_stopped",
}


class RouterEmitter:
    def __init__(self, realtime: RealtimeEmitter, batch: HTTPBatchEmitter):
        self.realtime = realtime
        self.batch = batch

    async def start(self):
        await self.realtime.start()
        await self.batch.start()

    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        event_obj = Event.normalize(event)

        try:
            # --------------------------------------------------
            # 🔥 REALTIME PATH (instant UI updates)
            # --------------------------------------------------
            if event_obj.event_type in REALTIME_EVENTS:
                await self.realtime.emit(event_obj)

            # --------------------------------------------------
            # 🔥 CRITICAL EVENTS → FORCE PERSISTENCE
            # --------------------------------------------------
            if event_obj.event_type in CRITICAL_EVENTS:
                await self.batch.emit(event_obj)

                # 🚨 CRITICAL FIX: flush immediately for terminal events
                if event_obj.event_type == "scan_completed":
                    logger.warning(f"flush for scan_completed: {event_obj.scan_id}")
                    await self.batch.flush()

            # --------------------------------------------------
            # 🧠 NORMAL EVENTS → batch only
            # --------------------------------------------------
            elif event_obj.event_type not in REALTIME_EVENTS:
                await self.batch.emit(event_obj)

        except Exception as e:
            logger.error(f"RouterEmitter emit failed: {e}", exc_info=True)

    async def flush(self):
        # Only batch needs flushing
        await self.batch.flush()

    async def close(self):
        # Ensure everything is flushed before closing
        try:
            await self.batch.flush()
        except Exception as e:
            logger.warning(f"Final batch flush failed: {e}")

        await self.realtime.close()
        await self.batch.close()
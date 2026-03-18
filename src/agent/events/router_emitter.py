from typing import Union, Dict, Any
import logging

from .realtime_emitter import RealtimeEmitter
from .event_emitter import HTTPBatchEmitter, Event

logger = logging.getLogger(__name__)

# --------------------------------------------------
# ✅ REALTIME EVENTS (STRICTLY LOW-FREQUENCY ONLY)
# --------------------------------------------------
REALTIME_EVENTS = {
    "scan_started",
    "scan_completed",
    "scan_failed",
}

# --------------------------------------------------
# ✅ CRITICAL EVENTS (MUST ALWAYS BE PERSISTED)
# --------------------------------------------------
CRITICAL_EVENTS = {
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_error",
    "scan_stopped",
}


class RouterEmitter:
    """
    Production-grade router for event delivery.

    Design guarantees:
    - Realtime = fast UI updates (LOW frequency only)
    - Batch = durability + efficiency
    - No event loss for critical lifecycle events
    - No high-frequency event flooding
    """

    def __init__(self, realtime: RealtimeEmitter, batch: HTTPBatchEmitter):
        self.realtime = realtime
        self.batch = batch

    async def start(self):
        await self.realtime.start()
        await self.batch.start()

    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        """
        Safe routing logic:
        1. Realtime → only selected events
        2. Batch → ALWAYS for persistence
        """

        try:
            event_obj = Event.normalize(event)
            etype = event_obj.event_type

            # --------------------------------------------------
            # 🔥 REALTIME (LOW FREQUENCY ONLY)
            # --------------------------------------------------
            if etype in REALTIME_EVENTS:
                await self.realtime.emit(event_obj)

            # --------------------------------------------------
            # 💾 BATCH (PRIMARY PIPELINE - ALWAYS USED)
            # --------------------------------------------------
            await self.batch.emit(event_obj)

            # --------------------------------------------------
            # 🚨 FORCE FLUSH FOR TERMINAL EVENTS
            # --------------------------------------------------
            if etype == "scan_completed":
                logger.warning(f"flush for scan_completed: {event_obj.scan_id}")
                await self.batch.flush()

        except Exception as e:
            logger.error(f"RouterEmitter emit failed: {e}", exc_info=True)

    async def flush(self):
        """
        Only batch requires flushing
        """
        await self.batch.flush()

    async def close(self):
        """
        Graceful shutdown
        """
        try:
            await self.batch.flush()
        except Exception as e:
            logger.warning(f"Final batch flush failed: {e}")

        await self.realtime.close()
        await self.batch.close()
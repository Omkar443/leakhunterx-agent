import asyncio
from typing import Union, Dict, Any
import logging

from .realtime_emitter import RealtimeEmitter
from .event_emitter import HTTPBatchEmitter, Event

logger = logging.getLogger(__name__)

# --------------------------------------------------
#  REALTIME EVENTS (STRICTLY LOW-FREQUENCY ONLY)
# --------------------------------------------------
REALTIME_EVENTS = {
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_progress",
    "discovery_started",     # drives "Crawling" phase in timeline — must be instant
    "analysis_started",      # drives "JS Analysis" phase in timeline — must be instant
    "js_analysis_summary",   # drives "Finalizing" phase in timeline — must be instant
}

# --------------------------------------------------
#  CRITICAL EVENTS (MUST ALWAYS BE PERSISTED)
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
    Journal lifecycle and evidence through the same ordered delivery path.
    The backend publishes UI notifications after committing the evidence.
    """

    def __init__(self, realtime: RealtimeEmitter, batch: HTTPBatchEmitter):
        self.realtime = realtime
        self.batch = batch

    async def start(self):
        await self.realtime.start()
        await self.batch.start()

    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        obj = Event.normalize(event)
        terminal = obj.event_type in {'scan_completed', 'scan_analysis_finished'}
        if terminal and self.batch._evidence_failed:
            from .outbox import DeliveryPending
            raise DeliveryPending('Scan evidence is incomplete; completion refused')
        # The outbox preserves creation order, including terminal events. Journal
        # completion before sending so an outage cannot lose the completion signal.
        await self.batch.emit(obj)
        if terminal or obj.event_type in CRITICAL_EVENTS:
            await self.batch.drain()
        elif obj.event_type in REALTIME_EVENTS:
            await self.batch.flush()

    async def flush(self):
        """
        Only batch requires flushing
        """
        await self.batch.flush()

    async def drain(self):
        await self.batch.drain()

    async def close(self):
        """
        Graceful shutdown.

        FIX: realtime.close() and batch.close() now run concurrently
        (not sequentially) so a slow/hanging realtime connection can
        never block the durable batch path from closing. Each is also
        given its own hard bound here as a backstop, on top of
        whatever internal timeouts each emitter already enforces.
        """
        try:
            await self.batch.flush()
        except Exception as e:
            logger.warning(f"Final batch flush failed: {e}")

        async def _close_realtime():
            try:
                await asyncio.wait_for(self.realtime.close(), timeout=4.0)
            except asyncio.TimeoutError:
                logger.warning("RouterEmitter: realtime.close() timed out after 4.0s")
            except Exception as e:
                logger.warning(f"RouterEmitter: realtime.close() failed: {e}")

        async def _close_batch():
            try:
                await asyncio.wait_for(self.batch.close(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("RouterEmitter: batch.close() timed out after 5.0s")
            except Exception as e:
                logger.warning(f"RouterEmitter: batch.close() failed: {e}")

        await asyncio.gather(_close_realtime(), _close_batch())

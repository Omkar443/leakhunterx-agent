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
            #  TERMINAL EVENTS → STRONG DELIVERY GUARANTEE
            # --------------------------------------------------
            if etype in {"scan_completed", "scan_failed"}:
                logger.warning(f" TERMINAL EVENT: {etype} → sending immediately, batch drains in background")

                # --------------------------------------------------
                #  FIX: Send the terminal event via realtime FIRST,
                #  with no dependency on batch retry/backoff timing.
                #  The UI needs to know the scan is done NOW —
                #  artifact persistence can finish in the background.
                # --------------------------------------------------
                await self.realtime.emit(event_obj)

                # --------------------------------------------------
                #  Also persist to batch for durability, but as a
                #  background task — do NOT block on it, and do NOT
                #  await any retry backoff before returning.
                # --------------------------------------------------
                async def _drain_batch_after_terminal():
                    try:
                        await self.batch.emit(event_obj)
                        await self.batch.flush()
                    except Exception as e:
                        logger.warning(f"Background batch drain failed: {e}")

                asyncio.create_task(_drain_batch_after_terminal())

                return  #  stop here (do not continue normal flow)

            # --------------------------------------------------
            #  NORMAL FLOW (NON-TERMINAL EVENTS)
            #  FIX: events already delivered via realtime must NOT
            #  also be duplicated into the batch buffer — this was
            #  causing a redundant backlog to build up throughout
            #  the scan, then dump all at once at completion,
            #  making phases/progress appear to lag far behind
            #  the agent's actual real-time pace.
            # --------------------------------------------------
            if etype in REALTIME_EVENTS:
                await self.realtime.emit(event_obj)
            else:
                await self.batch.emit(event_obj)

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
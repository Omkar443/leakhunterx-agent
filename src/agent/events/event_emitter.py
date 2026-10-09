"""
Unified event transport system for SaaS + Local Agent architecture.
Transport-agnostic, pluggable event emission with buffering and retry logic.
Non-blocking, thread-safe, with dead letter queue support.

LOCKED VERSION - Production ready.
"""

# Supported event types (non-exhaustive):
# - scan_started
# - scan_completed
# - scan_failed
# - scan_progress   <-- NEW (event-based progress reporting)
# - module_error
# - component_stats


import json
import time
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import aiohttp
from pathlib import Path
import uuid


def _json_safe(value):
    """
    Recursively convert value into JSON-serializable form.
    CRITICAL: prevents emitter crashes due to sets, tuples, objects.
    """
    if isinstance(value, dict):
        return {
            str(k): _json_safe(v)
            for k, v in value.items()
            if k is not None
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


@dataclass
class Event:
    """Standardized event structure for all scan operations"""
    event_type: str
    scan_id: str
    timestamp: int = 0
    data: Dict[str, Any] = None
    event_id: str = None
 
    def __post_init__(self):
        self.event_id = self.event_id or str(uuid.uuid4())
        if self.timestamp == 0:
            self.timestamp = int(time.time())
        if self.data is None:
            self.data = {}
 
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to JSON-safe dictionary for emission"""
        return {
            "event_id": self.event_id,
            "event_type": str(self.event_type),
            "scan_id": str(self.scan_id),
            "timestamp": int(self.timestamp),
            "data": _json_safe(self.data or {}),
        }

 
    @classmethod
    def normalize(cls, event_data: Union['Event', Dict[str, Any]]) -> 'Event':
        """Normalize input to Event object with injected timestamp"""
        if isinstance(event_data, Event):
            return event_data
 
        # Ensure timestamp is present
        if "timestamp" not in event_data or event_data["timestamp"] == 0:
            event_data = {**event_data, "timestamp": int(time.time())}
 
        # Ensure required fields
        if "event_type" not in event_data:
            raise ValueError("Event missing 'event_type' field")
        if "scan_id" not in event_data:
            raise ValueError("Event missing 'scan_id' field")
 
        return cls(
            event_type=event_data["event_type"],
            scan_id=event_data["scan_id"],
            timestamp=event_data["timestamp"],
            data=event_data.get("data", {}),
            event_id=event_data.get("event_id")
        )


# ─────────────────────────────────────────────
#  LEAKHUNTERX REPORT CONTRACT FILTER
# ─────────────────────────────────────────────
# This filter enforces the LeakHunterX Report Contract.
# If an event is dropped here, it MUST NOT affect
# final user-visible reports.
# ─────────────────────────────────────────────

CONTRACT_CRITICAL_EVENTS = {
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_error",
    "scan_stopped",
    "artifact_batch_ready",
    "scan_progress",   #  allow progress events to backend
}

CONTRACT_DROP_EVENTS = {
    # "scan_progress",  ← allow progress to reach backend
    "heartbeat_debug",
    "analysis_timing",
    "retry_attempt",
    "confidence_score_only",
}

def _passes_report_contract(event: Event) -> bool:
    """
    Enforce LeakHunterX Report Contract.

    True  → event MAY be sent
    False → event MUST be dropped safely

    HARD GUARANTEE:
    Dropping a False event cannot change the final report.
    """

    etype = event.event_type
    data = event.data or {}

    # ─────────────────────────────
    # 0️ ABSOLUTE SAFETY NET
    # ─────────────────────────────
    # If artifacts are present in ANY form, never drop
    if "artifacts" in data:
        return True

    # ─────────────────────────────
    # 1️ Sacred lifecycle & artifact events
    # ─────────────────────────────
    if etype in CONTRACT_CRITICAL_EVENTS:
        return True

    # ─────────────────────────────
    # 2️ Hard-drop known telemetry
    # ─────────────────────────────
    if etype in CONTRACT_DROP_EVENTS:
        return False

    # ─────────────────────────────
    # 3️ Conditional report relevance
    # ─────────────────────────────
    if etype == "js_analysis_complete":
        meta = data.get("metadata") or {}
        return (
            meta.get("secret_count", 0) > 0
            or meta.get("endpoint_count", 0) > 0
        )

    if etype == "endpoint_found":
        severity = data.get("severity")
        confidence = data.get("confidence", 0)

        if severity in ("MEDIUM", "HIGH", "CRITICAL"):
            return True

        if confidence and confidence >= 0.7:
            return True

        return False

    # Legacy / defensive allow
    if etype == "secret_found":
        return True

    # ─────────────────────────────
    # 4️ Default: allow (future-proof)
    # ─────────────────────────────
    return True


class BaseEventEmitter(ABC):
    """
    Abstract base class for all event emitters.
    Defines the interface for transport-agnostic event delivery.
    """
 
    def __init__(self, name: str = "unnamed"):
        self.name = name
        self._is_started = False
        self._is_closing = False
        self._flush_in_progress = False
        self._flush_lock = asyncio.Lock()
        self.logger = logging.getLogger(f"emitter.{name}")
 
    async def start(self) -> None:
        """Initialize emitter resources"""
        if self._is_started:
            return
        self._is_started = True
        await self._start_impl()
        self.logger.info(f"Emitter '{self.name}' started")
 
    async def close(self) -> None:
        """Cleanup resources"""
        if self._is_closing:
            return
        self._is_closing = True
        self.logger.info(f"Emitter '{self.name}' closing")
        await self._close_impl()
        self._is_started = False
 
    @abstractmethod
    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        """
        Emit a single event.
 
        CRITICAL: Must not block scan execution.
        Should be fire-and-forget for async operations.
        """
        pass
 
    @abstractmethod
    async def flush(self) -> None:
        """Flush any buffered events"""
        pass
 
    async def _start_impl(self) -> None:
        """Implementation-specific startup"""
        pass
 
    async def _close_impl(self) -> None:
        """Implementation-specific cleanup"""
        pass
 
    def is_healthy(self) -> bool:
        """Check if emitter is healthy"""
        return self._is_started and not self._is_closing


class DeadLetterQueue:
    """Persistent storage for failed events with replay capability"""
 
    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("dlq")
 
    def save_failed_batch(self, batch_id: str, events: List[Event], error: str) -> None:
        """Save failed batch to disk"""
        try:
            filepath = self.storage_dir / f"failed_{batch_id}_{int(time.time())}.jsonl"
            with open(filepath, 'w', encoding='utf-8') as f:
                for event in events:
                    record = {
                        "event": event.to_dict(),
                        "error": error,
                        "failed_at": int(time.time()),
                        "retry_count": 0,
                        "batch_id": batch_id
                    }
                    f.write(json.dumps(record) + "\n")
            self.logger.warning(f"Saved {len(events)} failed events to {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save DLQ batch: {e}")
 
    def get_failed_batches(self) -> List[Path]:
        """Get list of failed batch files"""
        return list(self.storage_dir.glob("failed_*.jsonl"))
 
    def get_replayable_events(self, max_age_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get events that can be replayed (not too old and retryable).

        SAFETY GUARANTEES:
        - Never replays events older than max_age_hours
        - Enforces retry ceiling (retry_count < 3)
        - Increments retry_count atomically per record
        - Preserves on-disk format (no schema change)
        """

        replayable: List[Dict[str, Any]] = []
        cutoff_time = time.time() - (max_age_hours * 3600)

        for filepath in self.get_failed_batches():
            updated_records = []
            file_modified = False

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        record = json.loads(line.strip())

                        failed_at = record.get("failed_at", 0)
                        retry_count = record.get("retry_count", 0)

                        # Skip expired or exhausted records
                        if failed_at <= cutoff_time or retry_count >= 3:
                            updated_records.append(record)
                            continue

                        # Mark record as attempted
                        record["retry_count"] = retry_count + 1
                        replayable.append(record)
                        updated_records.append(record)
                        file_modified = True

                # Persist retry_count updates back to disk
                if file_modified:
                    with open(filepath, "w", encoding="utf-8") as f:
                        for record in updated_records:
                            f.write(json.dumps(record) + "\n")

            except Exception as e:
                self.logger.error(f"Error processing DLQ file {filepath}: {e}")

        return replayable



class HTTPBatchEmitter(BaseEventEmitter):
    """
    Production emitter - buffers events and sends batches to SaaS backend.
    Non-blocking with automatic retry, dead letter queue, and thread-safe flushing.
 
    LOCKED VERSION - Production ready.
    """
 
    def __init__(
        self,
        endpoint: str,
        agent_id: str = "leakhunterx",
        batch_size: int = 100,
        flush_interval: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        api_key: Optional[str] = None,
        max_buffer_size: int = 10000,
        dlq_enabled: bool = True,
        dlq_dir: Optional[Path] = None,
        auto_recover: bool = True  # NEW: Auto-recovery from DLQ
    ):
        """
        Initialize HTTP batch emitter.
 
        Args:
            endpoint: SaaS backend endpoint URL
            agent_id: Unique agent identifier
            batch_size: Number of events per batch
            flush_interval: Maximum seconds between flushes
            max_retries: Maximum retry attempts for failed batches
            retry_delay: Initial retry delay in seconds (exponential backoff)
            api_key: Optional API key for authentication
            max_buffer_size: Maximum buffer size before dropping events
            dlq_enabled: Enable dead letter queue for failed batches
            dlq_dir: Directory for DLQ storage (default: ./dlq)
            auto_recover: Automatically attempt to replay events from DLQ (default: True)
        """
        super().__init__(name=f"http.{agent_id}")
 
        self.endpoint = endpoint
        self.agent_id = agent_id
        self.batch_size = max(1, min(200, int(batch_size)))
        self.flush_interval = flush_interval
        self.max_retries = max(0, min(6, int(max_retries)))
        self.retry_delay = max(0.1, min(10, float(retry_delay)))
        self.api_key = api_key
        self.max_buffer_size = max_buffer_size
 
        # Event buffer with thread-safe access
        self._buffer: List[Event] = []
        self._buffer_lock = asyncio.Lock()
        self._last_flush = time.time()
        self._send_lock = asyncio.Lock()
 
        # Background tasks
        self._flush_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None  # FIX 1: Track stats task
        self._recovery_task: Optional[asyncio.Task] = None  # NEW: Recovery task
        self._send_tasks: List[asyncio.Task] = []
 
        # HTTP session
        self._session: Optional[aiohttp.ClientSession] = None
 
        # Stats
        self._stats = {
            "emitted": 0,
            "sent": 0,
            "failed": 0,
            "dropped": 0,
            "retries": 0,
            "dlq_saved": 0,
            "flushes": 0,
            "last_success": 0,
            "recovered": 0,  # NEW: Track recovered events
            "recovery_attempts": 0  # NEW: Track recovery attempts
        }
 
        # Dead letter queue
        self.dlq_enabled = dlq_enabled
        self.dlq_dir = dlq_dir or Path("./dlq")
        self.dlq = DeadLetterQueue(self.dlq_dir) if dlq_enabled else None
 
        # Recovery settings
        self.auto_recover = auto_recover
        self._recovery_lock = asyncio.Lock()
        self._last_recovery_attempt = 0
        from .outbox import DurableOutbox
        import hashlib
        namespace = hashlib.sha256(f'{endpoint}:{agent_id}'.encode()).hexdigest()[:24]
        self.outbox = DurableOutbox(self.dlq_dir / namespace / 'outbox.sqlite3')
        self._pending_count = self.outbox.count()
        self._delivery_task = None
        self._evidence_failed = False
        self._rejected_scan_ids = set()
        self._recovery_interval = 30
 
    async def _start_impl(self) -> None:
        """Initialize HTTP session and start background flusher"""
        await asyncio.to_thread(self._import_legacy_deliveries)
        self._pending_count = await asyncio.to_thread(self.outbox.count)
        await self._ensure_session()
 
        if self.flush_interval > 0:
            self._flush_task = asyncio.create_task(self._background_flusher())
 
        # Emit stats periodically
        self._stats_task = asyncio.create_task(self._emit_stats_periodically())
 
        # Start recovery task if enabled
        if self.auto_recover and self.dlq_enabled:
            self._recovery_task = asyncio.create_task(self._background_recovery())
        await self.flush()

    def _import_legacy_deliveries(self):
        """Carry pre-upgrade failed batches forward without their old retry expiry."""
        import hashlib
        for path in self.dlq_dir.glob('failed_*.jsonl'):
            if path.is_symlink():
                raise ValueError('Legacy delivery journal must not be a symbolic link')
            with path.open(encoding='utf-8') as source:
                for line in source:
                    record = json.loads(line).get('event')
                    if not isinstance(record, dict):
                        raise ValueError('Invalid legacy delivery journal')
                    if not record.get('event_id'):
                        record['event_id'] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
                    self.outbox.append(Event.normalize(record).to_dict())
            path.rename(path.with_suffix('.imported'))
 
    async def _ensure_session(self) -> None:
        """Create HTTP session if needed"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
 
            #  FIXED: Correct headers that match backend expectations
            headers = {
                "User-Agent": f"LeakHunterX-Agent/{self.agent_id}",
                "X-Agent-Id": self.agent_id,          #  Backend expects X-Agent-Id (not X-Agent-ID)
                "Content-Type": "application/json",   #  Required for POST requests
                "X-Agent-Version": "1.0.0"
            }
 
            #  FIXED: Backend expects X-Agent-Secret (not x-agent-key)
            if self.api_key:
                headers["X-Agent-Secret"] = self.api_key
 
            #  DEBUG: Log headers for verification
            self.logger.debug("Creating authenticated HTTP delivery session")
 
            connector = aiohttp.TCPConnector(limit=100)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector
            )
 
    async def _background_flusher(self) -> None:
        """Background task for periodic flushing"""
        while not self._is_closing:
            try:
                await asyncio.sleep(min(5, self.flush_interval))
 
                # FIX 3: Read buffer length with lock
                async with self._buffer_lock:
                    buffer_len = await asyncio.to_thread(self.outbox.count)
                    should_flush = (
                        buffer_len > 0 and
                        time.time() - self._last_flush >= min(5, self.flush_interval)
                    )
 
                if should_flush:
                    # flush owns one delivery task; do not accumulate finished tasks.
                    await self.flush()
 
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Background flusher error: {e}")
                continue
 
    async def _background_recovery(self) -> None:
        while not self._is_closing:
            try:
                await asyncio.sleep(self._recovery_interval)
                await self.flush()
            except asyncio.CancelledError:
                raise

    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        if self._is_closing:
            raise RuntimeError('Event delivery is closing')
        obj = Event.normalize(event)
        if not _passes_report_contract(obj):
            self._stats['dropped'] += 1
            return
        # Returning from emit means the event survives process termination.
        try:
            added = await asyncio.to_thread(self.outbox.append, obj.to_dict())
        except Exception:
            self._evidence_failed = True
            raise
        self._stats['emitted'] += 1
        self._pending_count += int(added)
        if self._stats['emitted'] % min(self.batch_size, 200) == 0:
            await self.flush()

    async def flush(self) -> None:
        if self._delivery_task and not self._delivery_task.done():
            return
        self._delivery_task = asyncio.create_task(self._background_delivery())

    async def _background_delivery(self):
        from .outbox import DeliveryPending
        try:
            await self.drain()
        except DeliveryPending:
            self.logger.warning('Delivery pending; evidence retained in local outbox')
        except Exception as error:
            self.logger.error('Delivery deferred: %s', type(error).__name__)

    async def drain(self):
        from .outbox import DeliveryPending
        async with self._send_lock:
            while True:
                batch = await asyncio.to_thread(self.outbox.next_batch)
                if not batch:
                    return
                batch_id, records = batch
                events = [Event.normalize(record) for record in records]
                if not await self._send_batch_attempt(batch_id, events):
                    if self._rejected_scan_ids:
                        moved = await asyncio.to_thread(self.outbox.quarantine_unassigned, batch_id, self._rejected_scan_ids)
                        self._pending_count = await asyncio.to_thread(self.outbox.count)
                        self.logger.warning('Quarantined %s server-rejected records; evidence retained locally', moved)
                        continue
                    raise DeliveryPending('Backend has not acknowledged preceding evidence')
                await asyncio.to_thread(self.outbox.acknowledge, batch_id)
                self._pending_count = max(0, self._pending_count - len(records))

    async def _send_batch_attempt(self, batch_id: str, events: List[Event]) -> bool:
        self._rejected_scan_ids = set()
        await self._ensure_session()
        payload = {'events': [{'event': e.to_dict()} for e in events], 'batch_id': batch_id,
                   'agent_id': self.agent_id, 'batch_size': len(events)}
        json.dumps(payload, allow_nan=False)
        for attempt in range(self.max_retries + 1):
            try:
                async with self._session.post(self.endpoint, json=payload, allow_redirects=False,
                        ssl=self.endpoint.startswith('https://')) as response:
                    if response.status in (200, 202):
                        receipt = await response.json()
                        if (receipt.get('status') != 'accepted' or receipt.get('received') != len(events)
                                or receipt.get('batch_id') != batch_id):
                            self.logger.warning('Backend acknowledgement is incomplete')
                            return False
                        self._stats['sent'] += len(events)
                        self._stats['last_success'] = int(time.time())
                        return True
                    if response.status not in (429, 500, 502, 503, 504):
                        if response.status == 403:
                            # Authentication failures and legacy/unstructured errors
                            # remain pending. Only an explicit atomic ownership rejection
                            # from this authenticated endpoint permits isolation.
                            raw = await response.content.read(65537)
                            if len(raw) <= 65536:
                                try:
                                    detail = json.loads(raw).get('detail')
                                    supplied = {str(e.scan_id) for e in events}
                                    rejected = detail.get('rejected_scan_ids') if isinstance(detail, dict) else None
                                    if (isinstance(detail, dict) and detail.get('code') == 'scan_not_assigned'
                                            and detail.get('batch_id') == batch_id
                                            and isinstance(rejected, list) and 0 < len(rejected) <= len(supplied)
                                            and all(isinstance(value, str) and value in supplied for value in rejected)):
                                        self._rejected_scan_ids = set(rejected)
                                except (ValueError, TypeError, AttributeError):
                                    pass
                        self.logger.warning('Delivery rejected: HTTP %s; outbox retained', response.status)
                        return False
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            except Exception as error:
                self.logger.warning('Delivery response failure: %s', type(error).__name__)
                return False
            if attempt < self.max_retries:
                self._stats['retries'] += 1
                await asyncio.sleep(min(30, self.retry_delay * (2 ** attempt)))
        return False

    def _cleanup_completed_tasks(self) -> None:
        """Remove completed tasks from tracking"""
        self._send_tasks = [t for t in self._send_tasks if not t.done()]
 
    async def _emit_stats_periodically(self) -> None:
        """
        Periodically collect emitter statistics.

        IMPORTANT:
        - Stats are NOT emitted to backend
        - Stats are NOT persisted
        - Stats are intended for local / UI / monitoring use only
        - This avoids feedback loops and DB noise
        """
        while not self._is_closing:
            try:
                await asyncio.sleep(60)  # Every minute

                # Collect stats snapshot (local-only)
                _ = {
                    "emitter": self.name,
                    "stats": self.get_stats(),
                    "buffer_size": self._pending_count,
                    "healthy": self.is_healthy(),
                    "pending_tasks": len(self._send_tasks),
                    "timestamp": int(time.time()),
                }

                # NOTE:
                # This data is intentionally NOT sent via this emitter.
                # It can be forwarded to:
                # - local UI channel
                # - websocket
                # - SSE
                # - debug overlay
                # without touching backend storage.

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Stats collector error: {e}")
 
    async def _get_buffer_size(self) -> int:
        """Thread-safe buffer size getter"""
        async with self._buffer_lock:
            return self._pending_count
 
    async def _close_impl(self) -> None:
        tasks = [t for t in (self._flush_task, self._stats_task, self._recovery_task, self._delivery_task) if t]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await asyncio.wait_for(self.drain(), 3)
        except (asyncio.TimeoutError, Exception):
            self.logger.warning('Shutdown delivery deferred; local evidence retained')
        finally:
            if self._session and not self._session.closed:
                await self._session.close()

    def get_stats(self) -> Dict[str, Any]:
        """
        Return emitter statistics.

        NOTE:
        This method is intentionally synchronous.
        Stats are best-effort and must NEVER block or require await.
        """

        buffer_size = self._pending_count
        pending_tasks = int(bool(self._delivery_task and not self._delivery_task.done()))

        return {
            **self._stats,
            "buffer_size": buffer_size,
            "pending_tasks": pending_tasks,
            "is_closing": self._is_closing,
            "flush_in_progress": self._flush_in_progress,
            "dlq_enabled": self.dlq_enabled,
            "auto_recover": self.auto_recover,
            "health": "healthy" if self.is_healthy() else "unhealthy"
        }
 
    async def recover_failed_events(self) -> int:
        before = await asyncio.to_thread(self.outbox.count)
        await self.drain()
        return before


class StdoutEmitter(BaseEventEmitter):
    """
    Debug/Development emitter - outputs JSON to stdout.
    Uses async execution to avoid blocking scan.
 
    LOCKED VERSION - Production ready.
    """
 
    def __init__(
        self,
        writer: Optional[Callable[[str], None]] = None,
        pretty: bool = False,
        name: str = "stdout",
        **kwargs
    ):
        super().__init__(name=name)
        self.writer = writer or (lambda x: print(x, flush=True))
        self.pretty = pretty
        self._write_queue = asyncio.Queue(maxsize=1000)
        self._writer_task: Optional[asyncio.Task] = None
 
    async def _start_impl(self) -> None:
        """Start background writer task"""
        self._writer_task = asyncio.create_task(self._writer_loop())
 
    async def _writer_loop(self) -> None:
        """Background task for async writing"""
        while not self._is_closing:
            try:
                # Non-blocking wait with timeout
                try:
                    event_str = await asyncio.wait_for(
                        self._write_queue.get(),
                        timeout=0.1
                    )
                except asyncio.TimeoutError:
                    continue
 
                # Write synchronously but in executor
                await asyncio.get_event_loop().run_in_executor(
                    None, self.writer, event_str
                )
                self._write_queue.task_done()
 
            except asyncio.CancelledError:
                break
            except Exception:
                # Don't crash on write errors
                continue
 
    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        """
        Correct behavior:
        - ONLY print
        - NO routing
        """

        if self._is_closing:
            return

        try:
            event_obj = Event.normalize(event)
            event_str = json.dumps(event_obj.to_dict(), ensure_ascii=False)

            try:
                self._write_queue.put_nowait(event_str)
            except asyncio.QueueFull:
                pass

        except Exception as e:
            self.logger.error(f"Emit error: {e}")
 
    async def flush(self) -> None:
        """
        Flush buffered events (NON-BLOCKING ONLY).
        """

        if self._is_closing or self._flush_in_progress:
            return

        async with self._flush_lock:
            self._flush_in_progress = True
            try:
                await self._flush_impl()
            finally:
                self._flush_in_progress = False

 
    async def _close_impl(self) -> None:
        """Wait for writer task to finish"""
        if self._writer_task:
            # Signal completion
            await self.flush()
            # Cancel and wait
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass


class NullEmitter(BaseEventEmitter):
    """
    Test emitter - discards all events.
    Used for unit tests and performance testing.
 
    LOCKED VERSION - Production ready.
    """
 
    def __init__(self):
        super().__init__(name="null")
        self.emitted_events: List[Event] = []
 
    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        """Store event for verification"""
        try:
            event_obj = Event.normalize(event)
            self.emitted_events.append(event_obj)
        except Exception as e:
            self.logger.error(f"Emit error: {e}")
 
    async def flush(self) -> None:
        """No buffering for null emitter"""
        pass
 
    def get_events(self) -> List[Dict[str, Any]]:
        """Get all emitted events for testing"""
        return [e.to_dict() for e in self.emitted_events]
 
    def clear(self) -> None:
        """Clear stored events"""
        self.emitted_events.clear()


class CallbackEmitter(BaseEventEmitter):
    """
    Flexible emitter that routes events to a callback.
    Useful for custom integrations and testing.
 
    LOCKED VERSION - Production ready.
    """
 
    def __init__(self, callback: Callable[[Event], None], name: str = "callback"):
        super().__init__(name=name)
        self.callback = callback
 
    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        """Pass event to callback"""
        try:
            event_obj = Event.normalize(event)
            # Run callback in executor to avoid blocking
            await asyncio.get_event_loop().run_in_executor(
                None, self.callback, event_obj
            )
        except Exception as e:
            self.logger.error(f"Emit error: {e}")
 
    async def flush(self) -> None:
        """No buffering for callback emitter"""
        pass


class FileEmitter(BaseEventEmitter):
    """
    File-based emitter for local testing and debugging.
    Writes events to a file in JSONL format.
 
    LOCKED VERSION - Production ready.
    """
 
    def __init__(self, filepath: str, mode: str = "a"):
        super().__init__(name=f"file.{filepath}")
        self.filepath = filepath
        self.mode = mode
        self._file = None
        self._write_queue = asyncio.Queue(maxsize=1000)
        self._writer_task: Optional[asyncio.Task] = None
 
    async def _start_impl(self) -> None:
        """Open file and start writer task"""
        self._file = open(self.filepath, self.mode, encoding="utf-8")
        self._writer_task = asyncio.create_task(self._file_writer_loop())
 
    async def _file_writer_loop(self) -> None:
        """Background task for async file writing"""
        while not self._is_closing:
            try:
                event_str = await asyncio.wait_for(
                    self._write_queue.get(),
                    timeout=0.1
                )
 
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._file.write(event_str + "\n")
                )
                self._write_queue.task_done()
 
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"File write error: {e}")
                continue
 
    async def emit(self, event: Union[Event, Dict[str, Any]]) -> None:
        """Queue event for file writing"""
        if self._is_closing:
            return
 
        try:
            event_obj = Event.normalize(event)
            event_str = json.dumps(event_obj.to_dict(), ensure_ascii=False)
 
            try:
                self._write_queue.put_nowait(event_str)
            except asyncio.QueueFull:
                # Drop rather than block
                pass
 
        except Exception as e:
            self.logger.error(f"Emit error: {e}")
 
    async def flush(self) -> None:
        """Wait for write queue to empty"""
        await self._write_queue.join()
        if self._file:
            await asyncio.get_event_loop().run_in_executor(
                None, self._file.flush
            )
 
    async def _close_impl(self) -> None:
        """Close file and writer task"""
        if self._writer_task:
            await self.flush()
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
 
        if self._file:
            await asyncio.get_event_loop().run_in_executor(
                None, self._file.close
            )


from typing import Optional, Dict, Any
from pathlib import Path

def create_emitter(
    emitter_type: str = "stdout",
    config: Optional[Dict[str, Any]] = None,
    name: Optional[str] = None,
) -> BaseEventEmitter:
    """
    Factory function to create event emitters.

    IMPORTANT DESIGN RULES:
    - emitter_type comes ONLY from runtime (CLI / env), never from AgentConfig
    - config MUST be a plain dict (already serialized)
    - NO implicit mode inference
    - NO access to config.mode or LHX_MODE

    Args:
        emitter_type: "stdout", "http", "null", "callback", "file"
        config: Plain dictionary with emitter-relevant config
        name: Optional emitter name override

    Returns:
        Initialized (but not started) BaseEventEmitter

    Raises:
        ValueError / TypeError on invalid usage
    """

    # ------------------------------
    # Hard safety checks
    # ------------------------------
    if config is None:
        config = {}

    if not isinstance(config, dict):
        raise TypeError(
            "create_emitter() expects `config` to be a dict. "
            "Did you accidentally pass AgentConfig?"
        )

    emitter_type = emitter_type.lower().strip()

    # ------------------------------
    # STDOUT EMITTER
    # ------------------------------
    if emitter_type == "stdout":
        return StdoutEmitter(
            pretty=bool(config.get("pretty", False)),
            name=name or "stdout",
        )

    # ------------------------------
    # HTTP EMITTER (SaaS / backend)
    # ------------------------------
    if emitter_type == "http":
        from .router_emitter import RouterEmitter
        from .realtime_emitter import RealtimeEmitter
 
        base_url = config.get("backend_url") or config.get("http_endpoint")
        if not base_url:
            raise ValueError("HTTP emitter requires backend_url")

        endpoint = base_url.rstrip("/") + "/api/v1/agent/events"

        # Existing batch emitter (UNCHANGED)
        batch = HTTPBatchEmitter(
            endpoint=endpoint,
            agent_id=config.get("agent_id", "leakhunterx"),
            api_key=config.get("agent_api_key"),
            batch_size=int(config.get("artifact_batch_size", 100)),
            flush_interval=int(config.get("flush_interval", 30)),
            max_retries=int(config.get("max_retries", 3)),
            retry_delay=float(config.get("retry_delay", 1.0)),
            max_buffer_size=int(config.get("max_buffer_size", 10000)),
            dlq_enabled=bool(config.get("dlq_enabled", True)),
            dlq_dir=Path(config.get("dlq_dir", "./dlq")),
            auto_recover=bool(config.get("auto_recover", True)),
        )

        # New realtime emitter
        realtime = RealtimeEmitter(
            endpoint=endpoint,
            agent_id=config.get("agent_id", "leakhunterx"),
            api_key=config.get("agent_api_key"),
        )

        return RouterEmitter(realtime=realtime, batch=batch)

    # ------------------------------
    # NULL EMITTER (tests)
    # ------------------------------
    if emitter_type == "null":
        return NullEmitter()

    # ------------------------------
    # FILE EMITTER (debugging)
    # ------------------------------
    if emitter_type == "file":
        filepath = config.get("file_path") or "events.jsonl"
        return FileEmitter(
            filepath=filepath,
            mode=config.get("file_mode", "a"),
        )

    # ------------------------------
    # CALLBACK EMITTER
    # ------------------------------
    if emitter_type == "callback":
        callback = config.get("callback")
        if not callable(callback):
            raise ValueError("Callback emitter requires a callable `callback`")
        return CallbackEmitter(callback=callback, name=name or "callback")

    # ------------------------------
    # Unknown emitter
    # ------------------------------
    raise ValueError(f"Unknown emitter type: {emitter_type}")


# Event builder utilities with improved type safety
def build_scan_event(
    event_type: str,
    scan_id: str,
    data: Optional[Dict[str, Any]] = None,
    **extra_data
) -> Dict[str, Any]:
    """Build a standardized scan event"""
    event_data = {
        "event_type": event_type,
        "scan_id": scan_id,
        "timestamp": int(time.time()),
        "data": data or {}
    }
 
    # Add any extra data to the data dict
    if extra_data:
        event_data["data"].update(extra_data)
 
    return event_data


def build_error_event(
    scan_id: str,
    module: str,
    error: str,
    context: Optional[Dict[str, Any]] = None,
    severity: str = "error"
) -> Dict[str, Any]:
    """Build a standardized error event"""
    data = {
        "module": module,
        "error": error,
        "severity": severity,
        "context": context or {},
        "timestamp": int(time.time())
    }
    return build_scan_event("module_error", scan_id, data)


def build_stats_event(
    scan_id: str,
    metrics: Dict[str, Any],
    component: str = "orchestrator"
) -> Dict[str, Any]:
    """Build a standardized stats event"""
    data = {
        "component": component,
        "metrics": metrics,
        "timestamp": int(time.time())
    }
    return build_scan_event("component_stats", scan_id, data)

# FIX 3: FIX PROGRESS EVENT AT SOURCE (AGENT SIDE)
def build_progress_event(
    scan_id: str,
    phase: str,
    current: Optional[int] = None,
    total: Optional[int] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a standardized scan progress event.

    SAFETY GUARANTEES:
    - Never emits 0/0
    - Never emits invalid totals
    - Never emits current > total
    - Never emits fake 1/1 early completion
    """

    data: Dict[str, Any] = {
        "phase": phase,
    }

    # --------------------------------------------------
    #  CRITICAL FIX 1: VALID TOTAL ONLY
    # --------------------------------------------------
    if total is not None and total > 1:
        data["total_files"] = total
    else:
        #  Drop invalid totals (0 or 1)
        total = None

    # --------------------------------------------------
    #  CRITICAL FIX 2: VALID CURRENT
    # --------------------------------------------------
    if current is not None:
        current = max(0, current)

        # Clamp to total if present
        if total is not None:
            current = min(current, total)

        data["processed_files"] = current

    # --------------------------------------------------
    #  CRITICAL FIX 3: PREVENT FAKE COMPLETION
    # --------------------------------------------------
    if total is not None and current is not None:
        if total <= 1:
            # Drop invalid progress entirely
            return build_scan_event(
                event_type="scan_progress",
                scan_id=scan_id,
                data={
                    "phase": phase,
                    "message": message or "Processing",
                },
            )

    # --------------------------------------------------
    # Optional message
    # --------------------------------------------------
    if message:
        data["message"] = message

    return build_scan_event(
        event_type="scan_progress",
        scan_id=scan_id,
        data=data,
    )

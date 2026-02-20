import time
import uuid
from typing import Dict, Any, Optional

# ─────────────────────────────────────────────
# MVP EVENT THROTTLING POLICY (AGENT-SIDE)
# ─────────────────────────────────────────────

# Always emitted — NEVER throttled
ALWAYS_ALLOW_EVENTS = {
    "scan_started",
    "scan_completed",
    "scan_failed",
    "scan_error",
    "secret_found",
}

# Completely dropped in MVP (noise / internal)
DROP_EVENTS = {
    "batch_started",
    "batch_completed",
    "initial_stats",
    "crawl_started",
    "crawl_completed",
    "crawl_final_stats",
    "task_failed",
    "processing_error",
    "parse_error",
}

# Snapshot-only events (only latest kept, flushed on terminal)
SNAPSHOT_EVENTS = {
    "scan_progress",
    "stats_update",
}

# Deduplicated / rate-limited events
# key = data[field]
DEDUP_EVENTS = {
    "url_fetching": "url",
    "url_fetched": "url",
    "retry_triggered": "url",
    "dns_failure": "domain",
    "rate_limit_exceeded": "domain",
    "circuit_breaker_active": "domain",
}


# ─────────────────────────────────────────────
# EVENT BUILDER (CANONICAL, FUTURE-PROOF)
# ─────────────────────────────────────────────
def build_event(
    *,
    event_type: str,
    scan_id: str,
    data: dict | None = None,
    scope: str = "scan",
    schema_version: int = 1,
) -> dict:
    """
    Build a validated, future-proof event dict.
    """
    if not event_type:
        raise ValueError("event_type is required")

    if scope == "scan" and not scan_id:
        raise ValueError("scan_id is required for scan events")

    return {
        "schema_version": schema_version,
        "scope": scope,                 # scan | system
        "event_type": event_type,
        "scan_id": scan_id,
        "timestamp": int(time.time()),
        "data": data or {},
    }


# ─────────────────────────────────────────────
# 🔑 SINGLE OFFICIAL EVENT EMISSION API
# ─────────────────────────────────────────────
async def emit_event(context, event_type: str, data: dict | None = None):
    """
    The ONLY allowed way to emit events from scan logic.

    GUARANTEES:
    - scan_id ALWAYS injected
    - schema consistency
    - MVP-safe throttling
    - transport-agnostic
    """

    # ─────────────────────────────────────────────
    # 1️⃣ STRICT CONTEXT VALIDATION
    # ─────────────────────────────────────────────
    if context is None:
        raise RuntimeError("emit_event called with None context")

    if not hasattr(context, "scan_id") or not context.scan_id:
        raise RuntimeError("emit_event: Context missing valid scan_id")

    if not hasattr(context, "event_emitter") or context.event_emitter is None:
        raise RuntimeError("emit_event: Context missing event_emitter")

    emitter = context.event_emitter

    if not hasattr(emitter, "emit") or not callable(emitter.emit):
        raise RuntimeError("event_emitter must expose async emit(event)")

    # ─────────────────────────────────────────────
    # 2️⃣ MVP EVENT THROTTLING (SCAN-LOCAL)
    # ─────────────────────────────────────────────
    throttle = context.shared_state.setdefault("_event_throttle", {
        "last_emit": {},        # (event_type, key) -> timestamp
        "latest_snapshot": {},  # event_type -> data
    })

    now = time.time()
    payload = data or {}

    # --- Always allow critical events ---
    if event_type not in ALWAYS_ALLOW_EVENTS:

        # Drop noise entirely
        if event_type in DROP_EVENTS:
            return

        # Snapshot-only events
        if event_type in SNAPSHOT_EVENTS:
            throttle["latest_snapshot"][event_type] = payload
            return

        # Deduplicated events (rate-limited)
        if event_type in DEDUP_EVENTS:
            key_field = DEDUP_EVENTS[event_type]
            key_value = payload.get(key_field)

            if not key_value:
                return

            dedup_key = (event_type, key_value)
            last_time = throttle["last_emit"].get(dedup_key, 0)

            # ⏱ 5s cooldown per key (MVP-safe default)
            if now - last_time < 5:
                return

            throttle["last_emit"][dedup_key] = now

    # ─────────────────────────────────────────────
    # 3️⃣ BUILD CANONICAL EVENT
    # ─────────────────────────────────────────────
    event = build_event(
        event_type=event_type,
        scan_id=context.scan_id,
        data=payload,
        scope="scan",
    )

    # ─────────────────────────────────────────────
    # 4️⃣ FLUSH SNAPSHOTS ON TERMINAL EVENTS
    # ─────────────────────────────────────────────
    if event_type in ("scan_completed", "scan_failed", "scan_error"):
        snapshots = throttle.get("latest_snapshot", {})

        for snap_type, snap_data in snapshots.items():
            snapshot_event = build_event(
                event_type=snap_type,
                scan_id=context.scan_id,
                data=snap_data,
                scope="scan",
            )
            await emitter.emit(snapshot_event)

        snapshots.clear()

    # ─────────────────────────────────────────────
    # 5️⃣ EMIT EVENT (EMITTER HANDLES BATCHING)
    # ─────────────────────────────────────────────
    await emitter.emit(event)

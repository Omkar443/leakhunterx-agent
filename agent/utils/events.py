import time
import uuid


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


async def emit_event(context, event_type: str, data: dict | None = None):
    """
    The ONLY allowed way to emit events from scan logic.

    Guarantees:
    - scan_id is ALWAYS present
    - consistent event schema
    - SaaS-safe emission
    - transport-agnostic
    """

    # ─────────────────────────────────────────────
    # 1️⃣ Validate context (STRICT)
    # ─────────────────────────────────────────────
    if context is None:
        raise RuntimeError("emit_event called with None context")

    if not hasattr(context, "scan_id") or not context.scan_id:
        raise RuntimeError("emit_event: Context missing valid scan_id")

    if not hasattr(context, "event_emitter") or context.event_emitter is None:
        raise RuntimeError("emit_event: Context missing event_emitter")

    emitter = context.event_emitter

    if not hasattr(emitter, "emit") or not callable(emitter.emit):
        raise RuntimeError("event_emitter must expose an async emit(event) method")

    # ─────────────────────────────────────────────
    # 2️⃣ Build canonical event
    # ─────────────────────────────────────────────
    event = build_event(
        event_type=event_type,
        scan_id=context.scan_id,     # 🔑 ALWAYS injected here
        data=data or {},
        scope="scan",
    )

    # ─────────────────────────────────────────────
    # 3️⃣ Emit SINGLE EVENT (emitter handles batching)
    # ─────────────────────────────────────────────
    await emitter.emit(event)

#!/usr/bin/env python3
"""
LeakHunterX Agent - Main Entry Point
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import argparse
import os
import time
from typing import Optional, Tuple, Dict, Any, Callable
from urllib.parse import urlparse
import hashlib
import json
import httpx
import platform
import re

# ─────────────────────────────────────────────
#  PACKAGE-SAFE IMPORTS (CRITICAL CHANGE)
# ─────────────────────────────────────────────

from .config.config import AgentConfig
from .events.event_emitter import create_emitter
from .orchestrator import ScanOrchestrator, ScanStatus
from .state_manager import StateManager
from .utils.helpers import get_version
from .pair_agent import pair_agent
from .utils.secret_path import get_agent_secret_path

# ─────────────────────────────────────────────
# CONSOLE OUTPUT — clean, structured, no emojis
# ─────────────────────────────────────────────

import datetime

# ─────────────────────────────────────────────
#  ANSI COLORS — no new dependency required
# ─────────────────────────────────────────────
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def _supports_color() -> bool:
    # Disable colors when piping to a file/log or on unsupported terminals
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    if not _supports_color():
        return text
    return f"{color}{text}{C.RESET}"


def _now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")

def console_banner(version: str) -> None:
    print(f"\n{_c(f'LeakHunterX Agent v{version}', C.BOLD + C.CYAN)}\n")

def console_agent_ready(agent_id: str, backend_url: str) -> None:
    print(f"  Agent ID   {_c(agent_id, C.GRAY)}")
    print(f"  Backend    {_c(backend_url, C.GRAY)}")
    print(f"  Status     {_c('connected', C.GREEN)}")
    print()

def console_waiting() -> None:
    print("Waiting for scan assignments. Press Ctrl+C to stop.\n")

def console_scan_received(scan_id: str, target: str) -> None:
    started = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{_c('Scan received.', C.BOLD)}\n")
    print(f"  Scan ID    {_c(scan_id, C.GRAY)}")
    print(f"  Target     {_c(target, C.CYAN)}")
    print(f"  Started    {_c(started, C.GRAY)}")
    print()

def console_phase(phase: str, message: str) -> None:
    # Pad phase name to fixed width for alignment
    padded = f"[ {phase:<10} ]"
    color = C.GREEN if phase == "completed" else C.CYAN
    print(f"  {_c(padded, color)}   {message}")

def console_progress_bar(current: int, total: int, width: int = 20) -> None:
    """
    Render a live, in-place progress bar for the analysis phase.
    Uses \r to overwrite the same line — real counts only, sourced
    directly from the agent's own processed/total JS file tallies.
    Newline handling is the caller's responsibility (see
    PhaseConsoleInterceptor._end_progress_bar_if_active) so this bar
    is safe to call repeatedly without ever leaking onto the next
    phase's line.
    """
    pct = min(100, int((current / total) * 100)) if total else 0
    filled = int(width * pct / 100)
    bar = "█" * filled + "░" * (width - filled)
    bar_colored = _c(bar, C.CYAN)
    line = f"  [ {'analysis':<10} ]   [{bar_colored}] {pct}% ({current}/{total} files)"
    # \r returns to line start; pad with spaces to clear any leftover chars
    print(f"\r{line}   ", end="", flush=True)

def console_scan_done(
    scan_id: str,
    potential_secrets: int,
    potential_endpoints: int,
    backend_url: str
) -> None:
    """
    Honest completion summary.

    IMPORTANT: the agent only detects CANDIDATE matches via pattern
    matching — it does not know if the backend's relevance/validation
    gate will confirm them as real findings. Never label these as
    "CRITICAL" or "HIGH" here — that would assert unvalidated data as
    confirmed fact, which is exactly the kind of trust-eroding fake
    signal this tool must avoid. Confirmed, severity-scored findings
    only exist after backend validation — direct the user there.
    """
    print()
    total_candidates = potential_secrets + potential_endpoints

    if total_candidates == 0:
        # print(f"  {_c('Result', C.BOLD)}     No candidate matches detected")
        pass
    else:
        parts = []
        if potential_secrets > 0:
            parts.append(f"{potential_secrets} potential secret(s)")
        if potential_endpoints > 0:
            parts.append(f"{potential_endpoints} potential endpoint(s)")
        print(
            f"  {_c('Result', C.BOLD)}     "
            f"{_c(', '.join(parts), C.YELLOW)} queued for validation"
        )

    print(f"  {_c('Go to the Scans section on LeakHunterX to download the report.', C.CYAN)}")
    print(f"  {_c(f'Scan ID: {scan_id}', C.DIM)}")
    print()

def console_stopping() -> None:
    print("\nStopping agent...\n")
    print("  Agent disconnected.\n")
    print("Agent stopped.\n")

def console_error(message: str) -> None:
    print(f"\nError: {message}\n")

def console_revoked() -> None:
    print("\nAgent session revoked by dashboard.\n")
    print("Re-pair this agent with:")
    print("  lhx-agent pair\n")


logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Optional dependency
# ─────────────────────────────────────────────

try:
    import psutil
except ImportError:
    psutil = None


# Constants for consistent intervals
HEARTBEAT_INTERVAL = 5
SCAN_POLL_INTERVAL = 10
ACTION_POLL_INTERVAL = 3

#  ADD: Global shutdown lock (ISSUE #1)
AGENT_SHUTTING_DOWN = False
#  ADD: HTTP client for signal handler (ISSUE #3)
_HTTP_CLIENT_FOR_SIGNAL: Optional[httpx.AsyncClient] = None

# ─────────────────────────────────────────────
#  COOPERATIVE SHUTDOWN SIGNAL
#
# Every polling loop used to park in a bare `asyncio.sleep(interval)`.
# A bare sleep is not interruptible: setting `should_exit` from the
# signal handler did nothing until the sleep expired on its own, so
# Ctrl+C stalled for up to SCAN_POLL_INTERVAL (10s) in the main loop
# and HEARTBEAT_INTERVAL (5s) in the heartbeat loop before shutdown
# even STARTED. That was the entire perceived "lag".
#
# All loops now wait on this event with a timeout instead, so they wake
# the instant shutdown is signalled and fall through immediately.
# ─────────────────────────────────────────────
_SHUTDOWN_EVENT: Optional[asyncio.Event] = None

# Guarantees the disconnect heartbeat is delivered exactly once, no
# matter which of the several shutdown paths gets there first.
_DISCONNECT_SENT = False


def init_shutdown_event() -> asyncio.Event:
    """Create (once) the shutdown event, bound to the running loop."""
    global _SHUTDOWN_EVENT
    if _SHUTDOWN_EVENT is None:
        _SHUTDOWN_EVENT = asyncio.Event()
    return _SHUTDOWN_EVENT


def signal_shutdown() -> None:
    """
    Wake every waiting loop.

    Uses call_soon_threadsafe rather than Event.set() directly: this is
    invoked from an OS signal handler, and while that runs on the main
    thread, the event loop itself may be parked in select()/IOCP.
    call_soon_threadsafe writes to the loop's self-pipe, which is what
    actually wakes the selector - a bare set() would schedule the
    waiters' callbacks but leave the loop asleep until its next timer.
    """
    ev = _SHUTDOWN_EVENT
    if ev is None or ev.is_set():
        return
    try:
        asyncio.get_running_loop().call_soon_threadsafe(ev.set)
    except RuntimeError:
        # No running loop (or already closed) - best effort.
        try:
            ev.set()
        except Exception:
            pass


def is_shutting_down() -> bool:
    """True once shutdown has been signalled by any path."""
    if AGENT_SHUTTING_DOWN:
        return True
    return _SHUTDOWN_EVENT is not None and _SHUTDOWN_EVENT.is_set()


async def interruptible_sleep(seconds: float) -> bool:
    """
    Sleep up to `seconds`, returning early the moment shutdown is
    signalled.

    Returns True if we woke because of shutdown, False on normal expiry.
    """
    ev = _SHUTDOWN_EVENT
    if ev is None:
        await asyncio.sleep(seconds)
        return False

    if ev.is_set():
        return True

    try:
        await asyncio.wait_for(ev.wait(), timeout=seconds)
        return True
    except asyncio.TimeoutError:
        return False

# ─────────────────────────────────────────────
#  SCAN RESULTS NORMALIZATION HELPER
# ─────────────────────────────────────────────

def normalize_scan_findings(findings: Any) -> dict:
    """
    Normalize scan findings to backend contract.

    Backend expects:
    {
        "findings": { ... }
    }

    NEVER send lists.
    """
    if findings is None:
        return {
            "findings": {
                "leaks_found": 0,
                "files": [],
                "severity": "info",
            }
        }

    if isinstance(findings, list):
        return {
            "findings": {
                "leaks_found": len(findings),
                "files": [],
                "severity": "info",
            }
        }

    if isinstance(findings, dict):
        # If findings already has a "findings" key, return as-is
        if "findings" in findings and isinstance(findings["findings"], dict):
            return findings

        # Otherwise wrap the entire dict as findings
        return {
            "findings": findings
        }

    raise ValueError(f"Invalid findings payload type: {type(findings)}")


async def send_scan_failed(scan_id: str, reason: str = "agent_interrupted"):
    """
    Guaranteed delivery of scan_failed event.
    Uses its own short-lived HTTP client.
    """
    try:
        agent_id, agent_secret = load_agent_credentials()

        async with httpx.AsyncClient(
            base_url=AgentConfig.from_env().backend_url,
            headers={
                "X-Agent-Id": agent_id,
                "X-Agent-Secret": agent_secret,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=5,
        ) as client:
            await client.post(
                "/api/v1/agent/events",
                json={
                    "events": [
                        {
                            "event": {
                                "event_type": "scan_failed",
                                "scan_id": scan_id,
                                "timestamp": int(time.time()),
                                "data": {
                                    "reason": reason
                                },
                            }
                        }
                    ]
                },
            )

        logger.info(f"scan_failed delivered for scan {scan_id}")

    except Exception as e:
        logger.error(f"FAILED to deliver scan_failed event: {e}")


def send_scan_failed_sync(scan_id: str, reason: str = "agent_interrupted") -> None:
    """
    Signal-safe, blocking scan_failed sender.
    MUST NOT touch asyncio.
    """
    try:
        agent_id, agent_secret = load_agent_credentials()
        config = AgentConfig.from_env()

        with httpx.Client(
            base_url=config.backend_url,
            headers={
                "X-Agent-Id": agent_id,
                "X-Agent-Secret": agent_secret,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=3.0,
        ) as client:
            client.post(
                "/api/v1/agent/events",
                json={
                    "events": [
                        {
                            "event": {
                                "event_type": "scan_failed",
                                "scan_id": scan_id,
                                "timestamp": int(time.time()),
                                "data": {"reason": reason},
                            }
                        }
                    ]
                },
            )

        logger.info(f"[SYNC] scan_failed delivered for scan {scan_id}")

    except Exception as e:
        logger.error(f"[SYNC] FAILED to deliver scan_failed: {e}")


class NormalizingHttpClient(httpx.AsyncClient):
    """
    HTTP client that normalizes scan results payload before sending.
    """

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """
        Intercept POST requests to scan results endpoint and normalize payload.
        """
        # Check if this is a scan results submission
        if "/agent/scans/" in url and "/results" in url and "json" in kwargs:
            json_data = kwargs["json"]

            #  FIXED: Only normalize when "findings" key exists in the payload
            if isinstance(json_data, dict) and "findings" in json_data:
                normalized = normalize_scan_findings(json_data["findings"])
                kwargs["json"] = normalized
                logger.debug(f"Normalized scan results payload for {url}")

        return await super().post(url, **kwargs)


# ─────────────────────────────────────────────
#  AGENT HEARTBEAT HELPERS
# ─────────────────────────────────────────────

AGENT_START_TIME = time.time()

def collect_os_metrics() -> dict:
    """
    Collect lightweight OS + process metrics.
    Safe to call frequently.
    """
    try:
        if psutil is None:
            logger.debug("psutil not installed, skipping OS metrics")
            return {}

        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()

        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": mem.percent,
            "disk_percent": disk.percent,
            "network_kbps": int(
                (net.bytes_sent + net.bytes_recv) / 1024
            ),
            "uptime_seconds": int(time.time() - AGENT_START_TIME),
        }
    except Exception as e:
        logger.debug(f"Metrics collection failed: {e}")
        return {}


async def heartbeat_loop(
    client: httpx.AsyncClient,
    signal_handler,
    state_provider: Callable[[], str],  # returns agent_state string
    interval: int = HEARTBEAT_INTERVAL,
):
    """
    Periodically send heartbeat to backend.
    Runs until shutdown signal is received.
    """
    logger.info(f"Heartbeat loop started (interval: {interval}s)")
    #  FIX: Add AGENT_SHUTTING_DOWN check (ISSUE #2)
    while not signal_handler.should_exit and not is_shutting_down():
        try:
            metrics = collect_os_metrics()

            payload = {
                "state": state_provider(),
                "cpu_percent": metrics.get("cpu_percent"),
                "memory_percent": metrics.get("memory_percent"),
                "disk_percent": metrics.get("disk_percent"),
                "network_kbps": metrics.get("network_kbps"),
                "uptime_seconds": metrics.get("uptime_seconds"),
                "version": get_version(),
                "mode": "backend",
            }

            logger.debug(f"Sending heartbeat: {payload['state']}")
            resp = await client.post("/api/v1/agent/heartbeat", json=payload)
            resp.raise_for_status()
            logger.debug("Heartbeat sent successfully")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                console_revoked()
                signal_handler.should_exit = True
                signal_shutdown()   # wake every polling loop immediately
                signal_handler.agent_revoked = True
            elif e.response.status_code >= 400:
                logger.warning(f"Heartbeat rejected: {e.response.status_code}")
        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")

        # Interruptible: wakes immediately on shutdown instead of
        # holding the loop for the full interval.
        if await interruptible_sleep(interval):
            break

    logger.info("Heartbeat loop stopped")


def _disconnect_payload() -> dict:
    return {
        "state": "disconnected",
        "cpu_percent": 0,
        "memory_percent": 0,
        "disk_percent": 0,
        "network_kbps": 0,
        "uptime_seconds": int(time.time() - AGENT_START_TIME),
        "version": get_version(),
        "mode": "backend",
    }


async def send_disconnect(client: httpx.AsyncClient, attempts: int = 2) -> bool:
    """
    Tell the backend this agent is going away.

    Idempotent across every shutdown path (normal exit, second Ctrl+C,
    watchdog force-exit) via the _DISCONNECT_SENT latch, so the backend
    never sees a duplicate and we never skip it because "someone else
    probably sent it".

    Retries once on transport failure with a short per-attempt timeout.
    A disconnect that arrives late is useless - the process is about to
    die - so the budget stays small and bounded rather than inheriting
    the client's much longer default timeout.
    """
    global _DISCONNECT_SENT

    if _DISCONNECT_SENT:
        return True
    if not client or client.is_closed:
        return False

    for attempt in range(1, attempts + 1):
        try:
            resp = await client.post(
                "/api/v1/agent/heartbeat",
                json=_disconnect_payload(),
                timeout=2.0,
            )
            if resp.status_code < 400:
                _DISCONNECT_SENT = True
                logger.info("Disconnect signal sent to backend")
                return True
            logger.debug(
                f"Disconnect rejected ({resp.status_code}) on attempt {attempt}"
            )
        except Exception as e:
            logger.debug(f"Disconnect attempt {attempt}/{attempts} failed: {e}")

        if attempt < attempts:
            await asyncio.sleep(0.2)

    return False


def send_disconnect_sync(timeout: float = 2.0) -> bool:
    """
    Blocking, asyncio-free disconnect.

    Last-resort path used when the event loop is being abandoned - a
    second Ctrl+C or the watchdog force-exit. Previously both of those
    called os._exit() directly, so the backend was never told and the
    agent sat there showing "connected" until its heartbeat timed out
    server-side. This is the same latch as the async version, so it is a
    no-op if the graceful path already delivered it.
    """
    global _DISCONNECT_SENT

    if _DISCONNECT_SENT:
        return True

    try:
        agent_id, agent_secret = load_agent_credentials()
        config = AgentConfig.from_env()

        with httpx.Client(
            base_url=config.backend_url,
            headers={
                "X-Agent-Id": agent_id,
                "X-Agent-Secret": agent_secret,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=timeout,
        ) as client:
            resp = client.post("/api/v1/agent/heartbeat", json=_disconnect_payload())

        if resp.status_code < 400:
            _DISCONNECT_SENT = True
            logger.info("[SYNC] Disconnect signal sent to backend")
            return True

        logger.debug(f"[SYNC] Disconnect rejected ({resp.status_code})")
        return False

    except Exception as e:
        logger.debug(f"[SYNC] Failed to send disconnect: {e}")
        return False


def get_agent_state(orchestrator: Optional[ScanOrchestrator]) -> str:
    #  FIX: Add hard shutdown lock (ISSUE #1)
    if AGENT_SHUTTING_DOWN:
        return "disconnected"

    if not orchestrator:
        return "connected"

    if orchestrator.status == ScanStatus.RUNNING:
        return "scanning"

    if orchestrator.status in (
        ScanStatus.ERROR,
        ScanStatus.COMPLETED,
    ):
        return "connected"

    return "connected"


# ─────────────────────────────────────────────
#  AGENT ACTION POLLING
# ─────────────────────────────────────────────

async def action_polling_loop(
    client: httpx.AsyncClient,
    signal_handler,
    orchestrator_ref: Callable[[], Optional[ScanOrchestrator]],
    interval: int = ACTION_POLL_INTERVAL,
):
    """
    Poll backend for agent actions and execute them.
    """
    logger.info(f"Action polling loop started (interval: {interval}s)")

    #  FIX: Stop polling immediately during shutdown
    while not signal_handler.should_exit and not is_shutting_down():
        try:
            resp = await client.get("/api/v1/agent/action")
            resp.raise_for_status()
            data = resp.json()

            action = data.get("action")
            if not action:
                if await interruptible_sleep(interval):
                    break
                continue

            logger.info(f"Received agent action: {action}")

            orchestrator = orchestrator_ref()

            if action == "restart":
                logger.info("Restart requested by backend → initiating graceful shutdown")
                signal_handler.restart_requested = True
                signal_handler.should_exit = True
                signal_shutdown()   # wake every polling loop immediately

                if orchestrator:
                    try:
                        await orchestrator.stop_scan()
                    except Exception as e:
                        logger.debug(f"Failed to stop scan on restart: {e}")

            elif action == "disconnect":
                logger.info("Disconnect requested → stopping agent")
                signal_handler.should_exit = True
                signal_shutdown()   # wake every polling loop immediately

                if orchestrator:
                    try:
                        await orchestrator.stop_scan()
                    except Exception as e:
                        logger.debug(f"Failed to stop scan on disconnect: {e}")

            elif action == "start_scan":
                logger.info("Start scan requested (noop – backend assigns scans)")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                console_revoked()
                signal_handler.should_exit = True
                signal_shutdown()   # wake every polling loop immediately
                signal_handler.agent_revoked = True

            elif e.response.status_code == 404:
                # Backend might not have this endpoint yet
                logger.debug("Action endpoint not found (404)")
                if await interruptible_sleep(interval * 2):
                    break

            else:
                logger.debug(f"Action polling failed: {e}")
                if await interruptible_sleep(interval):
                    break

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"Action polling failed: {e}")
            if await interruptible_sleep(interval):
                break

    logger.info("Action polling loop stopped")


def load_agent_credentials() -> Tuple[str, str]:
    """
    Load agent ID and secret from the secret file.
    Returns: (agent_id, agent_secret)

    Raises:
        RuntimeError: If credentials cannot be loaded
    """
    secret_path = get_agent_secret_path()

    if not os.path.exists(secret_path):
        raise RuntimeError(
            f"Agent secret file not found at: {secret_path}\n"
            "Please run 'python3 pair_agent.py' first to pair the agent."
        )

    try:
        with open(secret_path, 'r') as f:
            data = json.load(f)

        agent_id = data.get("agent_id")
        agent_secret = data.get("agent_secret")

        if not agent_id or not agent_secret:
            raise RuntimeError(
                f"Invalid agent secret file format in {secret_path}.\n"
                "Please run 'python3 pair_agent.py' to re-pair the agent."
            )

        logger.info(f"Loaded agent credentials from: {secret_path}")
        return agent_id, agent_secret

    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Failed to parse agent secret file {secret_path}: {e}\n"
            "Please run 'python3 pair_agent.py' to re-pair the agent."
        )
    except Exception as e:
        raise RuntimeError(f"Failed to load agent credentials: {e}")


def ensure_agent_is_registered(config: AgentConfig) -> None:  #  FIX: Accept config parameter
    """
    Ensures agent is paired and authorized.
    Runs pair_agent.py automatically if needed.
    """
    #  FIX: Guard against async context
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("Pairing must run before async runtime starts")
    except RuntimeError:
        pass  # No running loop, this is good

    try:
        agent_id, agent_secret = load_agent_credentials()

        #  FIX: Use passed config instead of calling AgentConfig.from_env() again
        resp = httpx.get(
            f"{config.backend_url}/api/v1/agent/status",
            headers={
                "X-Agent-Id": agent_id,
                "X-Agent-Secret": agent_secret,
                "Accept": "application/json",
            },
            timeout=10,
        )

        if resp.status_code == 200:
            logger.info(" Agent registration verified with backend")
            return

        logger.warning(" Agent credentials invalid or revoked")

    except Exception as e:
        logger.warning(f"Agent verification failed: {e}")

    #  FIX: Use direct function call instead of subprocess
    # If we reach here → pairing required
    logger.warning(" Agent is not paired or has been revoked")
    logger.warning("Launching agent pairing flow...")

    try:
        pair_agent(pairing_token=None)
    except Exception as e:
        logger.error(f" Agent pairing failed: {e}")
        sys.exit(75)


async def authenticate_agent(
    config: AgentConfig,
) -> tuple[str, str, Dict[str, str]]:
    """
    Load agent credentials from secret file.
    Authentication is performed by heartbeat, not status check.

    Returns: (agent_id, agent_secret, headers)

    Raises:
        RuntimeError: If credentials cannot be loaded
    """
    agent_id, agent_secret = load_agent_credentials()

    logger.info(f"Loaded credentials for agent_id: {agent_id}")

    headers = {
        "X-Agent-Id": agent_id,
        "X-Agent-Secret": agent_secret,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    return agent_id, agent_secret, headers


async def poll_for_scan(
    client: httpx.AsyncClient,
    signal_handler,
    # NOTE: The 'interval' parameter is intentionally unused.
    # Caller controls the polling frequency by sleeping between calls.
    # This parameter is kept for API backward compatibility.
) -> Optional[Dict[str, Any]]:
    """
    Poll backend for assigned scans.
    Returns scan data if available, None otherwise.

    Note: The caller must control polling frequency by sleeping between calls.
    This function does not implement any delay.
    """
    try:
        logger.debug("Polling for assigned scans...")
        resp = await client.get("/api/v1/agent/scans")
        resp.raise_for_status()

        scan = resp.json()

        if not scan:
            logger.debug("No scan assigned")
            return None

        if not isinstance(scan, dict):
            logger.error(f"Invalid scan payload type: {type(scan)}")
            return None

        if "scan_id" not in scan or "target" not in scan:
            logger.error(f"Invalid scan payload received: {scan}")
            return None

        logger.info(f"Received scan assignment: {scan['scan_id']} → {scan['target']}")
        return scan

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            console_revoked()
            signal_handler.should_exit = True
            signal_shutdown()   # wake every polling loop immediately
            signal_handler.agent_revoked = True
            return None
        elif e.response.status_code == 404:
            logger.debug("Scan endpoint not found (404)")
        else:
            logger.error(f"Error polling for scans: {e.response.status_code}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error polling for scans: {e}")
        return None


class PhaseConsoleInterceptor:
    """
    Wraps the emitter to intercept phase events
    and print clean phase output to terminal.
    Does not affect event delivery to backend.
    
    Intercepts two event types:
    - phase_started  (from _phase_tracker: discovery, crawling, analysis)
    - scan_progress  (from _safe_emit_phase: finalizing, completed)
    """
    
    PHASE_MESSAGES = {
        "discovery":   "Discovering subdomains...",
        "crawling":    "Crawling target...",
        "analysis":    "Analyzing JavaScript files...",
        "finalizing":  "Finalizing scan...",
        "completed":   "Scan finished.",
    }

    # Track which phases have been printed to avoid duplicates
    # because scan_progress fires multiple times per phase
    def __init__(self, wrapped_emitter, backend_url: str = ""):
        self._emitter = wrapped_emitter
        self._printed_phases = set()
        self._backend_url = backend_url
        self._progress_bar_active = False
    
    async def emit(self, event):
        # Pass to real emitter first — never block delivery
        await self._emitter.emit(event)
        
        # Extract event type and phase
        event_type = None
        phase = None
        
        if isinstance(event, dict):
            event_type = event.get("event_type")
            data = event.get("data") or {}
            phase = data.get("phase")
        
        # Intercept phase_started (discovery, crawling, analysis)
        if event_type == "phase_started" and phase:
            self._end_progress_bar_if_active()
            if phase not in self._printed_phases:
                message = self.PHASE_MESSAGES.get(phase, f"{phase}...")
                console_phase(phase, message)
                self._printed_phases.add(phase)
            return

        # Intercept scan_progress for finalizing and completed
        # _safe_emit_phase uses scan_progress not phase_started
        if event_type == "scan_progress" and phase:
            if phase in ("finalizing", "completed"):
                self._end_progress_bar_if_active()
                if phase not in self._printed_phases:
                    message = self.PHASE_MESSAGES.get(phase, f"{phase}...")
                    console_phase(phase, message)
                    self._printed_phases.add(phase)
                return

            # Live progress bar during analysis — real, agent-verified
            # counts (processed/total JS files), no validation claims.
            if phase == "analysis":
                data = event.get("data") or {}
                current = data.get("current")
                total = data.get("total")
                if isinstance(current, int) and isinstance(total, int) and total > 0:
                    console_progress_bar(current, total)
                    self._progress_bar_active = True
            return
        
        # Intercept scan_completed for the final done summary
        if event_type == "scan_completed":
            data = event.get("data") or {}
            metrics = data.get("metrics") or {}
            # completed phase may not have been caught above
            # so ensure it prints
            if "completed" not in self._printed_phases:
                self._end_progress_bar_if_active()
                console_phase("completed", "Scan finished.")
                self._printed_phases.add("completed")

            self._end_progress_bar_if_active()

            # Print honest, non-fabricated completion summary using
            # the agent's own real candidate counts — never asserted
            # as confirmed/validated findings (see console_scan_done).
            scan_id = data.get("scan_id") or event.get("scan_id")
            backend_url = self._backend_url
            if scan_id and backend_url:
                console_scan_done(
                    scan_id=scan_id,
                    potential_secrets=int(metrics.get("potential_secrets", 0)),
                    potential_endpoints=int(metrics.get("discovered_endpoints", 0)),
                    backend_url=backend_url,
                )

    def _end_progress_bar_if_active(self) -> None:
        """
        Ensure any in-progress live progress bar line is terminated
        with a newline before printing anything else, so subsequent
        output never gets appended to the same line.
        """
        if self._progress_bar_active:
            print()
            self._progress_bar_active = False
    
    # Proxy all other attributes to real emitter
    def __getattr__(self, name):
        return getattr(self._emitter, name)


async def run_backend_agent_loop(
    config: Dict[str, Any],
    client: httpx.AsyncClient,
    operator_id: str,
    signal_handler: SignalHandler
) -> None:
    """
    Run the main backend agent loop after authentication.
    Terminal scan state (scan_failed) is handled by SignalHandler.
    This loop must exit fast on shutdown.
    """

    orchestrator: Optional[ScanOrchestrator] = None
    scan_task: Optional[asyncio.Task] = None

    # ─────────────────────────────────────────────
    # Background tasks (heartbeat + actions)
    # ─────────────────────────────────────────────
    heartbeat_task = asyncio.create_task(
        heartbeat_loop(
            client=client,
            signal_handler=signal_handler,
            state_provider=lambda: get_agent_state(orchestrator),
            interval=HEARTBEAT_INTERVAL,
        )
    )

    action_task = asyncio.create_task(
        action_polling_loop(
            client=client,
            signal_handler=signal_handler,
            orchestrator_ref=lambda: orchestrator,
            interval=ACTION_POLL_INTERVAL,
        )
    )

    try:
        logger.info("Agent ready — waiting for scan assignments")
        logger.info(
            f"Heartbeat: {HEARTBEAT_INTERVAL}s | Scan poll: {SCAN_POLL_INTERVAL}s"
        )

        while not signal_handler.should_exit and not is_shutting_down():
            try:
                scan = await poll_for_scan(client, signal_handler)

                # Re-check after the network round trip: shutdown may
                # have been signalled while the poll was in flight, and
                # starting a scan at that point would just have to be
                # torn down again.
                if signal_handler.should_exit or is_shutting_down():
                    break

                if not scan:
                    if await interruptible_sleep(SCAN_POLL_INTERVAL):
                        break
                    continue

                scan_id = scan["scan_id"]
                target = scan["target"]

                console_scan_received(scan_id, target)

                # ─────────────────────────────────────────────
                # Create HTTP emitter
                # ─────────────────────────────────────────────
                emitter = create_emitter("http", config=config)
                if not emitter:
                    logger.error("Emitter creation failed — skipping scan")
                    if await interruptible_sleep(SCAN_POLL_INTERVAL):
                        break
                    continue

                # Wrap emitter for phase console output
                emitter = PhaseConsoleInterceptor(emitter, backend_url=config.get("backend_url", ""))

                await emitter.start()

                orchestrator = ScanOrchestrator(
                    target_url=target,
                    config=config,
                    emitter=emitter,
                    operator_id=operator_id,
                    scan_id=scan_id,
                )

                signal_handler.set_orchestrator(orchestrator)

                try:
                    scan_task = asyncio.create_task(orchestrator.start_scan())
                    signal_handler.set_scan_task(scan_task)
                    await scan_task

                    logger.info(f"Scan completed successfully → {scan_id}")

                except asyncio.CancelledError:
                    # Cancellation is expected during shutdown
                    logger.info(f"Scan cancelled → {scan_id}")
                    raise

                except Exception as e:
                    logger.error(
                        f"Scan execution error → {scan_id}: {e}",
                        exc_info=True,
                    )
                    #  DO NOT send scan_failed here
                    # SignalHandler is the single source of truth

                finally:
                    # Stop producing events immediately
                    if scan_task and not scan_task.done():
                        scan_task.cancel()
                        # Bounded: a task that swallows CancelledError in
                        # its own cleanup would otherwise hang shutdown
                        # here indefinitely.
                        try:
                            await asyncio.wait_for(scan_task, timeout=3.0)
                        except (asyncio.CancelledError, asyncio.TimeoutError):
                            pass

                    scan_task = None
                    orchestrator = None
                    signal_handler.set_scan_task(None)
                    signal_handler.set_orchestrator(None)

                    # Best-effort emitter close (non-blocking)
                    try:
                        await asyncio.wait_for(emitter.close(), timeout=2.0)
                    except Exception:
                        pass

                if await interruptible_sleep(SCAN_POLL_INTERVAL):
                    break

            except asyncio.CancelledError:
                logger.info("Backend agent loop cancelled")
                break

            except Exception:
                logger.error(
                    "Unhandled error in backend agent loop",
                    exc_info=True,
                )
                if await interruptible_sleep(SCAN_POLL_INTERVAL):
                    break

    finally:
        logger.info("Shutting down backend agent loop")

        # ─────────────────────────────────────────────
        # ORDERING MATTERS.
        #
        # The disconnect used to be the LAST step, after up to ~6s of
        # task teardown - but the watchdog force-exits at
        # (shutdown_timeout + 5) = 7s by default. So on any shutdown
        # where teardown wasn't instant, os._exit() fired before the
        # disconnect was ever attempted, and the backend kept showing
        # the agent as connected until its own heartbeat timeout.
        #
        # Now: cancel the background loops first (instant, non-blocking,
        # and stops any further heartbeat from racing us back to
        # "connected"), then send the disconnect while we still have a
        # live client and plenty of watchdog budget, and only then do
        # the slow awaits.
        # ─────────────────────────────────────────────
        for task in (heartbeat_task, action_task):
            if task and not task.done():
                task.cancel()

        # Disconnect FIRST - highest-value, lowest-cost signal.
        try:
            await asyncio.wait_for(send_disconnect(client), timeout=3.0)
        except Exception as e:
            logger.debug(f"Async disconnect failed: {e}")

        # Cancel + await scan task with a HARD bound — never await
        # indefinitely, even though we just cancelled it.
        if scan_task and not scan_task.done():
            scan_task.cancel()
            try:
                await asyncio.wait_for(scan_task, timeout=3.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    *(t for t in (heartbeat_task, action_task) if t),
                    return_exceptions=True,
                ),
                timeout=2.0,
            )
        except asyncio.TimeoutError:
            logger.warning("Heartbeat/action task shutdown timed out")

        # If the async path could not deliver it (client already torn
        # down, loop dying, transport error), fall back to a blocking
        # send so the backend is still told.
        if not _DISCONNECT_SENT:
            send_disconnect_sync(timeout=2.0)

        logger.info("Backend agent shutdown complete")

        # ─────────────────────────────────────────────
        #  Mark shutdown complete LAST — only once everything
        #  above has actually finished — so the watchdog stays
        #  armed for the ENTIRE cleanup sequence, not just the
        #  part after this line.
        # ─────────────────────────────────────────────
        signal_handler.mark_shutdown_complete()




class AgentCLI:
    """Command-line interface handler."""

    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="LeakHunterX Security Scanning Agent",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  lhx-agent pair lhx_xxxxxxxxxxxx    Pair with dashboard token
  lhx-agent run                      Start agent (normal usage)
  lhx-agent run --log-level DEBUG    Start with verbose logging
  lhx-agent --version                Show version

Documentation:
  https://leakhunterx.com/docs
    """
        )

        # ─────────────────────────────────────────────
        #  GLOBAL OPTIONS (ALWAYS PRESENT)
        # ─────────────────────────────────────────────
        parser.add_argument(
            "--version",
            action="version",
            version=f"LeakHunterX Agent v{get_version()}"
        )

        parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="INFO",
            help="Logging level (default: INFO)"
        )

        parser.add_argument(
            "--log-file",
            help="Optional log file path"
        )

        parser.add_argument(
            "--operator-id",
            default="user",
            help="Operator identifier for audit logs (default: user)"
        )

        parser.add_argument(
            "--mode",
            choices=["stdout", "http"],
            default="stdout",
            help="Emission mode (default: stdout)"
        )

        parser.add_argument(
            "--shutdown-timeout",
            type=int,
            default=2,
            help="Graceful shutdown timeout in seconds (default: 2)"
        )

        #  IMPORTANT: define these globally so they ALWAYS exist
        parser.add_argument(
            "--resume-scan",
            default=None,
            help=argparse.SUPPRESS
        )

        parser.add_argument(
            "--cli",
            action="store_true",
            help=argparse.SUPPRESS
        )

        parser.add_argument(
            "target_url",
            nargs="?",
            default=None,
            help=argparse.SUPPRESS
        )

        # ─────────────────────────────────────────────
        # SUBCOMMANDS
        # ─────────────────────────────────────────────
        subparsers = parser.add_subparsers(dest="command")

        # ---- pair command ----
        pair_parser = subparsers.add_parser(
            "pair",
            help="Pair agent with backend using a pairing token"
        )
        pair_parser.add_argument(
            "token",
            nargs="?",
            help="Pairing token from dashboard"
        )

        # ---- run command ----
        run_parser = subparsers.add_parser(
            "run",
            help="Run agent normally"
        )
        run_parser.add_argument(
            "target_url",
            nargs="?",
            help="Target URL to scan (optional if resuming)"
        )
        run_parser.add_argument(
            "--resume-scan",
            help="Resume a previous scan by scan_id"
        )
        run_parser.add_argument(
            "--cli", "-c",
            action="store_true",
            help="Run agent in CLI mode (interactive scanning)"
        )
        run_parser.add_argument(
            "--version",
            action="version",
            version=f"LeakHunterX Agent v{get_version()}"
        )

        # Backward compatibility
        parser.set_defaults(command="run")

        return parser.parse_args()

    @staticmethod
    def normalize_operator_id(operator_id: str) -> str:
        if not operator_id or not isinstance(operator_id, str):
            return "anonymous"
        return operator_id.strip()[:256]

    @staticmethod
    def setup_logging(level: str, log_file: Optional[str] = None) -> None:
        log_level = getattr(logging, level.upper(), logging.INFO)

        # If DEBUG — show logs to terminal
        # If INFO or above — suppress terminal logs entirely
        # Logs still go to file if log_file is set
        
        handlers = []

        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
            )
            handlers.append(file_handler)

        if level.upper() == "DEBUG":
            # Debug mode: show structured logs to terminal
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                    datefmt="%H:%M:%S"
                )
            )
            handlers.append(stream_handler)
        else:
            # Production mode: suppress all terminal log output
            # User sees only structured console_* output
            handlers.append(logging.NullHandler())

        logging.basicConfig(level=log_level, handlers=handlers, force=True)

        # Silence noisy third-party loggers always
        for noisy in ["urllib3", "asyncio", "httpx", "aiohttp", "hpack"]:
            logging.getLogger(noisy).setLevel(logging.ERROR)



class SignalHandler:
    """Handle OS signals for graceful shutdown with escalation."""

    def __init__(self, shutdown_timeout: int = 2):
        self.should_exit = False
        self.shutdown_timeout = shutdown_timeout
        self._original_handlers = {}
        self._orchestrator = None
        self._scan_task = None
        self._shutdown_started_at: Optional[float] = None
        self._signal_count = 0

        self.restart_requested = False
        self.agent_revoked = False

    def setup(self) -> None:
        signals = [signal.SIGINT]
        if hasattr(signal, 'SIGTERM'):
            signals.append(signal.SIGTERM)

        for sig in signals:
            self._original_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, self._handle_signal)

    def restore(self) -> None:
        for sig, handler in self._original_handlers.items():
            if handler:
                signal.signal(sig, handler)

    def set_orchestrator(self, orchestrator: ScanOrchestrator) -> None:
        """Set the current orchestrator for graceful shutdown handling."""
        self._orchestrator = orchestrator

    def set_scan_task(self, scan_task: asyncio.Task) -> None:
        """Set the current scan task for cancellation."""
        self._scan_task = scan_task

    def mark_shutdown_complete(self) -> None:
        """
        Mark shutdown as fully completed, disarming the watchdog.

        NOTE: AGENT_SHUTTING_DOWN is deliberately NOT reset here. It used
        to be flipped back to False, which un-latched the global shutdown
        state at the exact moment teardown finished - so anything still
        running (a straggler heartbeat, get_agent_state) would report the
        agent as live again on its way out. Shutdown is terminal; the
        flag stays set. Clearing _shutdown_started_at is what disarms the
        watchdog, which is the actual purpose of this method.
        """
        self._shutdown_started_at = None

    async def graceful_shutdown(self) -> None:
        """Immediate shutdown - cancel scan task and stop orchestrator."""
        if self._shutdown_started_at:
            return
            
        self._shutdown_started_at = time.time()
        
        # Cancel the scan task immediately
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            try:
                await asyncio.wait_for(self._scan_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        # Stop the orchestrator
        if self._orchestrator:
            try:
                await asyncio.wait_for(self._orchestrator.stop_scan(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                pass

    def _handle_signal(self, signum, frame) -> None:
        signame = signal.Signals(signum).name
        self._signal_count += 1

        if self._signal_count == 1:
            logger.info(f"Received signal {signame}, initiating graceful shutdown...")
            self.should_exit = True

            global AGENT_SHUTTING_DOWN
            AGENT_SHUTTING_DOWN = True
            self._shutdown_started_at = time.time()

            #  WAKE EVERY POLLING LOOP NOW.
            # Without this, `should_exit` is only observed the next time
            # a loop finishes its sleep - up to 10s later. This is what
            # made Ctrl+C feel unresponsive.
            signal_shutdown()

            #  STOP PRODUCING EVENTS IMMEDIATELY (instant, non-blocking)
            if self._scan_task and not self._scan_task.done():
                self._scan_task.cancel()

            #  FIX: never do blocking network I/O inside a signal handler.
            # Schedule the scan_failed notification onto the event loop
            # instead — it will run as a normal async task with its own
            # bounded timeout, so a slow/unreachable backend can never
            # stall shutdown.
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon(self._schedule_scan_failed_notification)
            except RuntimeError:
                # No running loop somehow — fall back to the old
                # synchronous path as a last resort so the event is
                # still attempted.
                if self._orchestrator:
                    send_scan_failed_sync(
                        scan_id=self._orchestrator.scan_id,
                        reason="agent_interrupted",
                    )

            return

        # ─────────────────────────────────────────────
        #  SECOND SIGNAL: user is impatient — exit NOW
        # ─────────────────────────────────────────────
        logger.warning(f"Received second signal ({signame}) → forcing immediate exit")
        self._force_exit()

    def _force_exit(self):
        """
        Force process exit.

        Still tells the backend first. This path (second Ctrl+C, or the
        watchdog) previously went straight to os._exit(), so the most
        common "impatient user" shutdown never sent a disconnect at all.
        The sync send is latched and hard-bounded at 1.5s, so it cannot
        turn a force-exit into another hang.
        """
        try:
            send_disconnect_sync(timeout=1.5)
        except Exception:
            pass
        logger.error("Force exiting process")
        os._exit(130)

    def _schedule_scan_failed_notification(self) -> None:
        """
        Called via loop.call_soon from the signal handler (same thread,
        so this is safe). Creates the actual async task that sends
        scan_failed, bounded by its own timeout.
        """
        if self._orchestrator:
            asyncio.create_task(
                self._send_scan_failed_with_timeout(self._orchestrator.scan_id)
            )

    async def _send_scan_failed_with_timeout(self, scan_id: str) -> None:
        """Bounded, non-blocking scan_failed delivery."""
        try:
            await asyncio.wait_for(
                send_scan_failed(scan_id, reason="agent_interrupted"),
                timeout=3.0,
            )
        except Exception as e:
            logger.debug(f"scan_failed notification failed or timed out: {e}")




def _calculate_config_hash(config: AgentConfig) -> str:
    """Calculate stable hash for AgentConfig using JSON serialization."""
    config_dict = config.to_dict(redact_secrets=True)  #  Use redact_secrets=True for safety
    config_json = json.dumps(config_dict, sort_keys=True)
    return hashlib.sha256(config_json.encode()).hexdigest()[:16]


async def resume_scan(
    scan_id: str,
    config: AgentConfig,
    mode: str,
    operator_id: str,
    signal_handler: SignalHandler
) -> bool:
    """Resume a previous scan."""
    emitter = None
    try:
        state_manager = StateManager()

        # Load state
        if hasattr(state_manager, 'load_scan_state_async'):
            state = await state_manager.load_scan_state_async(scan_id)
        else:
            state = state_manager.load_scan_state(scan_id)

        if not state:
            logger.error(f"No scan state found for scan_id: {scan_id}")
            return False

        # Handle both ScanState objects and legacy dicts
        if hasattr(state, "to_dict"):
            state_dict = state.to_dict()
        else:
            state_dict = state

        if state_dict.get("status") in [ScanStatus.COMPLETED.value]:
            logger.error(f"Scan {scan_id} is already {state_dict['status']}, cannot resume")
            return False

        # Validate config compatibility
        stored_hash = state_dict.get("config_hash")
        if stored_hash:
            current_hash = _calculate_config_hash(config)
            if stored_hash != current_hash:
                logger.error(f"Config mismatch detected. Stored: {stored_hash}, Current: {current_hash}")
                logger.error("Refusing to resume scan with different configuration.")
                return False

        logger.info(f"Resuming scan {scan_id} from state: {state_dict['status']}")

        # Pass dict to create_emitter (redact secrets for logging safety)
        emitter = create_emitter(mode, config.to_dict(redact_secrets=True))
        if not emitter:
            raise RuntimeError(f"Failed to create emitter for mode: {mode}")

        # Create orchestrator with resume state
        orchestrator = ScanOrchestrator(
            target_url=state_dict["target_url"],
            config=config.to_dict(redact_secrets=True),
            emitter=emitter,
            state_manager=state_manager,
            operator_id=operator_id,
            scan_id=scan_id,
            resume_state=state_dict
        )

        signal_handler.set_orchestrator(orchestrator)

        # Run scan
        await orchestrator.start_scan()
        return True

    except Exception as e:
        logger.error(f"Failed to resume scan: {e}", exc_info=True)
        return False


async def run_scan(
    target_url: str,
    config: AgentConfig,
    mode: str,
    operator_id: str,
    signal_handler: SignalHandler
) -> None:
    """
    Main scan execution coroutine.
    """
    logger.info(f"Starting scan of {target_url}")
    logger.info(f"Emission mode: {mode}, Operator: {operator_id}")

    try:
        # Use redact_secrets=True for logging safety
        emitter = create_emitter(mode, config.to_dict(redact_secrets=True))
        if not emitter:
            raise RuntimeError(f"Failed to create emitter for mode: {mode}")

        # Initialize orchestrator
        await emitter.start()

        orchestrator = ScanOrchestrator(
            target_url=target_url,
            config=config.to_dict(redact_secrets=True),
            emitter=emitter,
            operator_id=operator_id
        )


        signal_handler.set_orchestrator(orchestrator)

        # Run scan
        await orchestrator.start_scan()

        logger.info("Scan completed successfully")

    except Exception as e:
        logger.error(f"Fatal error during scan: {e}", exc_info=True)
        raise



async def run_backend_agent(
    config: AgentConfig,
    mode: str,
    operator_id: str,
    signal_handler: SignalHandler
) -> None:
    """Run agent in backend mode with automatic scan assignment."""
    logger.info("Starting agent in BACKEND mode")
    logger.info(f"Backend URL: {config.backend_url}")

    try:
        # Authenticate the agent (load stored creds)
        agent_id, agent_secret, headers = await authenticate_agent(config)

        # Clean startup output
        console_agent_ready(agent_id, config.backend_url)
        console_waiting()

        # Create authenticated HTTP client for heartbeat / scans / actions
        async with NormalizingHttpClient(
            base_url=config.backend_url,
            headers=headers,
            timeout=10,
        ) as client:

            #  FIX: Register client for signal handler (ISSUE #3)
            global _HTTP_CLIENT_FOR_SIGNAL
            _HTTP_CLIENT_FOR_SIGNAL = client

            #  IMPORTANT FIX:
            # Inject agent_id + agent_secret into config for HTTP emitter
            emitter_config = {
                **config.to_dict(redact_secrets=True),  # Use redact_secrets=True for safety
                "agent_id": agent_id,              # used by HTTPBatchEmitter
                "agent_api_key": agent_secret,     # maps to X-Agent-Secret
                "backend_url": config.backend_url, # ensure endpoint correctness
            }

            logger.info("Emitter config prepared for backend event transport")

            # Start the main backend loop with FIXED emitter config
            await run_backend_agent_loop(
                config=emitter_config,  #  FIXED: Pass dict directly (orchestrator expects Dict[str, Any])
                client=client,
                operator_id=operator_id,
                signal_handler=signal_handler
            )

    except RuntimeError as e:
        if "revoked" in str(e).lower() or "invalid" in str(e).lower():
            logger.error(f"Agent authentication failed: {e}")
            logger.error("Please run 'python3 pair_agent.py' to re-pair the agent.")
            sys.exit(75)  # Special exit code for agent revocation
        else:
            logger.error(f"Backend agent failed: {e}", exc_info=True)
            sys.exit(1)

    except Exception as e:
        logger.error(f"Backend agent failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        #  FIX: Clear client reference (ISSUE #3)
        _HTTP_CLIENT_FOR_SIGNAL = None



async def async_main(config: AgentConfig, args: argparse.Namespace) -> None:  #  FIX: Accept config and args parameters
    """Async main entry point."""

    #  FIX: Arguments are now passed from main()
    # No need to parse args here again
    logger.info(f"LeakHunterX Agent v{get_version()} starting up...")

    # Normalize operator ID
    operator_id = AgentCLI.normalize_operator_id(args.operator_id)

    #  FIX: Configuration is now passed as parameter from main()
    logger.debug("Using configuration loaded in main()")

    # Setup signal handling with fast shutdown.
    # The shutdown event must be created on the running loop BEFORE any
    # polling loop starts waiting on it.
    init_shutdown_event()
    signal_handler = SignalHandler(shutdown_timeout=args.shutdown_timeout)
    signal_handler.setup()

    # Create shutdown watchdog
    async def shutdown_watchdog():
        """
        Watchdog that force-exits if shutdown takes too long.

        Bound is derived from --shutdown-timeout (default 2s) plus a
        buffer for the bounded cleanup steps (disconnect, emitter close,
        component cleanup) that legitimately need a moment.

        FIXED: the old ceiling was shutdown_timeout + 5 = 7s, but the
        cleanup path's own serial timeout budget (scan task 3s + task
        gather 3s + disconnect 1.5s, plus a 2s emitter close) exceeded
        that. The watchdog therefore force-exited *during* normal,
        healthy shutdown - killing the disconnect before it was sent.
        The ceiling now sits above the worst-case cleanup budget, so it
        only fires when something is genuinely wedged, which is what a
        watchdog is for. Shutdown is fast because the loops now wake
        immediately, not because the watchdog is trigger-happy.
        """
        max_wait = max(signal_handler.shutdown_timeout + 12, 12)

        while True:
            await asyncio.sleep(0.25)
            if signal_handler._shutdown_started_at:
                elapsed = time.time() - signal_handler._shutdown_started_at
                if elapsed > max_wait:
                    logger.error(
                        f"Shutdown watchdog: stuck for {elapsed:.1f}s "
                        f"(limit {max_wait:.0f}s) → forcing exit"
                    )
                    # _force_exit sends a latched sync disconnect first,
                    # so even a wedged shutdown still notifies the backend.
                    signal_handler._force_exit()

    watchdog_task = None

    # Decide execution mode (CLI vs BACKEND) BEFORE the try, so the
    # finally block below can rely on it even if startup fails early.
    agent_mode = os.getenv("LH_AGENT_MODE", "backend").lower()

    try:
        # Start shutdown watchdog
        watchdog_task = asyncio.create_task(shutdown_watchdog())

        if agent_mode == "backend":
            # Prevent resume in backend mode
            if args.resume_scan:
                logger.error("Resume is not allowed in backend mode")
                sys.exit(3)

            await run_backend_agent(
                config=config,
                mode=args.mode,
                operator_id=operator_id,
                signal_handler=signal_handler
            )
            return

        # CLI MODE (for direct scanning)
        # Note: For production, consider using DEBUG level for scan internals
        # and INFO level only for lifecycle events
        if args.resume_scan:
            success = await resume_scan(
                scan_id=args.resume_scan,
                config=config,
                mode=args.mode,
                operator_id=operator_id,
                signal_handler=signal_handler
            )
            if not success:
                state_manager = StateManager()
                if hasattr(state_manager, "load_scan_state_async"):
                    state = await state_manager.load_scan_state_async(args.resume_scan)
                else:
                    state = state_manager.load_scan_state(args.resume_scan)

                if not state:
                    sys.exit(5)

                # Handle both ScanState objects and legacy dicts
                if hasattr(state, "to_dict"):
                    state_dict = state.to_dict()
                else:
                    state_dict = state

                stored_hash = state_dict.get("config_hash")
                if stored_hash:
                    current_hash = _calculate_config_hash(config)
                    if stored_hash != current_hash:
                        sys.exit(4)

                sys.exit(3)

        elif args.target_url:
            is_valid, error_msg = AgentCLI.validate_url(args.target_url)
            if not is_valid:
                logger.error(f"Invalid target URL: {error_msg}")
                sys.exit(3)

            await run_scan(
                target_url=args.target_url,
                config=config,
                mode=args.mode,
                operator_id=operator_id,
                signal_handler=signal_handler
            )

        else:
            logger.error("Either target_url or --resume-scan must be provided")
            sys.exit(3)

    except KeyboardInterrupt:
        console_stopping()
        if signal_handler:
            signal_shutdown()
            try:
                await signal_handler.graceful_shutdown()
            except Exception:
                pass
        sys.exit(130)

    except asyncio.CancelledError:
        logger.info("Scan was cancelled")
        signal_shutdown()
        sys.exit(130)

    finally:
        # Cancel watchdog task
        if watchdog_task and not watchdog_task.done():
            watchdog_task.cancel()
            try:
                await watchdog_task
            except asyncio.CancelledError:
                pass

        # FINAL SAFETY NET: guarantee the backend learns we are gone.
        # run_backend_agent's own finally normally handles this, but it
        # is skipped entirely if we never got that far (auth failure,
        # KeyboardInterrupt during startup, an exception on the way in).
        # Latched, so this is a no-op when it already went out.
        if agent_mode == "backend" and not _DISCONNECT_SENT:
            send_disconnect_sync(timeout=2.0)

        signal_handler.restore()

        if signal_handler.restart_requested:
            logger.info("Exiting for supervisor restart (exit code 75)")
            sys.exit(75)

        logger.info("Agent shutdown complete")


def main() -> None:
    """Synchronous main entry point for setup."""
    # Windows compatibility for asyncio
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    #  FIX: Parse CLI arguments once at the beginning
    cli = AgentCLI()
    args = cli.parse_args()

    #  FIX: Setup logging once, not twice
    cli.setup_logging(args.log_level, args.log_file)

    #  Explicit pairing mode
    if args.command == "pair":
        logger.info(f"LeakHunterX Agent v{get_version()}")
        token = args.token
        if token:
            logger.info(f"Using provided pairing token")
        else:
            logger.info("No token provided - will prompt for token")
        pair_agent(pairing_token=token)
        sys.exit(0)

    # Run mode (default) - load config and continue
    logger.info(f"LeakHunterX Agent v{get_version()} starting up...")

    #  CRITICAL: Load config early (sync) before any async operations
    try:
        config = AgentConfig.from_env()
        logger.debug("Configuration loaded from environment variables")
    except Exception as e:
        logger.error(f"Failed to load config from environment: {e}")
        sys.exit(2)

    #  CRITICAL: Ensure agent is registered BEFORE asyncio starts
    ensure_agent_is_registered(config)

    try:
        #  FIX: Pass both config and args to async_main
        asyncio.run(async_main(config, args))
    except KeyboardInterrupt:
        console_stopping()
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
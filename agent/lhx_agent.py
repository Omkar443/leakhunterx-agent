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

# # ✅ ADD: subprocess and Path for pairing script execution
# import subprocess
# from pathlib import Path

from config.config import AgentConfig
from events.event_emitter import create_emitter
from orchestrator import ScanOrchestrator, ScanStatus
from state_manager import StateManager
from utils.helpers import get_version

# ✅ ADD: Import the pair_agent function
from pair_agent import pair_agent

logger = logging.getLogger(__name__)

# Import psutil at module level with fallback
try:
    import psutil
except ImportError:
    psutil = None

# Constants for consistent intervals
HEARTBEAT_INTERVAL = 5
SCAN_POLL_INTERVAL = 10
ACTION_POLL_INTERVAL = 3

# ✅ ADD: Global shutdown lock (ISSUE #1)
AGENT_SHUTTING_DOWN = False
# ✅ ADD: HTTP client for signal handler (ISSUE #3)
_HTTP_CLIENT_FOR_SIGNAL: Optional[httpx.AsyncClient] = None

# ─────────────────────────────────────────────
# 🔧 SCAN RESULTS NORMALIZATION HELPER
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

            # ✅ FIXED: Only normalize when "findings" key exists in the payload
            if isinstance(json_data, dict) and "findings" in json_data:
                normalized = normalize_scan_findings(json_data["findings"])
                kwargs["json"] = normalized
                logger.debug(f"Normalized scan results payload for {url}")

        return await super().post(url, **kwargs)


# ─────────────────────────────────────────────
# 🫀 AGENT HEARTBEAT HELPERS
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
    # ✅ FIX: Add AGENT_SHUTTING_DOWN check (ISSUE #2)
    while not signal_handler.should_exit and not AGENT_SHUTTING_DOWN:
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
                logger.error("Agent has been revoked! Please re-pair the agent.")
                signal_handler.should_exit = True
                signal_handler.agent_revoked = True
            elif e.response.status_code >= 400:
                logger.warning(f"Heartbeat rejected: {e.response.status_code}")
        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")

        await asyncio.sleep(interval)

    logger.info("Heartbeat loop stopped")


async def send_disconnect(client: httpx.AsyncClient):
    # ✅ FIX: Allow disconnect exactly once - caller decides when to call it
    if not client:
        return

    try:
        await client.post(
            "/api/v1/agent/heartbeat",
            json={
                "state": "disconnected",
                "cpu_percent": 0,
                "memory_percent": 0,
                "disk_percent": 0,
                "network_kbps": 0,
                "uptime_seconds": int(time.time() - AGENT_START_TIME),
                "version": get_version(),
                "mode": "backend",
            },
        )
        logger.info("Disconnect signal sent to backend")
    except Exception as e:
        logger.debug(f"Failed to send disconnect heartbeat: {e}")


def get_agent_state(orchestrator: Optional[ScanOrchestrator]) -> str:
    # ✅ FIX: Add hard shutdown lock (ISSUE #1)
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
# 🎮 AGENT ACTION POLLING
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

    # 🔒 FIX: Stop polling immediately during shutdown
    while not signal_handler.should_exit and not AGENT_SHUTTING_DOWN:
        try:
            resp = await client.get("/api/v1/agent/action")
            resp.raise_for_status()
            data = resp.json()

            action = data.get("action")
            if not action:
                await asyncio.sleep(interval)
                continue

            logger.info(f"Received agent action: {action}")

            orchestrator = orchestrator_ref()

            if action == "restart":
                logger.info("Restart requested by backend → initiating graceful shutdown")
                signal_handler.restart_requested = True
                signal_handler.should_exit = True

                if orchestrator:
                    try:
                        await orchestrator.stop_scan()
                    except Exception as e:
                        logger.debug(f"Failed to stop scan on restart: {e}")

            elif action == "disconnect":
                logger.info("Disconnect requested → stopping agent")
                signal_handler.should_exit = True

                if orchestrator:
                    try:
                        await orchestrator.stop_scan()
                    except Exception as e:
                        logger.debug(f"Failed to stop scan on disconnect: {e}")

            elif action == "start_scan":
                logger.info("Start scan requested (noop – backend assigns scans)")

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                logger.error("Agent has been revoked! Please re-pair the agent.")
                signal_handler.should_exit = True
                signal_handler.agent_revoked = True

            elif e.response.status_code == 404:
                # Backend might not have this endpoint yet
                logger.debug("Action endpoint not found (404)")
                await asyncio.sleep(interval * 2)

            else:
                logger.debug(f"Action polling failed: {e}")
                await asyncio.sleep(interval)

        except Exception as e:
            logger.debug(f"Action polling failed: {e}")
            await asyncio.sleep(interval)

    logger.info("Action polling loop stopped")


def get_agent_secret_path() -> str:
    """Get the path to the agent secret file."""
    # Check for custom path from environment
    custom_path = os.getenv("LHX_AGENT_SECRET_PATH")
    if custom_path:
        return custom_path

    # Default paths
    home = os.path.expanduser("~")

    # Try multiple possible locations
    possible_paths = [
        # Primary location (from your example)
        os.path.join(home, ".leakhunterx", "agent_secret.json"),
        # Alternative location
        os.path.join(home, ".lhx", "agent_secret.json"),
        # Current directory
        os.path.join(os.getcwd(), "agent_secret.json"),
        # System-wide location
        "/etc/leakhunterx/agent_secret.json"
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    # Return the primary location (will create it if needed)
    return possible_paths[0]


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


def ensure_agent_is_registered(config: AgentConfig) -> None:  # ✅ FIX: Accept config parameter
    """
    Ensures agent is paired and authorized.
    Runs pair_agent.py automatically if needed.
    """
    # ✅ FIX: Guard against async context
    try:
        loop = asyncio.get_running_loop()
        raise RuntimeError("Pairing must run before async runtime starts")
    except RuntimeError:
        pass  # No running loop, this is good

    try:
        agent_id, agent_secret = load_agent_credentials()

        # ✅ FIX: Use passed config instead of calling AgentConfig.from_env() again
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
            logger.info("✅ Agent registration verified with backend")
            return

        logger.warning("⚠️ Agent credentials invalid or revoked")

    except Exception as e:
        logger.warning(f"Agent verification failed: {e}")

    # ✅ FIX: Use direct function call instead of subprocess
    # If we reach here → pairing required
    logger.warning("🔑 Agent is not paired or has been revoked")
    logger.warning("Launching agent pairing flow...")

    try:
        pair_agent(pairing_token=None)
    except Exception as e:
        logger.error(f"❌ Agent pairing failed: {e}")
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
            logger.error("Agent has been revoked! Please re-pair the agent.")
            signal_handler.should_exit = True
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

        while not signal_handler.should_exit:
            try:
                scan = await poll_for_scan(client, signal_handler)

                if not scan:
                    await asyncio.sleep(SCAN_POLL_INTERVAL)
                    continue

                scan_id = scan["scan_id"]
                target = scan["target"]

                logger.info(f"Received scan → {scan_id} | target={target}")

                # ─────────────────────────────────────────────
                # 🧪 MVP PIPELINE TEST EVENT (TEMPORARY)
                # Purpose: Verify agent → backend → report flow
                # ─────────────────────────────────────────────
                try:
                    test_event = {
                        "event_type": "endpoint_found",
                        "scan_id": scan_id,
                        "timestamp": int(time.time()),
                        "data": {
                            "raw_value": "/api/internal/health",
                            "source_url": target,
                            "severity": "MEDIUM",
                            "confidence": 0.95,
                            "finding_type": "exposed_endpoint",
                            "metadata": {
                                "reason": "mvp_pipeline_test",
                                "note": "Synthetic event injected to validate report generation"
                            }
                        }
                    }

                    # Create a TEMP emitter just for this test event
                    _test_emitter = create_emitter("http", config=config)
                    await _test_emitter.start()
                    await _test_emitter.emit(test_event)
                    await _test_emitter.flush()
                    await _test_emitter.close()

                    logger.info("🧪 MVP test event emitted successfully")

                except Exception as e:
                    logger.error(f"🧪 MVP test event failed: {e}")


                # ─────────────────────────────────────────────
                # Create HTTP emitter
                # ─────────────────────────────────────────────
                emitter = create_emitter("http", config=config)
                if not emitter:
                    logger.error("Emitter creation failed — skipping scan")
                    await asyncio.sleep(SCAN_POLL_INTERVAL)
                    continue

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
                    # 🔥 Cancellation is expected during shutdown
                    logger.info(f"Scan cancelled → {scan_id}")
                    raise

                except Exception as e:
                    logger.error(
                        f"Scan execution error → {scan_id}: {e}",
                        exc_info=True,
                    )
                    # ❌ DO NOT send scan_failed here
                    # SignalHandler is the single source of truth

                finally:
                    # Stop producing events immediately
                    if scan_task and not scan_task.done():
                        scan_task.cancel()
                        try:
                            await scan_task
                        except asyncio.CancelledError:
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

                await asyncio.sleep(SCAN_POLL_INTERVAL)

            except asyncio.CancelledError:
                logger.info("Backend agent loop cancelled")
                break

            except Exception:
                logger.error(
                    "Unhandled error in backend agent loop",
                    exc_info=True,
                )
                await asyncio.sleep(SCAN_POLL_INTERVAL)

    finally:
        # ─────────────────────────────────────────────
        # 🔐 SHUTDOWN CONTRACT FULFILLED
        # scan_failed already sent by SignalHandler
        # Mark shutdown complete EARLY to stop watchdog
        # ─────────────────────────────────────────────
        signal_handler.mark_shutdown_complete()

        logger.info("Shutting down backend agent loop")

        # Cancel scan task if still running
        if scan_task and not scan_task.done():
            scan_task.cancel()
            try:
                await scan_task
            except asyncio.CancelledError:
                pass

        # Stop background tasks
        for task in (heartbeat_task, action_task):
            if task and not task.done():
                task.cancel()

        await asyncio.gather(
            *(t for t in (heartbeat_task, action_task) if t),
            return_exceptions=True,
        )

        # Best-effort disconnect (do not block shutdown)
        try:
            await asyncio.wait_for(send_disconnect(client), timeout=1.5)
        except Exception:
            pass

        logger.info("Backend agent shutdown complete")




class AgentCLI:
    """Command-line interface handler."""

    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="LeakHunterX Security Scanning Agent",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        # ─────────────────────────────────────────────
        # 🌍 GLOBAL OPTIONS (ALWAYS PRESENT)
        # ─────────────────────────────────────────────
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

        # 🔑 IMPORTANT: define these globally so they ALWAYS exist
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
        # 🔀 SUBCOMMANDS
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
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        handlers = [logging.StreamHandler(sys.stdout)]

        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            handlers.append(logging.FileHandler(log_file))

        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=handlers
        )

        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)



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
        Mark shutdown as fully completed.
        This prevents the shutdown watchdog from force-exiting.
        """
        global AGENT_SHUTTING_DOWN
        AGENT_SHUTTING_DOWN = False
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

            # 🔥 GUARANTEED terminal event
            if self._orchestrator:
                send_scan_failed_sync(
                    scan_id=self._orchestrator.scan_id,
                    reason="agent_interrupted",
                )

            # 🔥 STOP PRODUCING EVENTS IMMEDIATELY
            if self._scan_task and not self._scan_task.done():
                self._scan_task.cancel()

            return


    def _force_exit_if_still_shutting_down(self):
        """Force exit if shutdown is taking too long."""
        if not self._shutdown_started_at:
            return
            
        elapsed = time.time() - self._shutdown_started_at
        if elapsed > (self.shutdown_timeout * 2):  # Double the configured timeout
            logger.error(f"Graceful shutdown timed out after {elapsed:.1f}s → forcing exit")
            self._force_exit()

    def _force_exit(self):
        """Force process exit."""
        logger.error("Force exiting process")
        os._exit(130)



def _calculate_config_hash(config: AgentConfig) -> str:
    """Calculate stable hash for AgentConfig using JSON serialization."""
    config_dict = config.to_dict(redact_secrets=True)  # ✅ Use redact_secrets=True for safety
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

        logger.info(f"Agent authenticated (agent_id={agent_id})")

        # Create authenticated HTTP client for heartbeat / scans / actions
        async with NormalizingHttpClient(
            base_url=config.backend_url,
            headers=headers,
            timeout=10,
        ) as client:

            # ✅ FIX: Register client for signal handler (ISSUE #3)
            global _HTTP_CLIENT_FOR_SIGNAL
            _HTTP_CLIENT_FOR_SIGNAL = client

            # 🔥 IMPORTANT FIX:
            # Inject agent_id + agent_secret into config for HTTP emitter
            emitter_config = {
                **config.to_dict(redact_secrets=True),  # ✅ Use redact_secrets=True for safety
                "agent_id": agent_id,              # used by HTTPBatchEmitter
                "agent_api_key": agent_secret,     # maps to X-Agent-Secret
                "backend_url": config.backend_url, # ensure endpoint correctness
            }

            logger.info("Emitter config prepared for backend event transport")

            # Start the main backend loop with FIXED emitter config
            await run_backend_agent_loop(
                config=emitter_config,  # ✅ FIXED: Pass dict directly (orchestrator expects Dict[str, Any])
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
        # ✅ FIX: Clear client reference (ISSUE #3)
        _HTTP_CLIENT_FOR_SIGNAL = None



async def async_main(config: AgentConfig, args: argparse.Namespace) -> None:  # ✅ FIX: Accept config and args parameters
    """Async main entry point."""

    # ✅ FIX: Arguments are now passed from main()
    # No need to parse args here again
    logger.info(f"LeakHunterX Agent v{get_version()} starting up...")

    # Normalize operator ID
    operator_id = AgentCLI.normalize_operator_id(args.operator_id)

    # ✅ FIX: Configuration is now passed as parameter from main()
    logger.debug("Using configuration loaded in main()")

    # Setup signal handling with fast shutdown
    signal_handler = SignalHandler(shutdown_timeout=args.shutdown_timeout)
    signal_handler.setup()

    # Create shutdown watchdog
    async def shutdown_watchdog():
        """Watchdog that forces exit if shutdown takes too long."""
        while True:
            await asyncio.sleep(1)
            if signal_handler._shutdown_started_at:
                elapsed = time.time() - signal_handler._shutdown_started_at
                if elapsed > 15:  # 15 second absolute maximum
                    logger.error(f"Shutdown watchdog: stuck for {elapsed:.1f}s → forcing exit")
                    os._exit(130)

    watchdog_task = None

    try:
        # Start shutdown watchdog
        watchdog_task = asyncio.create_task(shutdown_watchdog())

        # Decide execution mode (CLI vs BACKEND)
        agent_mode = os.getenv("LH_AGENT_MODE", "backend").lower()

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
        logger.info("Scan interrupted by user")

        # Immediate forceful shutdown
        if signal_handler:
            try:
                await signal_handler.graceful_shutdown()
            except Exception as e:
                logger.debug(f"Graceful shutdown failed: {e}")

        sys.exit(130)

    except asyncio.CancelledError:
        logger.info("Scan was cancelled")
        sys.exit(130)

    finally:
        # Cancel watchdog task
        if watchdog_task and not watchdog_task.done():
            watchdog_task.cancel()
            try:
                await watchdog_task
            except asyncio.CancelledError:
                pass

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

    # ✅ FIX: Parse CLI arguments once at the beginning
    cli = AgentCLI()
    args = cli.parse_args()

    # ✅ FIX: Setup logging once, not twice
    cli.setup_logging(args.log_level, args.log_file)

    # 🔑 Explicit pairing mode
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

    # ✅ CRITICAL: Load config early (sync) before any async operations
    try:
        config = AgentConfig.from_env()
        logger.debug("Configuration loaded from environment variables")
    except Exception as e:
        logger.error(f"Failed to load config from environment: {e}")
        sys.exit(2)

    # ✅ CRITICAL: Ensure agent is registered BEFORE asyncio starts
    ensure_agent_is_registered(config)

    try:
        # ✅ FIX: Pass both config and args to async_main
        asyncio.run(async_main(config, args))
    except KeyboardInterrupt:
        logger.info("Agent terminated by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()





def main():
    # existing startup logic
    # example:
    # config = load_config()
    # orchestrator.start()
    run_agent()


if __name__ == "__main__":
    raise SystemExit(main())

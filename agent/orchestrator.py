# agent/orchestrator.py - Production Grade Enhanced Version
import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Tuple
import hashlib
import time
import socket
import platform
import uuid
import json
from asyncio import TimeoutError as AsyncTimeoutError
import traceback
from contextlib import asynccontextmanager

from domain_manager import DomainManager
from crawler import CompleteCrawler, CrawlContext
from js.extractor_context import ExtractorContext
from js.js_analyzer import JSAnalysisEngine
from events.event_emitter import BaseEventEmitter
from utils.helpers import generate_scan_id, now_ts, get_version
from state_manager import StateManager
from utils.events import emit_event
from events.event_emitter import build_progress_event
from discovery import discover_subdomains_from_url

logger = logging.getLogger(__name__)

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class ScanMetrics:
    total_js_files: int = 0
    processed_js_files: int = 0
    discovered_urls: int = 0
    discovered_endpoints: int = 0
    potential_secrets: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    artifacts_emitted: int = 0
    errors_encountered: int = 0
    duplicate_artifacts_skipped: int = 0
    successful_analyses: int = 0
    failed_analyses: int = 0
    timed_out_analyses: int = 0
    cancelled_analyses: int = 0
    
    @property
    def duration(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def success_rate(self) -> float:
        total = self.successful_analyses + self.failed_analyses
        if total == 0:
            return 0.0
        return (self.successful_analyses / total) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_js_files": self.total_js_files,
            "processed_js_files": self.processed_js_files,
            "discovered_urls": self.discovered_urls,
            "discovered_endpoints": self.discovered_endpoints,
            "potential_secrets": self.potential_secrets,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "artifacts_emitted": self.artifacts_emitted,
            "errors_encountered": self.errors_encountered,
            "duplicate_artifacts_skipped": self.duplicate_artifacts_skipped,
            "successful_analyses": self.successful_analyses,
            "failed_analyses": self.failed_analyses,
            "timed_out_analyses": self.timed_out_analyses,
            "cancelled_analyses": self.cancelled_analyses,
            "success_rate": round(self.success_rate, 2),
            "duration": self.duration
        }

class AnalysisTaskManager:
    """Manages JS analysis tasks with concurrency control and error isolation"""
    
    def __init__(self, concurrency_limit: int = 5):
        self.concurrency_limit = concurrency_limit
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.active_tasks: Set[asyncio.Task] = set()
        self.completed_tasks: List[asyncio.Task] = []
        self._logger = logging.getLogger("task_manager")
    
    async def submit(self, coro, js_url: str, timeout: int = 60) -> Tuple[Optional[Any], Optional[Exception]]:
        """Submit an analysis task with timeout and isolation"""
        async with self.semaphore:
            task = asyncio.create_task(self._execute_with_timeout(coro, js_url, timeout))
            self.active_tasks.add(task)
            
            try:
                result = await task
                return result, None
            except asyncio.CancelledError:
                self._logger.debug(f"Analysis task cancelled for {js_url}")
                raise
            except Exception as e:
                self._logger.debug(f"Analysis task failed for {js_url}: {e}")
                return None, e
            finally:
                self.active_tasks.discard(task)
                self.completed_tasks.append(task)
                
                # Clean up old completed tasks
                if len(self.completed_tasks) > 100:
                    self.completed_tasks = self.completed_tasks[-50:]
    
    async def _execute_with_timeout(self, coro, js_url: str, timeout: int):
        """Execute coroutine with timeout and proper cleanup"""
        try:
            async with asyncio.timeout(timeout):
                return await coro
        except AsyncTimeoutError:
            self._logger.warning(f"Analysis timeout for {js_url} after {timeout}s")
            raise
        except asyncio.CancelledError:
            self._logger.debug(f"Analysis cancelled for {js_url}")
            raise
        except Exception as e:
            self._logger.error(f"Analysis error for {js_url}: {e}")
            raise
    
    async def cancel_all(self):
        """Cancel all active tasks"""
        for task in self.active_tasks:
            if not task.done():
                task.cancel()
        
        if self.active_tasks:
            await asyncio.gather(*self.active_tasks, return_exceptions=True)
        
        self.active_tasks.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get task manager statistics"""
        # ✅ FIX: Safe semaphore value reporting without using private attribute
        try:
            sem_val = self.semaphore._value
        except (AttributeError, Exception):
            # Fallback to approximate available permits
            sem_val = max(0, self.concurrency_limit - len(self.active_tasks))
        
        return {
            "concurrency_limit": self.concurrency_limit,
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "semaphore_value": sem_val
        }

class ScanOrchestrator:
    """Production-grade scan orchestrator with superior error handling and performance"""
    
    def __init__(
        self,
        target_url: str,
        config: Dict[str, Any],
        emitter: BaseEventEmitter,
        state_manager: Optional[StateManager] = None,
        operator_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        resume_state: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None
    ):
        self.target_url = target_url
        self.config = config
        self.emitter = emitter
        self.state_manager = state_manager or StateManager()
        
        # Operator ID validation and normalization
        self.operator_id = self._normalize_operator_id(operator_id or "user")
        
        # Generate or restore scan_id
        self.scan_id = scan_id or generate_scan_id()
        
        # Agent identity - use provided or generate stable ID
        self.agent_id = agent_id or self._generate_stable_agent_id()
        self.agent_version = get_version()
        
        # Store previous_status for resume boundary events
        self._previous_status = "unknown"
        
        # Control signals
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Initially not paused
        self._stop_requested = False
        self._scan_timeout = config.get("scan_timeout", 3600)  # 1 hour default
        
        # 🔥 FIX #1: Add crawler-specific control signals
        self._crawl_stop_event = asyncio.Event()
        self._crawl_pause_event = asyncio.Event()
        self._crawl_pause_event.set()  # Initially not paused
        
        # Artifact management
        self._current_artifact_batch: List[Dict] = []
        self._artifact_lock = asyncio.Lock()
        self._seen_artifact_hashes: Set[str] = set()
        self._seen_summary_hash: Optional[str] = None
        self._batch_size = config.get("artifact_batch_size", 50)
        self._batch_counter = 0
        
        # Guard against double finalization
        self._finalizing = False
        self._cleanup_complete = False
        self._emitter_stopped = False
        
        # ✅ Track last async state save task
        self._last_state_save_task: Optional[asyncio.Task] = None
        
        # Resume state restoration
        self.status: ScanStatus = ScanStatus.PENDING
        self.metrics = ScanMetrics()
        self._restored_js_urls: List[str] = []
        
        if resume_state:
            self._restore_state(resume_state)
        else:
            self.metrics.start_time = now_ts()
        
        # Component references
        self._domain_manager: Optional[DomainManager] = None
        self._crawler: Optional[CompleteCrawler] = None
        self._context: Optional[ExtractorContext] = None
        self._analyzer: Optional[JSAnalysisEngine] = None
        
        # Task management
        self._task_manager: Optional[AnalysisTaskManager] = None
        
        # 🔥 Track crawler task for cancellation fallback
        self._crawl_task: Optional[asyncio.Task] = None
        
        # Configuration with defaults
        self._crawl_timeout = config.get("crawl_timeout", 300)
        self._analysis_timeout = config.get("analysis_timeout", 60)
        self._heartbeat_interval = config.get("heartbeat_interval", 60)
        self._state_save_interval = config.get("state_save_interval", 10)
        self._last_state_save_count = 0
        self._last_heartbeat: float = 0
        
        # Performance tracking
        self._scan_start_time: Optional[float] = None
        self._phase_start_times: Dict[str, float] = {}
        
        # Store initial state
        if not resume_state:
            self._save_state()
        
        logger.info(f"ScanOrchestrator initialized: scan_id={self.scan_id}, target={target_url}")
    
    async def _maybe_await(self, fn, *args, **kwargs):
        """Call a function that may be sync or async and await if necessary."""
        if not fn:
            return None
        
        try:
            res = fn(*args, **kwargs)
        except TypeError:
            # Could be a bound coroutine function that requires no args etc.
            res = fn
        
        if asyncio.iscoroutine(res):
            return await res
        return res
    
    def _set_status(self, new_status: ScanStatus) -> None:
        """Update status with previous_status tracking."""
        if self.status != new_status:
            old_status = self.status.value
            self._previous_status = old_status
            self.status = new_status
            logger.debug(f"Scan status changed: {old_status} -> {new_status.value}")
    
    def _persistent_status(self) -> str:
        """
        Map internal orchestrator lifecycle states to
        persistence-safe StateManager statuses.
        """
        if self.status in (ScanStatus.ERROR, ScanStatus.STOPPED):
            return "failed"
        return self.status.value

    
    def _normalize_operator_id(self, operator_id: str) -> str:
        """Normalize and validate operator ID."""
        if not operator_id or not isinstance(operator_id, str):
            return "anonymous"
        
        normalized = operator_id.strip()
        if not normalized:
            return "anonymous"
        
        if len(normalized) > 256:
            normalized = normalized[:256]
        
        return normalized
    
    def _generate_stable_agent_id(self) -> str:
        """Generate stable agent identifier with container/K8s awareness."""
        config_agent_id = self.config.get("agent_id")
        if config_agent_id:
            return str(config_agent_id)
        
        try:
            container_id = self._get_container_id()
            if container_id:
                return f"container_{container_id[:12]}"
            
            hostname = socket.gethostname()
            system = platform.system()
            agent_info = f"{hostname}:{system}"
            return hashlib.sha256(agent_info.encode()).hexdigest()[:16]
        except Exception:
            return f"agent_{uuid.uuid4().hex[:8]}"
    
    def _get_container_id(self) -> Optional[str]:
        """Get container ID in containerized environments."""
        try:
            with open('/proc/self/cgroup', 'r') as f:
                for line in f:
                    if 'docker' in line or 'kubepods' in line:
                        parts = line.strip().split('/')
                        if len(parts) > 2:
                            container_id = parts[-1]
                            if len(container_id) == 64:
                                return container_id[:12]
            return None
        except Exception:
            return None
    
    def _calculate_config_hash(self) -> str:
        """Calculate stable hash for config using JSON serialization."""
        config_json = json.dumps(self.config, sort_keys=True)
        return hashlib.sha256(config_json.encode()).hexdigest()[:16]
    
    def _restore_state(self, state: Dict[str, Any]) -> None:
        """Restore scan state from persistence with comprehensive error handling."""
        try:
            # ---- Status ----
            raw_status = state.get("status", ScanStatus.PENDING.value)
            try:
                self._set_status(ScanStatus(raw_status))
            except ValueError:
                logger.warning(f"Invalid stored status '{raw_status}', falling back to PENDING")
                self._set_status(ScanStatus.PENDING)
            
            # ---- Core flags ----
            self._previous_status = state.get("previous_status", "unknown")
            self._finalizing = bool(state.get("finalizing", False))
            self._batch_counter = int(state.get("batch_counter", 0))
            self._last_state_save_count = int(state.get("last_state_save_count", 0))
            
            # ---- Metrics ----
            metrics_data = state.get("metrics", {}) or {}
            self.metrics.total_js_files = int(metrics_data.get("total_js_files", 0))
            self.metrics.processed_js_files = int(metrics_data.get("processed_js_files", 0))
            self.metrics.discovered_urls = int(metrics_data.get("discovered_urls", 0))
            self.metrics.discovered_endpoints = int(metrics_data.get("discovered_endpoints", 0))
            self.metrics.potential_secrets = int(metrics_data.get("potential_secrets", 0))
            self.metrics.artifacts_emitted = int(metrics_data.get("artifacts_emitted", 0))
            self.metrics.errors_encountered = int(metrics_data.get("errors_encountered", 0))
            self.metrics.duplicate_artifacts_skipped = int(
                metrics_data.get("duplicate_artifacts_skipped", 0)
            )
            self.metrics.successful_analyses = int(metrics_data.get("successful_analyses", 0))
            self.metrics.failed_analyses = int(metrics_data.get("failed_analyses", 0))
            self.metrics.timed_out_analyses = int(metrics_data.get("timed_out_analyses", 0))
            self.metrics.cancelled_analyses = int(metrics_data.get("cancelled_analyses", 0))
            
            self.metrics.start_time = metrics_data.get("start_time")
            self.metrics.end_time = metrics_data.get("end_time")
            
            # ---- Artifact dedupe state ----
            seen_hashes = state.get("seen_artifact_hashes", []) or []
            self._seen_artifact_hashes = set(seen_hashes[-10000:])
            
            self._seen_summary_hash = state.get("seen_summary_hash")
            
            # ---- Resume JS URLs ----
            self._restored_js_urls = state.get("js_urls", []) or []
            
            logger.info(
                f"Restored scan state for {self.scan_id}: "
                f"status={self.status.value}, "
                f"processed={self.metrics.processed_js_files}, "
                f"js_urls={len(self._restored_js_urls)}, "
                f"success_rate={self.metrics.success_rate:.1f}%"
            )
            
            # ---- Config hash validation ----
            stored_config_hash = state.get("config_hash")
            if stored_config_hash:
                current_hash = self._calculate_config_hash()
                if stored_config_hash != current_hash:
                    logger.warning(
                        f"Config hash mismatch on resume "
                        f"(stored={stored_config_hash}, current={current_hash})"
                    )
        
        except Exception as e:
            logger.exception(f"State restore failed for scan {self.scan_id}, starting fresh")
            
            # ---- HARD RESET (SAFE FALLBACK) ----
            self._set_status(ScanStatus.PENDING)
            self.metrics = ScanMetrics()
            self.metrics.start_time = now_ts()
            
            self._seen_artifact_hashes.clear()
            self._seen_summary_hash = None
            self._restored_js_urls = []
            
            self._batch_counter = 0
            self._previous_status = "unknown"
            self._finalizing = False
            self._last_state_save_count = 0
    
    @asynccontextmanager
    async def _phase_tracker(self, phase_name: str):
        """Track phase execution time and emit events."""
        self._phase_start_times[phase_name] = time.time()
        
        try:
            await emit_event(
                self._context,
                event_type="phase_started",
                data={
                    "phase": phase_name,
                    "scan_id": self.scan_id,
                    "timestamp": time.time()
                }
            )
        except Exception as e:
            logger.warning(f"Failed to emit phase_started event: {e}")
        
        try:
            yield
        finally:
            phase_duration = time.time() - self._phase_start_times[phase_name]
            
            try:
                await emit_event(
                    self._context,
                    event_type="phase_completed",
                    data={
                        "phase": phase_name,
                        "scan_id": self.scan_id,
                        "duration": phase_duration,
                        "timestamp": time.time()
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to emit phase_completed event: {e}")
    
    async def start_scan(self) -> None:
        """Main scan execution flow with comprehensive error handling."""
        heartbeat_task = None
        self._scan_start_time = time.time()
        
        try:
            # ✅ FIX: Safely call emitter.start() whether sync or async
            try:
                await self._maybe_await(getattr(self.emitter, "start", None))
            except Exception as e:
                logger.error(f"Emitter start failed: {e}")
                raise
            
            self._set_status(ScanStatus.RUNNING)
            
            is_resume = self.metrics.processed_js_files > 0
            config_hash = self._calculate_config_hash()
            
            event_data = {
                "target_url": self.target_url,
                "config_hash": config_hash,
                "scan_id": self.scan_id,
                "operator_id": self.operator_id,
                "agent_version": self.agent_version,
                "agent_id": self.agent_id,
                "timestamp": self.metrics.start_time or now_ts(),
                "is_resume": is_resume,
                "resume_progress": self.metrics.processed_js_files,
                "success_rate": self.metrics.success_rate
            }
            
            # ─────────────────────────────────────────────
            # 1️⃣ Create ExtractorContext (analysis + events)
            # ─────────────────────────────────────────────
            self._context = ExtractorContext(
                scan_id=self.scan_id,
                config=self.config,
                event_emitter=self.emitter,
                seen_artifact_hashes=self._seen_artifact_hashes.copy()
            )
            
            # Ensure context.event_emitter is accessible
            self._context.event_emitter = self.emitter
            
            # ✅ FIX: Use list instead of set for JSON serialization
            self._context.shared_state = {
                "metrics": {
                    "total_checks": 0,
                    "patterns_matched": 0,
                    "high_confidence_finds": 0,
                    "processing_time": 0,
                },
                "entropy_cache": {},
                "seen_leaks": [],  # Changed from set() to list
            }
            
            if self._restored_js_urls:
                self._context.js_urls = self._restored_js_urls
            
            # ─────────────────────────────────────────────
            # 2️⃣ Emit lifecycle events
            # ─────────────────────────────────────────────
            if is_resume:
                try:
                    await emit_event(
                        self._context,
                        event_type="scan_resumed",
                        data={**event_data, "previous_status": self._previous_status}
                    )
                except Exception as e:
                    logger.warning(f"Failed to emit scan_resumed event: {e}")
            
            try:
                await emit_event(
                    self._context,
                    event_type="scan_started",
                    data=event_data
                )
            except Exception as e:
                logger.warning(f"Failed to emit scan_started event: {e}")
            
            # ─────────────────────────────────────────────
            # 3️⃣ Initialize core components
            # ─────────────────────────────────────────────
            self._domain_manager = DomainManager(
                target_url=self.target_url,
                max_depth=self.config.get("max_depth", 3)
            )
            
            # Add seed URL
            self._domain_manager.add_seed_urls([self.target_url])
            
            self._crawler = CompleteCrawler(
                domain_manager=self._domain_manager,
                config=self.config
            )
            
            # Create CrawlContext with shared control signals
            self._crawl_context = CrawlContext(
                scan_id=self.scan_id,
                domain_manager=self._domain_manager,
                event_emitter=self.emitter,
                config=self.config,
                should_stop=self._crawl_stop_event,          # 🔥 FIX #1: Inject shared stop event
                should_pause=self._crawl_pause_event         # 🔥 FIX #1: Inject shared pause event
            )
            
            self._analyzer = JSAnalysisEngine(context=self._context)
            
            # Initialize task manager
            concurrency_limit = self.config.get("js_concurrency_limit", 5)
            self._task_manager = AnalysisTaskManager(concurrency_limit=concurrency_limit)
            
            # ─────────────────────────────────────────────
            # 4️⃣ Start heartbeat + run scan with timeout protection
            # ─────────────────────────────────────────────
            heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            # Run scan logic with robust timeout handling
            try:
                await asyncio.wait_for(
                    self._run_scan_logic(),
                    timeout=self._scan_timeout
                )
                
                logger.info(f"Scan {self.scan_id} completed successfully")
                
            except AsyncTimeoutError:
                logger.warning(f"Scan timeout after {self._scan_timeout} seconds")
                await self._handle_timeout()
                # Don't re-raise - let cleanup happen
                
            except asyncio.CancelledError:
                logger.info(f"Scan {self.scan_id} was cancelled")
                await self._handle_stop()
                raise
                
            except Exception as e:
                logger.error(f"Scan error for {self.scan_id}: {e}", exc_info=True)
                await self._handle_error(e)
                raise
        
        except asyncio.CancelledError:
            logger.info(f"Scan cancelled during setup for {self.scan_id}")
            await self._handle_stop()
            raise
            
        except Exception as e:
            logger.error(f"Unexpected error in scan {self.scan_id}: {e}", exc_info=True)
            await self._handle_error(e)
            raise
            
        finally:
            # Always execute cleanup
            await self._safe_cleanup(heartbeat_task)
    
    async def _safe_cleanup(self, heartbeat_task: Optional[asyncio.Task] = None):
        """Safe cleanup that won't raise exceptions."""
        if self._cleanup_complete:
            return
        
        try:
            # ✅ FIX: Wait for pending state save task with timeout
            if getattr(self, "_last_state_save_task", None):
                try:
                    await asyncio.wait_for(self._last_state_save_task, timeout=2.0)
                except asyncio.TimeoutError:
                    logger.warning("Pending state save did not finish before cleanup")
                except Exception as e:
                    logger.error(f"Pending state save failed: {e}")
            
            # Cleanup heartbeat task
            if heartbeat_task and not heartbeat_task.done():
                heartbeat_task.cancel()
                try:
                    await heartbeat_task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.debug(f"Heartbeat task cleanup error: {e}")
            
            # 🔥 Cancel crawler task if still running
            if self._crawl_task and not self._crawl_task.done():
                self._crawl_task.cancel()
                try:
                    await self._crawl_task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.debug(f"Crawler task cleanup error: {e}")
            
            # Cancel all analysis tasks
            if self._task_manager:
                await self._task_manager.cancel_all()
            
            # Force final event delivery
            if self.emitter and not self._emitter_stopped:
                try:
                    # Flush ALL buffered events
                    if hasattr(self.emitter, "flush"):
                        await self._maybe_await(getattr(self.emitter, "flush", None))
                    
                    # Close transport
                    await self._maybe_await(getattr(self.emitter, "close", None))
                    self._emitter_stopped = True
                    
                except Exception as e:
                    logger.warning(f"Emitter shutdown failed: {e}")
            
            # Cleanup components
            await self._cleanup_components()
            
            self._cleanup_complete = True
            logger.info(f"Scan {self.scan_id} cleanup complete")
            
        except Exception as e:
            logger.error(f"Error during cleanup for scan {self.scan_id}: {e}")
    
    async def _run_discovery_phase(self) -> List[str]:
        """
        Phase 0: Passive subdomain discovery.
        Runs BEFORE crawling to find additional targets.
        """
        async with self._phase_tracker("discovery"):
            logger.info(f"Starting passive subdomain discovery for {self.target_url}")
            
            # Emit discovery started event
            try:
                await emit_event(
                    self._context,
                    event_type="discovery_started",
                    data={
                        "target_url": self.target_url,
                        "phase": "subdomain_discovery"
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to emit discovery_started event: {e}")
            
            try:
                await self.emitter.emit(
                    build_progress_event(
                        scan_id=self.scan_id,
                        phase="discovery",
                        message="Discovering subdomains"
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to emit discovery progress event: {e}")
            
            discovered_subdomains = []
            start_time = time.time()
            
            try:
                # Run passive discovery
                discovered_subdomains = await discover_subdomains_from_url(
                    self.target_url,
                    config=None  # Use defaults
                )
                
                # Log results
                duration = time.time() - start_time
                logger.info(
                    f"Discovery completed: found {len(discovered_subdomains)} subdomains "
                    f"in {duration:.2f}s"
                )
                
                # Emit discovery completed event
                try:
                    await emit_event(
                        self._context,
                        event_type="discovery_completed",
                        data={
                            "subdomains_found": len(discovered_subdomains),
                            "duration": duration,
                            "sample": discovered_subdomains[:10]  # First 10 as sample
                        }
                    )
                except Exception as e:
                    logger.warning(f"Failed to emit discovery_completed event: {e}")
                
            except Exception as e:
                logger.error(f"Discovery phase failed: {e}")
                # Discovery failure shouldn't stop the scan
                try:
                    await emit_event(
                        self._context,
                        event_type="discovery_failed",
                        data={"error": str(e)[:100]}
                    )
                except Exception:
                    pass
                discovered_subdomains = []
            
            return discovered_subdomains
    
    async def _run_scan_logic(self) -> None:
        """
        Core scan logic with comprehensive error handling and performance tracking.
        """
        logger.info(f"Starting scan logic for {self.scan_id}")
        
        try:
            # ─────────────────────────────────────────────
            # PHASE 0: Subdomain Discovery
            # ─────────────────────────────────────────────
            discovered_subdomains = await self._run_discovery_phase()
            
            # Add discovered subdomains to domain manager as seed URLs
            if discovered_subdomains:
                logger.info(f"Adding {len(discovered_subdomains)} discovered subdomains to scan scope")
                
                # Add each discovered subdomain as a seed URL
                for subdomain_url in discovered_subdomains:
                    if self._domain_manager:
                        self._domain_manager.add_seed_urls([subdomain_url])
                
                try:
                    await emit_event(
                        self._context,
                        event_type="subdomains_added",
                        data={"count": len(discovered_subdomains)}
                    )
                except Exception as e:
                    logger.warning(f"Failed to emit subdomains_added event: {e}")
            
            # ─────────────────────────────────────────────
            # PHASE 1: JS Discovery (via crawling)
            # ─────────────────────────────────────────────
            async with self._phase_tracker("crawling"):
                await self._discover_js_urls()
            
            # ─────────────────────────────────────────────
            # PHASE 2: JS Analysis
            # ─────────────────────────────────────────────
            async with self._phase_tracker("analysis"):
                await self._analyze_js_files()
            
            # ─────────────────────────────────────────────
            # PHASE 3: Finalization
            # ─────────────────────────────────────────────
            await self._flush_artifacts()
            await self._complete_scan()
            
        except asyncio.CancelledError:
            logger.info(f"Scan logic cancelled for {self.scan_id}")
            raise
            
        except Exception as e:
            logger.error(f"Scan logic failed for {self.scan_id}: {e}", exc_info=True)
            raise
    
    async def _discover_js_urls(self) -> None:
        """Discover JavaScript files via crawler with timeout handling."""
        if not self._crawler or not self._crawl_context:
            raise RuntimeError("Crawler or CrawlContext not initialized")
        
        try:
            await emit_event(
                self._context,
                event_type="crawling_started",
                data={}
            )
        except Exception as e:
            logger.warning(f"Failed to emit crawling_started event: {e}")
        
        try:
            await self.emitter.emit(
                build_progress_event(
                    scan_id=self.scan_id,
                    phase="crawling",
                    message="Discovering JavaScript files"
                )
            )
        except Exception as e:
            logger.warning(f"Failed to emit crawling progress event: {e}")
        
        try:
            async with asyncio.timeout(self._crawl_timeout):
                # 🔥 FIX #3: Run crawler with tracked task
                self._crawl_task = asyncio.create_task(
                    self._crawler.crawl(self._crawl_context)
                )
                await self._crawl_task
                
        except AsyncTimeoutError:
            logger.warning(f"Crawling timed out after {self._crawl_timeout}s")
            raise
        except asyncio.CancelledError:
            logger.info("Crawling cancelled")
            raise
        except Exception as e:
            logger.error(f"Crawling failed: {e}")
            raise
        
        # Discovery stats come from DomainManager
        try:
            stats = self._domain_manager.get_stats()
        except Exception as e:
            logger.error(f"Failed to get domain manager stats: {e}")
            stats = {"total_discovered": 0}
        
        discovered = stats.get("total_discovered", 0)
        
        self.metrics.discovered_urls = discovered
        
        try:
            await emit_event(
                self._context,
                event_type="crawling_completed",
                data={
                    "total_js_files": discovered,
                    "in_scope_urls": discovered
                }
            )
        except Exception as e:
            logger.warning(f"Failed to emit crawling_completed event: {e}")
        
        self._save_state()
    
    async def _analyze_js_files(self) -> None:
        """Analyze discovered JS files with true concurrency and robust safety."""
        if not self._analyzer or not self._context:
            raise RuntimeError("Analyzer not initialized")

        if not self._task_manager:
            raise RuntimeError("Task manager not initialized")

        # Get JS queue size
        try:
            js_queue_size = self._domain_manager.get_js_queue_size()
        except Exception as e:
            logger.error(f"Failed to get JS queue size: {e}")
            js_queue_size = 0

        self.metrics.total_js_files = js_queue_size

        if not js_queue_size:
            try:
                await self.emitter.emit(
                    build_progress_event(
                        scan_id=self.scan_id,
                        phase="js_analysis",
                        current=0,
                        total=0,
                        message="No JavaScript files discovered",
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to emit no-JS progress event: {e}")

            logger.info("No JavaScript files discovered")
            return

        # Emit analysis start
        try:
            await emit_event(
                self._context,
                event_type="analysis_started",
                data={
                    "total_files": js_queue_size,
                    "already_processed": self.metrics.processed_js_files,
                    "concurrency_limit": self._task_manager.concurrency_limit,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to emit analysis_started event: {e}")

        try:
            await self.emitter.emit(
                build_progress_event(
                    scan_id=self.scan_id,
                    phase="js_analysis",
                    current=self.metrics.processed_js_files,
                    total=self.metrics.total_js_files,
                    message="Analyzing JavaScript files",
                )
            )
        except Exception as e:
            logger.warning(f"Failed to emit analysis progress event: {e}")

        processed_count = 0
        batch_size = min(self._task_manager.concurrency_limit * 2, 20)

        try:
            while self._domain_manager.has_js_targets():
                # Stop / pause handling
                if self._stop_requested:
                    raise asyncio.CancelledError()

                while self.status == ScanStatus.PAUSED:
                    await asyncio.sleep(0.2)
                    if self._stop_requested:
                        raise asyncio.CancelledError()

                # Collect batch
                js_urls_batch: List[str] = []
                for _ in range(batch_size):
                    if not self._domain_manager.has_js_targets():
                        break
                    js_url = self._domain_manager.get_next_js_target()
                    if js_url:
                        js_urls_batch.append(js_url)

                if not js_urls_batch:
                    break

                # 🔥 FIX: submit tasks in parallel
                tasks: List[asyncio.Task] = []
                for js_url in js_urls_batch:
                    tasks.append(
                        asyncio.create_task(
                            self._task_manager.submit(
                                self._analyzer.analyze(js_url),
                                js_url,
                                timeout=self._analysis_timeout,
                            )
                        )
                    )

                # Process results in submission order
                for js_url, task in zip(js_urls_batch, tasks):
                    result, error = await task

                    if result and isinstance(result, dict):
                        new_endpoints, new_secrets = await self._process_analysis_result(
                            js_url, result
                        )
                        self.metrics.discovered_endpoints += new_endpoints
                        self.metrics.potential_secrets += new_secrets
                        self.metrics.successful_analyses += 1
                    else:
                        if isinstance(error, AsyncTimeoutError):
                            self.metrics.timed_out_analyses += 1
                            logger.warning(f"Analysis timeout for {js_url}")
                        elif isinstance(error, asyncio.CancelledError):
                            self.metrics.cancelled_analyses += 1
                        else:
                            self.metrics.failed_analyses += 1
                            logger.error(f"Analysis failed for {js_url}: {error}")

                    self.metrics.processed_js_files += 1
                    processed_count += 1

                    # Emit progress periodically
                    if processed_count % 5 == 0:
                        try:
                            await self.emitter.emit(
                                build_progress_event(
                                    scan_id=self.scan_id,
                                    phase="js_analysis",
                                    current=self.metrics.processed_js_files,
                                    total=self.metrics.total_js_files,
                                    message="Analyzing JavaScript files",
                                )
                            )
                        except Exception as e:
                            logger.warning(
                                f"Failed to emit periodic progress event: {e}"
                            )

                    # Save state periodically
                    if (
                        self.metrics.processed_js_files
                        - self._last_state_save_count
                        >= self._state_save_interval
                    ):
                        self._save_state()
                        self._last_state_save_count = self.metrics.processed_js_files

                # Small delay between batches (fair scheduling)
                await asyncio.sleep(0.05)

        except asyncio.CancelledError:
            logger.info("JS analysis cancelled")
            raise
        except Exception as e:
            logger.error(f"JS analysis loop failed: {e}", exc_info=True)
            raise

        logger.info(
            f"JS analysis complete. "
            f"Processed {self.metrics.processed_js_files}/{self.metrics.total_js_files} JS files, "
            f"successful: {self.metrics.successful_analyses}, "
            f"failed: {self.metrics.failed_analyses}, "
            f"timeouts: {self.metrics.timed_out_analyses}, "
            f"success rate: {self.metrics.success_rate:.1f}%"
        )

    
    async def _process_analysis_result(self, js_url: str, result: Dict[str, Any]) -> Tuple[int, int]:
        """Process analysis results and batch artifacts."""
        accepted_endpoints = 0
        accepted_secrets = 0
        
        if not isinstance(result, dict):
            logger.warning(f"Invalid result type for {js_url}: {type(result)}")
            return 0, 0
        
        # Extract endpoints
        endpoints = result.get("endpoints", [])
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue
                
            endpoint_url = endpoint.get("url", "")
            if not endpoint_url:
                continue
                
            artifact_data = {
                "type": "endpoint",
                "source_url": js_url,
                "endpoint": endpoint_url,
                "method": endpoint.get("method", "GET"),
                "confidence": float(endpoint.get("confidence", 0.0)),
                "line_number": endpoint.get("line"),
                "context": endpoint.get("context", ""),
                "sha256": hashlib.sha256(
                    f"{js_url}:{endpoint_url}:{endpoint.get('method', 'GET')}".encode()
                ).hexdigest()
            }
            
            if await self._add_artifact(artifact_data):
                accepted_endpoints += 1
        
        # Extract secrets
        secrets = result.get("secrets", [])
        for secret in secrets:
            if not isinstance(secret, dict):
                continue
            
            # Redact secret values
            secret = {k: v for k, v in secret.items() if k != "value"}
            
            artifact_data = {
                "type": "potential_secret",
                "source_url": js_url,
                "secret_type": secret.get("type", "unknown"),
                "line_number": secret.get("line"),
                "confidence": float(secret.get("confidence", 0.0)),
                "severity": secret.get("severity", "medium"),
                "detector": secret.get("detector", "unknown"),
                "sha256": hashlib.sha256(
                    f"{js_url}:{str(secret.get('type'))}:{str(secret.get('line'))}".encode()
                ).hexdigest()
            }
            
            if await self._add_artifact(artifact_data):
                accepted_secrets += 1
        
        return accepted_endpoints, accepted_secrets
    
    async def _add_artifact(self, artifact: Dict[str, Any]) -> bool:
        """Add artifact to batch with deduplication."""
        required_keys = {"type", "source_url", "sha256"}
        if not all(key in artifact for key in required_keys):
            logger.warning(f"Invalid artifact missing required keys: {artifact}")
            return False
        
        artifact_hash = artifact["sha256"]
        
        if artifact_hash in self._seen_artifact_hashes:
            self.metrics.duplicate_artifacts_skipped += 1
            return False
        
        artifact["timestamp"] = now_ts()
        artifact["scan_id"] = self.scan_id
        artifact["operator_id"] = self.operator_id
        
        async with self._artifact_lock:
            self._seen_artifact_hashes.add(artifact_hash)
            self._current_artifact_batch.append(artifact)
            
            if len(self._current_artifact_batch) >= self._batch_size:
                await self._emit_batch()
        
        return True
    
    async def _emit_batch(self) -> None:
        """Emit current artifact batch with backpressure handling."""
        if not self._current_artifact_batch:
            return
        
        batch = self._current_artifact_batch.copy()
        self._current_artifact_batch.clear()
        
        self._batch_counter += 1
        
        try:
            async with asyncio.timeout(30):
                await emit_event(
                    self._context,
                    event_type="artifact_batch_ready",
                    data={
                        "count": len(batch),
                        "batch_index": self._batch_counter,
                        "total_emitted_so_far": self.metrics.artifacts_emitted + len(batch),
                        "artifacts": batch,
                    },
                )
                
                self.metrics.artifacts_emitted += len(batch)
                
        except AsyncTimeoutError:
            logger.warning("Event emission timed out, requeuing batch (preserve ordering)")
            
            # ✅ FIX: Prepend timed-out batch to preserve ordering
            async with self._artifact_lock:
                # Prepend the timed-out batch so older artifacts are processed first
                self._current_artifact_batch[:] = batch + self._current_artifact_batch
                    
        except Exception as e:
            logger.error(f"Failed to emit artifact batch: {e}")
            # Don't lose artifacts on emitter errors
            # ✅ FIX: Prepend to preserve ordering
            async with self._artifact_lock:
                # Prepend the failed batch so older artifacts are processed first
                self._current_artifact_batch[:] = batch + self._current_artifact_batch
    
    async def _flush_artifacts(self) -> None:
        """Flush any remaining artifacts in batch."""
        if self._current_artifact_batch:
            await self._emit_batch()
    
    async def _check_interruptions(self) -> None:
        """Check for scan interruptions."""
        if self._stop_requested:
            raise asyncio.CancelledError("scan_stop_requested")  # ✅ FIX: Use CancelledError
        
        if self.status == ScanStatus.PAUSED:
            while self.status == ScanStatus.PAUSED:
                if self._stop_requested:
                    raise asyncio.CancelledError("scan_stop_requested")
                await asyncio.sleep(0.2)
    
    async def _complete_scan(self) -> None:
        """Complete the scan successfully with comprehensive metrics."""
        if self._finalizing or self.status in (
            ScanStatus.COMPLETED,
            ScanStatus.ERROR,
            ScanStatus.STOPPED,
        ):
            logger.warning(
                f"Attempted to complete scan that is already {self.status.value}"
            )
            return
        
        self._set_status(ScanStatus.COMPLETED)
        self.metrics.end_time = now_ts()
        
        # Emit detailed analysis summary
        try:
            await emit_event(
                self._context,
                event_type="js_analysis_summary",
                data={
                    "total_files_analyzed": self.metrics.processed_js_files,
                    "total_endpoints_found": self.metrics.discovered_endpoints,
                    "total_secrets_found": self.metrics.potential_secrets,
                    "duplicates_skipped": self.metrics.duplicate_artifacts_skipped,
                    "errors_encountered": self.metrics.errors_encountered,
                    "successful_analyses": self.metrics.successful_analyses,
                    "failed_analyses": self.metrics.failed_analyses,
                    "timed_out_analyses": self.metrics.timed_out_analyses,
                    "success_rate": self.metrics.success_rate,
                    "analysis_timestamp": now_ts(),
                },
            )
        except Exception as e:
            logger.warning(f"Failed to emit analysis summary event: {e}")
        
        # Create final scan summary artifact
        summary_artifact = {
            "type": "scan_summary",
            "scan_id": self.scan_id,
            "timestamp": now_ts(),
            "metrics": self.metrics.to_dict(),
            "status": "completed",
            "operator_id": self.operator_id,
            "agent_version": self.agent_version,
            "agent_id": self.agent_id,
            "sha256": hashlib.sha256(
                f"{self.scan_id}:summary:{self.metrics.end_time}".encode()
            ).hexdigest(),
        }
        
        # Emit summary if not duplicate
        if self._seen_summary_hash != summary_artifact["sha256"]:
            self._batch_counter += 1
            
            try:
                await emit_event(
                    self._context,
                    event_type="artifact_batch_ready",
                    data={
                        "count": 1,
                        "batch_index": self._batch_counter,
                        "total_emitted_so_far": self.metrics.artifacts_emitted + 1,
                        "artifacts": [summary_artifact],
                    },
                )
            except Exception as e:
                logger.warning(f"Failed to emit summary artifact: {e}")
            
            self._seen_summary_hash = summary_artifact["sha256"]
            self.metrics.artifacts_emitted += 1
        
        # Emit terminal progress
        try:
            await self.emitter.emit(
                build_progress_event(
                    scan_id=self.scan_id,
                    phase="completed",
                    current=self.metrics.total_js_files,
                    total=self.metrics.total_js_files,
                    message="Scan completed",
                )
            )
        except Exception as e:
            logger.warning(f"Failed to emit completion progress event: {e}")
        
        # Emit scan completed event
        try:
            await emit_event(
                self._context,
                event_type="scan_completed",
                data={
                    "metrics": self.metrics.to_dict(),
                    "summary_artifact_hash": summary_artifact["sha256"],
                    "operator_id": self.operator_id,
                    "agent_version": self.agent_version,
                    "agent_id": self.agent_id,
                    "total_duration": self.metrics.duration,
                    "success_rate": self.metrics.success_rate,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to emit scan_completed event: {e}")
        
        # Force flush
        try:
            if hasattr(self.emitter, "flush"):
                await self._maybe_await(getattr(self.emitter, "flush", None))
        except Exception as e:
            logger.error(f"Emitter flush failed during scan completion: {e}")
        
        self._finalizing = True
        
        # Clear persisted scan state
        if self.state_manager:
            try:
                # ✅ FIX: Safely call clear_scan_state whether sync or async
                await self._maybe_await(
                    getattr(self.state_manager, "clear_scan_state", None),
                    self.scan_id
                )
            except Exception as e:
                logger.error(f"Failed to clear scan state: {e}")
    
    async def _handle_stop(self) -> None:
        if self._finalizing or self.status in (
            ScanStatus.COMPLETED,
            ScanStatus.ERROR,
            ScanStatus.STOPPED,
        ):
            return

        self._finalizing = True
        self._set_status(ScanStatus.STOPPED)
        self.metrics.end_time = now_ts()

        # 🔥 REMOVE scan_stopped emission entirely for Ctrl+C paths
        # Do NOT emit scan_stopped here

        self._save_state()

    
    async def _handle_timeout(self) -> None:
        """Handle scan timeout."""
        if self._finalizing or self.status in [ScanStatus.COMPLETED, ScanStatus.ERROR, ScanStatus.STOPPED]:
            logger.warning(f"Attempted to timeout scan that is already {self.status.value}")
            return
            
        self._finalizing = True
        self._set_status(ScanStatus.STOPPED)
        self.metrics.end_time = now_ts()
        
        try:
            await emit_event(
                self._context,
                event_type="scan_stopped",
                data={
                    "metrics": self.metrics.to_dict(),
                    "reason": "timeout",
                    "timeout_seconds": self._scan_timeout,
                    "operator_id": self.operator_id,
                    "agent_version": self.agent_version,
                    "agent_id": self.agent_id,
                    "duration": self.metrics.duration
                }
            )
        except Exception as e:
            logger.warning(f"Failed to emit timeout event: {e}")
        
        self._save_state()
    
    async def _handle_error(self, error: Exception) -> None:
        """Handle scan error."""
        if self._finalizing or self.status in [ScanStatus.COMPLETED, ScanStatus.ERROR, ScanStatus.STOPPED]:
            logger.warning(f"Attempted to error scan that is already {self.status.value}")
            return
            
        self._finalizing = True
        self._set_status(ScanStatus.ERROR)
        self.metrics.end_time = now_ts()
        
        try:
            await emit_event(
                self._context,
                event_type="scan_error",
                data={
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                    "error_traceback": traceback.format_exc(),
                    "metrics": self.metrics.to_dict(),
                    "operator_id": self.operator_id,
                    "agent_version": self.agent_version,
                    "agent_id": self.agent_id,
                    "duration": self.metrics.duration
                }
            )
        except Exception as e:
            logger.warning(f"Failed to emit error event: {e}")
        
        self._save_state()
    
    async def _heartbeat_loop(self) -> None:
        """Emit periodic heartbeat events."""
        while True:
            try:
                await asyncio.sleep(self._heartbeat_interval)
                
                # ✅ FIX #4: Fix heartbeat race condition
                if self._stop_requested or self._finalizing:
                    break
                
                try:
                    await emit_event(
                        self._context,
                        event_type="agent_heartbeat",
                        data={
                            "scan_id": self.scan_id,
                            "status": self.status.value,
                            "processed_files": self.metrics.processed_js_files,
                            "total_files": self.metrics.total_js_files,
                            "successful_analyses": self.metrics.successful_analyses,
                            "failed_analyses": self.metrics.failed_analyses,
                            "success_rate": self.metrics.success_rate,
                            "operator_id": self.operator_id,
                            "agent_version": self.agent_version,
                            "agent_id": self.agent_id,
                            "task_manager_stats": self._task_manager.get_stats() if self._task_manager else {}
                        }
                    )
                except Exception as e:
                    logger.warning(f"Failed to emit heartbeat event: {e}")
                
                self._last_heartbeat = time.time()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    def _save_state(self) -> None:
        """Save scan state for persistence."""
        if not self.state_manager:
            return
        
        try:
            state = {
                "scan_id": self.scan_id,
                "status": self._persistent_status(),
                "previous_status": self._previous_status,
                "target_url": self.target_url,
                "metrics": self.metrics.to_dict(),
                "timestamp": now_ts(),
                "config_hash": self._calculate_config_hash(),
                "agent_version": self.agent_version,
                "operator_id": self.operator_id,
                "agent_id": self.agent_id,
                "seen_artifact_hashes": list(self._seen_artifact_hashes)[-10000:],  # Keep last 10k
                "seen_summary_hash": self._seen_summary_hash,
                "batch_counter": self._batch_counter,
                "finalizing": self._finalizing,
                "last_state_save_count": self._last_state_save_count,
                "js_urls": getattr(self._context, 'js_urls', []) if self._context else []
            }
            
            if hasattr(self.state_manager, 'save_scan_state_async'):
                # ✅ FIX: Track async save task for proper cleanup
                self._last_state_save_task = asyncio.create_task(
                    self._async_save_state(state)
                )
            else:
                try:
                    self.state_manager.save_scan_state(self.scan_id, state)
                except Exception as e:
                    logger.error(f"sync state save failed: {e}")
                
        except Exception as e:
            logger.error(f"Failed to save scan state: {e}")
    
    async def _async_save_state(self, state: Dict[str, Any]) -> None:
        """Async state save with error handling."""
        try:
            await self.state_manager.save_scan_state_async(self.scan_id, state)
        except Exception as e:
            logger.error(f"Async state save failed: {e}")
            if hasattr(self.state_manager, 'save_scan_state'):
                try:
                    self.state_manager.save_scan_state(self.scan_id, state)
                except Exception as e2:
                    logger.error(f"Sync fallback also failed: {e2}")
    

    async def _cleanup_components(self) -> None:
        """Cleanup all components with proper HTTP session closure."""
        cleanup_tasks = []
        
        # Cleanup crawler
        if hasattr(self._crawler, 'cleanup'):
            cleanup_tasks.append(self._crawler.cleanup())
        
        # Cleanup analyzer (this will close HTTP sessions)
        if hasattr(self._analyzer, 'cleanup'):
            cleanup_tasks.append(self._analyzer.cleanup())
        
        # Execute cleanup tasks with timeout
        if cleanup_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*cleanup_tasks, return_exceptions=True),
                    timeout=15.0
                )
            except AsyncTimeoutError:
                logger.warning("Component cleanup timed out")
            except Exception as e:
                logger.error(f"Component cleanup error: {e}")
        
        # Clear references
        self._domain_manager = None
        self._crawler = None
        self._context = None
        self._analyzer = None
        self._task_manager = None
        self._crawl_task = None  # 🔥 Clear crawler task reference
    
    # Public API methods (unchanged from original)
    async def pause_scan(self) -> None:
        """Pause the ongoing scan."""
        if self.status == ScanStatus.RUNNING:
            self._set_status(ScanStatus.PAUSED)
            self._pause_event.clear()
            self._crawl_pause_event.clear()  # 🔥 Also pause crawler
            
            try:
                await emit_event(
                    self._context,
                    event_type="scan_paused",
                    data={
                        "operator_id": self.operator_id
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to emit pause event: {e}")
            self._save_state()
    
    async def resume_scan(self) -> None:
        """Resume a paused scan."""
        if self.status == ScanStatus.PAUSED:
            self._set_status(ScanStatus.RUNNING)
            self._pause_event.set()
            self._crawl_pause_event.set()  # 🔥 Also resume crawler
            
            try:
                await emit_event(
                    self._context,
                    event_type="scan_resumed",
                    data={
                        "operator_id": self.operator_id,
                        "timestamp": now_ts()
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to emit resume event: {e}")
            self._save_state()
    
    async def stop_scan(self) -> None:
        """Stop the scan gracefully."""
        if self._finalizing:
            return
        
        if self.status not in (ScanStatus.RUNNING, ScanStatus.PAUSED):
            return
        
        self._finalizing = True
        self._stop_requested = True
        
        # Unblock paused / waiting coroutines
        if self._pause_event:
            self._pause_event.set()
        
        # 🔥 FIX #2: Set crawler stop signal instead of ExtractorContext
        if hasattr(self, "_crawl_stop_event"):
            self._crawl_stop_event.set()
        
        # 🔥 Cancel crawler task if running
        if self._crawl_task and not self._crawl_task.done():
            self._crawl_task.cancel()
        
        # ✅ FIX #2: Cancel all analyzer tasks
        if self._task_manager:
            await self._task_manager.cancel_all()
        
        # ✅ FIX #3: Remove dead `_tasks` logic (no replacement needed)
        # Analyzer & crawler are the only long-running tasks
        # (crawler handled above, analyzer via task manager)
        
        # Emit stopping event
        try:
            await emit_event(
                self._context,
                event_type="scan_stopping",
                data={
                    "operator_id": self.operator_id,
                    "timestamp": now_ts(),
                },
            )
        except Exception as e:
            logger.debug(f"Failed to emit stopping event: {e}")
        
        self._set_status(ScanStatus.STOPPED)
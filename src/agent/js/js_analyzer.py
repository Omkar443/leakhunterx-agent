"""
JSAnalysisEngine - Production Grade Enhanced Version (v2)

Responsible for:
- Fetching JavaScript resources
- Extracting endpoints
- Detecting secrets
- Emitting structured security events

CHANGELOG (this revision - all additive, no external interface changes):
- NEW: application-level concurrency limiting via asyncio.Semaphore.
  DEFAULT_CONCURRENT_REQUESTS was defined in the original file but never
  actually used anywhere - nothing bounded how many JS files could be
  fetched in parallel. Now wired into the real fetch path.
- NEW: request coalescing - if two callers request the same js_url
  while a fetch for it is already in flight, the second call awaits
  the first one's result instead of firing a duplicate request. Common
  when multiple pages reference the same bundled JS file.
- NEW: session-creation race guard. get_session() previously had a
  check-then-create race: two coroutines calling it concurrently while
  self._session is None could both pass the check and each create a
  session, leaking one. Now guarded with an asyncio.Lock + double-checked
  locking.
- FIXED: cleanup() was resetting the circuit breaker to
  CircuitBreaker() with hardcoded defaults, silently discarding your
  configured circuit_breaker_max_failures / circuit_breaker_reset_timeout
  for the rest of the engine's lifetime after any cleanup() call.
- NEW: bounded total fetch deadline. The original retry loop had no
  ceiling on retries + backoff + 429 Retry-After waits stacking up -
  a hostile/misbehaving server could keep a single fetch alive far
  longer than intended. Now wrapped in one asyncio.wait_for deadline.
- NEW: cache TTL. ContentCache previously served cached content forever
  once stored - on a long-running scan that content can go stale.
  get() now checks staleness against a configurable TTL.
- NEW: dependency-free Prometheus text-format metrics exporter on
  AnalysisMetrics (no prometheus_client dependency required).
- NEW: get_health_status() - lightweight snapshot for orchestrator
  monitoring / a /health endpoint.
- NEW: optional async context manager support (`async with
  JSAnalysisEngine(context) as engine:`) that calls cleanup() on exit.
  Purely additive - existing manual .cleanup() calls still work.

NO other behavior changes. All original method names, signatures, and
return shapes are preserved exactly.
"""

import os
import hashlib
import time
import asyncio
import logging
import ssl
import socket
from typing import List, Dict, Set, Tuple, Optional, Any, Callable
from dataclasses import dataclass, asdict, field
from collections import defaultdict, OrderedDict
from urllib.parse import urlparse, urljoin
from asyncio import TimeoutError as AsyncTimeoutError
from contextlib import asynccontextmanager

import aiohttp

# ------------------------------------------------------------
# PACKAGE-RELATIVE IMPORTS (CRITICAL FIX - unchanged from original)
# ------------------------------------------------------------

from ..utils.events import emit_event
from ..utils.pipeline import ScanResolver, guarded_get
from .extractor_context import ExtractorContext
from .js_extractor import LinkExtractor
from .leak_detector import SecretScanner


logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_FETCH_TIMEOUT = 30
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_CONCURRENT_REQUESTS = 10
MAX_JS_FILE_SIZE = 15 * 1024 * 1024  # 15MB
CHUNK_READ_SIZE = 8192  # 8KB chunks for streaming
DEFAULT_CACHE_TTL_SECONDS = 1800  # NEW: 30 minutes
ANALYSIS_FAILURE_REASONS = {
    "http_error", "network_error", "download_timeout", "response_limit",
    "invalid_content", "scope_refused", "download_error", "circuit_open",
    "extraction_timeout", "analysis_timeout", "analysis_error",
    "access_denied", "resource_missing", "rate_limited", "server_error",
}
UNAVAILABLE_RESOURCE_REASONS = {
    "http_error", "resource_missing", "access_denied", "rate_limited",
    "server_error", "network_error", "download_timeout", "response_limit",
    "invalid_content", "circuit_open", "scope_refused",
}


def fetch_deadline(config):
    timeout = config.get("js_fetch_timeout", DEFAULT_FETCH_TIMEOUT)
    retries = config.get("js_fetch_retries", DEFAULT_RETRY_ATTEMPTS)
    return config.get("js_fetch_total_deadline", max(timeout * retries + 30, 60))


def analysis_deadline(config):
    # Download retries and extraction both fit inside the task budget.
    # The assignment deadline independently bounds the entire scan.
    return max(config.get("analysis_timeout", 60),
               fetch_deadline(config) + config.get("extraction_timeout", 60) + 5)


class CircuitBreaker:
    """Intelligent circuit breaker for URL failures with exponential backoff"""

    def __init__(self, max_failures: int = 3, reset_timeout: int = 300):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self._failures: Dict[str, Tuple[int, float]] = {}
        self._logger = logging.getLogger("circuit_breaker")

    def is_allowed(self, url: str) -> bool:
        """Check if request to URL is allowed"""
        if url not in self._failures:
            return True

        failures, last_failure = self._failures[url]
        if failures < self.max_failures:
            return True

        # Exponential backoff based on failure count
        backoff_time = min(self.reset_timeout * (2 ** (failures - self.max_failures)), 3600)
        time_since_failure = time.time() - last_failure

        if time_since_failure > backoff_time:
            # Reset after backoff period
            del self._failures[url]
            return True

        return False

    def record_failure(self, url: str):
        """Record a failure for the URL"""
        if url not in self._failures:
            self._failures[url] = (1, time.time())
        else:
            failures, _ = self._failures[url]
            self._failures[url] = (failures + 1, time.time())

        failures, _ = self._failures[url]
        if failures >= self.max_failures:
            self._logger.warning(f"Circuit breaker opened for {url} after {failures} failures")

    def record_success(self, url: str):
        """Record success and reset failures for URL"""
        if url in self._failures:
            del self._failures[url]


class ContentCache:
    """
    Intelligent content cache with LRU eviction and TTL-based staleness.

    CHANGED: access order now uses OrderedDict (O(1) move-to-end) instead
    of a plain list with .remove() (O(n)) - same eviction behavior, more
    efficient at larger cache sizes. Also added an optional TTL: entries
    older than ttl_seconds are treated as a miss and evicted on read.
    ttl_seconds=None preserves the original "never expires" behavior.
    """

    def __init__(self, max_size: int = 100, ttl_seconds: Optional[int] = DEFAULT_CACHE_TTL_SECONDS):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[str, int, float]] = {}  # url_hash -> (content, size, timestamp)
        self._access_order: "OrderedDict[str, None]" = OrderedDict()

    def get(self, key: str) -> Optional[Tuple[str, int]]:
        """Get content from cache, updating access order. Returns None on miss or staleness."""
        if key not in self._cache:
            return None

        content, size, timestamp = self._cache[key]

        # NEW: TTL staleness check
        if self.ttl_seconds is not None and (time.time() - timestamp) > self.ttl_seconds:
            del self._cache[key]
            self._access_order.pop(key, None)
            return None

        # Update access order (LRU) - O(1) via OrderedDict
        self._access_order.pop(key, None)
        self._access_order[key] = None

        return content, size

    def set(self, key: str, content: str, size: int):
        """Set content in cache with LRU eviction"""
        if key in self._cache:
            # Update existing
            self._cache[key] = (content, size, time.time())
            self._access_order.pop(key, None)
            self._access_order[key] = None
            return

        # Check if we need to evict
        if len(self._cache) >= self.max_size and self._access_order:
            lru_key, _ = self._access_order.popitem(last=False)
            self._cache.pop(lru_key, None)

        # Add new entry
        self._cache[key] = (content, size, time.time())
        self._access_order[key] = None

    def clear(self):
        """Clear the cache"""
        self._cache.clear()
        self._access_order.clear()


class HTTPClientManager:
    """Manages HTTP client connections with connection pooling and reuse"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._logger = logging.getLogger("http_manager")
        # NEW: guards session creation against a check-then-create race
        # when multiple coroutines call get_session() concurrently before
        # any session exists.
        self._creation_lock = asyncio.Lock()

    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with connection pooling"""
        if self._session is None or self._session.closed:
            async with self._creation_lock:
                # Double-checked locking: another coroutine may have
                # created the session while we were waiting for the lock.
                if self._session is None or self._session.closed:
                    await self._create_session()
        return self._session

    async def _create_session(self):
        """Create HTTP session with optimized settings"""
        verify_ssl = self.config.get("verify_ssl", True)
        timeout = self.config.get("js_fetch_timeout", DEFAULT_FETCH_TIMEOUT)

        # Configure SSL context
        if verify_ssl:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = True
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

        # Create connector with connection pooling
        self._connector = aiohttp.TCPConnector(
            ssl=self._ssl_context,
            resolver=ScanResolver(self.config.get("allow_private_targets", False)),
            limit=self.config.get("max_connections", 100),
            limit_per_host=self.config.get("max_connections_per_host", 10),
            ttl_dns_cache=300,  # 5 minutes DNS cache
            enable_cleanup_closed=True,
            force_close=False,  # Keep-alive connections
            use_dns_cache=True
        )

        # Configure timeout
        client_timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=min(10, timeout),
            sock_read=max(0.1, timeout - 5),
            sock_connect=min(10, timeout)
        )

        # Create session with default headers
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=client_timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/javascript,text/javascript,*/*;q=0.9',
                'Accept-Language': 'en-US,en;q=0.9',
                # aiohttp advertises only encodings supported by this installation.
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'script',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'cross-site',
            },
            trust_env=False  # A proxy could bypass the scan resolver's address checks.
        )

    async def close(self):
        """Close HTTP session and connections"""
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self._connector = None


@dataclass
class AnalysisMetrics:
    """Comprehensive analysis metrics"""
    total_checks: int = 0
    patterns_matched: int = 0
    high_confidence_finds: int = 0
    processing_time: float = 0
    cache_hits: int = 0
    duplicates_skipped: int = 0
    content_downloaded: int = 0
    files_analyzed: int = 0
    http_errors: int = 0
    timeouts: int = 0
    circuit_breaker_hits: int = 0
    coalesced_fetches: int = 0  # NEW: count of requests that were deduped via in-flight coalescing

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_prometheus_text(self, scan_id: str = "") -> str:
        """
        NEW: render current metrics in Prometheus text exposition format.
        Dependency-free - no prometheus_client import required. Suitable
        for a /metrics scrape endpoint or for shipping to a pushgateway.
        """
        labels = f'{{scan_id="{scan_id}"}}' if scan_id else ""
        rows = [
            ("js_analysis_total_checks", self.total_checks),
            ("js_analysis_patterns_matched", self.patterns_matched),
            ("js_analysis_high_confidence_finds", self.high_confidence_finds),
            ("js_analysis_processing_time_seconds", self.processing_time),
            ("js_analysis_cache_hits", self.cache_hits),
            ("js_analysis_duplicates_skipped", self.duplicates_skipped),
            ("js_analysis_content_downloaded", self.content_downloaded),
            ("js_analysis_files_analyzed", self.files_analyzed),
            ("js_analysis_http_errors", self.http_errors),
            ("js_analysis_timeouts", self.timeouts),
            ("js_analysis_circuit_breaker_hits", self.circuit_breaker_hits),
            ("js_analysis_coalesced_fetches", self.coalesced_fetches),
        ]
        return "\n".join(f"{name}{labels} {value}" for name, value in rows) + "\n"


class EventCollector:
    """Collects events from analyzers for structured output with deduplication"""

    def __init__(self):
        self.endpoints: Set[str] = set()
        self.secrets: List[Dict[str, Any]] = []
        self._endpoint_hashes: Set[str] = set()
        self._secret_hashes: Set[str] = set()
        self.reset()

    def reset(self):
        """Reset all collected data"""
        self.endpoints.clear()
        self.secrets.clear()
        self._endpoint_hashes.clear()
        self._secret_hashes.clear()

    def collect_endpoint(self, event: Dict[str, Any]):
        data = event.get('data') if isinstance(event.get('data'), dict) else event
        endpoint = data.get('raw_value') or data.get('url')
        if event.get('event_type') == 'endpoint_found' and endpoint:
            self.endpoints.add(endpoint)

    def collect_secret(self, event: Dict[str, Any]):
        if event.get('event_type') != 'secret_found':
            return
        data = event.get('data') if isinstance(event.get('data'), dict) else event
        metadata = data.get('metadata') or {}
        fingerprint = data.get('fingerprint')
        key = (fingerprint or hashlib.sha256(str(data.get('raw_value', '')).encode()).hexdigest(),
               data.get('file_path') or data.get('source_url'), data.get('line_number'))
        if key in self._secret_hashes:
            return
        self._secret_hashes.add(key)
        allowed = ('type', 'category', 'severity', 'confidence', 'fingerprint', 'file_path', 'line_number',
                   'source_url', 'source_sha256', 'asset_id', 'coverage_policy', 'evidence_version', 'match_evidence_mask', 'match_length',
                   'code_context', 'context_start_line', 'context_end_line', 'context_truncated', 'validation_status',
                   'detector_policy', 'suppressed_by_local_policy', 'ignore_policy_sha256', 'provider_validation')
        item = {field: data[field] for field in allowed if field in data}
        item.setdefault('type', data.get('finding_type', 'Unknown'))
        item.setdefault('code_context', metadata.get('context'))
        item.setdefault('line_number', metadata.get('line_number'))
        # Structured results and artifact batches contain redacted evidence only.
        item['value'] = '[REDACTED]'
        self.secrets.append(item)


@dataclass
class JSAnalysisResult:
    """Enhanced JS analysis result with performance metrics"""
    js_url: str
    endpoints: List[str]
    secrets: List[Dict]
    content_hash: str
    file_size: int
    analysis_time: float
    confidence_score: float
    success: bool
    http_status: Optional[int] = None
    content_type: Optional[str] = None
    encoding: Optional[str] = None
    download_time: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    failure_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for event emission"""
        result = asdict(self)
        # Redact sensitive secret values in the dictionary
        for secret in result.get("secrets", []):
            if "value" in secret:
                secret["value"] = "[REDACTED]"
        return result


class _WrappedEmitter:
    """
    Enhanced event emitter wrapper with rate limiting and batching
    """

    def __init__(self, original_emitter, collector: EventCollector, scan_id: str):
        self._original = original_emitter
        self._collector = collector
        self._scan_id = scan_id
        self._emitted_count = 0

    async def emit(self, event: Dict[str, Any]):
        if event.get('event_type') == 'endpoint_found' and isinstance(event.get('data'), dict):
            from .evidence import redact_neighbors
            data = dict(event['data'])
            value = data.get('raw_value')
            if isinstance(value, str) and redact_neighbors(value) != value:
                return  # A detected credential literal is not an endpoint.
            for key in ('raw_value', 'url', 'source_url'):
                if isinstance(data.get(key), str):
                    data[key] = redact_neighbors(data[key])
            event = {**event, 'data': data}
        # Force scan_id
        event.setdefault("scan_id", self._scan_id)

        # Add timestamp if not present
        event.setdefault("timestamp", time.time())

        # Collect events
        if event.get("event_type") == "endpoint_found":
            self._collector.collect_endpoint(event)
        elif event.get("event_type") == "secret_found":
            self._collector.collect_secret(event)

        # Forward to the real emitter
        try:
            await self._original.emit(event)
            self._emitted_count += 1
        except Exception as e:
            logging.getLogger("wrapped_emitter").error("Finding delivery failed: %s", type(e).__name__)
            from ..events.outbox import DeliveryPending
            raise DeliveryPending('Finding evidence was not journaled') from e


class JSAnalysisEngine:
    """
    Production-grade JS analysis engine with superior error handling,
    performance optimizations, and enhanced leak detection.
    """

    def __init__(self, context: ExtractorContext):
        """
        Initialize extractor engine with shared scan context.

        Args:
            context: ExtractorContext containing shared state, config, and emitter
        """
        if context is None:
            raise ValueError("ExtractorContext cannot be None")

        # Shared context (single source of truth)
        self.context = context
        self.config = context.config
        self._fetch_final_urls = {}

        # Initialize components
        self._initialize_components()
        self._fetch_failures = OrderedDict()

        # Setup logging
        self.logger = logging.getLogger("js_analysis_engine")
        self.logger.info(f"[{self.context.scan_id}] JSAnalysisEngine initialized")

    def _initialize_components(self):
        """Initialize all engine components"""
        # Event / artifact collector
        self.collector = EventCollector()

        # HTTP client manager
        self.http_manager = HTTPClientManager(self.config)

        # Circuit breaker for URL failures
        # Defaults aligned with crawler.py's circuit breaker (5 failures /
        # 60s cooldown) so a single config value tunes both consistently,
        # and neither one can lock out a domain/URL for the whole scan on
        # a few transient failures.
        self.circuit_breaker = CircuitBreaker(
            max_failures=self.config.get("circuit_breaker_max_failures", 5),
            reset_timeout=self.config.get("circuit_breaker_reset_timeout", 60)
        )

        # Content cache
        cache_size = self.config.get("content_cache_size", 100)
        cache_ttl = self.config.get("content_cache_ttl_seconds", DEFAULT_CACHE_TTL_SECONDS)
        self.content_cache = ContentCache(max_size=cache_size, ttl_seconds=cache_ttl)

        # Stateless extractors (safe to recreate)
        self.link_extractor = LinkExtractor(
            base_url=self.config.get("base_url") or self.config.get("target_url")
        )

        self.secret_scanner = SecretScanner(
            aggressive=self.config.get("aggressive_secrets", True)
        )

        # Analysis metrics
        self.metrics = AnalysisMetrics()

        # Domain handling
        self.domain = (
            self.config.get("domain")
            or self.config.get("base_domain")
            or ""
        )

        # NEW: bounds how many JS fetches this engine instance runs in
        # parallel. Previously DEFAULT_CONCURRENT_REQUESTS was defined
        # but never actually used anywhere.
        self._fetch_semaphore = asyncio.Semaphore(
            self.config.get("max_concurrent_js_fetches", DEFAULT_CONCURRENT_REQUESTS)
        )

        # NEW: in-flight request coalescing. Maps js_url -> asyncio.Future
        # of the eventual (content, file_size, http_status, content_type,
        # download_time) tuple, so duplicate concurrent requests for the
        # same URL share one fetch instead of hitting the network twice.
        self._in_flight_fetches: Dict[str, "asyncio.Future"] = {}

    async def __aenter__(self):
        """NEW: optional async context manager support."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """NEW: ensures cleanup() runs when used as `async with JSAnalysisEngine(...)`."""
        await self.cleanup()

    def _wrap_event_emitter(self, original_emitter):
        """Wrap the event emitter for event collection"""
        return _WrappedEmitter(
            original_emitter,
            self.collector,
            self.context.scan_id
        )

    def _generate_content_hash(self, content: str) -> str:
        """Generate hash for content deduplication with normalization"""
        if not content:
            return ""
        # Normalize content for consistent hashing
        normalized = content.strip()
        normalized = normalized.replace('\r\n', '\n')
        normalized = normalized.replace('\r', '\n')
        # Remove excessive whitespace
        lines = [line.strip() for line in normalized.split('\n') if line.strip()]
        normalized = '\n'.join(lines)
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

    def _is_duplicate_content(self, content_hash: str) -> bool:
        """Check if content is duplicate with proper deduplication"""
        content_hashes = self.context.shared_state.setdefault("content_hashes", set())

        if content_hash in content_hashes:
            self.metrics.duplicates_skipped += 1
            return True

        return False

    def _failed_fetch(self, js_url, reason, status=None, content_type=None):
        if reason == "http_error":
            reason = ("access_denied" if status in {401, 403} else
                      "resource_missing" if status in {404, 410} else
                      "rate_limited" if status == 429 else
                      "server_error" if isinstance(status, int) and 500 <= status <= 599 else reason)
        self._fetch_failures[js_url] = reason
        self._fetch_failures.move_to_end(js_url)
        while len(self._fetch_failures) > 100:
            self._fetch_failures.popitem(last=False)
        return None, 0, status, content_type, 0.0

    async def _fetch_js_content_with_retry(
        self,
        js_url: str,
        max_retries: int = None,
        timeout: int = None
    ) -> Tuple[Optional[str], int, Optional[int], Optional[str], float]:
        """
        Fetch JS content with intelligent retry logic, timeout handling,
        and comprehensive error recovery.

        CHANGED: this is now a thin coordination layer around
        _fetch_js_content_core() - it handles the circuit breaker check,
        cache check, and request coalescing, then delegates the actual
        network fetch (semaphore-bounded, deadline-bounded) to the core
        method. The retry/backoff/validation logic itself is unchanged,
        just moved into _fetch_js_content_core().
        """

        if not self.circuit_breaker.is_allowed(js_url):
            self.metrics.circuit_breaker_hits += 1
            self.logger.debug(f"[{self.context.scan_id}] Circuit breaker blocked: {js_url}")
            return self._failed_fetch(js_url, "circuit_open")

        # Cache check
        cache_key = f"content_{hashlib.md5(js_url.encode()).hexdigest()}"
        cached = self.content_cache.get(cache_key)
        if cached:
            self.metrics.cache_hits += 1
            content, file_size = cached
            return content, file_size, 200, "application/javascript", 0.0

        # NEW: request coalescing - if another coroutine is already
        # fetching this exact URL, await its result instead of firing a
        # duplicate network request.
        existing_future = self._in_flight_fetches.get(js_url)
        if existing_future is not None:
            self.metrics.coalesced_fetches += 1
            self.logger.debug(f"[{self.context.scan_id}] Coalescing duplicate in-flight fetch: {js_url}")
            return await asyncio.shield(existing_future)

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._in_flight_fetches[js_url] = future

        try:
            result = await self._fetch_js_content_core(js_url, max_retries, timeout)
            if not future.done():
                future.set_result(result)
            return result
        except asyncio.CancelledError:
            if not future.done():
                future.cancel()
            raise
        except Exception as e:
            if not future.done():
                future.set_exception(e)
            raise
        finally:
            # Only this coroutine (the one that created the future) removes
            # it, so late-arriving coalesced callers that already grabbed
            # a reference to `future` above can still safely await it.
            self._in_flight_fetches.pop(js_url, None)

    async def _fetch_js_content_core(
        self,
        js_url: str,
        max_retries: int = None,
        timeout: int = None
    ) -> Tuple[Optional[str], int, Optional[int], Optional[str], float]:
        """
        NEW: semaphore-bounded, deadline-bounded wrapper around the
        original retry loop (now _fetch_js_content_retry_loop). Ensures
        this engine instance never has more than max_concurrent_js_fetches
        network fetches in flight at once, and that no single URL's
        retries + backoff + 429 waits can run past a total deadline.
        """
        max_retries = max_retries or self.config.get("js_fetch_retries", DEFAULT_RETRY_ATTEMPTS)
        timeout = timeout or self.config.get("js_fetch_timeout", DEFAULT_FETCH_TIMEOUT)
        total_deadline = fetch_deadline({**self.config, "js_fetch_timeout": timeout,
                                        "js_fetch_retries": max_retries})

        async with self._fetch_semaphore:
            try:
                return await asyncio.wait_for(
                    self._fetch_js_content_retry_loop(js_url, max_retries, timeout),
                    timeout=total_deadline
                )
            except AsyncTimeoutError:
                self.metrics.timeouts += 1
                self.circuit_breaker.record_failure(js_url)
                self.logger.warning(
                    f"[{self.context.scan_id}] Total fetch deadline ({total_deadline}s) "
                    f"exceeded for {js_url}"
                )
                return self._failed_fetch(js_url, "download_timeout")

    async def _fetch_js_content_retry_loop(
        self,
        js_url: str,
        max_retries: int,
        timeout: int
    ) -> Tuple[Optional[str], int, Optional[int], Optional[str], float]:
        """
        Original retry loop, unchanged in logic - only renamed and moved
        out of _fetch_js_content_with_retry so it can be wrapped by the
        semaphore + total deadline in _fetch_js_content_core().
        """
        download_start = time.time()

        for attempt in range(max_retries):
            try:
                session = await self.http_manager.get_session()

                if attempt > 0:
                    backoff = min(2 ** attempt, 30)
                    await asyncio.sleep(backoff)

                async with guarded_get(session,
                    js_url,
                    in_scope=getattr(self.context, "scope_check", None),
                    allow_private=self.config.get("allow_private_targets", False),
                    raise_for_status=False
                ) as response:

                    http_status = response.status
                    content_type = response.headers.get("Content-Type", "")

                    if http_status not in {200, 204}:
                        self.metrics.http_errors += 1

                        if 400 <= http_status < 500 and http_status != 429:
                            self.circuit_breaker.record_failure(js_url)
                            self.logger.warning(f"[{self.context.scan_id}] Client error {http_status} for {js_url}")
                            return self._failed_fetch(js_url, "http_error", http_status, content_type)

                        if http_status == 429:
                            retry_after = response.headers.get("Retry-After", "5")
                            try:
                                delay = float(retry_after)
                                await asyncio.sleep(min(max(delay, 0), 30) if delay == delay else 5)
                            except (ValueError, OverflowError):
                                await asyncio.sleep(5)
                            continue

                        if 500 <= http_status < 600:
                            if attempt < max_retries - 1:
                                continue
                            self.circuit_breaker.record_failure(js_url)
                            return self._failed_fetch(js_url, "http_error", http_status, content_type)
                        return self._failed_fetch(js_url, "http_error", http_status, content_type)

                    content_length = response.headers.get("Content-Length")
                    max_size = self.config.get("max_js_file_size", MAX_JS_FILE_SIZE)

                    if content_length:
                        try:
                            file_size = int(content_length)
                        except ValueError:
                            file_size = 0  # Streaming still enforces the size limit.
                        if file_size > max_size:
                            self.logger.warning(f"[{self.context.scan_id}] JS file too large: {js_url}")
                            self.circuit_breaker.record_failure(js_url)
                            return self._failed_fetch(js_url, "response_limit", http_status, content_type)

                    content_bytes = bytearray()
                    async for chunk in response.content.iter_chunked(CHUNK_READ_SIZE):
                        content_bytes.extend(chunk)
                        if len(content_bytes) > max_size:
                            self.logger.warning(f"[{self.context.scan_id}] JS file exceeds size limit: {js_url}")
                            self.circuit_breaker.record_failure(js_url)
                            return self._failed_fetch(js_url, "response_limit", http_status, content_type)

                    file_size = len(content_bytes)

                    if http_status != 204 and not self._validate_js_content(content_bytes, content_type):
                        self.circuit_breaker.record_failure(js_url)
                        return self._failed_fetch(js_url, "invalid_content", http_status, content_type)

                    # DO NOT call response.get_encoding()
                    encoding = response.charset or "utf-8"

                    try:
                        content = content_bytes.decode(encoding, errors="replace")
                    except (UnicodeDecodeError, LookupError):
                        for enc in ("utf-8", "latin-1", "iso-8859-1", "cp1252"):
                            try:
                                content = content_bytes.decode(enc, errors="replace")
                                encoding = enc
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            self.circuit_breaker.record_failure(js_url)
                            return self._failed_fetch(js_url, "invalid_content", http_status, content_type)

                    cache_key = f"content_{hashlib.md5(js_url.encode()).hexdigest()}"
                    self.content_cache.set(cache_key, content, file_size)
                    self.circuit_breaker.record_success(js_url)
                    self._fetch_failures.pop(js_url, None)
                    self._fetch_final_urls[js_url] = str(response.url)
                    self.metrics.content_downloaded += 1

                    download_time = time.time() - download_start
                    return content, file_size, http_status, content_type, download_time

            except (aiohttp.ClientError, socket.gaierror) as e:
                self.metrics.http_errors += 1
                self.logger.warning(
                    f"[{self.context.scan_id}] Network error fetching {js_url} "
                    f"(attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt >= max_retries - 1:
                    self.circuit_breaker.record_failure(js_url)
                    return self._failed_fetch(js_url, "download_timeout" if isinstance(e, AsyncTimeoutError) else "network_error")

            except AsyncTimeoutError:
                self.metrics.timeouts += 1
                self.logger.warning(
                    f"[{self.context.scan_id}] Timeout fetching {js_url} (attempt {attempt + 1}/{max_retries})"
                )
                if attempt >= max_retries - 1:
                    self.circuit_breaker.record_failure(js_url)
                    return self._failed_fetch(js_url, "download_timeout")

            except asyncio.CancelledError:
                raise

            except Exception as e:
                self.logger.error(f"[{self.context.scan_id}] Unexpected error fetching {js_url}: {e}", exc_info=True)
                self.circuit_breaker.record_failure(js_url)
                from ..utils.pipeline import PipelineError
                reason = "scope_refused" if isinstance(e, PipelineError) else "download_error"
                return self._failed_fetch(js_url, reason)

        self.circuit_breaker.record_failure(js_url)
        return self._failed_fetch(js_url, "http_error", 429)

    def _validate_js_content(self, content_bytes: bytes, content_type: str) -> bool:
        """
        Validate that content is actually JavaScript.

        Args:
            content_bytes: Raw content bytes
            content_type: HTTP Content-Type header

        Returns:
            True if content appears to be valid JavaScript
        """
        if not content_bytes:
            return any(t in content_type.lower() for t in ("javascript", "ecmascript"))
        if content_bytes.count(b'\x00') / len(content_bytes) >= 0.01:
            return False
        prefix = content_bytes[:512].lstrip().lower()
        if prefix.startswith((b'<!doctype html', b'<html', b'<body')):
            return False

        # Check content type
        content_type_lower = content_type.lower()
        if 'javascript' in content_type_lower or 'ecmascript' in content_type_lower or 'application/json' in content_type_lower:
            return True

        # Check for common JS patterns in first 1KB
        sample = content_bytes[:1024].decode('ascii', errors='ignore')

        # Check for JavaScript keywords
        js_keywords = ['function', 'var ', 'let ', 'const ', 'return ', 'if ', 'for ', 'while ']
        keyword_count = sum(1 for keyword in js_keywords if keyword in sample)

        # Check for common JS patterns
        js_patterns = ['() =>', '=>', '{', '}', ';', '=', '//', '/*']
        pattern_count = sum(1 for pattern in js_patterns if pattern in sample)

        # Check for binary content
        null_bytes = content_bytes.count(b'\x00')
        null_ratio = null_bytes / max(1, len(content_bytes))

        # Heuristic: If it has JS keywords or patterns and isn't binary, it's probably JS
        if (keyword_count >= 2 or pattern_count >= 3) and null_ratio < 0.01:
            return True

        return False

    async def analyze_js_content(self, js_url: str, content: Optional[str] = None, acquisition: Optional[str] = None) -> JSAnalysisResult:
        """
        Analyze JS content with comprehensive error handling and performance tracking.

        Args:
            js_url: URL of the JavaScript file
            content: Optional pre-fetched content (for testing/caching)

        Returns:
            JSAnalysisResult with analysis findings
        """
        analysis_start = time.time()

        # Reset collector for this analysis
        # Each concurrent asset owns its collector and emitter context.
        import copy
        collector = EventCollector()
        analysis_context = copy.copy(self.context)
        if acquisition:
            analysis_context.shared_state = {**self.context.shared_state, 'acquisition_policy':acquisition}
        analysis_context.event_emitter = _WrappedEmitter(self.context.event_emitter, collector, self.context.scan_id)

        # Update metrics
        self.metrics.files_analyzed += 1

        # Track download separately
        download_time = 0.0
        http_status = None
        content_type = None
        encoding = None

        # Download content if not provided
        if content is None:
            try:
                content, file_size, http_status, content_type, download_time = \
                    await self._fetch_js_content_with_retry(js_url)

                if content is None:
                    # Emit detailed failure event
                    await emit_event(
                        self.context,
                        event_type="js_download_failed",
                        data={
                            "js_url": js_url,
                            "reason": self._fetch_failures.get(js_url, "download_error"),
                            "http_status": http_status,
                            "timestamp": time.time(),
                            "attempts": self.config.get("js_fetch_retries", DEFAULT_RETRY_ATTEMPTS)
                        }
                    )

                    return JSAnalysisResult(
                        js_url=js_url,
                        endpoints=[],
                        secrets=[],
                        content_hash="",
                        file_size=0,
                        analysis_time=time.time() - analysis_start,
                        confidence_score=0.0,
                        success=False,
                        http_status=http_status,
                        content_type=content_type,
                        download_time=download_time,
                        error="Failed to fetch content",
                        failure_reason=self._fetch_failures.get(js_url, "download_error")
                    )
            except asyncio.CancelledError:
                self.logger.debug(f"[{self.context.scan_id}] Analysis cancelled during fetch for {js_url}")
                raise
            except Exception as e:
                self.logger.error(f"[{self.context.scan_id}] Unexpected error during fetch for {js_url}: {e}", exc_info=True)
                return JSAnalysisResult(
                    js_url=js_url,
                    endpoints=[],
                    secrets=[],
                    content_hash="",
                    file_size=0,
                    analysis_time=time.time() - analysis_start,
                    confidence_score=0.0,
                    success=False,
                    error=type(e).__name__,
                    failure_reason="download_error"
                )
        else:
            file_size = len(content.encode('utf-8'))
            http_status = 200
            content_type = 'application/javascript'

        # Check for duplicate content
        content_hash = self._generate_content_hash(content)
        if self._is_duplicate_content(content_hash):
            # Emit duplicate event
            await emit_event(
                self.context,
                event_type="js_duplicate_skipped",
                data={
                    "js_url": js_url,
                    "content_hash": content_hash,
                    "file_size": file_size,
                    "timestamp": time.time()
                }
            )

            return JSAnalysisResult(
                js_url=js_url,
                endpoints=[],
                secrets=[],
                content_hash=content_hash,
                file_size=file_size,
                analysis_time=time.time() - analysis_start,
                confidence_score=0.0,
                success=True,
                http_status=http_status,
                content_type=content_type,
                download_time=download_time,
                metadata={"duplicate_skipped": True}
            )

        # Wrap event emitter for this analysis
        original_emitter = self.context.event_emitter

        try:
            # Set base URL for extractor
            link_extractor = LinkExtractor(base_url=js_url)

            # Run extractors with timeout
            extract_timeout = self.config.get("extraction_timeout", 60)
            extraction_tasks = [
                asyncio.create_task(link_extractor.extract(content, js_url, analysis_context)),
                asyncio.create_task(self.secret_scanner.scan(content, js_url, analysis_context)),
            ]

            try:
                async with asyncio.timeout(extract_timeout):
                    # Run extractors in parallel if they support it
                    await asyncio.gather(*extraction_tasks)
            except AsyncTimeoutError:
                self.logger.warning(f"[{self.context.scan_id}] Extraction timeout for {js_url}")
                # Partial extraction is not a successful file analysis.
                raise
            finally:
                # gather does not cancel siblings when one extractor raises.
                for task in extraction_tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*extraction_tasks, return_exceptions=True)

        except asyncio.CancelledError:
            self.logger.debug(f"[{self.context.scan_id}] Analysis cancelled during extraction for {js_url}")
            raise
        except Exception as e:
            from ..events.outbox import DeliveryPending
            if isinstance(e, DeliveryPending):
                raise
            self.logger.error("[%s] Extraction failed for %s (%s)", self.context.scan_id, js_url, type(e).__name__)
            raise
        finally:
            # Restore original emitter
            pass  # The shared emitter was never modified.

        # Calculate confidence score
        confidence = self._calculate_confidence_score(
            list(collector.endpoints),
            collector.secrets,
            file_size
        )

        # Calculate analysis time
        analysis_time = time.time() - analysis_start

        # Build result
        result = JSAnalysisResult(
            js_url=js_url,
            endpoints=list(collector.endpoints),
            secrets=collector.secrets,
            content_hash=content_hash,
            file_size=file_size,
            analysis_time=analysis_time,
            confidence_score=confidence,
            success=True,
            http_status=http_status,
            content_type=content_type,
            download_time=download_time,
            metadata={
                "endpoint_count": len(collector.endpoints),
                "secret_count": len(collector.secrets),
                "analysis_duration": analysis_time
            }
        )

        # Emit analysis completion event
        try:
            await emit_event(
                self.context,
                event_type="js_analysis_complete",
                # Findings already travel individually and in bounded artifact
                # batches. Repeating a large bundle's full results here can
                # exceed the outbox limit despite successful evidence delivery.
                data={"resource_id": hashlib.sha256(js_url.encode()).hexdigest(),
                      "content_hash": content_hash, "file_size": file_size,
                      "endpoint_count": len(result.endpoints), "secret_count": len(result.secrets),
                      "analysis_time": analysis_time, "success": True}
            )
        except Exception as e:
            self.logger.error("[%s] Analysis completion evidence failed (%s)", self.context.scan_id, type(e).__name__)
            raise

        self.context.shared_state.setdefault("content_hashes", set()).add(content_hash)
        return result

    def _calculate_confidence_score(self, endpoints: List[str], secrets: List[Dict], file_size: int) -> float:
        """Calculate confidence score based on findings quality and quantity"""
        score = 0.0

        # Endpoints contribute to score (more endpoints = higher confidence)
        if endpoints:
            unique_endpoints = len(set(endpoints))
            endpoint_score = min(unique_endpoints * 0.15, 0.6)
            score += endpoint_score

        # Secrets contribute significantly (weighted by confidence)
        if secrets:
            total_secret_confidence = sum(secret.get('confidence', 0) for secret in secrets)
            secret_count = len(secrets)
            secret_score = min((total_secret_confidence * 0.4) + (secret_count * 0.1), 0.8)
            score += secret_score

        # File size indicates importance (larger files often have more code)
        if file_size > 50000:  # 50KB+
            score += 0.25
        elif file_size > 10000:  # 10KB+
            score += 0.15
        elif file_size > 1000:  # 1KB+
            score += 0.05

        # Normalize score
        return min(max(score, 0.0), 1.0)

    async def analyze(self, js_url: str) -> Dict[str, Any]:
        """
        Public analyzer entrypoint expected by orchestrator.
        Enhanced with comprehensive error handling.

        Args:
            js_url: URL of JavaScript file to analyze

        Returns:
            Analysis results as dictionary
        """
        try:
            captured = self.context.shared_state.get('browser_scripts', {}).pop(js_url, None)
            if captured is not None:
                self._fetch_final_urls[js_url] = js_url
            result = await self.analyze_js_content(js_url, captured, acquisition='browser_response_v1') if captured is not None else await self.analyze_js_content(js_url)

            if result:
                result_dict = result.to_dict()
                from ..asset_coverage import observe, canonical_asset_url
                if not result.success or js_url not in self._fetch_final_urls or result.http_status != 200:
                    outcome = 'unavailable'
                elif result.metadata.get('duplicate_skipped'):
                    outcome = 'duplicate'
                elif canonical_asset_url(self._fetch_final_urls.get(js_url, js_url)) != canonical_asset_url(js_url):
                    outcome = 'redirected'
                else:
                    outcome = 'analyzed'
                receipt_context = self.context
                if captured is not None:
                    import copy
                    self.context.shared_state.setdefault('observed_assets', {})
                    receipt_context = copy.copy(self.context)
                    receipt_context.shared_state = {**self.context.shared_state, 'acquisition_policy':'browser_response_v1'}
                await observe(receipt_context, js_url, 'javascript', outcome, result.content_hash or None)
                # Add metrics to result
                result_dict["metrics"] = self.metrics.to_dict()
                return result_dict
            else:
                return {
                    "js_url": js_url,
                    "success": False,
                    "error": "Analysis returned no result",
                    "metrics": self.metrics.to_dict()
                }

        except asyncio.CancelledError:
            self.logger.debug(f"[{self.context.scan_id}] Analysis cancelled for {js_url}")
            raise
        except Exception as e:
            self.logger.error("[%s] Analysis failed for %s (%s)", self.context.scan_id, js_url, type(e).__name__)
            from ..events.outbox import DeliveryPending
            if isinstance(e, DeliveryPending):
                raise
            return {
                "js_url": js_url,
                "success": False,
                "error": type(e).__name__,
                "failure_reason": "extraction_timeout" if isinstance(e, AsyncTimeoutError) else "analysis_error",
                "metrics": self.metrics.to_dict()
            }

    def get_health_status(self) -> Dict[str, Any]:
        """
        NEW: lightweight health snapshot for orchestrator-level monitoring
        or a /health endpoint. Read-only - does not mutate any state.
        """
        open_circuits = [
            url for url, (failures, _) in self.circuit_breaker._failures.items()
            if failures >= self.circuit_breaker.max_failures
        ]
        return {
            "scan_id": self.context.scan_id,
            "session_active": bool(self.http_manager._session and not self.http_manager._session.closed),
            "open_circuit_count": len(open_circuits),
            "open_circuits_sample": open_circuits[:5],
            "cache_size": len(self.content_cache._cache),
            "in_flight_fetches": len(self._in_flight_fetches),
            "available_fetch_slots": self._fetch_semaphore._value if hasattr(self._fetch_semaphore, "_value") else None,
        }

    def reset(self):
        """Reset analyzer state"""
        self.collector.reset()
        self.metrics = AnalysisMetrics()

    async def cleanup(self):
        """Cleanup resources"""
        await self.http_manager.close()
        self.content_cache.clear()
        # FIXED: previously reset to CircuitBreaker() with hardcoded
        # defaults (max_failures=3, reset_timeout=300), silently
        # discarding the configured circuit_breaker_max_failures /
        # circuit_breaker_reset_timeout for the rest of the engine's
        # lifetime after any cleanup() call. Now rebuilt from config,
        # same as _initialize_components() does.
        self.circuit_breaker = CircuitBreaker(
            max_failures=self.config.get("circuit_breaker_max_failures", 5),
            reset_timeout=self.config.get("circuit_breaker_reset_timeout", 60)
        )
        self.logger.debug(f"[{self.context.scan_id}] JSAnalysisEngine cleanup complete")


# Backward compatibility - original class names
JSAnalyzer = JSAnalysisEngine
EnterpriseJSAnalyzer = JSAnalysisEngine

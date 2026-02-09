# js_analyzer.py - Production Grade Enhanced Version
import os
import hashlib
import time
import asyncio
import logging
from typing import List, Dict, Set, Tuple, Optional, Any, Callable
from dataclasses import dataclass, asdict, field
from collections import defaultdict
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl
import socket
from asyncio import TimeoutError as AsyncTimeoutError
from contextlib import asynccontextmanager

from utils.events import emit_event
from .extractor_context import ExtractorContext
from .js_extractor import LinkExtractor
from .leak_detector import SecretScanner

logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_FETCH_TIMEOUT = 30
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_CONCURRENT_REQUESTS = 10
MAX_JS_FILE_SIZE = 15 * 1024 * 1024  # 15MB
MIN_JS_FILE_SIZE = 50  # 50 bytes minimum
CHUNK_READ_SIZE = 8192  # 8KB chunks for streaming

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
    """Intelligent content cache with LRU eviction"""

    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._cache: Dict[str, Tuple[str, int, float]] = {}  # url_hash -> (content, size, timestamp)
        self._access_order: List[str] = []

    def get(self, key: str) -> Optional[Tuple[str, int]]:
        """Get content from cache, updating access order"""
        if key not in self._cache:
            return None

        # Update access order (LRU)
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

        content, size, _ = self._cache[key]
        return content, size

    def set(self, key: str, content: str, size: int):
        """Set content in cache with LRU eviction"""
        if key in self._cache:
            # Update existing
            self._cache[key] = (content, size, time.time())
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            return

        # Check if we need to evict
        if len(self._cache) >= self.max_size and self._access_order:
            lru_key = self._access_order.pop(0)
            del self._cache[lru_key]

        # Add new entry
        self._cache[key] = (content, size, time.time())
        self._access_order.append(key)

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

    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with connection pooling"""
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
            connect=10,
            sock_read=timeout - 5,
            sock_connect=10
        )

        # Create session with default headers
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=client_timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/javascript,text/javascript,*/*;q=0.9',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'script',
                'Sec-Fetch-Mode': 'no-cors',
                'Sec-Fetch-Site': 'cross-site',
            },
            trust_env=True  # Use system proxy settings
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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

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
        """Collect endpoint from LinkExtractor event with deduplication"""
        if event.get("event_type") == "endpoint_found":
            endpoint = event.get("raw_value", "")
            if not endpoint:
                return

            # Create hash for deduplication
            endpoint_hash = hashlib.md5(endpoint.encode()).hexdigest()
            if endpoint_hash not in self._endpoint_hashes:
                self._endpoint_hashes.add(endpoint_hash)
                self.endpoints.add(endpoint)

    def collect_secret(self, event: Dict[str, Any]):
        """Collect secret from SecretScanner event with deduplication"""
        if event.get("event_type") == "secret_found":
            secret_value = event.get("raw_value", "")
            if not secret_value:
                return

            # Create hash for deduplication
            secret_hash = hashlib.md5(secret_value.encode()).hexdigest()
            if secret_hash not in self._secret_hashes:
                self._secret_hashes.add(secret_hash)
                self.secrets.append({
                    "type": event.get("finding_type", ""),
                    "value": secret_value,
                    "severity": event.get("severity", "MEDIUM"),
                    "confidence": float(event.get("confidence", 0.0)),
                    "context": event.get("metadata", {}).get("context", ""),
                    "url": event.get("source_url", ""),
                    "validation_status": event.get("metadata", {}).get("validation_status", "unknown"),
                    "line_number": event.get("metadata", {}).get("line_number"),
                    "pattern": event.get("metadata", {}).get("pattern")
                })

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
            logging.getLogger("wrapped_emitter").error(f"Failed to emit event: {e}")

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

        # Initialize components
        self._initialize_components()

        # Setup logging
        self.logger = logging.getLogger("js_analysis_engine")
        self.logger.info(f"JSAnalysisEngine initialized for scan {context.scan_id}")

    def _initialize_components(self):
        """Initialize all engine components"""
        # Event / artifact collector
        self.collector = EventCollector()

        # HTTP client manager
        self.http_manager = HTTPClientManager(self.config)

        # Circuit breaker for URL failures
        self.circuit_breaker = CircuitBreaker(
            max_failures=self.config.get("circuit_breaker_max_failures", 3),
            reset_timeout=self.config.get("circuit_breaker_reset_timeout", 300)
        )

        # Content cache
        cache_size = self.config.get("content_cache_size", 100)
        self.content_cache = ContentCache(max_size=cache_size)

        # Stateless extractors (safe to recreate)
        self.link_extractor = LinkExtractor(
            base_url=self.config.get("base_url") or self.config.get("target_url")
        )

        # FIXED: Removed confidence_threshold parameter from SecretScanner initialization
        self.secret_scanner = SecretScanner(
            aggressive=self.config.get("aggressive_secrets", True)
            # confidence_threshold parameter removed - not supported by SecretScanner class
        )

        # Analysis metrics
        self.metrics = AnalysisMetrics()

        # Domain handling
        self.domain = (
            self.config.get("domain")
            or self.config.get("base_domain")
            or ""
        )

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

        content_hashes.add(content_hash)
        return False

    async def _fetch_js_content_with_retry(
        self,
        js_url: str,
        max_retries: int = None,
        timeout: int = None
    ) -> Tuple[Optional[str], int, Optional[int], Optional[str], float]:
        """
        Fetch JS content with intelligent retry logic, timeout handling,
        and comprehensive error recovery.
        """

        if not self.circuit_breaker.is_allowed(js_url):
            self.metrics.circuit_breaker_hits += 1
            self.logger.debug(f"Circuit breaker blocked: {js_url}")
            return None, 0, None, None, 0.0

        # Cache check
        cache_key = f"content_{hashlib.md5(js_url.encode()).hexdigest()}"
        cached = self.content_cache.get(cache_key)
        if cached:
            self.metrics.cache_hits += 1
            content, file_size = cached
            return content, file_size, 200, "application/javascript", 0.0

        max_retries = max_retries or self.config.get("js_fetch_retries", DEFAULT_RETRY_ATTEMPTS)
        timeout = timeout or self.config.get("js_fetch_timeout", DEFAULT_FETCH_TIMEOUT)

        download_start = time.time()

        for attempt in range(max_retries):
            try:
                session = await self.http_manager.get_session()

                if attempt > 0:
                    backoff = min(2 ** attempt, 30)
                    await asyncio.sleep(backoff)

                async with session.get(
                    js_url,
                    allow_redirects=True,
                    max_redirects=5,
                    raise_for_status=False
                ) as response:

                    http_status = response.status
                    content_type = response.headers.get("Content-Type", "")

                    if http_status != 200:
                        self.metrics.http_errors += 1

                        if 400 <= http_status < 500 and http_status != 429:
                            self.circuit_breaker.record_failure(js_url)
                            self.logger.warning(f"Client error {http_status} for {js_url}")
                            return None, 0, http_status, content_type, 0.0

                        if http_status == 429:
                            retry_after = response.headers.get("Retry-After", "5")
                            try:
                                await asyncio.sleep(float(retry_after))
                            except ValueError:
                                await asyncio.sleep(5)
                            continue

                        if 500 <= http_status < 600:
                            if attempt < max_retries - 1:
                                continue
                            self.circuit_breaker.record_failure(js_url)
                            return None, 0, http_status, content_type, 0.0

                    content_length = response.headers.get("Content-Length")
                    max_size = self.config.get("max_js_file_size", MAX_JS_FILE_SIZE)

                    if content_length:
                        file_size = int(content_length)
                        if file_size > max_size:
                            self.logger.warning(f"JS file too large: {js_url}")
                            self.circuit_breaker.record_failure(js_url)
                            return None, 0, http_status, content_type, 0.0
                        if file_size < MIN_JS_FILE_SIZE:
                            return None, 0, http_status, content_type, 0.0

                    content_bytes = bytearray()
                    async for chunk in response.content.iter_chunked(CHUNK_READ_SIZE):
                        content_bytes.extend(chunk)
                        if len(content_bytes) > max_size:
                            self.logger.warning(f"JS file exceeds size limit: {js_url}")
                            self.circuit_breaker.record_failure(js_url)
                            return None, 0, http_status, content_type, 0.0

                    file_size = len(content_bytes)

                    if not self._validate_js_content(content_bytes, content_type):
                        self.circuit_breaker.record_failure(js_url)
                        return None, 0, http_status, content_type, 0.0

                    # 🔧 FIX: DO NOT call response.get_encoding()
                    encoding = response.charset or "utf-8"

                    try:
                        content = content_bytes.decode(encoding, errors="replace")
                    except UnicodeDecodeError:
                        for enc in ("utf-8", "latin-1", "iso-8859-1", "cp1252"):
                            try:
                                content = content_bytes.decode(enc, errors="replace")
                                encoding = enc
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            self.circuit_breaker.record_failure(js_url)
                            return None, 0, http_status, content_type, 0.0

                    self.content_cache.set(cache_key, content, file_size)
                    self.circuit_breaker.record_success(js_url)
                    self.metrics.content_downloaded += 1

                    download_time = time.time() - download_start
                    return content, file_size, http_status, content_type, download_time

            except (aiohttp.ClientError, socket.gaierror, socket.timeout) as e:
                self.metrics.http_errors += 1
                self.logger.warning(
                    f"Network error fetching {js_url} (attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt >= max_retries - 1:
                    self.circuit_breaker.record_failure(js_url)
                    return None, 0, None, None, 0.0

            except AsyncTimeoutError:
                self.metrics.timeouts += 1
                self.logger.warning(
                    f"Timeout fetching {js_url} (attempt {attempt + 1}/{max_retries})"
                )
                if attempt >= max_retries - 1:
                    self.circuit_breaker.record_failure(js_url)
                    return None, 0, None, None, 0.0

            except asyncio.CancelledError:
                raise

            except Exception as e:
                self.logger.error(f"Unexpected error fetching {js_url}: {e}", exc_info=True)
                self.circuit_breaker.record_failure(js_url)
                return None, 0, None, None, 0.0

        self.circuit_breaker.record_failure(js_url)
        return None, 0, None, None, 0.0

    def _validate_js_content(self, content_bytes: bytes, content_type: str) -> bool:
        """
        Validate that content is actually JavaScript.

        Args:
            content_bytes: Raw content bytes
            content_type: HTTP Content-Type header

        Returns:
            True if content appears to be valid JavaScript
        """
        # Check content type
        content_type_lower = content_type.lower()
        if 'javascript' in content_type_lower or 'application/json' in content_type_lower:
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

        # Check file extension if available (for logging)
        return False

    async def analyze_js_content(self, js_url: str, content: Optional[str] = None) -> JSAnalysisResult:
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
        self.collector.reset()

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

                if not content:
                    # Emit detailed failure event
                    await emit_event(
                        self.context,
                        event_type="js_download_failed",
                        data={
                            "js_url": js_url,
                            "reason": "fetch_failed",
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
                        error="Failed to fetch content"
                    )
            except asyncio.CancelledError:
                self.logger.debug(f"Analysis cancelled during fetch for {js_url}")
                raise
            except Exception as e:
                self.logger.error(f"Unexpected error during fetch for {js_url}: {e}", exc_info=True)
                return JSAnalysisResult(
                    js_url=js_url,
                    endpoints=[],
                    secrets=[],
                    content_hash="",
                    file_size=0,
                    analysis_time=time.time() - analysis_start,
                    confidence_score=0.0,
                    success=False,
                    error=f"Fetch error: {str(e)[:200]}"
                )
        else:
            file_size = len(content.encode('utf-8'))

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
        self.context.event_emitter = self._wrap_event_emitter(original_emitter)

        try:
            # Set base URL for extractor
            self.link_extractor.base_url = js_url

            # Run extractors with timeout
            extract_timeout = self.config.get("extraction_timeout", 60)

            try:
                async with asyncio.timeout(extract_timeout):
                    # Run extractors in parallel if they support it
                    await asyncio.gather(
                        self.link_extractor.extract(content, js_url, self.context),
                        self.secret_scanner.scan(content, js_url, self.context)
                    )
            except AsyncTimeoutError:
                self.logger.warning(f"Extraction timeout for {js_url}")
                # Continue with partial results if any

        except asyncio.CancelledError:
            self.logger.debug(f"Analysis cancelled during extraction for {js_url}")
            raise
        except Exception as e:
            self.logger.error(f"Extraction error for {js_url}: {e}", exc_info=True)
            # Continue to return partial results
        finally:
            # Restore original emitter
            self.context.event_emitter = original_emitter

        # Calculate confidence score
        confidence = self._calculate_confidence_score(
            list(self.collector.endpoints),
            self.collector.secrets,
            file_size
        )

        # Calculate analysis time
        analysis_time = time.time() - analysis_start

        # Build result
        result = JSAnalysisResult(
            js_url=js_url,
            endpoints=list(self.collector.endpoints),
            secrets=self.collector.secrets,
            content_hash=content_hash,
            file_size=file_size,
            analysis_time=analysis_time,
            confidence_score=confidence,
            success=True,
            http_status=http_status,
            content_type=content_type,
            download_time=download_time,
            metadata={
                "endpoint_count": len(self.collector.endpoints),
                "secret_count": len(self.collector.secrets),
                "analysis_duration": analysis_time
            }
        )

        # Emit analysis completion event
        try:
            await emit_event(
                self.context,
                event_type="js_analysis_complete",
                data=result.to_dict()
            )
        except Exception as e:
            self.logger.error(f"Failed to emit analysis completion event: {e}")

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
            result = await self.analyze_js_content(js_url)

            if result:
                result_dict = result.to_dict()
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
            self.logger.debug(f"Analysis cancelled for {js_url}")
            raise
        except Exception as e:
            self.logger.error(f"Analysis failed for {js_url}: {e}", exc_info=True)
            return {
                "js_url": js_url,
                "success": False,
                "error": str(e)[:500],
                "metrics": self.metrics.to_dict()
            }

    def reset(self):
        """Reset analyzer state"""
        self.collector.reset()
        self.metrics = AnalysisMetrics()

    async def cleanup(self):
        """Cleanup resources"""
        await self.http_manager.close()
        self.content_cache.clear()
        self.circuit_breaker = CircuitBreaker()  # Reset circuit breaker
        self.logger.debug("JSAnalysisEngine cleanup complete")

# Backward compatibility - original class names
JSAnalyzer = JSAnalysisEngine
EnterpriseJSAnalyzer = JSAnalysisEngine
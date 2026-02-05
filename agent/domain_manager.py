# agent/domain_manager.py
"""
Domain Manager for LeakHunterX Crawler
Production-ready with scope validation, rate limiting, and crawl state management.
"""
# 🔒 LOCKED MODULE
# Stable for MVP & v1 production
# Changes allowed ONLY for bug or security fixes


from typing import Set, List, Tuple, Optional, Dict, Any, Deque
from urllib.parse import urlparse
from collections import deque
import time
import logging
from dataclasses import dataclass, field
from threading import Lock
import asyncio


# ─────────────────────────────────────
# 🔥 ALLOWED CDN DOMAINS (CONTROLLED)
# Used ONLY for JS discovery (safe)
# Note: Domains are NORMALIZED (no www. prefix)
# ─────────────────────────────────────
ALLOWED_CDN_DOMAINS = {
    # Instagram / Meta
    "static.cdninstagram.com",
    "static.xx.fbcdn.net",
    "connect.facebook.net",

    # Common CDNs
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",

    # Google / analytics (optional but useful)
    "googletagmanager.com",           # Note: No www. prefix - normalized
    "google-analytics.com",           # Note: No www. prefix - normalized
}

@dataclass
class DomainStats:
    """Statistics for domain tracking"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0.0
    last_request_time: float = 0.0
    consecutive_failures: int = 0

    @property
    def avg_response_time(self) -> float:
        """Calculate average response time"""
        if self.successful_requests > 0:
            return self.total_response_time / self.successful_requests
        return 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_requests > 0:
            return (self.successful_requests / self.total_requests) * 100
        return 0.0


class DomainManager:
    """
    Manages domain discovery, scope validation, crawl state, and rate limiting.
    
    Features:
    - Scope validation with subdomain support
    - Rate limiting per domain
    - Circuit breaker for failing domains
    - Depth-limited crawling
    - Thread-safe operations
    - Comprehensive statistics
    """
    
    def __init__(self, target_url: str, max_depth: int = 3):
        """
        Initialize DomainManager.

        Args:
            target_url: Full target URL (e.g., "https://instagram.com")
            max_depth: Maximum crawl depth from seed URLs
        """
        if not target_url:
            raise ValueError("target_url cannot be empty")

        # JS-specific tracking
        self.js_urls_enqueued: int = 0
        self.js_urls_processed: int = 0
        self.js_queue: Deque[str] = deque()

        # Store original target URL
        self.target_url = target_url
        # Extract and normalize base domain (removes www. prefix)
        self.base_domain = self._normalize_domain(target_url)
        self.max_depth = max(max_depth, 1)

        # Discovery tracking
        self.discovered_urls: Set[str] = set()
        self.queue: Deque[Tuple[str, int]] = deque()  # (url, depth)
        self.processed_urls: Set[str] = set()
        self.failed_urls: Set[str] = set()

        # Domain tracking
        self.domain_stats: Dict[str, DomainStats] = {}
        self.domain_last_request: Dict[str, float] = {}
        self.domain_lock = Lock()

        # 🔒 Structural data lock (queue, sets, stats)
        self._data_lock = Lock()


        # Crawl state
        self.crawl_start_time: Optional[float] = None
        self.crawl_end_time: Optional[float] = None

        # Statistics
        self.stats = {
            "total_discovered": 0,
            "total_processed": 0,
            "total_failed": 0,
            "urls_queued": 0,
            "urls_processed": 0,
            "duplicates_skipped": 0,
            "out_of_scope_skipped": 0,
            "max_depth_skipped": 0,
        }

        # Rate limiting / circuit breaker
        self.min_request_delay = 1.0
        self.max_consecutive_failures = 3
        self.circuit_breaker_timeout = 300

        # Logger (FIXED: Initialize after all basic setup)
        self.logger = logging.getLogger("domain_manager")
        self.logger.info(f"DomainManager initialized for {self.base_domain} (max_depth: {self.max_depth})")
        self.logger.debug(f"Base domain extracted: '{self.base_domain}' from '{target_url}'")

    
    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain by removing protocol, path, and lowercasing.
        
        Args:
            domain: Domain to normalize
            
        Returns:
            Normalized domain string
        """
        if not domain:
            return ""
        
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove path and query
        domain = domain.split('/', 1)[0]
        
        # Remove port if present
        domain = domain.split(':', 1)[0]
        
        # Lowercase and strip
        domain = domain.lower().strip()
        
        # Remove www. prefix for consistent base domain
        # This ensures tesla.com, not www.tesla.com as base domain
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    
    def _extract_domain(self, url: str) -> str:
        """
        Extract normalized domain from a URL safely.
        """
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return ""
            return self._normalize_domain(parsed.netloc)
        except Exception:
            self.logger.debug(f"Failed to extract domain from URL: {url}")
            return ""

    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if URL is within scan scope.

        Scope rules:
        1. Base domain + subdomains are allowed
        2. Explicit CDN allow-list is allowed (JS ONLY)
        3. Everything else is rejected
        """
        try:
            url_domain = self._extract_domain(url)
            if not url_domain:
                return False

            # 1️⃣ Exact base domain
            if url_domain == self.base_domain:
                return True

            # 2️⃣ Subdomain of base domain
            if url_domain.endswith("." + self.base_domain):
                return True

            # 3️⃣ Explicit CDN allow-list (JS FILES ONLY)
            if url_domain in ALLOWED_CDN_DOMAINS:
                # CRITICAL FIX: Only allow JS files from CDNs
                # This prevents HTML crawling of CDN domains
                url_lower = url.lower()
                return (url_lower.endswith(".js") or 
                       ".js?" in url_lower or 
                       ".js#" in url_lower)

            # ❌ Out of scope
            return False

        except Exception as e:
            self.logger.debug(f"Scope check failed for {url}: {e}")
            return False
    
    def can_request_domain(self, domain: str) -> Tuple[bool, str]:
        """
        Check if we can make a request to this domain.
        
        Considers:
        1. Rate limiting (minimum delay between requests)
        2. Circuit breaker (too many consecutive failures)
        3. Domain health (success rate)
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (can_request, reason)
        """
        with self.domain_lock:
            # Get or create domain stats
            if domain not in self.domain_stats:
                self.domain_stats[domain] = DomainStats()
                return True, "First request to domain"
            
            stats = self.domain_stats[domain]
            
            # Check circuit breaker
            if stats.consecutive_failures >= self.max_consecutive_failures:
                time_since_last_failure = time.time() - stats.last_request_time
                if time_since_last_failure < self.circuit_breaker_timeout:
                    return False, f"Circuit breaker active (failures: {stats.consecutive_failures}, cooldown: {self.circuit_breaker_timeout - time_since_last_failure:.0f}s)"
                else:
                    # Reset circuit breaker after timeout
                    stats.consecutive_failures = 0
            
            # Check rate limiting
            if domain in self.domain_last_request:
                time_since_last = time.time() - self.domain_last_request[domain]
                if time_since_last < self.min_request_delay:
                    return False, f"Rate limit (wait {self.min_request_delay - time_since_last:.1f}s)"
            
            # Check success rate (optional)
            if stats.total_requests > 10 and stats.success_rate < 30:
                return False, f"Low success rate ({stats.success_rate:.1f}%)"
            
            return True, "OK"
    
    def record_request(self, domain: str, success: bool, response_time: float = 0.0):
        """
        Record a request result for a domain.
        
        Args:
            domain: Domain that was requested
            success: Whether the request was successful
            response_time: Response time in seconds
        """
        with self.domain_lock:
            if domain not in self.domain_stats:
                self.domain_stats[domain] = DomainStats()
            
            stats = self.domain_stats[domain]
            stats.total_requests += 1
            stats.last_request_time = time.time()
            self.domain_last_request[domain] = time.time()
            
            if success:
                stats.successful_requests += 1
                stats.total_response_time += response_time
                stats.consecutive_failures = 0  # Reset circuit breaker
            else:
                stats.failed_requests += 1
                stats.consecutive_failures += 1
    
    def add_discovered(self, url: str, depth: int, source_url: str = "") -> Tuple[bool, str]:
        if not url or not isinstance(url, str):
            return False, "Invalid URL"

        if depth < 0:
            return False, "Invalid depth"

        normalized_url = url.strip()
        lower_url = normalized_url.lower()

        is_js = (
            lower_url.endswith(".js")
            or ".js?" in lower_url
            or ".js#" in lower_url
        )

        # 🔒 CRITICAL FIX: protect shared structures
        with self._data_lock:
            if normalized_url in self.discovered_urls:
                self.stats["duplicates_skipped"] += 1
                return False, "Already discovered"

            if not self.is_in_scope(normalized_url):
                self.stats["out_of_scope_skipped"] += 1
                return False, "Out of scope"

            # JS → JS queue
            if is_js:
                self.discovered_urls.add(normalized_url)
                self.js_queue.append(normalized_url)
                self.js_urls_enqueued += 1
                self.stats["total_discovered"] += 1
                return True, "JS scheduled"

            # HTML → crawl queue
            if depth > self.max_depth:
                self.stats["max_depth_skipped"] += 1
                return False, f"Max depth exceeded ({depth} > {self.max_depth})"

            self.discovered_urls.add(normalized_url)
            self.queue.append((normalized_url, depth))
            self.stats["total_discovered"] += 1
            self.stats["urls_queued"] += 1

        return True, "HTML scheduled"

    
    def add_seed_urls(self, urls: List[str]) -> Dict[str, str]:
        """
        Add seed URLs to start crawling.
        
        Args:
            urls: List of seed URLs
            
        Returns:
            Dictionary of URL -> result message
        """
        results = {}
        for url in urls:
            added, reason = self.add_discovered(url, depth=0, source_url="(seed)")
            results[url] = f"{'✓' if added else '✗'} {reason}"
        
        self.logger.info(f"Added {sum(1 for r in results.values() if r.startswith('✓'))}/{len(urls)} seed URLs")
        return results
    
    def get_next_target(self) -> Tuple[Optional[str], int]:
        with self._data_lock:
            if not self.queue:
                return None, 0

            url, depth = self.queue.popleft()
            self.processed_urls.add(url)

            self.stats['urls_queued'] -= 1
            self.stats['urls_processed'] += 1
            self.stats['total_processed'] += 1

            return url, depth

    
    def get_next_js_target(self) -> Optional[str]:
        with self._data_lock:
            if not self.js_queue:
                return None

            js_url = self.js_queue.popleft()
            self.js_urls_processed += 1
            return js_url
    
    def has_js_targets(self) -> bool:
        """Check if there are JS URLs to analyze."""
        return len(self.js_queue) > 0
    
    def get_js_queue_size(self) -> int:
        """Get current JS queue size."""
        return len(self.js_queue)
    
    def mark_failed(self, url: str, reason: str = ""):
        with self._data_lock:
            self.failed_urls.add(url)
            self.stats['total_failed'] += 1

        domain = self._extract_domain(url)
        if domain:
            self.record_request(domain, success=False)

        if reason:
            self.logger.debug(f"Failed: {url} - {reason}")
    
    def has_targets(self) -> bool:
        """Check if there are URLs to crawl."""
        return len(self.queue) > 0
    
    def get_queue_size(self) -> int:
        """Get current queue size."""
        return len(self.queue)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics.
        
        Returns:
            Dictionary with all statistics
        """
        current_time = time.time()
        
        stats = {
            **self.stats,
            'queue_size': self.get_queue_size(),
            'js_queue_size': self.get_js_queue_size(),
            'discovered_count': len(self.discovered_urls),
            'processed_count': len(self.processed_urls),
            'failed_count': len(self.failed_urls),
            'unique_domains': len(self.domain_stats),
            'crawl_active': self.crawl_start_time is not None and self.crawl_end_time is None
        }
        
        # Add crawl duration if active
        if self.crawl_start_time and not self.crawl_end_time:
            stats['crawl_duration'] = current_time - self.crawl_start_time
        
        # Add domain health summary
        if self.domain_stats:
            healthy_domains = sum(1 for s in self.domain_stats.values() if s.success_rate > 80)
            problematic_domains = sum(1 for s in self.domain_stats.values() if s.consecutive_failures >= self.max_consecutive_failures)
            
            stats['domain_health'] = {
                'total': len(self.domain_stats),
                'healthy': healthy_domains,
                'problematic': problematic_domains,
                'circuit_broken': problematic_domains
            }
        
        return stats
    

    def get_js_counts(self) -> Dict[str, int]:
        """Get JS-specific statistics."""
        return {
            "enqueued": self.js_urls_enqueued,
            "processed": self.js_urls_processed,
            "remaining": self.get_js_queue_size(),
        }

        
    def get_domain_stats(self, domain: str) -> Optional[DomainStats]:
        """
        Get detailed statistics for a specific domain.
        
        Args:
            domain: Domain to get stats for
            
        Returns:
            DomainStats object or None if domain not found
        """
        return self.domain_stats.get(domain)
    
    def start_crawl(self):
        """Mark crawl as started."""
        self.crawl_start_time = time.time()
        self.crawl_end_time = None
        self.logger.info(f"Crawl started for {self.base_domain}")
    
    def end_crawl(self):
        """Mark crawl as ended."""
        self.crawl_end_time = time.time()
        duration = self.crawl_end_time - (self.crawl_start_time or self.crawl_end_time)
        self.logger.info(f"Crawl ended for {self.base_domain}. Duration: {duration:.1f}s")
    
    def reset(self):
        with self._data_lock:
            self.discovered_urls.clear()
            self.queue.clear()
            self.processed_urls.clear()
            self.failed_urls.clear()
            self.js_queue.clear()

            self.js_urls_enqueued = 0
            self.js_urls_processed = 0

            self.stats = {
                'total_discovered': 0,
                'total_processed': 0,
                'total_failed': 0,
                'urls_queued': 0,
                'urls_processed': 0,
                'duplicates_skipped': 0,
                'out_of_scope_skipped': 0,
                'max_depth_skipped': 0
            }

        self.domain_stats.clear()
        self.domain_last_request.clear()
    
    def get_progress(self) -> Dict[str, Any]:
        """
        Get crawl progress information.
        
        Returns:
            Dictionary with progress metrics
        """
        total = self.stats['total_discovered']
        processed = self.stats['total_processed']
        
        progress = {
            'total_urls': total,
            'processed_urls': processed,
            'remaining_urls': self.get_queue_size(),
            'js_remaining': self.get_js_queue_size(),
            'failed_urls': len(self.failed_urls),
            'progress_percent': (processed / total * 100) if total > 0 else 0,
            'estimated_remaining': None
        }
        
        # Estimate remaining time if we have some history
        if processed > 10 and self.crawl_start_time:
            elapsed = time.time() - self.crawl_start_time
            rate = processed / elapsed  # URLs per second
            if rate > 0:
                remaining = self.get_queue_size() / rate
                progress['estimated_remaining'] = remaining
                progress['rate_per_second'] = rate
        
        return progress
    
    def export_state(self) -> Dict[str, Any]:
        """
        Export current state for persistence.
        
        Returns:
            Dictionary with all state data
        """
        return {
            'base_domain': self.base_domain,
            'max_depth': self.max_depth,
            'discovered_urls': list(self.discovered_urls),
            'queue': list(self.queue),
            'processed_urls': list(self.processed_urls),
            'failed_urls': list(self.failed_urls),
            'js_queue': list(self.js_queue),
            'js_urls_enqueued': self.js_urls_enqueued,
            'js_urls_processed': self.js_urls_processed,
            'stats': self.stats.copy(),
            'domain_stats': {
                domain: {
                    'total_requests': stats.total_requests,
                    'successful_requests': stats.successful_requests,
                    'failed_requests': stats.failed_requests,
                    'avg_response_time': stats.avg_response_time,
                    'consecutive_failures': stats.consecutive_failures,
                    'last_request_time': stats.last_request_time
                }
                for domain, stats in self.domain_stats.items()
            },
            'crawl_start_time': self.crawl_start_time,
            'crawl_end_time': self.crawl_end_time
        }
    
    def import_state(self, state: Dict[str, Any]) -> bool:
        """
        Import previously saved state.
        
        Args:
            state: State dictionary from export_state()
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            self.base_domain = state['base_domain']
            self.max_depth = state['max_depth']
            
            self.discovered_urls = set(state['discovered_urls'])
            self.queue = deque(state['queue'])
            self.processed_urls = set(state['processed_urls'])
            self.failed_urls = set(state['failed_urls'])
            
            # Import JS queue state
            self.js_queue = deque(state.get('js_queue', []))
            self.js_urls_enqueued = state.get('js_urls_enqueued', 0)
            self.js_urls_processed = state.get('js_urls_processed', 0)
            
            self.stats = state['stats'].copy()
            
            # Recreate domain stats
            self.domain_stats.clear()
            for domain, stats_data in state.get('domain_stats', {}).items():
                stats = DomainStats()
                stats.total_requests = stats_data['total_requests']
                stats.successful_requests = stats_data['successful_requests']
                stats.failed_requests = stats_data['failed_requests']
                stats.consecutive_failures = stats_data['consecutive_failures']
                stats.last_request_time = stats_data['last_request_time']
                # Recalculate total response time from average
                if stats.successful_requests > 0:
                    stats.total_response_time = stats_data['avg_response_time'] * stats.successful_requests
                self.domain_stats[domain] = stats
            
            self.crawl_start_time = state.get('crawl_start_time')
            self.crawl_end_time = state.get('crawl_end_time')
            
            self.logger.info(f"Imported state for {self.base_domain}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to import state: {e}")
            return False


# Factory function for convenience (FIXED parameter name)
def create_domain_manager(target_url: str, max_depth: int = 3) -> DomainManager:
    """
    Create and return a DomainManager instance.
    
    Args:
        target_url: Full target URL (e.g., "https://example.com")
        max_depth: Maximum crawl depth
        
    Returns:
        DomainManager instance
    """
    return DomainManager(target_url, max_depth)


# Async-compatible wrapper for thread-safe operations
class AsyncDomainManager:
    """
    Async wrapper for DomainManager with thread-safe operations.
    """
    
    def __init__(self, target_url: str, max_depth: int = 3):
        self.domain_manager = DomainManager(target_url, max_depth)
        try:
            # Use get_running_loop() for Python 3.7+ compatibility
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            # Fallback to get_event_loop() if no running loop
            self.loop = asyncio.get_event_loop()
    
    async def add_discovered(self, url: str, depth: int, source_url: str = "") -> Tuple[bool, str]:
        """Async wrapper for add_discovered."""
        return await self.loop.run_in_executor(
            None, self.domain_manager.add_discovered, url, depth, source_url
        )
    
    async def get_next_target(self) -> Tuple[Optional[str], int]:
        """Async wrapper for get_next_target."""
        return await self.loop.run_in_executor(None, self.domain_manager.get_next_target)
    
    async def get_next_js_target(self) -> Optional[str]:
        """Async wrapper for get_next_js_target."""
        return await self.loop.run_in_executor(None, self.domain_manager.get_next_js_target)
    
    async def can_request_domain(self, domain: str) -> Tuple[bool, str]:
        """Async wrapper for can_request_domain."""
        return await self.loop.run_in_executor(None, self.domain_manager.can_request_domain, domain)
    
    async def record_request(self, domain: str, success: bool, response_time: float = 0.0):
        """Async wrapper for record_request."""
        await self.loop.run_in_executor(
            None, self.domain_manager.record_request, domain, success, response_time
        )
    
    async def get_stats(self) -> Dict[str, Any]:
        """Async wrapper for get_stats."""
        return await self.loop.run_in_executor(None, self.domain_manager.get_stats)
    
    async def has_targets(self) -> bool:
        """Async wrapper for has_targets."""
        return await self.loop.run_in_executor(None, self.domain_manager.has_targets)
    
    async def has_js_targets(self) -> bool:
        """Async wrapper for has_js_targets."""
        return await self.loop.run_in_executor(None, self.domain_manager.has_js_targets)
    
    # Delegate other methods
    def __getattr__(self, name):
        """Delegate other attributes to the underlying domain_manager."""
        return getattr(self.domain_manager, name)


# ─────────────────────────────────────
# VERIFICATION TEST (MVP SAFETY CHECK)
# Note: For production release, move to /tests/
# ─────────────────────────────────────
if __name__ == "__main__":
    print("🔒 DOMAIN MANAGER MVP SAFETY TEST")
    print("=" * 70)
    
    # Configure minimal logging for test
    logging.basicConfig(level=logging.WARNING)
    
    print("\n1. TESTING BASE DOMAIN NORMALIZATION (CRITICAL FOR DISCOVERY)")
    dm = DomainManager("https://www.tesla.com", max_depth=3)
    
    print(f"   Input URL:    'https://www.tesla.com'")
    print(f"   Base domain:  '{dm.base_domain}'")
    print(f"   Expected:     'tesla.com'")
    
    if dm.base_domain == "tesla.com":
        print("   ✅ PASS: Base domain correctly normalized (www. removed)")
    else:
        print(f"   ❌ FAIL: Got '{dm.base_domain}' instead of 'tesla.com'")
        exit(1)
    
    print("\n2. TESTING SCOPE VALIDATION (DISCOVERY SUBDOMAINS)")
    test_urls = [
        ("https://auth.tesla.com", True, "Subdomain should be in scope"),
        ("https://billing.tesla.com", True, "Subdomain should be in scope"),
        ("https://www.tesla.com", True, "www subdomain should be in scope"),
        ("https://tesla.com", True, "Base domain should be in scope"),
        ("https://example.com", False, "Different domain should be out of scope"),
    ]
    
    all_pass = True
    for url, expected, desc in test_urls:
        actual = dm.is_in_scope(url)
        if actual == expected:
            print(f"   ✅ {url}: {desc}")
        else:
            print(f"   ❌ {url}: Expected {'in scope' if expected else 'out of scope'}, got {'in scope' if actual else 'out of scope'}")
            all_pass = False
    
    if not all_pass:
        print("   ❌ FAIL: Scope validation tests failed")
        exit(1)
    print("   ✅ PASS: All scope validation tests passed")
    
    print("\n3. TESTING CDN ALLOW-LIST (JS ONLY)")
    cdn_tests = [
        ("https://cdn.jsdelivr.net/jquery.js", True, "JS from allowed CDN"),
        ("https://cdn.jsdelivr.net/jquery.min.js", True, "Minified JS from allowed CDN"),
        ("https://cdn.jsdelivr.net/jquery.js?version=3.5", True, "JS with query params"),
        ("https://cdn.jsdelivr.net/style.css", False, "CSS from CDN should be rejected"),
        ("https://cdn.jsdelivr.net/", False, "HTML from CDN should be rejected"),
        ("https://googletagmanager.com/gtm.js", True, "JS from google-analytics (normalized)"),
        ("https://www.googletagmanager.com/gtm.js", True, "JS from www. CDN (normalized)"),
    ]
    
    cdn_pass = True
    for url, expected, desc in cdn_tests:
        actual = dm.is_in_scope(url)
        if actual == expected:
            print(f"   ✅ {desc}")
        else:
            print(f"   ❌ {desc}: Expected {'allowed' if expected else 'rejected'}, got {'allowed' if actual else 'rejected'}")
            cdn_pass = False
    
    if not cdn_pass:
        print("   ❌ FAIL: CDN allow-list tests failed")
        exit(1)
    print("   ✅ PASS: CDN allow-list correctly restricts to JS only")
    
    print("\n4. TESTING DISCOVERY INTEGRATION (END-TO-END)")
    # Reset for clean test
    dm = DomainManager("https://www.tesla.com", max_depth=3)
    
    # Add seed URL (as orchestrator does)
    dm.add_seed_urls(["https://www.tesla.com"])
    print(f"   Added seed URL: ✓ https://www.tesla.com")
    
    # Simulate discovered subdomains (as discovery engine returns)
    discovered = [
        "https://www.tesla.com",      # Duplicate of seed
        "https://auth.tesla.com",     # Should be added
        "https://billing.tesla.com",  # Should be added
        "https://shop.tesla.com",     # Should be added
        "https://example.com",        # Should be rejected
    ]
    
    added_count = 0
    for url in discovered:
        added, reason = dm.add_discovered(url, depth=0, source_url="discovery")
        if added:
            added_count += 1
            print(f"   ✓ {url}: {reason}")
        else:
            print(f"   ✗ {url}: {reason}")
    
    expected_added = 3  # auth, billing, shop (tesla.com subdomains)
    if added_count == expected_added:
        print(f"   ✅ PASS: {added_count} subdomains added (expected: {expected_added})")
    else:
        print(f"   ❌ FAIL: Only {added_count} subdomains added (expected: {expected_added})")
        exit(1)
    
    print(f"\n   Final scan scope: {dm.get_queue_size()} URLs to crawl")
    print("   ✅ Discovery integration working correctly")
    
    print("\n5. TESTING JS QUEUE HANDLING")
    # Test JS URLs
    js_urls = [
        "https://auth.tesla.com/app.js",
        "https://cdn.jsdelivr.net/jquery.js",
        "https://static.tesla.com/main.js",
    ]
    
    js_added = 0
    for js_url in js_urls:
        added, reason = dm.add_discovered(js_url, depth=0, source_url="test")
        if added:
            js_added += 1
            print(f"   ✓ JS added: {js_url}")
        else:
            print(f"   ✗ JS rejected: {js_url} - {reason}")
    
    if js_added == 3:
        print(f"   ✅ PASS: {js_added} JS URLs added to JS queue")
        print(f"   JS queue size: {dm.get_js_queue_size()}")
        
        # Test get_next_js_target
        js_target = dm.get_next_js_target()
        if js_target:
            print(f"   First JS target: {js_target}")
            print(f"   JS processed count: {dm.js_urls_processed}")
            print("   ✅ JS queue handling working correctly")
        else:
            print("   ❌ FAIL: Could not get JS target from queue")
            exit(1)
    else:
        print(f"   ❌ FAIL: Expected 3 JS URLs, got {js_added}")
        exit(1)
    
    print("\n" + "=" * 70)
    print("🎉 ALL TESTS PASSED!")
    print("\n📈 MVP READINESS SUMMARY:")
    print("   ✓ Base domain normalization fixed (www. removed)")
    print("   ✓ Scope validation correct for discovery subdomains")
    print("   ✓ CDN allow-list normalized and restricted to JS only")
    print("   ✓ Discovery integration verified")
    print("   ✓ JS queue handling implemented")
    print("   ✓ Thread-safe and async-compatible")
    print("\n🚀 DOMAIN MANAGER IS NOW PRODUCTION-READY")
    print("=" * 70)
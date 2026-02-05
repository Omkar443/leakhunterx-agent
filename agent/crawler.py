#!/usr/bin/env python3

# 🔒 LOCKED MODULE
# Stable for MVP & v1 production
# Changes allowed ONLY for bug or security fixes
"""
LeakHunterX - COMPLETELY FIXED CRAWLER
FIXES APPLIED:
1. Domain-level deduplication (CRITICAL)
2. SSL verification disabled (Instagram blocking fix)
3. Enhanced JS pattern detection
4. Better Instagram/SPA handling
5. JS Identity & Variant Tracking (B2 - track JS variants)
6. All 4 critical bugs fixed
7. All original features preserved
"""

import asyncio
import aiohttp
import logging
import time
import socket
import random
import hashlib
import re
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Set, Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from domain_manager import DomainManager
from utils.events import emit_event

# 🔥 JS IDENTITY INTEGRATION - NEW IMPORT
from utils.js_identity import JSIdentityRegistry, compute_js_identity, compute_content_hash


# ─────────────────────────────────────
# 🔥 ENHANCED JS DISCOVERY PATTERNS
# ─────────────────────────────────────
SAFE_JS_PATTERNS = [
    r'import\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'import\s+.*?\s+from\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'src\s*=\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'loadScript\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
]

AGGRESSIVE_JS_PATTERNS = SAFE_JS_PATTERNS + [
    r'chunkFilename:\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'lazy\(\s*\(\)\s*=>\s*import\([\'"]([^\'"]+)[\'"]\)',
]

# Modern framework patterns (Instagram, React, Vue, etc.)
MODERN_JS_PATTERNS = [
    # Webpack/Bundler patterns
    r'["\']([^"\']+chunk[^"\']*\.js[^\'"]*)["\']',
    r'["\']([^"\']+bundle[^"\']*\.js[^\'"]*)["\']',
    r'["\']([^"\']+main\.[a-f0-9]{8}\.js[^\'"]*)["\']',
    r'["\']([^"\']+\.[a-f0-9]{8,}\.js[^\'"]*)["\']',
    r'webpackChunk[^=]+=\s*["\'][^"\']+["\']',
    
    # Framework-specific
    r'__webpack_require__\(\s*["\']([^"\']+)["\']',
    r'loadComponent\(\s*["\']([^"\']+\.js)["\']',
    
    # Generic patterns for modern apps
    r'["\'](/_next/[^"\']+\.js)["\']',
    r'["\'](/static/js/[^"\']+)["\']',
    r'["\'](/assets/[^"\']+\.js)["\']',
    r'["\'](/js/[^"\']+\.js)["\']',
    
    # Extensionless patterns (common in modern frameworks)
    r'import\(\s*["\']([^"\']+?)["\']',
    r'dynamicImport\(\s*["\']([^"\']+?)["\']',
    
    # Instagram-specific patterns
    r'["\']([^"\']+instagram[^"\']*\.js[^\'"]*)["\']',
    r'["\']([^"\']+ig[^"\']*\.js[^\'"]*)["\']',
    r'["\']([^"\']+fb[^"\']*\.js[^\'"]*)["\']',
    r'["\']([^"\']+react[^"\']*\.js[^\'"]*)["\']',
    r'["\']([^"\']+vendor[^"\']*\.js[^\'"]*)["\']',
]

# -------------------------------------------------
# 🔥 ENHANCED INLINE <script> JS DISCOVERY
# -------------------------------------------------
INLINE_JS_PATTERNS = [
    r'import\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'import\s+.*?\s+from\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'require\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
    r'["\'](https?://[^"\']+\.js[^\'"]*)["\']',
    r'["\'](/[^"\']+\.js[^\'"]*)["\']',
] + MODERN_JS_PATTERNS


@dataclass
class CrawlContext:
    """Context for crawl execution with pause/resume/stop support"""
    scan_id: str
    domain_manager: Any
    event_emitter: Any
    config: Dict[str, Any] = field(default_factory=dict)
    should_pause: asyncio.Event = field(default_factory=asyncio.Event)
    should_stop: asyncio.Event = field(default_factory=asyncio.Event)
    shared_state: Dict[str, Any] = field(default_factory=dict)
    
    async def check_pause_stop(self) -> bool:
        """Check if we should pause or stop (async-safe)"""
        if self.should_stop.is_set():
            return True
        if self.should_pause.is_set():
            await self.should_pause.wait()
        return self.should_stop.is_set()


class CompleteCrawler:
    """
    COMPLETELY FIXED CRAWLER WITH ALL ISSUES RESOLVED
    - URL normalization to prevent duplicates
    - DOMAIN-LEVEL DEDUPLICATION (CRITICAL FIX - HTML ONLY)
    - SSL verification DISABLED (Instagram blocking fix)
    - Enhanced JS pattern detection for modern frameworks
    - JS Identity & Variant Tracking (B2: track JS variants)
    - All 4 critical bugs fixed
    - Identity-aware JS enqueue to prevent duplicate analysis
    - All original features preserved
    """
    def __init__(
        self,
        domain_manager,
        config: dict,
        concurrency: int = 5,
        delay: float = 0.1
    ):
        """
        Initialize CompleteCrawler with fixes.

        Args:
            domain_manager: DomainManager instance (scope, rate limit, queue)
            config: Global scan configuration
            concurrency: Max concurrent HTTP requests
            delay: Delay between requests
        """
        
        # 🔑 Injected dependency (REQUIRED)
        self.domain_manager = domain_manager
        self.config = config

        # Concurrency & crawl limits
        self.concurrency = min(
            config.get("crawler_concurrency", concurrency),
            10
        )
        self.max_depth = config.get("max_depth", domain_manager.max_depth)
        self.delay = config.get("crawler_delay", delay)

        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None

        # Enhanced user agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            # Instagram-specific user agents
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1 Instagram 265.0.0.19.301",
            "Instagram 265.0.0.19.301 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"
        ]

        # Timeouts
        self.request_timeout = config.get("request_timeout", 30)
        self.max_pages = config.get("max_pages", 500)

        # 🔥 CRITICAL FIX: SSL verification DISABLED for Instagram
        self.verify_ssl = config.get("verify_ssl", False)  # Default to False

        # Logger
        self.logger = logging.getLogger("crawler")

        # 🔥 CRITICAL FIX: Domain-level deduplication tracking (HTML ONLY)
        self.processed_html_domains = set()
        self.seen_urls = set()  # For backward compatibility
        
        # Initialize state
        self.reset()

        self.logger.info(
            f"CompleteCrawler initialized "
            f"(concurrency={self.concurrency}, max_depth={self.max_depth}, ssl_verify={self.verify_ssl})"
        )

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL to prevent duplicates
        - Standardize protocol (prefer https)
        - Remove default ports
        - Remove trailing slashes
        - Lowercase domain
        - Normalize escaped forward slashes (\/ → /) and collapse multiple slashes
        """
        try:
            # NORMALIZE ESCAPED SLASHES AND COLLAPSE MULTIPLE SLASHES
            if '\\/' in url or '//' in url:
                import re
                
                # Replace escaped slashes
                url = url.replace('\\\\/', '/').replace('\\/', '/')
                
                # Collapse multiple slashes in path (preserve protocol)
                if '://' in url:
                    protocol, rest = url.split('://', 1)
                    if '/' in rest:
                        domain_end = rest.find('/')
                        if domain_end != -1:
                            domain = rest[:domain_end]
                            path = rest[domain_end:]  # Starts with /
                            path = re.sub(r'/{2,}', '/', path)  # Collapse 2+ slashes to 1
                            url = f"{protocol}://{domain}{path}"
                else:
                    url = re.sub(r'/{2,}', '/', url)
            
            parsed = urlparse(url)
            
            # Standardize scheme to https
            scheme = parsed.scheme if parsed.scheme else 'https'
            
            # Normalize netloc (domain + port)
            netloc = parsed.netloc.lower()
            if ':' in netloc:
                # Remove default ports
                if netloc.endswith(':80') or netloc.endswith(':443'):
                    netloc = netloc.split(':')[0]
            
            # Remove trailing slash from path
            path = parsed.path.rstrip('/') or '/'
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            return normalized
            
        except Exception:
            # Fallback: basic normalization with slash fix
            import re
            url = url.replace('\\/', '/') if '\\/' in url else url
            url = re.sub(r'/{2,}', '/', url)  # Collapse multiple slashes
            return url.lower().rstrip('/')


    def _get_domain_key(self, url: str) -> str:
        """
        Get domain key for deduplication and rate limiting
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            return domain
        except Exception:
            return url

    def _should_skip_html_domain(self, url: str) -> bool:
        """
        🔥 CRITICAL FIX #3: Check if domain should be skipped FOR HTML ONLY
        This prevents re-crawling same domain HTML multiple times
        BUT allows JS crawling from same domain
        """
        if not url.endswith('.js'):
            domain_key = self._get_domain_key(url)
            return domain_key in self.processed_html_domains
        return False

    async def _check_circuit_breaker(self, domain: str, context: CrawlContext) -> bool:
        """Circuit breaker for failing domains (async)"""
        if await context.check_pause_stop():
            return False
            
        crawler_state = context.shared_state.get("crawler", {})
        circuit_breaker = crawler_state.get("circuit_breaker", {})
        
        if domain in circuit_breaker:
            failures, last_attempt = circuit_breaker[domain]
            cooldown = 300  # 5 minutes
            
            if failures >= 3 and time.time() - last_attempt < cooldown:
                await emit_event(
                    context,
                    event_type="circuit_breaker_active",
                    data={
                        "domain": domain,
                        "failures": failures,
                        "cooldown_remaining": cooldown - (time.time() - last_attempt)
                    }
                )
                return False
                
            if time.time() - last_attempt >= cooldown:
                del circuit_breaker[domain]
                crawler_state["circuit_breaker"] = circuit_breaker
                context.shared_state["crawler"] = crawler_state
                
        return True

    async def _check_rate_limit(self, domain: str, context: CrawlContext) -> bool:
        """Rate limiting per domain (async)"""
        if await context.check_pause_stop():
            return False
            
        crawler_state = context.shared_state.get("crawler", {})
        rate_limit_tracker = crawler_state.get("rate_limit_tracker", {})
        
        if domain not in rate_limit_tracker:
            rate_limit_tracker[domain] = []
            
        current_time = time.time()
        # Clean old requests (last 15 seconds)
        rate_limit_tracker[domain] = [
            t for t in rate_limit_tracker[domain]
            if current_time - t < 15
        ]
        
        max_requests = 8  # Max 8 requests per 15 seconds
        if len(rate_limit_tracker[domain]) >= max_requests:
            await emit_event(
                context,
                event_type="rate_limit_exceeded",
                data={
                    "domain": domain,
                    "requests_in_window": len(rate_limit_tracker[domain])
                }
            )
            return False
            
        rate_limit_tracker[domain].append(current_time)
        crawler_state["rate_limit_tracker"] = rate_limit_tracker
        context.shared_state["crawler"] = crawler_state
        return True

    def _record_failure(self, domain: str, error_type: str, context: CrawlContext):
        """Record failure for circuit breaker"""
        crawler_state = context.shared_state.get("crawler", {})
        circuit_breaker = crawler_state.get("circuit_breaker", {})
        
        if domain not in circuit_breaker:
            circuit_breaker[domain] = [1, time.time()]
        else:
            circuit_breaker[domain][0] += 1
            circuit_breaker[domain][1] = time.time()  # 🔥 FIX 1: Removed extra bracket
            
        crawler_state["circuit_breaker"] = circuit_breaker
        context.shared_state["crawler"] = crawler_state

    def _record_success(self, domain: str, context: CrawlContext):
        """Reset circuit breaker on success"""
        crawler_state = context.shared_state.get("crawler", {})
        circuit_breaker = crawler_state.get("circuit_breaker", {})
        
        if domain in circuit_breaker:
            del circuit_breaker[domain]
            crawler_state["circuit_breaker"] = circuit_breaker
            context.shared_state["crawler"] = crawler_state

    async def check_dns(self, domain: str, context: CrawlContext) -> bool:
        """Enhanced DNS resolution check"""
        if await context.check_pause_stop():
            return False
            
        try:
            # Try IPv4 and IPv6
            socket.getaddrinfo(domain, 443, family=socket.AF_INET)
            return True
        except socket.gaierror:
            try:
                socket.getaddrinfo(domain, 443, family=socket.AF_INET6)
                return True
            except socket.gaierror:
                await emit_event(
                    context,
                    event_type="dns_failure",
                    data={"domain": domain}
                )
                return False
        except Exception:
            await emit_event(
                context,
                event_type="dns_error",
                data={"domain": domain}
            )
            return False

    def _get_enhanced_headers(self, url: str = "") -> Dict[str, str]:
        """Enhanced headers with better browser fingerprinting"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/avif,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'no-cache',
            'DNT': '1',
        }
        
        # Add Instagram-specific headers if domain matches
        if 'instagram.com' in url.lower():
            headers.update({
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1 Instagram 265.0.0.19.301',
                'X-IG-App-ID': '936619743392459',
                'X-Requested-With': 'XMLHttpRequest',
            })
        
        return headers

    def _is_duplicate_content(self, content: str, context: CrawlContext) -> bool:
        """Enhanced duplicate content detection"""
        if not content or len(content) < 100:
            return True
            
        content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()[:32]
        
        crawler_state = context.shared_state.get("crawler", {})
        content_hash_cache = crawler_state.get("content_hash_cache", set())
        
        if content_hash in content_hash_cache:
            asyncio.create_task(emit_event(
                context,
                event_type="duplicate_content_detected",
                data={"content_hash": content_hash[:8]}
            ))
            return True
            
        content_hash_cache.add(content_hash)
        crawler_state["content_hash_cache"] = content_hash_cache
        context.shared_state["crawler"] = crawler_state
        return False

    def _is_valid_content(self, content: str, context: CrawlContext) -> bool:
        """Validate content is actual HTML/JS"""
        if not content or len(content) < 200:  # Reduced from 500 for SPA pages
            asyncio.create_task(emit_event(
                context,
                event_type="content_too_small",
                data={"content_length": len(content)}
            ))
            return False
            
        # Check for common HTML/JS patterns
        html_indicators = ['<html', '<!DOCTYPE', '<script', '<div', '<body', '<head', '<title']
        js_indicators = ['function', 'var ', 'const ', 'let ', 'export', 'import', 'window.', 'document.']
        
        content_lower = content.lower()
        has_html = any(indicator in content_lower for indicator in html_indicators)
        has_js = any(indicator in content_lower for indicator in js_indicators)
        
        # For SPAs like Instagram, accept JSON-like responses too
        has_json = content.strip().startswith('{') or content.strip().startswith('[')
        
        return has_html or has_js or has_json

    async def _try_403_bypass(self, url: str, domain: str, context: CrawlContext) -> Tuple[str, str, int]:
        """
        COMPLETE 403 bypass with multiple techniques
        Returns: (url, content, status_code)
        """
        await emit_event(
            context,
            event_type="bypass_started",
            data={"domain": domain, "url": url}
        )
        
        bypass_techniques = [
            # Technique 1: Protocol fallback
            {'type': 'protocol', 'url': url.replace('https://', 'http://'), 'desc': 'HTTP fallback'},
            # Technique 2: Mobile user agent
            {'type': 'mobile', 'headers': {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
            }, 'desc': 'Mobile user agent'},
            # Technique 3: Bot user agent 
            {'type': 'bot', 'headers': {
                'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
            }, 'desc': 'Googlebot'},
            # Technique 4: Simple headers
            {'type': 'simple', 'headers': {
                'User-Agent': 'curl/7.68.0',
                'Accept': '*/*'
            }, 'desc': 'CURL headers'},
            # Technique 5: Instagram-specific
            {'type': 'instagram', 'headers': {
                'User-Agent': 'Instagram 265.0.0.19.301 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
                'X-IG-App-ID': '936619743392459',
                'X-Requested-With': 'XMLHttpRequest'
            }, 'desc': 'Instagram mobile app'}
        ]
        
        # 🔥 CRITICAL FIX: SSL verification DISABLED for bypass attempts
        verify_ssl = False
        
        for technique in bypass_techniques:
            if await context.check_pause_stop():
                return url, "", 403
                
            try:
                technique_type = technique['type']
                test_url = technique.get('url', url)
                headers = technique.get('headers', self._get_enhanced_headers(url))
                
                await emit_event(
                    context,
                    event_type="bypass_attempt",
                    data={
                        "domain": domain,
                        "technique": technique.get('desc', technique_type)
                    }
                )
                
                timeout = aiohttp.ClientTimeout(total=30, connect=10)
                connector = aiohttp.TCPConnector(ssl=verify_ssl)
                
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    headers=headers
                ) as session:
                    
                    async with session.get(test_url, ssl=verify_ssl, allow_redirects=True) as response:
                        content = await response.text(errors='ignore')
                        
                        if response.status == 200 and self._is_valid_content(content, context):
                            # Ensure metrics key exists
                            if "bypass_attempts" not in context.shared_state["metrics"]:
                                context.shared_state["metrics"]["bypass_attempts"] = 0
                            context.shared_state["metrics"]["bypass_attempts"] += 1
                            
                            await emit_event(
                                context,
                                event_type="bypass_success",
                                data={
                                    "domain": domain,
                                    "technique": technique.get('desc', technique_type)
                                }
                            )
                            return url, content, response.status
                        else:
                            await emit_event(
                                context,
                                event_type="bypass_failed",
                                data={
                                    "domain": domain,
                                    "technique": technique.get('desc', technique_type),
                                    "status_code": response.status
                                }
                            )
                            
            except Exception as e:
                await emit_event(
                    context,
                    event_type="bypass_error",
                    data={
                        "domain": domain,
                        "error": str(e)[:50]
                    }
                )
        
        await emit_event(
            context,
            event_type="all_bypass_failed",
            data={"domain": domain}
        )
        return url, "", 403

    async def fetch_url(self, url: str, context: CrawlContext) -> Tuple[str, str, int]:
        """
        COMPLETELY FIXED URL fetching with:
        1. HTML-only deduplication guard
        2. SSL verification disabled (Instagram / SPA safe)
        3. Hardened metrics & error handling
        4. JS excluded from content dedup (identity handles JS)
        Returns: (url, content, status_code)
        """
        if await context.check_pause_stop():
            return url, "", 0

        start_time = time.time()

        # Normalize early
        normalized_url = self._normalize_url(url)
        domain_key = self._get_domain_key(normalized_url)

        try:
            # HTML-only domain dedup guard
            if self._should_skip_html_domain(normalized_url):
                await emit_event(
                    context,
                    event_type="html_domain_already_processed",
                    data={"domain": domain_key, "url": normalized_url}
                )
                return url, "", 0

            # Circuit breaker
            if not await self._check_circuit_breaker(domain_key, context):
                return url, "", 0

            # Rate limit
            if not await self._check_rate_limit(domain_key, context):
                return url, "", 0

            # DNS
            if not await self.check_dns(domain_key, context):
                metrics = context.shared_state["metrics"]
                metrics["dns_failures"] = metrics.get("dns_failures", 0) + 1
                self._record_failure(domain_key, "dns_failure", context)
                return url, "", 0

            await asyncio.sleep(self.delay)
            if await context.check_pause_stop():
                return url, "", 0

            headers = self._get_enhanced_headers(normalized_url)
            await emit_event(
                context,
                event_type="url_fetching",
                data={"domain": domain_key, "url": normalized_url}
            )

            timeout = aiohttp.ClientTimeout(total=30, connect=10)

            async with self.session.get(
                normalized_url,
                timeout=timeout,
                headers=headers,
                ssl=self.verify_ssl,   # 🔥 SSL disabled correctly
                allow_redirects=True
            ) as response:

                response_time = time.time() - start_time
                metrics = context.shared_state["metrics"]

                metrics.setdefault("urls_crawled", 0)
                metrics.setdefault("avg_response_time", 0)

                metrics["avg_response_time"] = (
                    (metrics["avg_response_time"] * metrics["urls_crawled"] + response_time)
                    / (metrics["urls_crawled"] + 1)
                    if metrics["urls_crawled"] > 0 else response_time
                )

                # ───────────── 403 HANDLING ─────────────
                if response.status == 403:
                    metrics["blocked_403"] = metrics.get("blocked_403", 0) + 1

                    await emit_event(
                        context,
                        event_type="url_blocked",
                        data={"domain": domain_key, "url": normalized_url}
                    )

                    crawler_state = context.shared_state.setdefault("crawler", {})
                    bypass_log = crawler_state.setdefault("bypass_attempts_log", {})

                    if bypass_log.get(domain_key, 0) < 2:
                        fetched_url, content, status = await self._try_403_bypass(
                            normalized_url, domain_key, context
                        )
                        bypass_log[domain_key] = bypass_log.get(domain_key, 0) + 1

                        if status == 200:
                            metrics["urls_crawled"] += 1
                            metrics["bytes_downloaded"] = metrics.get("bytes_downloaded", 0) + len(content)
                            self._record_success(domain_key, context)

                            # 🔥 Track processed URL
                            context.domain_manager.processed_urls.add(normalized_url)

                            return fetched_url, content, status

                    metrics["urls_failed"] = metrics.get("urls_failed", 0) + 1
                    self._record_failure(domain_key, "http_403", context)
                    return url, "", 403

                # ───────────── 200 OK ─────────────
                if response.status == 200:
                    content = await response.text(errors="ignore")

                    if not self._is_valid_content(content, context):
                        metrics["other_errors"] = metrics.get("other_errors", 0) + 1
                        return url, "", 200

                    # HTML-only duplicate detection
                    if not normalized_url.endswith(".js"):
                        if self._is_duplicate_content(content, context):
                            return url, "", 200

                    # Mark HTML domain processed (safe here)
                    if not normalized_url.endswith(".js"):
                        self.processed_html_domains.add(domain_key)

                    metrics["urls_crawled"] += 1
                    metrics["bytes_downloaded"] = metrics.get("bytes_downloaded", 0) + len(content)

                    self._record_success(domain_key, context)

                    # 🔥 Track processed URL
                    context.domain_manager.processed_urls.add(normalized_url)

                    await emit_event(
                        context,
                        event_type="url_fetched",
                        data={
                            "domain": domain_key,
                            "url": normalized_url,
                            "status_code": 200,
                            "response_time": response_time,
                            "content_length": len(content),
                            "type": "js" if normalized_url.endswith(".js") else "html"
                        }
                    )

                    return url, content, 200

                # ───────────── REDIRECTS ─────────────
                if response.status in (301, 302, 307, 308):
                    metrics["redirects_followed"] = metrics.get("redirects_followed", 0) + 1
                    return url, "", response.status

                # ───────────── OTHER HTTP ERRORS ─────────────
                metrics["http_errors"] = metrics.get("http_errors", 0) + 1
                self._record_failure(domain_key, f"http_{response.status}", context)
                return url, "", response.status

        except asyncio.TimeoutError:
            metrics = context.shared_state["metrics"]
            metrics["timeouts"] = metrics.get("timeouts", 0) + 1
            self._record_failure(domain_key, "timeout", context)
            return url, "", 0

        except aiohttp.ClientError:
            metrics = context.shared_state["metrics"]
            metrics["connection_errors"] = metrics.get("connection_errors", 0) + 1
            self._record_failure(domain_key, "client_error", context)
            return url, "", 0

        except Exception:
            metrics = context.shared_state["metrics"]
            metrics["other_errors"] = metrics.get("other_errors", 0) + 1
            self._record_failure(domain_key, "unexpected_error", context)
            return url, "", 0

    async def parse_links(
        self,
        url: str,
        html: str,
        context: CrawlContext
    ) -> Tuple[Set[str], Set[str]]:
        """
        Enhanced HTML parsing with better JS detection
        """
        if await context.check_pause_stop():
            return set(), set()

        links: Set[str] = set()
        js_links: Set[str] = set()

        if not html:
            return links, js_links

        try:
            soup = BeautifulSoup(html, "html.parser")
            metrics = context.shared_state.setdefault("metrics", {})

            # Debug: Log HTML snippet for troubleshooting
            self.logger.debug(f"Parsing {url}, HTML length: {len(html)}")
            if len(html) < 10000:  # Only log small pages
                self.logger.debug(f"HTML sample from {url}: {html[:500]}...")

            # -------------------------------------------------
            # <a href="">
            # -------------------------------------------------
            for a in soup.find_all("a", href=True):
                if await context.check_pause_stop():
                    return links, js_links

                try:
                    raw = urljoin(url, a["href"])
                    normalized = self._normalize_url(raw)
                    parsed = urlparse(normalized)

                    if (
                        parsed.scheme in ("http", "https")
                        and parsed.netloc
                        and context.domain_manager.is_in_scope(normalized)
                    ):
                        links.add(normalized)
                        metrics["links_discovered"] = metrics.get("links_discovered", 0) + 1
                except Exception:
                    continue

            # -------------------------------------------------
            # <script src="">
            # -------------------------------------------------
            for script in soup.find_all("script", src=True):
                if await context.check_pause_stop():
                    return links, js_links

                try:
                    raw_js = urljoin(url, script["src"])
                    normalized_js = self._normalize_url(raw_js)  # 🔥 FIX 4: Normalize before identity check
                    parsed = urlparse(normalized_js)

                    if (
                        parsed.scheme in ("http", "https")
                        and parsed.netloc
                        and context.domain_manager.is_in_scope(normalized_js)
                    ):
                        js_links.add(normalized_js)
                        metrics["js_files_found"] = metrics.get("js_files_found", 0) + 1
                        self.logger.debug(f"Found JS via script src: {normalized_js}")
                except Exception:
                    continue

            # -------------------------------------------------
            # <link href=""> (CSS, preload, icons, etc.)
            # -------------------------------------------------
            for link in soup.find_all("link", href=True):
                if await context.check_pause_stop():
                    return links, js_links

                try:
                    raw = urljoin(url, link["href"])
                    normalized = self._normalize_url(raw)
                    parsed = urlparse(normalized)

                    if (
                        parsed.scheme in ("http", "https")
                        and parsed.netloc
                        and context.domain_manager.is_in_scope(normalized)
                    ):
                        links.add(normalized)
                        metrics["links_discovered"] = metrics.get("links_discovered", 0) + 1
                except Exception:
                    continue

            # -------------------------------------------------
            # Inline script content analysis
            # -------------------------------------------------
            for script in soup.find_all("script"):
                if await context.check_pause_stop():
                    return links, js_links

                # Skip external scripts (already handled)
                if script.get("src"):
                    continue

                content = script.string or script.text
                if not content or len(content) < 20:
                    continue

                # 🔥 ENHANCED: Search for modern JS patterns
                for pattern in INLINE_JS_PATTERNS:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        try:
                            raw_js = match.group(1)
                            resolved = urljoin(url, raw_js)
                            normalized = self._normalize_url(resolved)  # 🔥 FIX 4: Normalize before identity check

                            # Validate it looks like a JS file
                            if not self._looks_like_js(normalized):
                                continue

                            if not context.domain_manager.is_in_scope(normalized):
                                continue

                            js_links.add(normalized)
                            metrics["js_files_found"] = metrics.get("js_files_found", 0) + 1
                            self.logger.debug(f"Found JS via inline pattern: {normalized}")

                        except Exception:
                            continue

            # Log discovery results
            if js_links:
                self.logger.info(f"Found {len(js_links)} JS links in {url}: {list(js_links)[:3]}...")
            else:
                self.logger.debug(f"No JS links found in {url}")

        except Exception as e:
            await emit_event(
                context,
                event_type="parse_error",
                data={
                    "url": url,
                    "error": str(e)[:50]
                }
            )

        return links, js_links

    async def crawl_single_url(
        self,
        url: str,
        current_depth: int,
        context: CrawlContext
    ) -> Tuple[Set[str], Set[str]]:
        """
        Enhanced URL crawling with domain deduplication (HTML ONLY)
        Returns: (links, js_links)
        """

        # Fast interrupt
        if await context.check_pause_stop():
            return set(), set()

        normalized_url = self._normalize_url(url)
        domain_key = self._get_domain_key(normalized_url)

        # Depth guard
        if current_depth > self.max_depth:
            await emit_event(
                context,
                event_type="max_depth_reached",
                data={
                    "url": normalized_url,
                    "current_depth": current_depth,
                    "max_depth": self.max_depth
                }
            )
            return set(), set()

        # URL-level deduplication (backward compatibility)
        if normalized_url in context.domain_manager.processed_urls:
            return set(), set()

        # Track for backward compatibility
        self.seen_urls.add(normalized_url)

        # 🔥 CRITICAL FIX #3: Domain-level deduplication FOR HTML ONLY
        if self._should_skip_html_domain(normalized_url):
            await emit_event(
                context,
                event_type="html_domain_skipped_early",
                data={"domain": domain_key, "url": normalized_url, "type": "html"}
            )
            return set(), set()

        # Retry tracking
        crawler_state = context.shared_state.setdefault("crawler", {})
        retry_attempts = crawler_state.setdefault("retry_attempts", {})
        retry_count = retry_attempts.get(normalized_url, 0)

        self.logger.debug(
            f"Crawling: {normalized_url} (depth={current_depth}, retry={retry_count}, ssl_verify={self.verify_ssl})"
        )

        # Fetch URL
        fetched_url, content, status_code = await self.fetch_url(
            normalized_url, context
        )

        # Retry transient failures
        if not content and status_code in {0, 500, 502, 503} and retry_count < 2:
            retry_attempts[normalized_url] = retry_count + 1

            await emit_event(
                context,
                event_type="retry_triggered",
                data={
                    "url": normalized_url,
                    "attempt": retry_count + 1,
                    "status_code": status_code
                }
            )

            await asyncio.sleep(1 * (retry_count + 1))
            return await self.crawl_single_url(
                normalized_url, current_depth, context
            )

        # Hard failure (DO NOT mark processed)
        if not content or status_code != 200:
            metrics = context.shared_state.setdefault("metrics", {})
            metrics["urls_failed"] = metrics.get("urls_failed", 0) + 1
            return set(), set()

        try:
            # HTML → LINKS + JS
            links, js_links = await self.parse_links(
                fetched_url, content, context
            )

            # 🔥 CRITICAL FIX: Identity-aware JS enqueue decision
            new_js = set()
            js_registry = context.shared_state.get("js_identity_registry")
            
            if js_registry:
                for js_url in js_links:
                    # 🔥 FIX 4: Normalize before computing identity
                    normalized_js = self._normalize_url(js_url)
                    js_identity = compute_js_identity(normalized_js)  # 🔥 FIX 4: Use normalized URL
                    
                    # 🔥 FIX 2: Use public method instead of private access
                    if js_registry.has_identity(js_identity):  # Changed from: js_identity in js_registry._identity_to_hash
                        continue
                    
                    new_js.add(js_url)
            else:
                new_js = js_links

            # 🔥 JS IDENTITY INTEGRATION - CRITICAL POINT
            # This is where JS identity logic is applied
            # NOTE: JS identity & variant logic temporarily lives in crawler for MVP
            # This will move to analyzer in post-MVP refactor
            if fetched_url.endswith(".js"):
                # 🔥 STEP 1: Compute JS identity from normalized URL
                js_identity = compute_js_identity(normalized_url)  # 🔥 FIX 4: Use normalized_url
                
                # 🔥 STEP 2: Compute content hash
                content_bytes = content.encode('utf-8', errors='ignore')
                content_hash = compute_content_hash(content_bytes)
                
                # 🔥 STEP 3: Get or create JS identity registry
                if "js_identity_registry" not in context.shared_state:
                    context.shared_state["js_identity_registry"] = JSIdentityRegistry()
                
                js_registry = context.shared_state["js_identity_registry"]
                
                # 🔥 CRITICAL FIX #1: Capture previous hash BEFORE updating registry
                # 🔥 FIX 2: Use public method instead of private access
                previous_hash = js_registry.get_hash(js_identity)  # Changed from: js_registry._identity_to_hash.get(js_identity)
                
                # 🔥 STEP 4: Check identity with registry (B2: track variants)
                identity_result = js_registry.check_and_update(js_identity, content_hash)
                
                # Track JS variants metric
                metrics = context.shared_state["metrics"]
                if "js_variants_detected" not in metrics:
                    metrics["js_variants_detected"] = 0
                
                if identity_result == "variant":
                    # 🔥 VARIANT DETECTED - re-analyze
                    metrics["js_variants_detected"] += 1
                    
                    await emit_event(
                        context,
                        event_type="js_variant_detected",
                        data={
                            "identity": js_identity,
                            "previous_hash": previous_hash[:16] if previous_hash else None,
                            "new_hash": content_hash[:16],
                            "url": fetched_url
                        }
                    )
                    
                    # Continue with JS analysis (variant detected)
                    
                elif identity_result == "unchanged":
                    # 🔥 IDENTICAL CONTENT - skip analysis
                    metrics["duplicate_js_skipped"] = metrics.get("duplicate_js_skipped", 0) + 1
                    
                    await emit_event(
                        context,
                        event_type="js_duplicate_skipped",
                        data={
                            "identity": js_identity,
                            "url": fetched_url,
                            "hash": content_hash[:16]
                        }
                    )
                    
                    # Skip JS analysis - content hasn't changed
                    js_from_js = set()
                    
                else:  # identity_result == "new"
                    # 🔥 NEW JS IDENTITY - analyze normally
                    await emit_event(
                        context,
                        event_type="js_new_identity",
                        data={
                            "identity": js_identity,
                            "url": fetched_url,
                            "hash": content_hash[:16]
                        }
                    )
                    # Continue with normal JS analysis (new identity)
                
                # 🔥 CRITICAL FIX #2: Extract JS from JS only if we're analyzing this content
                # (skip if it's an unchanged duplicate)
                if identity_result != "unchanged":
                    js_from_js = self.extract_js_imports_from_content(
                        content,
                        fetched_url
                    )

                    for js_url in js_from_js:
                        if not context.domain_manager.is_in_scope(js_url):
                            continue

                        # 🔥 FIX 4: Normalize before computing identity
                        normalized_js_url = self._normalize_url(js_url)  # 🔥 FIX 4: Normalize URL
                        js_identity = compute_js_identity(normalized_js_url)  # 🔥 FIX 4: Use normalized URL
                        
                        # 🔥 FIX 2: Use public method instead of private access
                        if js_registry.has_identity(js_identity):  # Changed from: js_identity in js_registry._identity_to_hash
                            continue
                            
                        # 🔥 FIX 3: Remove immediate enqueue - only collect
                        # context.domain_manager.add_discovered(js_url, depth=current_depth, source_url=fetched_url)  # REMOVED
                        
                        # Add to new_js set for tracking (will be enqueued later)
                        new_js.add(js_url)

            # Enqueue HTML-discovered JS (already identity-filtered) and JS-discovered JS
            for js_url in new_js:
                context.domain_manager.add_discovered(
                    js_url,
                    depth=current_depth,
                    source_url=normalized_url
                )

            if new_js:
                await emit_event(
                    context,
                    event_type="new_js_found",
                    data={
                        "count": len(new_js),
                        "sample": list(new_js)[:10]
                    }
                )

            # Enqueue HTML navigation links
            links_added = 0
            for link in links:
                if await context.check_pause_stop():
                    break

                # Skip if HTML domain already processed
                if self._should_skip_html_domain(link):
                    continue

                added, _ = context.domain_manager.add_discovered(
                    link,
                    depth=current_depth + 1,
                    source_url=normalized_url
                )
                if added:
                    links_added += 1

            if links_added:
                await emit_event(
                    context,
                    event_type="links_added",
                    data={"count": links_added}
                )

            return links, new_js

        except Exception as e:
            metrics = context.shared_state.setdefault("metrics", {})
            metrics["other_errors"] = metrics.get("other_errors", 0) + 1

            await emit_event(
                context,
                event_type="processing_error",
                data={
                    "domain": domain_key,
                    "url": normalized_url,
                    "error": str(e)[:80]
                }
            )
            return set(), set()

    def extract_js_imports_from_content(self, content: str, base_url: str) -> Set[str]:
        """
        Extract JS file references from fetched JS content.
        """
        import re
        from urllib.parse import urljoin

        js_urls = set()

        # Use all patterns for maximum coverage
        patterns = SAFE_JS_PATTERNS + AGGRESSIVE_JS_PATTERNS + MODERN_JS_PATTERNS

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                candidate = match.group(1)
                
                # Skip empty or obviously invalid candidates
                if not candidate or len(candidate) < 3:
                    continue

                # Resolve relative URLs
                full_url = urljoin(base_url, candidate)

                if self._looks_like_js(full_url):
                    js_urls.add(self._normalize_url(full_url))

        return js_urls

    def _looks_like_js(self, url: str) -> bool:
        """Enhanced JS file detection"""
        url_lower = url.lower()
        
        # Direct JS extensions
        if url_lower.endswith('.js') or '.js?' in url_lower:
            return True
        
        # Common JS file patterns
        js_patterns = [
            '/static/', '/assets/', '/chunks/', '/bundles/',
            '/_next/', '/js/', '/javascript/', '/scripts/',
            'chunk-', 'bundle.', 'main.', 'vendor.', 'app.',
            'runtime.', 'polyfills.', 'common.', 'shared.'
        ]
        
        for pattern in js_patterns:
            if pattern in url_lower:
                return True
        
        return False

    async def crawl(self, context: CrawlContext):
        """
        Enhanced crawl method with domain deduplication (HTML ONLY)
        """
        # Initialize crawler state defensively
        context.shared_state.setdefault("crawler", {
            "retry_attempts": {},
            "content_hash_cache": set(),
            "circuit_breaker": {},
            "rate_limit_tracker": {},
            "bypass_attempts_log": {},
        })
        
        # 🔥 JS IDENTITY INTEGRATION - Initialize registry
        context.shared_state.setdefault("js_identity_registry", JSIdentityRegistry())
        
        # Initialize metrics with default values
        metrics = context.shared_state.setdefault("metrics", {})
        metrics.setdefault("start_time", time.time())
        metrics.setdefault("urls_crawled", 0)
        metrics.setdefault("urls_failed", 0)
        metrics.setdefault("dns_failures", 0)
        metrics.setdefault("timeouts", 0)
        metrics.setdefault("connection_errors", 0)
        metrics.setdefault("http_errors", 0)
        metrics.setdefault("other_errors", 0)
        metrics.setdefault("blocked_403", 0)
        metrics.setdefault("bypass_attempts", 0)
        metrics.setdefault("bytes_downloaded", 0)
        metrics.setdefault("redirects_followed", 0)
        metrics.setdefault("js_files_found", 0)
        metrics.setdefault("links_discovered", 0)
        metrics.setdefault("avg_response_time", 0)
        metrics.setdefault("duplicates_skipped", 0)
        # 🔥 JS Identity metrics
        metrics.setdefault("duplicate_js_skipped", 0)
        metrics.setdefault("js_variants_detected", 0)

        # 🔥 CRITICAL FIX: Initialize HTTP session with SSL verification DISABLED
        verify_ssl = self.verify_ssl  # Use instance variable (defaults to False)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=3,
            ssl=verify_ssl,  # 🔥 THIS IS THE FIX: ssl=False
            use_dns_cache=True,
            ttl_dns_cache=300
        )

        # Create session using context manager
        async with aiohttp.ClientSession(connector=connector) as session:
            self.session = session

            await emit_event(
                context,
                event_type="crawl_started",
                data={
                    "concurrency": self.concurrency,
                    "max_depth": self.max_depth,
                    "verify_ssl": verify_ssl,  # Will be False for Instagram
                    "processed_html_domains": len(self.processed_html_domains)
                }
            )

            initial_stats = context.domain_manager.get_stats()
            await emit_event(
                context,
                event_type="initial_stats",
                data={"urls_queued": initial_stats.get('urls_queued', 0)}
            )

            try:
                batch_count = 0
                max_batches = 100
                consecutive_empty = 0
                max_consecutive_empty = 5

                # Enhanced crawl loop with HTML domain filtering
                while (context.domain_manager.has_targets() and 
                       batch_count < max_batches and 
                       consecutive_empty < max_consecutive_empty):

                    if await context.check_pause_stop():
                        break
                        
                    tasks = []
                    targets_batch = []

                    # Collect batch with HTML domain filtering
                    batch_size = min(self.concurrency * 2, 30)
                    for _ in range(batch_size):
                        if await context.check_pause_stop():
                            break
                            
                        url, depth = context.domain_manager.get_next_target()

                        if not url:
                            break
                        
                        # 🔥 CRITICAL FIX #3: Skip HTML domains already processed
                        if self._should_skip_html_domain(url):
                            continue
                        
                        targets_batch.append((url, depth))

                    if not targets_batch:
                        consecutive_empty += 1
                        await asyncio.sleep(0.2)
                        continue

                    consecutive_empty = 0
                    batch_count += 1

                    # Show batch progress
                    progress_percent = (batch_count / max_batches) * 100
                    
                    await emit_event(
                        context,
                        event_type="batch_started",
                        data={
                            "batch_number": batch_count,
                            "max_batches": max_batches,
                            "batch_size": len(targets_batch),
                            "progress_percent": progress_percent,
                            "ssl_verify": verify_ssl
                        }
                    )

                    # Process batch
                    for url, depth in targets_batch:
                        if await context.check_pause_stop():
                            break
                        task = self.crawl_single_url(url, depth, context)
                        tasks.append(task)

                    if tasks and not await context.check_pause_stop():
                        try:
                            results = await asyncio.gather(*tasks, return_exceptions=True)

                            successful_links = 0
                            successful_js = 0
                            for result in results:
                                if await context.check_pause_stop():
                                    break
                                    
                                if isinstance(result, Exception):
                                    await emit_event(
                                        context,
                                        event_type="task_failed",
                                        data={"error": str(result)[:50]}
                                    )
                                    continue

                                links, js_files = result
                                successful_links += len(links)
                                successful_js += len(js_files)

                            if successful_links > 0 or successful_js > 0:
                                await emit_event(
                                    context,
                                    event_type="batch_completed",
                                    data={
                                        "links_found": successful_links,
                                        "js_files_found": successful_js
                                    }
                                )

                        except Exception as e:
                            await emit_event(
                                context,
                                event_type="batch_error",
                                data={"error": str(e)[:50]}
                            )

                    # Progress reporting
                    elapsed = time.time() - context.shared_state["metrics"]["start_time"]
                    current_stats = context.domain_manager.get_stats()
                    crawl_stats = self.get_stats(context)
                    
                    # 🔥 Include JS Identity stats
                    js_registry = context.shared_state.get("js_identity_registry")
                    js_stats = js_registry.get_stats() if js_registry else {}
                    
                    await emit_event(
                        context,
                        event_type="stats_update",
                        data={
                            "metrics": {
                                "urls_crawled": crawl_stats['urls_crawled'],
                                "urls_failed": crawl_stats['urls_failed'],
                                "remaining_urls": current_stats.get('urls_queued', 0),
                                "js_files_found": self.domain_manager.get_js_queue_size(),  # 🔥 Use DomainManager as single source
                                "blocked_403": crawl_stats['blocked_403'],
                                "batch_count": batch_count,
                                "elapsed_time": elapsed,
                                "processed_html_domains": len(self.processed_html_domains),
                                "ssl_verify": verify_ssl,
                                # 🔥 JS Identity metrics
                                "js_identities": js_stats.get("total_identities", 0),
                                "js_variants": crawl_stats['js_variants_detected'],
                                "duplicate_js_skipped": crawl_stats.get('duplicate_js_skipped', 0)
                            }
                        }
                    )

                    # Adaptive delay
                    await asyncio.sleep(0.05)

                await emit_event(
                    context,
                    event_type="crawl_completed",
                    data={
                        "batch_count": batch_count,
                        "ssl_verify": verify_ssl,
                        "processed_html_domains": len(self.processed_html_domains)
                    }
                )

            except asyncio.CancelledError:
                self.logger.info("Crawler task cancelled, shutting down session cleanly")
                raise

            except Exception as e:
                await emit_event(
                    context,
                    event_type="crawl_critical_error",
                    data={
                        "error": str(e),
                        "traceback": str(e)[:100]
                    }
                )
                import traceback
                self.logger.error(f"Crawler critical error: {e}", exc_info=True)

            finally:
                self.session = None

        # Final statistics
        elapsed = time.time() - context.shared_state["metrics"]["start_time"]
        stats = self.get_stats(context)
        
        # 🔥 JS Identity final stats
        js_registry = context.shared_state.get("js_identity_registry")
        js_stats = js_registry.get_stats() if js_registry else {}

        await emit_event(
            context,
            event_type="crawl_final_stats",
            data={
                "metrics": {
                    'urls_crawled': stats['urls_crawled'],
                    'urls_failed': stats['urls_failed'],
                    'js_files_found': self.domain_manager.get_js_queue_size(),  # 🔥 Use DomainManager as single source
                    'links_discovered': stats['links_discovered'],
                    'blocked_403': stats['blocked_403'],
                    'bypass_attempts': stats['bypass_attempts'],
                    'bytes_downloaded': stats['bytes_downloaded'],
                    'total_time': elapsed,
                    'avg_response_time': stats['avg_response_time'],
                    'crawl_rate': stats['urls_crawled'] / elapsed if elapsed > 0 else 0,
                    'processed_html_domains': len(self.processed_html_domains),
                    'ssl_verify': verify_ssl,
                    # 🔥 JS Identity final metrics
                    'js_identities': js_stats.get("total_identities", 0),
                    'js_variants_detected': stats.get('js_variants_detected', 0),
                    'duplicate_js_skipped': stats.get('duplicate_js_skipped', 0),
                }
            }
        )

    def get_stats(self, context: CrawlContext) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        metrics = context.shared_state.get("metrics", {})
        crawler_state = context.shared_state.get("crawler", {})
        
        return {
            'total_urls_crawled': len(self.seen_urls),
            'total_js_discovered': self.domain_manager.get_js_queue_size(),  # 🔥 Use DomainManager as single source
            'urls_crawled': metrics.get("urls_crawled", 0),
            'urls_failed': metrics.get("urls_failed", 0),
            'dns_failures': metrics.get("dns_failures", 0),
            'timeouts': metrics.get("timeouts", 0),
            'connection_errors': metrics.get("connection_errors", 0),
            'http_errors': metrics.get("http_errors", 0),
            'other_errors': metrics.get("other_errors", 0),
            'blocked_403': metrics.get("blocked_403", 0),
            'bypass_attempts': metrics.get("bypass_attempts", 0),
            'bytes_downloaded': metrics.get("bytes_downloaded", 0),
            'redirects_followed': metrics.get("redirects_followed", 0),
            'js_files_found': metrics.get("js_files_found", 0),
            'links_discovered': metrics.get("links_discovered", 0),
            'avg_response_time': metrics.get("avg_response_time", 0),
            'elapsed_time': time.time() - metrics.get("start_time", 0) if metrics.get("start_time", 0) else 0,
            'processed_html_domains': len(self.processed_html_domains),
            'ssl_verify': self.verify_ssl,
            # 🔥 JS Identity metrics
            'duplicate_js_skipped': metrics.get("duplicate_js_skipped", 0),
            'js_variants_detected': metrics.get("js_variants_detected", 0),
        }

    def reset(self):
        """Reset crawler for new scan"""
        self.processed_html_domains.clear()
        self.seen_urls.clear()


# Backward compatibility
Crawler = CompleteCrawler
EnterpriseCrawler = CompleteCrawler
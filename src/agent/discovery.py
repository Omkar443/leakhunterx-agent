#!/usr/bin/env python3
"""
LeakHunterX - Passive Subdomain Discovery
Production-grade, lightweight, minimal external dependencies.

DESIGN PRINCIPLES:
1. PASSIVE ONLY - no brute force, no wordlists
2. FAST - completes in < 10 seconds (bounded by max_total_time)
3. SAFE - no breaking changes to existing system
4. FOUNDATIONAL - sets stage for future expansion

CHANGELOG (this revision):
- NEW: Certificate Transparency (crt.sh) source - typically the single
  highest-yield passive source available. Toggle: config.use_ct_logs.
- NEW: HTTP retry with exponential backoff + jitter on transient
  failures (429/500/502/503/504, connection errors, timeouts).
- NEW: Optional aiodns-based async DNS resolver (falls back cleanly to
  the original loop.getaddrinfo path if aiodns isn't installed - this
  is a soft dependency, nothing breaks if you don't pip install it).
- NEW: Optional CNAME capture per verified result (only populated when
  aiodns is available). Additive field, defaults to None - does not
  break existing consumers of DiscoveryResult.to_dict().
- FIXED: asyncio.get_event_loop() -> asyncio.get_running_loop()
  (get_event_loop() is deprecated/unsafe to call with no running loop
  bound to the thread in newer Python versions).
- NEW: scan_id correlation id threaded through logs/metrics.
- NEW: small stagger between sequential HTTP requests to reduce the
  chance of tripping basic WAF rate-limit heuristics.

TO ENABLE THE OPTIONAL FASTER DNS PATH:
    pip install aiodns
If aiodns is not installed, everything still works exactly as before
via loop.getaddrinfo - this dependency is optional, not required.
"""

import asyncio
import logging
import random
import re
import socket
import time
import uuid
from typing import Set, List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl
import json
from dataclasses import dataclass, field
from collections import defaultdict

# ------------------------------------------------------------
# OPTIONAL: aiodns for true async DNS resolution.
# Soft dependency - if not installed, we transparently fall back to
# the original loop.getaddrinfo() based path. Nothing breaks either way.
# ------------------------------------------------------------
try:
    import aiodns  # type: ignore
    AIODNS_AVAILABLE = True
except ImportError:
    aiodns = None
    AIODNS_AVAILABLE = False


# ------------------------------------------------------------
# REALISTIC BROWSER HEADERS
# Many sites (Cloudflare, Akamai, basic WAFs, even plain nginx
# configs) 403 or silently drop requests with the default aiohttp
# User-Agent ("Python/3.x aiohttp/x"). Without this, HTTP-based
# discovery (headers, CSP, JS/HTML scraping) can silently return
# nothing for a large fraction of real-world targets.
# ------------------------------------------------------------
DEFAULT_DISCOVERY_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


@dataclass
class DiscoveryResult:
    """Structured result for discovered subdomain"""
    url: str
    source: str  # "dns", "common_prefix", "cname", "header", "js", "ct_log", etc.
    confidence: float = 1.0
    # NEW: best-effort CNAME target. Only populated when aiodns is
    # available and the record exists. Additive/optional - safe default.
    cname: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "source": self.source,
            "confidence": self.confidence,
            "cname": self.cname,
        }


@dataclass
class DiscoveryConfig:
    """Configuration for discovery engine"""
    # Timeouts
    http_timeout: int = 5
    dns_timeout: int = 2
    max_total_time: int = 10
    ct_log_timeout: int = 10  # NEW: crt.sh can be slower than regular HTTP targets

    # Limits
    max_subdomains: int = 50
    max_requests: int = 20

    # NEW: retry behavior for transient HTTP failures
    http_max_retries: int = 3
    http_retry_base_delay: float = 0.5  # seconds, doubles each retry + jitter

    # NEW: small delay between sequential requests to the same target
    # domain family, to look less like a scanner hammering the host.
    inter_request_delay: float = 0.2

    # Sources to use
    use_common_prefixes: bool = True
    use_cname_check: bool = True
    use_response_headers: bool = True
    use_js_extraction: bool = True
    use_http_extraction: bool = True
    use_second_pass: bool = True  # Optional second discovery pass
    use_ct_logs: bool = True  # NEW: Certificate Transparency (crt.sh)

    # Common subdomain prefixes (curated list)
    common_prefixes: List[str] = field(default_factory=lambda: [
        # Infrastructure
        "api", "www", "app", "dev", "test", "staging", "prod", "demo",
        # Services
        "admin", "dashboard", "console", "portal", "login", "auth",
        "account", "billing", "payments", "shop", "store",
        # Infrastructure (continued)
        "cdn", "static", "assets", "media", "uploads", "downloads",
        "images", "img", "video", "stream",
        # Development
        "development", "sandbox", "playground", "experiment",
        # Documentation
        "docs", "help", "support", "status", "monitor",
        # Email
        "mail", "email", "smtp", "imap", "pop",
        # Mobile
        "m", "mobile", "mobil", "wap",
        # Regional
        "us", "uk", "eu", "asia", "apac", "emea",
        # Special
        "origin", "edge", "gateway", "proxy", "vpn"
    ])


class DiscoveryEngine:
    """
    Lightweight, passive-only subdomain discovery.

    Methods:
    1. Common prefix checking (api., dev., staging., etc.)
    2. CNAME resolution (if domain resolves, it exists)
    3. HTTP response headers (CSP, redirects, etc.)
    4. HTML/JS extraction (from initial seed page)
    5. Certificate Transparency logs (crt.sh) - NEW
    6. Optional second pass for deeper discovery
    """

    def __init__(self, base_domain: str, config: Optional[DiscoveryConfig] = None):
        """
        Args:
            base_domain: Root domain (e.g., "example.com")
            config: Discovery configuration
        """
        self.base_domain = base_domain.lower().strip()
        self.config = config or DiscoveryConfig()
        self.logger = logging.getLogger("discovery")

        # NEW: correlation id for this scan, threaded through log lines
        # and metrics so multi-scan backends can filter logs per run.
        self.scan_id = uuid.uuid4().hex[:12]

        # HTTP client session - created on demand if not using async context
        self._session = None
        self._owns_session = False
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # NEW: async DNS resolver (aiodns), created lazily once we have a
        # running event loop. Stays None if aiodns isn't installed -
        # every call site below already handles that fallback.
        self._resolver = None

        # Wildcard DNS tracking - set by _detect_wildcard_dns()
        self.wildcard_detected: bool = False

        # Results storage
        self.discovered_results: List[DiscoveryResult] = []
        self.discovery_metrics: Dict[str, Any] = {
            "scan_id": self.scan_id,
            "start_time": 0,
            "end_time": 0,
            "methods_used": [],
            "candidates_tested": 0,
            "candidates_found": 0,
            "errors": 0,
            "requests_made": 0,
            "wildcard_dns_detected": False,
            "timed_out": False,
            "dns_resolver": "aiodns" if AIODNS_AVAILABLE else "getaddrinfo_fallback",
        }

    def _ensure_resolver(self) -> None:
        """
        Create the aiodns resolver if the library is available and we
        don't already have one. Must be called from within a running
        event loop. No-op (silently) if aiodns isn't installed - the
        rest of the code already falls back to loop.getaddrinfo.
        """
        if AIODNS_AVAILABLE and self._resolver is None:
            try:
                self._resolver = aiodns.DNSResolver(timeout=self.config.dns_timeout)
            except Exception as e:
                self.logger.debug(f"Could not initialize aiodns resolver, falling back: {e}")
                self._resolver = None

    async def __aenter__(self):
        """Async context manager entry"""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.http_timeout),
            connector=aiohttp.TCPConnector(ssl=self.ssl_context),
            headers=DEFAULT_DISCOVERY_HEADERS
        )
        self._owns_session = True
        self._ensure_resolver()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._session and self._owns_session:
            await self._session.close()
            self._session = None
            self._owns_session = False

    async def discover(self) -> List[DiscoveryResult]:
        """
        Run all passive discovery methods.
        Returns: List of discovered subdomains with metadata
        """
        self.discovery_metrics["start_time"] = time.time()

        # Ensure we have a session for HTTP discovery
        if (self.config.use_http_extraction or self.config.use_js_extraction
                or self.config.use_ct_logs) and not self._session:
            self.logger.warning("HTTP discovery requested but no session available. Creating temporary session.")
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.http_timeout),
                connector=aiohttp.TCPConnector(ssl=self.ssl_context),
                headers=DEFAULT_DISCOVERY_HEADERS
            )
            self._owns_session = True

        # Ensure resolver exists even if discover() is called without
        # going through __aenter__ first (matches the session fallback above).
        self._ensure_resolver()

        try:
            # max_total_time bounds the ENTIRE discovery pipeline as a
            # single unit, so a slow/rate-limiting target can't run past
            # its intended time budget.
            try:
                verified_results = await asyncio.wait_for(
                    self._run_discovery_pipeline(),
                    timeout=self.config.max_total_time
                )
            except asyncio.TimeoutError:
                self.logger.warning(
                    f"[{self.scan_id}] Discovery exceeded max_total_time "
                    f"({self.config.max_total_time}s) for {self.base_domain} - "
                    f"aborting this discovery run."
                )
                self.discovery_metrics["timed_out"] = True
                self.discovery_metrics["end_time"] = time.time()
                self.discovery_metrics["duration"] = (
                    self.discovery_metrics["end_time"] - self.discovery_metrics["start_time"]
                )
                return []

            self.discovered_results = verified_results

            self.discovery_metrics.update({
                "end_time": time.time(),
                "duration": time.time() - self.discovery_metrics["start_time"],
                "candidates_found": len(verified_results),
            })

            self.logger.info(
                f"[{self.scan_id}] Discovery complete: found {len(verified_results)} subdomains "
                f"in {self.discovery_metrics['duration']:.2f}s"
            )

            return verified_results

        except Exception as e:
            self.logger.error(f"[{self.scan_id}] Discovery failed: {e}")
            return []
        finally:
            # Clean up temporary session if we created it
            # (runs regardless of success, timeout, or error above)
            if self._session and self._owns_session:
                await self._session.close()
                self._session = None
                self._owns_session = False

    async def _run_discovery_pipeline(self) -> List[DiscoveryResult]:
        """
        Core discovery pipeline: wildcard check, CT logs, both discovery
        passes, confidence adjustment, dedup, verification, and result
        capping. Bounded as one unit by asyncio.wait_for(max_total_time)
        in discover().
        """
        # Check for wildcard DNS BEFORE trusting any DNS-based discovery
        # (common_prefix, cname). Must run first so downstream confidence
        # adjustment below can use the flag.
        if self.config.use_common_prefixes or self.config.use_cname_check:
            self.wildcard_detected = await self._detect_wildcard_dns()
            self.discovery_metrics["wildcard_dns_detected"] = self.wildcard_detected

        # NEW: Certificate Transparency logs. Independent of DNS-guessing
        # entirely - runs in parallel conceptually with the prefix/cname
        # passes below (kicked off here, awaited before we need it).
        ct_results: List[DiscoveryResult] = []
        if self.config.use_ct_logs:
            ct_results = await self._discover_from_ct_logs()
            if ct_results and "ct_log" not in self.discovery_metrics["methods_used"]:
                self.discovery_metrics["methods_used"].append("ct_log")
            self.discovery_metrics["candidates_tested"] += len(ct_results)

        # First pass - basic discovery
        first_pass_results = await self._run_discovery_pass(1)

        # Optional second pass - deeper discovery using first pass results
        second_pass_results = []
        if self.config.use_second_pass and first_pass_results:
            self.logger.debug(f"[{self.scan_id}] Running second discovery pass...")
            second_pass_results = await self._run_discovery_pass(2, first_pass_results)

        # Combine results from all sources
        all_results = first_pass_results + second_pass_results + ct_results

        # If wildcard DNS is active, DNS resolution alone is not
        # meaningful evidence a subdomain is real - every candidate
        # would resolve regardless. Down-weight (not drop) affected
        # results so they're still visible but clearly marked as
        # low-confidence rather than presented as equally trustworthy
        # as HTTP/CSP/JS/CT-sourced findings.
        # NOTE: ct_log results are deliberately NOT down-weighted here -
        # a cert being issued for a name is independent evidence from
        # wildcard DNS and isn't invalidated by it.
        if self.wildcard_detected:
            for result in all_results:
                if result.source in ("common_prefix", "cname"):
                    result.confidence = round(result.confidence * 0.3, 2)

        # Deduplicate and verify
        deduplicated = self._deduplicate_results(all_results)
        verified_results = await self._verify_results(deduplicated)

        # Cap results (safety first)
        if len(verified_results) > self.config.max_subdomains:
            self.logger.warning(
                f"[{self.scan_id}] Capping results from {len(verified_results)} to {self.config.max_subdomains}"
            )
            verified_results = verified_results[:self.config.max_subdomains]

        return verified_results

    async def _run_discovery_pass(self, pass_num: int,
                                  previous_results: List[DiscoveryResult] = None) -> List[DiscoveryResult]:
        """Run a discovery pass"""
        results_by_method = {}

        # Run discovery methods for this pass
        if pass_num == 1:
            # First pass uses basic methods
            if self.config.use_common_prefixes:
                results_by_method["common_prefix"] = await self._discover_from_common_prefixes()

            if self.config.use_cname_check:
                results_by_method["cname"] = await self._discover_from_cname_patterns()

        # Always run HTTP/JS extraction if enabled
        if self.config.use_http_extraction or self.config.use_js_extraction:
            if pass_num == 1:
                # First pass checks the base domain
                targets = [f"https://{self.base_domain}"]
            else:
                # Second pass checks previously discovered subdomains
                targets = [r.url for r in previous_results[:5]]  # Limit to 5 for safety

            http_results = await self._discover_from_http(targets)
            if http_results:
                results_by_method["http"] = http_results

        # Flatten and return all results
        all_results = []
        for method_name, results in results_by_method.items():
            all_results.extend(results)
            if method_name not in self.discovery_metrics["methods_used"]:
                self.discovery_metrics["methods_used"].append(method_name)

        self.discovery_metrics["candidates_tested"] += sum(len(r) for r in results_by_method.values())

        return all_results

    async def _discover_from_common_prefixes(self) -> List[DiscoveryResult]:
        """Check common subdomain prefixes (api., dev., etc.)"""
        results = []

        # Create subdomains to check
        candidates = [f"{prefix}.{self.base_domain}"
                     for prefix in self.config.common_prefixes]

        # Limit candidates
        candidates = candidates[:self.config.max_subdomains]

        # Check DNS resolution in batches
        batch_size = 10
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            batch_tasks = [
                self._check_dns_resolution_with_source(candidate, "common_prefix")
                for candidate in batch
            ]

            try:
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

                for candidate, result in zip(batch, batch_results):
                    if isinstance(result, Exception):
                        continue
                    if result:  # DNS resolved successfully
                        results.append(result)

            except Exception as e:
                self.logger.debug(f"[{self.scan_id}] Batch DNS check failed: {e}")
                continue

        return results

    async def _discover_from_cname_patterns(self) -> List[DiscoveryResult]:
        """Discover subdomains via common CNAME patterns"""
        results = []

        # Common subdomains that often have CNAMEs
        cname_candidates = [
            f"assets.{self.base_domain}",
            f"cdn.{self.base_domain}",
            f"static.{self.base_domain}",
            f"media.{self.base_domain}",
            f"uploads.{self.base_domain}",
            f"downloads.{self.base_domain}",
            f"images.{self.base_domain}",
            f"img.{self.base_domain}",
            f"video.{self.base_domain}",
        ]

        for candidate in cname_candidates:
            try:
                result = await self._check_dns_resolution_with_source(candidate, "cname")
                if result:
                    results.append(result)
            except Exception:
                continue

        return results

    # ------------------------------------------------------------
    # NEW: Certificate Transparency (crt.sh)
    # ------------------------------------------------------------
    async def _discover_from_ct_logs(self) -> List[DiscoveryResult]:
        """
        Query crt.sh's Certificate Transparency search for any certificate
        ever issued covering *.base_domain. This is a PASSIVE source (a
        public CT log mirror, no interaction with the target itself) and
        is typically the single highest-yield source available, since it
        surfaces subdomains that were never linked from any page and
        never guessed by a wordlist.

        crt.sh is a free, unauthenticated, community-run service known
        to be slow/flaky under load - failures here are non-fatal and
        simply mean this source contributes zero results for this run.
        """
        if not self._session:
            return []

        url = f"https://crt.sh/?q=%.{self.base_domain}&output=json"
        response_data = await self._fetch_with_retry(url, timeout_override=self.config.ct_log_timeout)

        if response_data is None:
            self.logger.debug(f"[{self.scan_id}] CT log lookup failed after retries")
            return []
        if response_data["status"] != 200:
            self.logger.debug(f"[{self.scan_id}] CT log lookup returned status {response_data['status']}")
            return []
        if not response_data["text"]:
            return []

        try:
            entries = json.loads(response_data["text"])
        except (json.JSONDecodeError, TypeError):
            self.logger.debug(f"[{self.scan_id}] CT log response was not valid JSON")
            return []

        if not isinstance(entries, list):
            return []

        results = []
        seen: Set[str] = set()
        base_parts = self.base_domain.split(".")

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name_value = entry.get("name_value", "") or ""
            for raw_name in name_value.split("\n"):
                name = raw_name.strip().lower().lstrip("*.")
                if not name or name in seen:
                    continue
                if name == self.base_domain or not name.endswith(self.base_domain):
                    continue

                # Same strict subdomain check used elsewhere in this file -
                # protects against a naive endswith() match like
                # "notexample.com" wrongly matching "example.com".
                name_parts = name.split(".")
                if name_parts[-len(base_parts):] != base_parts:
                    continue

                seen.add(name)
                results.append(DiscoveryResult(url=f"https://{name}", source="ct_log", confidence=0.85))

        return results

    # ------------------------------------------------------------
    # NEW: HTTP fetch helper with retry + backoff + jitter
    # ------------------------------------------------------------
    async def _fetch_with_retry(self, url: str, timeout_override: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        GET a URL with retry + exponential backoff + jitter on transient
        failures (429/500/502/503/504, connection errors, timeouts).

        Returns a plain dict snapshot of the response instead of the raw
        aiohttp response object, so retries can safely re-open the
        connection on each attempt without leaking unclosed responses:
            {"status": int, "headers": dict, "history": [urls...],
             "text": str, "final_url": str}
        Returns None if every attempt fails.
        """
        request_kwargs: Dict[str, Any] = {"allow_redirects": True}
        if timeout_override:
            request_kwargs["timeout"] = aiohttp.ClientTimeout(total=timeout_override)

        last_error: Optional[Exception] = None

        for attempt in range(self.config.http_max_retries):
            try:
                async with self._session.get(url, **request_kwargs) as response:
                    status = response.status

                    # Only retry on transient server-side / rate-limit errors,
                    # and only if we have attempts left.
                    if status in (429, 500, 502, 503, 504) and attempt < self.config.http_max_retries - 1:
                        delay = self.config.http_retry_base_delay * (2 ** attempt) + random.uniform(0, 0.25)
                        self.logger.debug(
                            f"[{self.scan_id}] Transient {status} for {url}, "
                            f"retrying in {delay:.2f}s (attempt {attempt + 1}/{self.config.http_max_retries})"
                        )
                        await asyncio.sleep(delay)
                        continue

                    headers = dict(response.headers)
                    history_netlocs = [str(hist_resp.url) for hist_resp in response.history]

                    text = ""
                    if self.config.use_js_extraction:
                        try:
                            text = await response.text()
                        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
                            text = ""
                    elif url.startswith("https://crt.sh"):
                        # crt.sh JSON must always be read regardless of the
                        # use_js_extraction toggle (that flag only governs
                        # target-site JS/HTML scraping).
                        try:
                            text = await response.text()
                        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
                            text = ""

                    return {
                        "status": status,
                        "headers": headers,
                        "history": history_netlocs,
                        "text": text,
                        "final_url": str(response.url),
                    }

            except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError) as e:
                last_error = e
                if attempt < self.config.http_max_retries - 1:
                    delay = self.config.http_retry_base_delay * (2 ** attempt) + random.uniform(0, 0.25)
                    self.logger.debug(
                        f"[{self.scan_id}] Request failed for {url} ({e}), "
                        f"retrying in {delay:.2f}s (attempt {attempt + 1}/{self.config.http_max_retries})"
                    )
                    await asyncio.sleep(delay)
                    continue
                self.logger.debug(f"[{self.scan_id}] Request permanently failed for {url}: {last_error}")
                return None

        return None

    async def _discover_from_http(self, targets: List[str]) -> List[DiscoveryResult]:
        """Discover subdomains from HTTP responses (headers, redirects, JS)"""
        if not self._session:
            self.logger.warning(f"[{self.scan_id}] HTTP discovery skipped: no session available")
            return []

        results = []

        for idx, target in enumerate(targets):
            if self.discovery_metrics["requests_made"] >= self.config.max_requests:
                self.logger.debug(f"[{self.scan_id}] Max requests reached, stopping HTTP discovery")
                break

            self.discovery_metrics["requests_made"] += 1
            response_data = await self._fetch_with_retry(target)

            if response_data is None:
                continue  # already logged inside _fetch_with_retry

            # Extract from response headers
            if self.config.use_http_extraction:
                header_results = self._extract_from_headers(response_data["headers"], target)
                results.extend(header_results)

            # Extract from response body (JS, HTML)
            if self.config.use_js_extraction and response_data["text"]:
                js_results = await self._extract_from_content(response_data["text"], target)
                results.extend(js_results)

            # Track redirect chain
            for redirect_url in response_data["history"]:
                parsed = urlparse(redirect_url)
                if parsed.netloc and parsed.netloc != urlparse(target).netloc:
                    results.append(DiscoveryResult(
                        url=f"https://{parsed.netloc}",
                        source="redirect",
                        confidence=0.9
                    ))

            # NEW: small stagger between sequential requests so we look
            # less like a scanner hammering the host back-to-back.
            if idx < len(targets) - 1:
                await asyncio.sleep(self.config.inter_request_delay + random.uniform(0, 0.15))

        return results

    def _extract_from_headers(self, headers: Dict[str, str],
                               source_url: str) -> List[DiscoveryResult]:
        """
        Extract subdomains from HTTP headers.

        CHANGED: now takes a plain header dict (from _fetch_with_retry's
        snapshot) instead of the live aiohttp response object, so it no
        longer needs to run inside the response's `async with` block and
        works cleanly with the retry path. Behavior/logic unchanged.
        """
        results = []

        # Check Content-Security-Policy header
        csp_header = headers.get('Content-Security-Policy', '')
        if csp_header:
            # Match CSP directive values that contain domains
            # Examples: *.example.com, https://api.example.com, example.com
            # Exclude: 'self', 'unsafe-inline', 'none', etc.
            csp_pattern = r'(?:https?:)?//([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})'
            matches = re.finditer(csp_pattern, csp_header)

            for match in matches:
                domain = match.group(1)
                # Remove wildcard prefix if present
                if domain.startswith('*.'):
                    domain = domain[2:]

                # Verify it's actually a subdomain of our target
                if (domain.endswith(self.base_domain) and
                    domain != self.base_domain and
                    '.' in domain[:-len(self.base_domain)-1]):
                    # Ensure it's not something like evil-example.com
                    domain_parts = domain.split('.')
                    base_parts = self.base_domain.split('.')
                    if domain_parts[-len(base_parts):] == base_parts:
                        result = DiscoveryResult(
                            url=f"https://{domain}",
                            source="csp_header",
                            confidence=0.8
                        )
                        results.append(result)

        # Check Location header for redirects
        location_header = headers.get('Location', '')
        if location_header:
            parsed = urlparse(location_header)
            if parsed.netloc and self.base_domain in parsed.netloc:
                # Verify it's actually a subdomain, not just contains the string
                if parsed.netloc.endswith(self.base_domain):
                    result = DiscoveryResult(
                        url=f"https://{parsed.netloc}",
                        source="location_header",
                        confidence=0.9
                    )
                    results.append(result)

        # Check Access-Control-Allow-Origin
        acao_header = headers.get('Access-Control-Allow-Origin', '')
        if acao_header and acao_header != '*':
            parsed = urlparse(acao_header)
            if parsed.netloc and parsed.netloc.endswith(self.base_domain):
                result = DiscoveryResult(
                    url=f"https://{parsed.netloc}",
                    source="acao_header",
                    confidence=0.7
                )
                results.append(result)

        return results

    async def _extract_from_content(self, content: str,
                                    source_url: str) -> List[DiscoveryResult]:
        """Extract subdomains from page content (JS, HTML)"""
        results = []

        # Pattern to find URLs in JavaScript/HTML
        url_patterns = [
            # JavaScript strings with URLs
            r'["\'](https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[^"\']*)["\']',
            r'["\'](//[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[^"\']*)["\']',
            # JavaScript variable assignments
            r'(?:url|domain|host|api)[\s=:]+["\']([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})["\']',
            # Common API endpoints in JS
            r'(?:fetch|axios|ajax|XMLHttpRequest)\(["\'](https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.' +
            re.escape(self.base_domain) + r'[^"\']*)["\']',
            # WebSocket connections
            r'ws[s]?://([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})',
        ]

        seen = set()
        for pattern in url_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                url_candidate = match.group(1)

                # Normalize URL
                if url_candidate.startswith('//'):
                    url_candidate = 'https:' + url_candidate
                elif not url_candidate.startswith('http'):
                    url_candidate = 'https://' + url_candidate

                # Extract domain
                try:
                    parsed = urlparse(url_candidate)
                    domain = parsed.netloc

                    # Check if it's a subdomain of our target
                    if (domain and
                        domain.endswith(self.base_domain) and
                        domain != self.base_domain and
                        domain not in seen):

                        # Ensure it's actually a subdomain, not just contains the string
                        domain_parts = domain.split('.')
                        base_parts = self.base_domain.split('.')
                        if domain_parts[-len(base_parts):] == base_parts:
                            seen.add(domain)
                            result = DiscoveryResult(
                                url=f"https://{domain}",
                                source="js_extraction",
                                confidence=0.6
                            )
                            results.append(result)
                except Exception:
                    continue

        return results

    async def _check_dns_resolution_with_source(
        self,
        hostname: str,
        source: str
    ) -> Optional[DiscoveryResult]:
        """
        Check if a hostname resolves via DNS (A or AAAA).

        CHANGED: uses aiodns for true async resolution when available
        (faster under concurrency, avoids exhausting the default
        executor thread pool that loop.getaddrinfo relies on). Falls
        back to the original loop.getaddrinfo path if aiodns isn't
        installed - behavior there is otherwise unchanged, aside from
        the get_event_loop() -> get_running_loop() fix.
        """
        if self._resolver is not None:
            for record_type in ("A", "AAAA"):
                try:
                    await asyncio.wait_for(
                        self._resolver.query(hostname, record_type),
                        timeout=self.config.dns_timeout
                    )
                    return DiscoveryResult(url=f"https://{hostname}", source=source)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    # aiodns.error.DNSError covers NXDOMAIN etc; caught
                    # broadly here since aiodns may be None-guarded above
                    # but its error module is only meaningful if imported.
                    if AIODNS_AVAILABLE and isinstance(e, aiodns.error.DNSError):
                        continue
                    self.logger.debug(f"[{self.scan_id}] aiodns lookup error for {hostname}: {e}")
                    continue
            return None

        # Fallback path: stdlib resolution via the running loop's executor.
        try:
            loop = asyncio.get_running_loop()  # FIXED: was get_event_loop()

            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    await asyncio.wait_for(
                        loop.getaddrinfo(hostname, 443, family=family),
                        timeout=self.config.dns_timeout
                    )
                    return DiscoveryResult(url=f"https://{hostname}", source=source)
                except (socket.gaierror, asyncio.TimeoutError):
                    continue

            return None

        except Exception as e:
            self.logger.debug(f"[{self.scan_id}] DNS resolution failed for {hostname}: {e}")
            return None

    async def _get_cname(self, hostname: str) -> Optional[str]:
        """
        NEW: best-effort CNAME lookup, used only during verification to
        enrich results with dangling-CNAME visibility. Returns None if
        aiodns isn't installed, there's no CNAME record, or the query
        fails/times out - this is purely additive and never raises.
        """
        if self._resolver is None:
            return None
        try:
            answer = await asyncio.wait_for(
                self._resolver.query(hostname, "CNAME"),
                timeout=self.config.dns_timeout
            )
            cname = getattr(answer, "cname", None)
            return str(cname).rstrip(".") if cname else None
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    async def _detect_wildcard_dns(self) -> bool:
        """
        Detect wildcard DNS (e.g. "*.example.com A 1.2.3.4").

        Without this check, every common_prefix/cname candidate resolves
        successfully on a wildcard domain, producing 40+ false-positive
        "subdomains" that are really all the same wildcard record.

        Probes a random, virtually-guaranteed-nonexistent label. If it
        resolves, wildcard DNS is active for this domain.
        """
        random_label = uuid.uuid4().hex[:16]
        probe_hostname = f"{random_label}-lhx-wildcard-check.{self.base_domain}"

        result = await self._check_dns_resolution_with_source(probe_hostname, "wildcard_probe")
        detected = result is not None

        if detected:
            self.logger.info(
                f"[{self.scan_id}] Wildcard DNS detected for {self.base_domain} "
                f"(random probe '{probe_hostname}' resolved). "
                f"DNS-based results will be treated as low-confidence."
            )

        return detected

    async def _verify_results(self, results: List[DiscoveryResult]) -> List[DiscoveryResult]:
        """
        Verify results still resolve (safety check).

        CHANGED: when aiodns is available, also attaches a best-effort
        CNAME to each verified result (additive - result.cname stays
        None if unavailable, existing behavior unaffected otherwise).
        """
        if not results:
            return []

        # Create verification tasks
        verification_tasks = []
        for result in results:
            # Extract hostname from URL
            parsed = urlparse(result.url)
            hostname = parsed.netloc

            # Create verification task
            task = self._check_dns_resolution_with_source(hostname, result.source)
            verification_tasks.append((result, hostname, task))

        # Run all verifications in parallel
        task_results = await asyncio.gather(*[task for _, _, task in verification_tasks],
                                           return_exceptions=True)

        # Collect verified results
        verified = []
        cname_tasks = []
        for (result, hostname, _), task_result in zip(verification_tasks, task_results):
            if isinstance(task_result, Exception):
                continue
            if task_result:  # DNS resolved successfully
                verified.append(result)
                if self._resolver is not None:
                    cname_tasks.append((result, hostname))

        # Best-effort CNAME enrichment, parallelized, only if resolver available.
        if cname_tasks:
            cname_results = await asyncio.gather(
                *[self._get_cname(hostname) for _, hostname in cname_tasks],
                return_exceptions=True
            )
            for (result, _), cname in zip(cname_tasks, cname_results):
                if isinstance(cname, Exception):
                    continue
                result.cname = cname

        return verified

    def _deduplicate_results(self, results: List[DiscoveryResult]) -> List[DiscoveryResult]:
        """Deduplicate results by URL, keeping highest confidence version"""
        url_map: Dict[str, DiscoveryResult] = {}

        for result in results:
            if result.url not in url_map:
                url_map[result.url] = result
            else:
                # Keep the result with higher confidence
                if result.confidence > url_map[result.url].confidence:
                    url_map[result.url] = result
                # If confidence is equal, prefer non-DNS sources (they're more interesting)
                elif (result.confidence == url_map[result.url].confidence and
                      result.source not in ["dns", "common_prefix", "cname"] and
                      url_map[result.url].source in ["dns", "common_prefix", "cname"]):
                    url_map[result.url] = result

        return list(url_map.values())

    def get_metrics(self) -> Dict[str, Any]:
        """Get discovery metrics"""
        return self.discovery_metrics.copy()

    def get_summary(self) -> Dict[str, Any]:
        """Get discovery summary"""
        return {
            "total_discovered": len(self.discovered_results),
            "sources": {r.source for r in self.discovered_results},
            "wildcard_dns_detected": self.wildcard_detected,
            "metrics": self.get_metrics()
        }


async def discover_subdomains_from_url(
    url: str,
    config: Optional[DiscoveryConfig] = None
) -> List[str]:
    """
    Convenience function to discover subdomains from a URL.

    Args:
        url: Target URL (e.g., "https://example.com")
        config: Discovery configuration

    Returns:
        List of discovered subdomain URLs (just URLs, no metadata)
    """
    try:
        # Extract base domain from URL
        parsed = urlparse(url)
        if not parsed.netloc:
            return []

        base_domain = parsed.netloc.lower()

        # Remove port if present
        if ':' in base_domain:
            base_domain = base_domain.split(':')[0]

        # Remove www. prefix for discovery
        if base_domain.startswith('www.'):
            base_domain = base_domain[4:]

        # Run discovery
        async with DiscoveryEngine(base_domain, config) as engine:
            results = await engine.discover()

        # Return just URLs
        return [result.url for result in results]

    except Exception as e:
        logging.getLogger("discovery").error(f"Discovery from URL failed: {e}")
        return []


async def discover_with_metadata(
    url: str,
    config: Optional[DiscoveryConfig] = None
) -> Tuple[List[DiscoveryResult], Dict[str, Any]]:
    """
    Discover subdomains with full metadata.

    Returns:
        Tuple of (discovery_results, metrics)
    """
    try:
        # Extract base domain from URL
        parsed = urlparse(url)
        if not parsed.netloc:
            return [], {"error": "Invalid URL"}

        base_domain = parsed.netloc.lower()

        # Remove port if present
        if ':' in base_domain:
            base_domain = base_domain.split(':')[0]

        # Remove www. prefix for discovery
        if base_domain.startswith('www.'):
            base_domain = base_domain[4:]

        # Run discovery
        async with DiscoveryEngine(base_domain, config) as engine:
            results = await engine.discover()

        return results, engine.get_summary()

    except Exception as e:
        logging.getLogger("discovery").error(f"Discovery with metadata failed: {e}")
        return [], {"error": str(e)}


# Test function with improved output
async def test_discovery():
    """Test the discovery engine with better output"""
    import sys

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    if len(sys.argv) < 2:
        print("Usage: python discovery.py <domain>")
        print("Example: python discovery.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    if not domain.startswith('http'):
        domain = f"https://{domain}"

    print(f"Testing discovery on: {domain}")
    if not AIODNS_AVAILABLE:
        print("(aiodns not installed - using getaddrinfo fallback for DNS. "
              "Run 'pip install aiodns' for faster/more reliable resolution.)")
    print("-" * 60)

    # Configure for better discovery
    config = DiscoveryConfig(
        use_http_extraction=True,
        use_js_extraction=True,
        use_second_pass=True,
        use_ct_logs=True,
        max_requests=10
    )

    # Run discovery with metadata
    results, summary = await discover_with_metadata(domain, config)

    if not results:
        print("No subdomains discovered (clean target or limited surface)")
        print("-" * 60)
        return

    # Apply hard cap for test safety
    MAX_TEST_RESULTS = 20
    if len(results) > MAX_TEST_RESULTS:
        print(f"Results capped to {MAX_TEST_RESULTS} for readability")
        results = results[:MAX_TEST_RESULTS]

    print(f"Found {len(results)} subdomains:")
    print()

    # Group by source for better visibility
    by_source = {}
    for result in results:
        by_source.setdefault(result.source, []).append(result)

    for source, source_results in by_source.items():
        print(f"  Source: {source} ({len(source_results)}):")
        for i, result in enumerate(source_results, 1):
            confidence_str = f" [conf: {result.confidence:.1f}]" if result.confidence < 1.0 else ""
            cname_str = f" -> CNAME {result.cname}" if result.cname else ""
            print(f"     {i:2d}. {result.url}{confidence_str}{cname_str}")
        print()

    print("-" * 60)
    print("Summary:")
    print(f"  - Total discovered: {len(results)}")
    print(f"  - Sources: {', '.join(by_source.keys())}")
    print(f"  - Duration: {summary.get('metrics', {}).get('duration', 0):.2f}s")
    print(f"  - Requests made: {summary.get('metrics', {}).get('requests_made', 0)}")

    # Sanity check - ensure all discovered domains are in scope
    parsed_target = urlparse(domain)
    target_root = parsed_target.netloc
    if target_root.startswith('www.'):
        target_root = target_root[4:]

    unrelated = []
    for result in results:
        parsed = urlparse(result.url)
        if not parsed.netloc.endswith(target_root):
            unrelated.append(result.url)

    if unrelated:
        print()
        print("Warning: Found domains outside target scope:")
        for domain in unrelated[:3]:  # Show first 3 only
            print(f"    - {domain}")
        if len(unrelated) > 3:
            print(f"    ... and {len(unrelated) - 3} more")


if __name__ == "__main__":
    asyncio.run(test_discovery())
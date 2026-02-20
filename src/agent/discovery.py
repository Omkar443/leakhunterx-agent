#!/usr/bin/env python3
"""
LeakHunterX - Passive Subdomain Discovery
Production-grade, lightweight, zero external dependencies.

DESIGN PRINCIPLES:
1. PASSIVE ONLY - no brute force, no wordlists
2. FAST - completes in < 10 seconds
3. SAFE - no breaking changes to existing system
4. FOUNDATIONAL - sets stage for future expansion
"""

import asyncio
import logging
import re
import socket
import time
from typing import Set, List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl
import json
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class DiscoveryResult:
    """Structured result for discovered subdomain"""
    url: str
    source: str  # "dns", "common_prefix", "cname", "header", "js", etc.
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "source": self.source,
            "confidence": self.confidence
        }


@dataclass
class DiscoveryConfig:
    """Configuration for discovery engine"""
    # Timeouts
    http_timeout: int = 5
    dns_timeout: int = 2
    max_total_time: int = 10

    # Limits
    max_subdomains: int = 50
    max_requests: int = 20

    # Sources to use
    use_common_prefixes: bool = True
    use_cname_check: bool = True
    use_response_headers: bool = True
    use_js_extraction: bool = True
    use_http_extraction: bool = True
    use_second_pass: bool = True  # Optional second discovery pass

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
    5. Optional second pass for deeper discovery
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
        
        # HTTP client session - created on demand if not using async context
        self._session = None
        self._owns_session = False
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        # Results storage
        self.discovered_results: List[DiscoveryResult] = []
        self.discovery_metrics: Dict[str, Any] = {
            "start_time": 0,
            "end_time": 0,
            "methods_used": [],
            "candidates_tested": 0,
            "candidates_found": 0,
            "errors": 0,
            "requests_made": 0
        }

    async def __aenter__(self):
        """Async context manager entry"""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.http_timeout),
            connector=aiohttp.TCPConnector(ssl=self.ssl_context)
        )
        self._owns_session = True
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
        if (self.config.use_http_extraction or self.config.use_js_extraction) and not self._session:
            self.logger.warning("HTTP discovery requested but no session available. Creating temporary session.")
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.http_timeout),
                connector=aiohttp.TCPConnector(ssl=self.ssl_context)
            )
            self._owns_session = True

        try:
            # First pass - basic discovery
            first_pass_results = await self._run_discovery_pass(1)
            
            # Optional second pass - deeper discovery using first pass results
            second_pass_results = []
            if self.config.use_second_pass and first_pass_results:
                self.logger.debug("Running second discovery pass...")
                second_pass_results = await self._run_discovery_pass(2, first_pass_results)
            
            # Combine results from both passes
            all_results = first_pass_results + second_pass_results
            
            # Deduplicate and verify
            deduplicated = self._deduplicate_results(all_results)
            verified_results = await self._verify_results(deduplicated)

            # Cap results (safety first)
            if len(verified_results) > self.config.max_subdomains:
                self.logger.warning(
                    f"Capping results from {len(verified_results)} to {self.config.max_subdomains}"
                )
                verified_results = verified_results[:self.config.max_subdomains]

            self.discovered_results = verified_results

            self.discovery_metrics.update({
                "end_time": time.time(),
                "duration": time.time() - self.discovery_metrics["start_time"],
                "candidates_found": len(verified_results),
            })

            self.logger.info(
                f"Discovery complete: found {len(verified_results)} subdomains "
                f"in {self.discovery_metrics['duration']:.2f}s"
            )

            return verified_results

        except Exception as e:
            self.logger.error(f"Discovery failed: {e}")
            return []
        finally:
            # Clean up temporary session if we created it
            if self._session and self._owns_session:
                await self._session.close()
                self._session = None
                self._owns_session = False

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
                self.logger.debug(f"Batch DNS check failed: {e}")
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

    async def _discover_from_http(self, targets: List[str]) -> List[DiscoveryResult]:
        """Discover subdomains from HTTP responses (headers, redirects, JS)"""
        if not self._session:
            self.logger.warning("HTTP discovery skipped: no session available")
            return []
        
        results = []
        headers_checked = set()
        
        for target in targets:
            if self.discovery_metrics["requests_made"] >= self.config.max_requests:
                self.logger.debug("Max requests reached, stopping HTTP discovery")
                break
            
            try:
                self.discovery_metrics["requests_made"] += 1
                async with self._session.get(target, allow_redirects=True) as response:
                    
                    # Extract from response headers
                    if self.config.use_http_extraction:
                        header_results = await self._extract_from_headers(response, target)
                        results.extend(header_results)
                    
                    # Extract from response body (JS, HTML)
                    if self.config.use_js_extraction:
                        try:
                            content = await response.text()
                            js_results = await self._extract_from_content(content, target)
                            results.extend(js_results)
                        except (aiohttp.ClientError, asyncio.TimeoutError):
                            pass
                    
                    # Track redirect chain
                    if response.history:
                        for hist_resp in response.history:
                            redirect_url = str(hist_resp.url)
                            parsed = urlparse(redirect_url)
                            if parsed.netloc and parsed.netloc != urlparse(target).netloc:
                                result = DiscoveryResult(
                                    url=f"https://{parsed.netloc}",
                                    source="redirect",
                                    confidence=0.9
                                )
                                results.append(result)
                                
            except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError) as e:
                self.logger.debug(f"HTTP request failed for {target}: {e}")
                continue
        
        return results

    async def _extract_from_headers(self, response: aiohttp.ClientResponse, 
                                    source_url: str) -> List[DiscoveryResult]:
        """Extract subdomains from HTTP headers"""
        results = []
        
        # Check Content-Security-Policy header
        csp_header = response.headers.get('Content-Security-Policy', '')
        if csp_header:
            # Extract domains from CSP - use stricter regex that captures domains properly
            csp_domains = []
            
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
        location_header = response.headers.get('Location', '')
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
        acao_header = response.headers.get('Access-Control-Allow-Origin', '')
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
        Check if a hostname resolves via DNS.
        Returns DiscoveryResult if it resolves, None otherwise.
        """
        try:
            loop = asyncio.get_event_loop()

            # Try IPv4 first
            try:
                await asyncio.wait_for(
                    loop.getaddrinfo(hostname, 443, family=socket.AF_INET),
                    timeout=self.config.dns_timeout
                )
                return DiscoveryResult(url=f"https://{hostname}", source=source)
            except (socket.gaierror, asyncio.TimeoutError):
                pass

            # Try IPv6
            try:
                await asyncio.wait_for(
                    loop.getaddrinfo(hostname, 443, family=socket.AF_INET6),
                    timeout=self.config.dns_timeout
                )
                return DiscoveryResult(url=f"https://{hostname}", source=source)
            except (socket.gaierror, asyncio.TimeoutError):
                pass

            return None

        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return None

    async def _verify_results(self, results: List[DiscoveryResult]) -> List[DiscoveryResult]:
        """Verify results still resolve (safety check)"""
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
            verification_tasks.append((result, task))
        
        # Run all verifications in parallel
        task_results = await asyncio.gather(*[task for _, task in verification_tasks], 
                                           return_exceptions=True)
        
        # Collect verified results
        verified = []
        for (result, _), task_result in zip(verification_tasks, task_results):
            if isinstance(task_result, Exception):
                continue
            if task_result:  # DNS resolved successfully
                verified.append(result)
        
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

    print(f"🔍 Testing discovery on: {domain}")
    print("─" * 60)

    # Configure for better discovery
    config = DiscoveryConfig(
        use_http_extraction=True,
        use_js_extraction=True,
        use_second_pass=True,
        max_requests=10
    )

    # Run discovery with metadata
    results, summary = await discover_with_metadata(domain, config)

    if not results:
        print("ℹ️  No subdomains discovered (clean target or limited surface)")
        print("─" * 60)
        return

    # Apply hard cap for test safety
    MAX_TEST_RESULTS = 20
    if len(results) > MAX_TEST_RESULTS:
        print(f"⚠️  Results capped to {MAX_TEST_RESULTS} for readability")
        results = results[:MAX_TEST_RESULTS]

    print(f"✅ Found {len(results)} subdomains:")
    print()

    # Group by source for better visibility
    by_source = {}
    for result in results:
        by_source.setdefault(result.source, []).append(result)

    for source, source_results in by_source.items():
        print(f"  📍 Source: {source} ({len(source_results)}):")
        for i, result in enumerate(source_results, 1):
            confidence_str = f" [conf: {result.confidence:.1f}]" if result.confidence < 1.0 else ""
            print(f"     {i:2d}. {result.url}{confidence_str}")
        print()

    print("─" * 60)
    print("📊 Summary:")
    print(f"  • Total discovered: {len(results)}")
    print(f"  • Sources: {', '.join(by_source.keys())}")
    print(f"  • Duration: {summary.get('metrics', {}).get('duration', 0):.2f}s")
    print(f"  • Requests made: {summary.get('metrics', {}).get('requests_made', 0)}")

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
        print("⚠️  Warning: Found domains outside target scope:")
        for domain in unrelated[:3]:  # Show first 3 only
            print(f"    • {domain}")
        if len(unrelated) > 3:
            print(f"    ... and {len(unrelated) - 3} more")


if __name__ == "__main__":
    asyncio.run(test_discovery())
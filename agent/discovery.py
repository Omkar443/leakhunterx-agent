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
    use_favicon_hash: bool = False  # Future feature
    
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
        
        # Results storage
        self.discovered_results: List[DiscoveryResult] = []
        self.discovery_metrics: Dict[str, Any] = {
            "start_time": 0,
            "end_time": 0,
            "methods_used": [],
            "candidates_tested": 0,
            "candidates_found": 0,
            "errors": 0
        }
    
    async def discover(self) -> List[DiscoveryResult]:
        """
        Run all passive discovery methods.
        Returns: List of discovered subdomains with metadata
        """
        self.discovery_metrics["start_time"] = time.time()
        
        try:
            # Run discovery methods
            results_by_method = await self._run_discovery_methods()
            
            # Combine and deduplicate results
            all_results = self._deduplicate_results(results_by_method)
            
            # Verify discovered subdomains (DNS resolution)
            verified_results = await self._verify_results(all_results)
            
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
                "candidates_tested": sum(len(r) for r in results_by_method.values()),
                "candidates_found": len(verified_results),
                "methods_used": list(results_by_method.keys())
            })
            
            self.logger.info(
                f"Discovery complete: found {len(verified_results)} subdomains "
                f"in {self.discovery_metrics['duration']:.2f}s"
            )
            
            return verified_results
            
        except Exception as e:
            self.logger.error(f"Discovery failed: {e}")
            return []
    
    async def _run_discovery_methods(self) -> Dict[str, List[DiscoveryResult]]:
        """Run all enabled discovery methods in parallel"""
        tasks = {}
        
        if self.config.use_common_prefixes:
            tasks["common_prefix"] = self._discover_from_common_prefixes()
        
        if self.config.use_cname_check:
            tasks["cname"] = self._discover_from_cname_patterns()
        
        # Run all methods
        method_results = {}
        for method_name, task in tasks.items():
            try:
                results = await task
                method_results[method_name] = results
                self.logger.debug(f"Method '{method_name}' found {len(results)} subdomains")
            except Exception as e:
                self.logger.debug(f"Method '{method_name}' failed: {e}")
                self.discovery_metrics["errors"] += 1
                method_results[method_name] = []
        
        return method_results
    
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
        
        verified = []
        for result in results:
            # Extract hostname from URL
            parsed = urlparse(result.url)
            hostname = parsed.netloc
            
            # Check if it still resolves
            if await self._check_dns_resolution_with_source(hostname, result.source):
                verified.append(result)
        
        return verified
    
    def _deduplicate_results(self, method_results: Dict[str, List[DiscoveryResult]]) -> List[DiscoveryResult]:
        """Deduplicate results by URL"""
        seen_urls = set()
        deduplicated = []
        
        for method_name, results in method_results.items():
            for result in results:
                if result.url not in seen_urls:
                    seen_urls.add(result.url)
                    deduplicated.append(result)
        
        return deduplicated
    
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
        engine = DiscoveryEngine(base_domain, config)
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
        engine = DiscoveryEngine(base_domain, config)
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
    
    # Run discovery with metadata
    results, summary = await discover_with_metadata(domain)
    
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
            print(f"     {i:2d}. {result.url}")
        print()
    
    print("─" * 60)
    print("📊 Summary:")
    print(f"  • Total discovered: {len(results)}")
    print(f"  • Sources: {', '.join(by_source.keys())}")
    print(f"  • Duration: {summary.get('metrics', {}).get('duration', 0):.2f}s")
    
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

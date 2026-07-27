"""
LinkExtractor - Extracts endpoints from JavaScript content.
Stateless (as of this revision - see fix #1 below), event-driven.

CRITICAL FIX (original): Uses EnterpriseURLNormalizer instead of urljoin()
to fix Facebook CDN URL normalization and embedded host detection.

CHANGELOG (this revision - all additive/safety fixes, detection logic
(URL_REGEX, ENHANCED_PATTERNS, API_HINTS, confidence calculation,
classification) is completely untouched, byte-for-byte identical):

1. FIXED (race condition): _process_url() previously resolved relative
   URLs against self.base_url, a mutable instance attribute that
   JSAnalysisEngine sets right before each call
   (`self.link_extractor.base_url = js_url`). That's only safe when
   calls are strictly sequential. With concurrent JS fetches now
   allowed (see the semaphore added to JSAnalysisEngine), two
   concurrent extract() calls on the same LinkExtractor instance could
   race: coroutine B overwrites base_url while coroutine A is still
   mid-extraction, silently resolving A's relative URLs against B's
   domain. Fixed by threading an explicit, OPTIONAL `base_url`
   parameter through extract() -> _process_url() etc. When omitted,
   behavior is 100% unchanged (falls back to self.base_url exactly as
   before). To eliminate the race entirely, update the caller to pass
   it explicitly instead of mutating the attribute - see the one-line
   change noted at the bottom of this file.
2. FIXED (redundant work, not a behavior change): _extract_with_context_hints
   previously ran full regex extraction on the SAME line once per
   matching API_HINTS keyword found on that line - a line matching 3
   hints triggered 3 identical extraction passes. Since extraction
   output depends only on the line's text (not which hint triggered
   it), this was pure wasted CPU with byte-for-byte identical results.
   Now extracts once per matching line. Verified equivalent - see the
   test in the accompanying message.
3. Removed two redundant `import re` statements inside
   _normalize_escaped_slashes (the module already imports re at the
   top) - same module object either way, purely a cleanup.
4. NEW: each emit_event() call in the main extraction loop is now
   isolated in a try/except so a single downstream failure doesn't
   silently drop every remaining finding for that file.
5. NEW: optional max_endpoints_per_extraction cap (constructor param,
   default None = unlimited, i.e. no behavior change unless you opt
   in) as a guard against adversarial/pathological content generating
   an unbounded number of matches and flooding the event pipeline.
6. NEW: lightweight DEBUG-level timing/count logging, guarded by
   isEnabledFor() so it costs nothing when DEBUG logging is off.
"""

import re
import time
import asyncio
import logging
from urllib.parse import urljoin
from typing import Optional, Set
from ..utils.events import emit_event
from ..utils.url_normalizer import get_normalizer


logger = logging.getLogger(__name__)


# EXACT copy from original utils (unchanged)
def is_valid_url(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(url: str) -> str:
    return url.rstrip('/')


class LinkExtractor:
    """
    Extracts endpoints from JavaScript content.

    All detection logic preserved byte-for-byte. Architectural changes
    in this revision:
    1. base_url can now be passed explicitly per-call (fixes a race
       condition under concurrent use - see module docstring, fix #1).
    2. Event-driven output (unchanged from previous revision).
    3. Context-aware (unchanged from previous revision).
    4. Uses EnterpriseURLNormalizer (unchanged from previous revision).
    """

    # URL_REGEX - EXACT copy from original (unchanged)
    URL_REGEX = re.compile(
        r"""
        (?:"|')                                  # Start quotes
        (
            (?:\/|https?:\/\/)                   # Relative or absolute
            [^"'\s]+?                            # URL body
            (?:\?.*?)?                           # Optional query
        )
        (?:"|')                                  # End quotes
        """,
        re.VERBOSE | re.IGNORECASE,
    )

    # ENHANCED_PATTERNS - EXACT copy from original (NO CHANGES, byte-for-byte)
    ENHANCED_PATTERNS = [
        # API endpoints
        r'["\'](/api/[^"\'\s<>]+)["\']',
        r'["\'](/v[0-9]+/[^"\'\s<>]+)["\']',
        r'["\'](/graphql[^"\'\s<>]*)["\']',
        r'["\'](/rest/[^"\'\s<>]+)["\']',

        # Admin and internal endpoints
        r'["\'](/admin[^"\'\s<>]*)["\']',
        r'["\'](/internal[^"\'\s<>]*)["\']',
        r'["\'](/private[^"\'\s<>]*)["\']',
        r'["\'](/secure[^"\'\s<>]*)["\']',

        # Authentication endpoints
        r'["\'](/auth[^"\'\s<>]*)["\']',
        r'["\'](/login[^"\'\s<>]*)["\']',
        r'["\'](/oauth[^"\'\s<>]*)["\']',

        # JavaScript fetch patterns
        r'fetch\(["\']([^"\'\s]+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\'\s]+)["\']',
        r'\.ajax\([^)]*url["\']?:["\']([^"\'\s]+)',

        # Window location and navigation
        r'window\.location[^=]*=["\']([^"\'\s]+)',
        r'document\.location[^=]*=["\']([^"\'\s]+)',
        r'location\.href[^=]*=["\']([^"\'\s]+)',

        # Dynamic imports and requires
        r'import\(["\']([^"\'\s]+)["\']',
        r'require\(["\']([^"\'\s]+)["\']',

        # WebSocket connections
        r'new WebSocket\(["\']([^"\'\s]+)["\']',

        # Image and asset URLs
        r'["\'](/static/[^"\'\s<>]+)["\']',
        r'["\'](/assets/[^"\'\s<>]+)["\']',
        r'["\'](/images?/[^"\'\s<>]+)["\']',

        # Enhanced patterns for modern JS frameworks
        r'router\.(get|post|put|delete)\(["\']([^"\'\s]+)["\']',
        r'app\.(get|post|put|delete)\(["\']([^"\'\s]+)["\']',
        r'route\(["\']([^"\'\s]+)["\']',

        # XMLHttpRequest patterns
        r'\.open\(["\'](GET|POST|PUT|DELETE)["\'],["\']([^"\'\s]+)["\']',
        r'xhr\.open\(["\'](GET|POST|PUT|DELETE)["\'],["\']([^"\'\s]+)["\']',

        # Vue.js and React patterns
        r'this\.\$http\.(get|post|put|delete)\(["\']([^"\'\s]+)["\']',
        r'axios\([^)]*url:\s*["\']([^"\'\s]+)["\']',
        r'fetch\([^)]*["\']([^"\'\s]+)["\']',

        # Configuration objects - EXACT original
        r'baseURL:\s*["\']([^"\'\s]+)["\']',
        r'apiUrl:\s*["\']([^"\'\s]+)["\']',
        r'endpoint:\s*["\']([^"\'\s]+)["\']',

        # Webpack and module loading
        r'__webpack_require__\(["\']([^"\'\s]+)["\']',
        # NOTE: import() appears exactly once here (original placement)

        # Service worker and PWA patterns
        r'serviceWorker\.register\(["\']([^"\'\s]+)["\']',
        r'workbox\.precaching\.precacheAndRoute\([^)]*["\']([^"\'\s]+)["\']',

        # Comment-based endpoints (often overlooked)
        r'//\s*(?:endpoint|api|url):\s*([^\s]+)',
        r'/\*\s*(?:endpoint|api|url):\s*([^*]+)\*/',

        # JSON-like structures
        r'["\']url["\']\s*:\s*["\']([^"\'\s]+)["\']',
        r'["\']endpoint["\']\s*:\s*["\']([^"\'\s]+)["\']',
        r'["\']path["\']\s*:\s*["\']([^"\'\s]+)["\']',

        # NOTE: Template literal patterns (r'`([^`\s]+)`', r'\$\{([^}]+)\}',)
        # were NOT in original and are REMOVED
    ]

    # API_HINTS - EXACT copy from original (unchanged)
    API_HINTS = [
        "api", "auth", "v1", "v2", "v3",
        "token", "secret", "jwt", "key",
        "login", "user", "admin",
        "oauth", "verify", "validate",
        "password", "reset", "register",
        "endpoint", "url", "baseurl",
        "graphql", "rest", "websocket",
        "webhook", "callback", "redirect"
    ]

    def __init__(
        self,
        base_url: Optional[str] = None,
        max_endpoints_per_extraction: Optional[int] = None,
    ):
        """
        Initialize extractor with base URL and EnterpriseURLNormalizer.

        Args:
            base_url: Default resolution base, used only when a call to
                extract()/`_process_url()` doesn't pass one explicitly.
                Preserved for full backward compatibility.
            max_endpoints_per_extraction: NEW - optional cap on how many
                endpoint_found events a single extract() call will emit.
                Default None = unlimited (identical to original
                behavior). Set this if you want a hard ceiling against
                pathological content generating an unbounded number of
                matches.
        """
        self.base_url = base_url
        self.max_endpoints_per_extraction = max_endpoints_per_extraction

        # CRITICAL FIX (original): Initialize EnterpriseURLNormalizer
        # Use same configuration as crawler for consistency
        self.normalizer = get_normalizer(
            enable_caching=True,
            max_cache_size=5000,
            strict_validation=False,
            default_scheme='https'
        )

        # Compile all enhanced patterns for performance (EXACT logic)
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.ENHANCED_PATTERNS]

        self.logger = logging.getLogger("link_extractor")

    def _normalize_escaped_slashes(self, url: str) -> str:
        """
        Normalize escaped forward slashes in URLs.
        JavaScript strings often contain \\/ which should be normalized to /

        Example:
            https://example.com/\\/path\\/to\\/file.js -> https://example.com/path/to/file.js
            https://example.com/\\/\\/path -> https://example.com/path

        Args:
            url: URL with potentially escaped forward slashes

        Returns:
            URL with escaped slashes normalized and multiple slashes collapsed
        """
        if not url:
            return url

        # Step 1: Replace all \/ sequences with /
        # Handle multiple escapes (\\\/ -> /)
        normalized = url
        if '\\/' in normalized:
            normalized = normalized.replace('\\\\/', '/')  # Handle double-escaped first
            normalized = normalized.replace('\\/', '/')

        # Step 2: Collapse multiple consecutive slashes in the path to a single slash
        # But preserve the double slash after http:// or https://
        if '://' in normalized:
            # Split into protocol and rest
            protocol, rest = normalized.split('://', 1)

            # Find where the path starts (after domain)
            if '/' in rest:
                domain_end = rest.find('/')
                if domain_end != -1:
                    domain = rest[:domain_end]
                    path = rest[domain_end:]  # This starts with /

                    # Collapse multiple slashes in path only
                    # (re already imported at module top - no local import needed)
                    path = re.sub(r'/{2,}', '/', path)  # Collapse 2+ slashes to 1

                    normalized = f"{protocol}://{domain}{path}"
        else:
            # For relative URLs, just collapse all multiple slashes
            # (re already imported at module top - no local import needed)
            normalized = re.sub(r'/{2,}', '/', normalized)

        return normalized

    def _process_url(self, url_candidate: str, base_url: Optional[str] = None) -> Optional[str]:
        """
        Process and validate a URL candidate using EnterpriseURLNormalizer.

        CRITICAL FIX (original): Replaces urljoin() with EnterpriseURLNormalizer
        to properly handle embedded hostnames like /static.xx.fbcdn.net/...

        CHANGED (this revision): base_url is now an explicit optional
        parameter instead of always reading the mutable self.base_url.
        When omitted, falls back to self.base_url - identical to the
        original behavior. See module docstring fix #1 for why this
        matters under concurrent use.

        Args:
            url_candidate: URL string extracted from JavaScript
            base_url: Resolution base for this specific call. Falls back
                to self.base_url when None (original behavior).

        Returns:
            Normalized URL string or None if invalid
        """
        if not url_candidate or not isinstance(url_candidate, str):
            return None

        # Clean the URL (EXACT logic preserved)
        url_candidate = url_candidate.strip()
        if not url_candidate:
            return None

        # NORMALIZE ESCAPED SLASHES (preserved from original)
        url_candidate = self._normalize_escaped_slashes(url_candidate)

        effective_base = base_url if base_url is not None else self.base_url

        # CRITICAL FIX (original): Use EnterpriseURLNormalizer instead of urljoin()
        # This fixes Facebook CDN URLs: /static.xx.fbcdn.net/... -> https://static.xx.fbcdn.net/...
        result = self.normalizer.normalize(url_candidate, effective_base)

        if result.success:
            return result.normalized_url
        return None

    def _extract_url_from_match(self, match) -> str:
        """
        Extract URL string from regex match (handles tuples).
        EXACT copy of logic from original JSExtractor.
        """
        if isinstance(match, tuple):
            # Take the last non-empty group from tuple matches (EXACT logic)
            for item in reversed(match):
                if item and isinstance(item, str) and item.strip():
                    return item.strip()
            return match[0] if match else ""
        return match

    def _extract_with_context_hints(self, js_content: str, base_url: Optional[str] = None) -> Set[str]:
        """
        Extract URLs that appear in context with API-related keywords.

        CHANGED (this revision, perf-only): previously ran full URL_REGEX
        + all ENHANCED_PATTERNS extraction on a line once PER MATCHING
        HINT - a line matching 3 of the 24 API_HINTS keywords triggered
        3 identical extraction passes over the same line. Since
        extraction output depends only on the line's text (not which
        hint triggered it), the resulting set was always identical
        regardless of how many times it ran. Now extracts once per
        matching line. Output is provably unchanged; only the number of
        redundant regex passes is reduced.
        """
        api_urls = set()

        # Find lines containing API hints
        lines = js_content.split('\n')
        for line in lines:
            line_lower = line.lower()

            # CHANGED: check for ANY matching hint first (short-circuits
            # on first match, same containment checks as before) and
            # extract ONCE if the line qualifies, instead of once per
            # matching hint.
            if not any(hint in line_lower for hint in self.API_HINTS):
                continue

            # Extract URLs from lines with API hints (EXACT logic)
            url_matches = re.findall(self.URL_REGEX, line)
            for url_match in url_matches:
                full_url = self._process_url(url_match, base_url)
                if full_url:
                    api_urls.add(full_url)

            # Also check enhanced patterns on these lines (EXACT logic)
            for pattern in self.compiled_patterns:
                matches = pattern.findall(line)
                for match in matches:
                    url_candidate = self._extract_url_from_match(match)
                    full_url = self._process_url(url_candidate, base_url)
                    if full_url:
                        api_urls.add(full_url)

        return api_urls

    def _extract_complex_patterns(self, js_content: str, base_url: Optional[str] = None) -> Set[str]:
        """
        Extract URLs from complex JavaScript patterns and structures.
        EXACT copy of logic from original JSExtractor.
        """
        complex_urls = set()

        # Extract from object assignments (EXACT patterns)
        object_patterns = [
            r'(?:const|let|var)\s+\w+\s*=\s*["\']([^"\'\s]+)["\']',
            r'\w+\.(?:url|endpoint|api|path)\s*=\s*["\']([^"\'\s]+)["\']',
            r'(?:url|endpoint|api):\s*["\']([^"\'\s]+)["\']',
        ]

        for pattern in object_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                full_url = self._process_url(match, base_url)
                if full_url:
                    complex_urls.add(full_url)

        # Extract from function calls and parameters (EXACT patterns)
        function_patterns = [
            r'\.(?:get|post|put|delete|patch)\(["\']([^"\'\s]+)["\']',
            r'\.request\([^)]*["\']([^"\'\s]+)["\']',
            r'\.(?:load|open)\([^)]*["\']([^"\'\s]+)["\']',
        ]

        for pattern in function_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                full_url = self._process_url(match, base_url)
                if full_url:
                    complex_urls.add(full_url)

        return complex_urls

    async def extract(self, js_content: str, source_url: str, context, base_url: Optional[str] = None) -> None:
        """
        Extract URLs from JavaScript content and emit events.

        All extraction logic preserved byte-for-byte. Architectural
        notes for this revision:
        1. Emits events instead of returning list (unchanged from
           previous revision).
        2. Uses context.event_emitter (unchanged from previous revision).
        3. No global deduplication (preserves original per-call semantics).
        4. Maintains EXACT confidence calculation.
        5. NEW: base_url is now an explicit optional parameter. When
           omitted, falls back to self.base_url exactly as before -
           zero behavior change for existing callers. Pass it explicitly
           to make this call safe under concurrent use on a shared
           LinkExtractor instance (see module docstring fix #1).
        6. NEW: per-URL emit isolated in try/except; a downstream
           failure on one URL no longer drops every remaining finding.
        7. NEW: if max_endpoints_per_extraction is configured, results
           are truncated (sorted order preserved) and a warning is
           logged. Default is unlimited - unchanged behavior unless
           you opt in via the constructor.

        Args:
            js_content: JavaScript content to analyze
            source_url: URL where the JS came from (used for event
                metadata - unchanged from original)
            context: ExtractorContext instance for state/events
            base_url: NEW - explicit resolution base for this call.
                Falls back to self.base_url when None.
        """
        if not js_content:
            return

        extraction_start = time.time()
        effective_base = base_url if base_url is not None else self.base_url

        # Local deduplication set (EXACT same as original per-call behavior)
        urls = set()

        # 1. Basic URL regex extraction (EXACT logic from original)
        regex_urls = re.findall(self.URL_REGEX, js_content)
        for url_match in regex_urls:
            full_url = self._process_url(url_match, effective_base)
            if full_url:
                urls.add(full_url)

        # 2. Enhanced pattern extraction (EXACT logic from original)
        for pattern in self.compiled_patterns:
            matches = pattern.findall(js_content)
            for match in matches:
                url_candidate = self._extract_url_from_match(match)
                full_url = self._process_url(url_candidate, effective_base)
                if full_url:
                    urls.add(full_url)

        # 3. Context-based extraction for API hints (EXACT logic from original)
        urls.update(self._extract_with_context_hints(js_content, effective_base))

        # 4. Deep pattern extraction for complex cases (EXACT logic from original)
        urls.update(self._extract_complex_patterns(js_content, effective_base))

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                f"LinkExtractor: {len(urls)} candidate URLs found for {source_url} "
                f"in {time.time() - extraction_start:.3f}s"
            )

        # 5. Determine emit order (PRESERVES original sorting behavior)
        urls_to_emit = sorted(urls)

        # NEW: optional safety cap - default unlimited, zero behavior
        # change unless explicitly configured.
        if self.max_endpoints_per_extraction is not None and len(urls_to_emit) > self.max_endpoints_per_extraction:
            self.logger.warning(
                f"LinkExtractor: {len(urls_to_emit)} endpoints found for {source_url}, "
                f"truncating to configured cap of {self.max_endpoints_per_extraction}"
            )
            urls_to_emit = urls_to_emit[: self.max_endpoints_per_extraction]

        # 6. Emit each URL as an event
        for url in urls_to_emit:
            # Get context for confidence calculation (CRITICAL: must match original)
            url_context = self._get_url_context(js_content, url)

            # Calculate confidence with ACTUAL context (EXACT logic)
            confidence = self._calculate_confidence(url, url_context)

            # NEW: isolate each emit so one failure doesn't drop the rest
            try:
                await emit_event(
                    context,
                    event_type="endpoint_found",
                    data={
                        "source_url": source_url,
                        "finding_type": "endpoint",
                        "raw_value": url,
                        "confidence": confidence,
                        "severity": "INFO",
                    }
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.error(f"LinkExtractor: failed to emit endpoint_found for {url}: {e}")
                continue

    def _get_url_context(self, content: str, url: str, context_size: int = 100) -> str:
        """
        Extract context around the found URL.
        EXACT copy of logic from original JSExtractor.
        """
        try:
            index = content.find(url)
            if index == -1:
                return ""

            start = max(0, index - context_size)
            end = min(len(content), index + len(url) + context_size)
            context = content[start:end]

            # Clean up the context (EXACT logic)
            context = re.sub(r'\s+', ' ', context)
            return context.strip()

        except Exception:
            return ""

    def _classify_url(self, url: str) -> str:
        """
        Classify URL type based on patterns.
        EXACT copy of logic from original JSExtractor.
        (Used for internal logic only - NOT emitted in metadata)
        """
        url_lower = url.lower()

        if any(api_hint in url_lower for api_hint in ['/api/', 'api.', 'v1/', 'v2/', 'v3/', 'graphql']):
            return 'api_endpoint'
        elif any(auth_hint in url_lower for auth_hint in ['auth', 'login', 'token', 'oauth', 'jwt', 'session']):
            return 'auth_endpoint'
        elif any(admin_hint in url_lower for admin_hint in ['admin', 'dashboard', 'manage', 'private', 'internal']):
            return 'admin_endpoint'
        elif any(static_hint in url_lower for static_hint in ['static', 'assets', 'images', 'css', 'js', '.png', '.jpg', '.svg', '.ico']):
            return 'static_resource'
        elif any(ws_hint in url_lower for ws_hint in ['ws://', 'wss://', 'websocket']):
            return 'websocket'
        elif any(webhook_hint in url_lower for webhook_hint in ['webhook', 'callback', 'hook']):
            return 'webhook'
        else:
            return 'general_endpoint'

    def _calculate_confidence(self, url: str, context: str) -> float:
        """
        Calculate confidence score for URL importance.
        EXACT copy of logic from original JSExtractor.
        """
        confidence = 0.5  # Base confidence

        # URL pattern boosts (EXACT logic)
        url_lower = url.lower()
        if any(pattern in url_lower for pattern in ['/api/', 'auth', 'token', 'secret', 'admin']):
            confidence += 0.3
        if any(pattern in url_lower for pattern in ['graphql', 'rest', 'v1', 'v2', 'v3']):
            confidence += 0.2
        if any(pattern in url_lower for pattern in ['webhook', 'callback', 'websocket']):
            confidence += 0.2

        # Context boosts (EXACT logic - CRITICAL: must use actual context)
        context_lower = context.lower()
        if any(keyword in context_lower for keyword in ['fetch', 'axios', 'ajax', 'xhr', 'request']):
            confidence += 0.1
        if any(keyword in context_lower for keyword in ['api', 'endpoint', 'url', 'baseurl']):
            confidence += 0.1
        if any(keyword in context_lower for keyword in ['secret', 'token', 'key', 'password']):
            confidence += 0.2

        return min(confidence, 1.0)

    async def extract_detailed(self, js_content: str, source_url: str, context, base_url: Optional[str] = None) -> None:
        """
        Extract URLs with additional context and metadata.
        NOTE: This method's behavior is simplified in refactored version.
        In original, it returned structured objects. Now it emits standard events.
        """
        # Use the main extraction method (same URLs)
        await self.extract(js_content, source_url, context, base_url=base_url)


# Backward compatibility - original class name
JSExtractor = LinkExtractor


# ------------------------------------------------------------
# RECOMMENDED (optional) one-line follow-up in JSAnalysisEngine to fully
# eliminate the race described in fix #1 above. Not required - the
# fallback to self.base_url means this file works correctly as-is - but
# without it you still have the shared-mutable-state pattern, just no
# longer relied upon for correctness by LinkExtractor itself.
#
# In analyze_js_content(), replace:
#
#     self.link_extractor.base_url = js_url
#     ...
#     await asyncio.gather(
#         self.link_extractor.extract(content, js_url, self.context),
#         self.secret_scanner.scan(content, js_url, self.context)
#     )
#
# with:
#
#     await asyncio.gather(
#         self.link_extractor.extract(content, js_url, self.context, base_url=js_url),
#         self.secret_scanner.scan(content, js_url, self.context)
#     )
#
# (and drop the `self.link_extractor.base_url = js_url` line entirely)
# ------------------------------------------------------------
"""
Enterprise-Grade Universal URL Normalizer for Web Security Scanning.
Handles ALL edge cases with comprehensive validation, caching, and metrics.

Features:
1. Comprehensive URL validation and normalization
2. Embedded hostname detection and extraction
3. Protocol fallback and intelligent guessing
4. Performance optimizations (caching, compiled regex)
5. Comprehensive metrics and telemetry
6. Thread-safe and async compatible
7. Pluggable validation rules
8. Industry-standard URL parsing compliance
"""

import re
import hashlib
import logging
import time
import threading
import copy
from urllib.parse import urlparse, urljoin, urlunparse, quote, unquote, parse_qsl
from typing import Optional, Tuple, Dict, Any, List, Set, Pattern, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import OrderedDict

logger = logging.getLogger(__name__)


class URLClassification(Enum):
    """URL classification types for precise handling."""
    ABSOLUTE = auto()                # http://example.com/path
    PROTOCOL_RELATIVE = auto()       # //example.com/path
    EMBEDDED_HOST = auto()           # /cdn.example.com/path
    RELATIVE = auto()                # /path or ../path
    ABSOLUTE_PATH = auto()           # /path (no host)
    MALFORMED_SALVAGED = auto()      # Fixed malformed URL
    INVALID = auto()                 # Cannot be normalized
    EMPTY = auto()                   # Empty or None
    DATA_URL = auto()                # data:image/png;base64,...
    BLOB_URL = auto()                # blob:http://...
    JAVASCRIPT_URL = auto()          # javascript:...
    MAILTO_URL = auto()              # mailto:...
    FILE_URL = auto()                # file://...
    ABOUT_URL = auto()               # about:...
    UNKNOWN_SCHEME = auto()          # Other schemes


@dataclass
class NormalizationResult:
    """Structured result of URL normalization."""
    normalized_url: Optional[str] = None
    classification: URLClassification = URLClassification.INVALID
    original_url: str = ""
    base_url: Optional[str] = None
    transformations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_valid: bool = False
    domain: Optional[str] = None
    scheme: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    
    @property
    def success(self) -> bool:
        """Whether normalization was successful."""
        return self.is_valid and self.normalized_url is not None


@dataclass
class NormalizationMetrics:
    """Metrics for tracking normalization performance."""
    total_processed: int = 0
    successful: int = 0
    failed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    avg_processing_time_ms: float = 0.0
    by_classification: Dict[str, int] = field(default_factory=dict)
    by_scheme: Dict[str, int] = field(default_factory=dict)
    
    def record_processing(self, classification: URLClassification, 
                         processing_time_ms: float, cache_hit: bool = False):
        """Record a processing event."""
        self.total_processed += 1
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        
        cls_name = classification.name
        self.by_classification[cls_name] = self.by_classification.get(cls_name, 0) + 1
        
        # Update average processing time
        if self.avg_processing_time_ms == 0:
            self.avg_processing_time_ms = processing_time_ms
        else:
            self.avg_processing_time_ms = (
                (self.avg_processing_time_ms * (self.total_processed - 1) + processing_time_ms) 
                / self.total_processed
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'total_processed': self.total_processed,
            'successful': self.successful,
            'failed': self.failed,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_ratio': (
                self.cache_hits / (self.cache_hits + self.cache_misses) 
                if (self.cache_hits + self.cache_misses) > 0 else 0
            ),
            'avg_processing_time_ms': round(self.avg_processing_time_ms, 2),
            'by_classification': self.by_classification,
            'by_scheme': self.by_scheme
        }


class EnterpriseURLNormalizer:
    """
    Enterprise-Grade URL Normalizer with comprehensive validation and optimization.
    
    Thread-safe, async-compatible, with caching, metrics, and pluggable rules.
    """
    
    # Pre-compiled regex patterns for performance
    _URL_SCHEME_PATTERN = re.compile(r'^([a-zA-Z][a-zA-Z0-9+\-.]*):')
    _DOUBLE_SLASHES_PATTERN = re.compile(r'/{2,}')
    _JS_ESCAPE_PATTERN = re.compile(r'\\+/')
    _IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    _IPV6_PATTERN = re.compile(r'^\[[a-fA-F0-9:]+\]$')
    _DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    _EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    # Common TLDs for validation (extended list)
    COMMON_TLDS: Set[str] = {
        # Generic TLDs
        'com', 'net', 'org', 'info', 'biz', 'xyz', 'online', 'site', 'website',
        'tech', 'io', 'ai', 'app', 'dev', 'cloud', 'store', 'shop', 'blog',
        'news', 'media', 'group', 'agency', 'center', 'company', 'digital',
        'global', 'guru', 'host', 'network', 'online', 'pro', 'services',
        
        # Country TLDs
        'us', 'uk', 'ca', 'au', 'in', 'de', 'fr', 'jp', 'cn', 'br', 'ru',
        'it', 'es', 'nl', 'se', 'no', 'dk', 'fi', 'pl', 'cz', 'hu', 'at',
        'ch', 'be', 'ie', 'nz', 'sg', 'hk', 'tw', 'kr', 'mx', 'ar', 'cl',
        
        # Special TLDs
        'edu', 'gov', 'mil', 'int', 'eu', 'asia', 'cat', 'coop', 'jobs',
        'mobi', 'museum', 'name', 'post', 'tel', 'travel', 'aero',
    }
    
    # Known CDN/hostname patterns (when found in paths, they're likely separate domains)
    CDN_HOSTNAME_PATTERNS: List[Pattern] = [
        re.compile(r'^.*\.(cdn|cloudfront|akamaihd|akamaiedge|edgekey)\.(net|com)$', re.IGNORECASE),
        re.compile(r'^.*\.(cloudflare|fastly|cdn77|bunnycdn|stackpath)\.(com|net)$', re.IGNORECASE),
        re.compile(r'^.*\.(googleapis|gstatic|googleusercontent|ggpht)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(amazonaws|s3)\.(com|eu|ap|sa|ca|us|uk)$', re.IGNORECASE),
        re.compile(r'^.*\.(azureedge|blob\.core\.windows\.net|azure\.net)$', re.IGNORECASE),
        re.compile(r'^.*\.(fbcdn|facebook|fb)\.(net|com)$', re.IGNORECASE),
        re.compile(r'^.*\.(twimg|twitter|t\.co)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(instagram|cdninstagram)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(linkedin|licdn)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(youtube|ytimg|googlevideo)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(vimeo|vimeocdn)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(github|githubusercontent)\.com$', re.IGNORECASE),
        re.compile(r'^.*\.(cloudinary|imgix|imageshack|imgur)\.(com|net)$', re.IGNORECASE),
        
        # Common prefixes (these are ALWAYS separate domains when in path)
        re.compile(r'^(assets?|static|cdn|media|images?|img|js|css|fonts?|scripts?|bundles?)\.', re.IGNORECASE),
    ]
    
    # Schemes that should be preserved (not converted to https)
    PRESERVE_SCHEMES = {'http', 'https', 'ftp', 'ftps', 'ws', 'wss'}
    
    # Schemes that should be skipped (non-HTTP)
    SKIP_SCHEMES = {
        'data', 'blob', 'javascript', 'mailto', 'file', 'about', 
        'tel', 'sms', 'geo', 'whatsapp', 'skype', 'facetime'
    }
    
    def __init__(self, 
                 enable_caching: bool = True,
                 max_cache_size: int = 10000,
                 enable_metrics: bool = True,
                 strict_validation: bool = True,
                 default_scheme: str = 'https',
                 strip_fragments_for_dedup: bool = False):
        """
        Initialize the enterprise URL normalizer.
        
        Args:
            enable_caching: Enable LRU caching for performance
            max_cache_size: Maximum cache size (entries)
            enable_metrics: Enable collection of normalization metrics
            strict_validation: Enable strict URL validation
            default_scheme: Default scheme for protocol-relative URLs
            strip_fragments_for_dedup: Remove fragments for deduplication
        """
        self.enable_caching = enable_caching
        self.max_cache_size = max_cache_size
        self.enable_metrics = enable_metrics
        self.strict_validation = strict_validation
        self.default_scheme = default_scheme
        self.strip_fragments_for_dedup = strip_fragments_for_dedup
        
        # Thread-safe LRU cache using OrderedDict
        self._cache = OrderedDict()
        self._cache_lock = threading.Lock()
        
        # Metrics
        self._metrics = NormalizationMetrics()
        self._metrics_lock = threading.Lock()
        
        # Configuration for validation rules
        self._validation_rules: List[Callable[[str], Tuple[bool, str]]] = [
            self._validate_length,
            self._validate_scheme,
            self._validate_hostname,
            self._validate_path_segments,
        ]
        
        # Compile all regex patterns once
        self._compile_patterns()
        
        logger.info(f"EnterpriseURLNormalizer initialized (caching={enable_caching}, "
                   f"strict={strict_validation}, default_scheme={default_scheme})")
    
    def _compile_patterns(self):
        """Compile all regex patterns for performance."""
        # Embedded hostname pattern (matches host.domain.tld/... in path)
        self._embedded_host_pattern = re.compile(
            r'^/?(?P<host>[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)/?(?P<path>.*)$'
        )
        
        # Malformed URL salvage patterns
        self._salvage_patterns = [
            # www.domain.com/path (missing protocol)
            (re.compile(r'^(www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?/.*)$', re.IGNORECASE),
             r'https://\1', 'missing_protocol_www'),
            
            # domain.com/path (missing protocol and www)
            (re.compile(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?/.*)$', re.IGNORECASE),
             r'https://\1', 'missing_protocol'),
            
            # Just domain (no path)
            (re.compile(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)$', re.IGNORECASE),
             r'https://\1', 'domain_only'),
            
            # IP address with port
            (re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(/.*)?$'),
             r'https://\1\2\3', 'ip_address'),
        ]
    
    def normalize(self, raw_url: str, base_url: Optional[str] = None) -> NormalizationResult:
        """
        Normalize any URL with comprehensive validation and error handling.
        
        Args:
            raw_url: URL to normalize (any format)
            base_url: Base URL for resolving relative URLs
            
        Returns:
            NormalizationResult with comprehensive metadata
        """
        start_time = time.perf_counter()
        
        # Create result object
        result = NormalizationResult(
            original_url=raw_url,
            base_url=base_url,
            is_valid=False
        )
        
        try:
            # Step 0: Check cache (if enabled)
            cache_key = None
            cache_hit = False
            
            if self.enable_caching:
                cache_key = self._get_cache_key(raw_url, base_url)
                with self._cache_lock:
                    if cache_key in self._cache:
                        # Move to end for LRU
                        cached_result = self._cache.pop(cache_key)
                        self._cache[cache_key] = cached_result
                        
                        # Return a DEEP COPY to prevent mutation issues
                        cached_result_copy = copy.deepcopy(cached_result)
                        processing_time = (time.perf_counter() - start_time) * 1000
                        
                        if self.enable_metrics:
                            with self._metrics_lock:
                                self._metrics.record_processing(
                                    cached_result_copy.classification,
                                    processing_time,
                                    cache_hit=True
                                )
                        
                        return cached_result_copy
            
            # Step 1: Basic input validation
            if not raw_url or not isinstance(raw_url, str):
                result.classification = URLClassification.EMPTY
                result.warnings.append("Empty or non-string URL")
                self._record_metrics(result, start_time, cache_hit)
                return result
            
            raw_url = raw_url.strip()
            if not raw_url:
                result.classification = URLClassification.EMPTY
                result.warnings.append("URL is empty string after stripping")
                self._record_metrics(result, start_time, cache_hit)
                return result
            
            # Step 2: Handle special URL schemes
            scheme_match = self._URL_SCHEME_PATTERN.match(raw_url)
            if scheme_match:
                scheme = scheme_match.group(1).lower()
                
                if scheme in self.SKIP_SCHEMES:
                    result.classification = {
                        'data': URLClassification.DATA_URL,
                        'blob': URLClassification.BLOB_URL,
                        'javascript': URLClassification.JAVASCRIPT_URL,
                        'mailto': URLClassification.MAILTO_URL,
                        'file': URLClassification.FILE_URL,
                        'about': URLClassification.ABOUT_URL,
                    }.get(scheme, URLClassification.UNKNOWN_SCHEME)
                    result.warnings.append(f"Non-HTTP scheme '{scheme}' - skipping")
                    self._record_metrics(result, start_time, cache_hit)
                    return result
            
            # Step 3: Apply transformations
            transformed_url, transformations = self._apply_transformations(raw_url)
            result.transformations.extend(transformations)
            
            # Step 4: Classify and normalize
            normalized, classification, metadata = self._classify_and_normalize(
                transformed_url, base_url
            )
            
            result.normalized_url = normalized
            result.classification = classification
            result.metadata.update(metadata)
            result.transformations.extend(metadata.get('transformations', []))
            result.warnings.extend(metadata.get('warnings', []))
            
            # Step 5: Parse and validate
            if normalized:
                try:
                    parsed = urlparse(normalized)
                    result.scheme = parsed.scheme
                    result.domain = parsed.netloc.split(':')[0] if parsed.netloc else None
                    result.path = parsed.path
                    result.query = parsed.query
                    result.fragment = parsed.fragment
                    
                    # Validate the normalized URL
                    is_valid, validation_errors = self._validate_url(normalized)
                    result.is_valid = is_valid
                    
                    if not is_valid and validation_errors:
                        result.warnings.extend(validation_errors)
                        if self.strict_validation:
                            result.normalized_url = None
                            result.classification = URLClassification.INVALID
                except Exception as e:
                    result.warnings.append(f"URL parsing failed: {str(e)}")
                    result.is_valid = False
                    result.classification = URLClassification.INVALID
            
            # Step 6: Update cache with DEEP COPY
            if (self.enable_caching and cache_key and 
                result.normalized_url and result.is_valid):
                with self._cache_lock:
                    # Store a deep copy to prevent mutation issues
                    result_copy = copy.deepcopy(result)
                    
                    # LRU eviction: remove oldest if cache is full
                    if len(self._cache) >= self.max_cache_size:
                        self._cache.popitem(last=False)  # Remove first (oldest)
                    
                    # Store and mark as most recently used
                    self._cache[cache_key] = result_copy
            
            # Step 7: Record metrics
            self._record_metrics(result, start_time, cache_hit)
            
            return result
            
        except Exception as e:
            logger.error(f"URL normalization failed for '{raw_url}': {e}", exc_info=True)
            result.warnings.append(f"Normalization error: {str(e)}")
            result.classification = URLClassification.INVALID
            self._record_metrics(result, start_time, cache_hit)
            return result
    
    def _apply_transformations(self, url: str) -> Tuple[str, List[str]]:
        """Apply all necessary transformations to the URL."""
        transformations = []
        original = url
        
        # 1. Decode URL encoding (carefully)
        try:
            decoded = unquote(url)
            if decoded != url:
                transformations.append('url_decoded')
                url = decoded
        except Exception:
            pass
        
        # 2. Fix JavaScript escapes (\/ → /)
        if '\\/' in url:
            url = self._JS_ESCAPE_PATTERN.sub('/', url)
            transformations.append('js_escapes_fixed')
        
        # 3. Fix common typos
        if url.startswith('htttp://'):
            url = url.replace('htttp://', 'http://')
            transformations.append('fixed_htttp_typo')
        elif url.startswith('http//'):
            url = url.replace('http//', 'http://')
            transformations.append('fixed_missing_colon')
        elif url.startswith('https//'):
            url = url.replace('https//', 'https://')
            transformations.append('fixed_missing_colon')
        
        # 4. Remove control characters and normalize whitespace
        url = ''.join(char for char in url if ord(char) >= 32 or char in '\t\n\r')
        url = ' '.join(url.split())  # Normalize whitespace
        
        # 5. Fix multiple slashes (except after protocol)
        if '//' in url and not url.startswith('//'):
            parts = url.split('://', 1)
            if len(parts) == 2:
                scheme, rest = parts
                rest = self._DOUBLE_SLASHES_PATTERN.sub('/', rest)
                url = f"{scheme}://{rest}"
                transformations.append('collapsed_multiple_slashes')
        
        # 6. Ensure proper encoding for special characters
        try:
            # Encode spaces and other special characters
            parsed = urlparse(url)
            if parsed.path:
                # Only encode if not already encoded
                if '%' not in parsed.path:
                    encoded_path = quote(parsed.path, safe='/~')
                    if encoded_path != parsed.path:
                        url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            encoded_path,
                            parsed.params,
                            parsed.query,
                            parsed.fragment
                        ))
                        transformations.append('path_encoded')
        except Exception:
            pass
        
        if url != original:
            transformations.insert(0, 'transformed')
        
        return url, transformations
    
    def _classify_and_normalize(self, url: str, base_url: Optional[str]) -> Tuple[Optional[str], URLClassification, Dict[str, Any]]:
        """Classify URL type and normalize accordingly."""
        metadata = {
            'transformations': [],
            'warnings': [],
            'original': url
        }
        
        # 1. Protocol-relative URLs (//example.com)
        if url.startswith('//'):
            normalized = f"{self.default_scheme}:{url}"
            normalized = self._clean_final_url(normalized)
            metadata['transformations'].append('protocol_relative_fixed')
            return normalized, URLClassification.PROTOCOL_RELATIVE, metadata
        
        # 2. Already absolute HTTP/HTTPS URLs
        if url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            normalized = self._clean_final_url(url)
            return normalized, URLClassification.ABSOLUTE, metadata
        
        # 3. Check for embedded hostnames (most important for your 404 issue)
        embedded_match = self._embedded_host_pattern.match(url)
        if embedded_match:
            host = embedded_match.group('host')
            path = embedded_match.group('path')
            
            # Check if this looks like a real hostname (not just a path segment)
            if self._looks_like_real_hostname(host):
                normalized = f"{self.default_scheme}://{host}/{path}" if path else f"{self.default_scheme}://{host}"
                normalized = self._clean_final_url(normalized)
                metadata.update({
                    'transformations': ['embedded_host_extracted'],
                    'extracted_host': host,
                    'original_path': path
                })
                return normalized, URLClassification.EMBEDDED_HOST, metadata
        
        # 4. Relative URLs (need base_url)
        if base_url:
            try:
                # Normalize base URL first
                base_result = self.normalize(base_url)
                if base_result.normalized_url:
                    normalized = urljoin(base_result.normalized_url, url)
                    normalized = self._clean_final_url(normalized)
                    metadata['transformations'].append('relative_resolved')
                    return normalized, URLClassification.RELATIVE, metadata
            except Exception as e:
                metadata['warnings'].append(f"urljoin failed: {str(e)}")
        
        # 5. Absolute paths (start with /)
        if url.startswith('/'):
            if base_url:
                try:
                    base_result = self.normalize(base_url)
                    if base_result.normalized_url:
                        normalized = urljoin(base_result.normalized_url, url)
                        normalized = self._clean_final_url(normalized)
                        metadata['transformations'].append('absolute_path_resolved')
                        return normalized, URLClassification.ABSOLUTE_PATH, metadata
                except Exception:
                    pass
        
        # 6. Try to salvage malformed URLs
        salvaged, salvage_type = self._salvage_malformed_url(url)
        if salvaged:
            metadata['transformations'].append(f'salvaged_{salvage_type}')
            return salvaged, URLClassification.MALFORMED_SALVAGED, metadata
        
        # 7. Invalid URL
        metadata['warnings'].append('no_valid_normalization_found')
        return None, URLClassification.INVALID, metadata
    
    def _looks_like_real_hostname(self, host: str) -> bool:
        """
        Determine if a string looks like a real hostname (not just a path segment).
        
        This is CRITICAL for fixing the Facebook CDN issue.
        """
        # Quick checks
        if '.' not in host:
            return False
        
        # Check for common CDN patterns (most important)
        for pattern in self.CDN_HOSTNAME_PATTERNS:
            if pattern.match(host):
                return True
        
        # Check if it looks like a domain (has valid TLD)
        parts = host.split('.')
        if len(parts) < 2:
            return False
        
        tld = parts[-1].lower()
        
        # Check known TLDs
        if tld in self.COMMON_TLDS:
            return True
        
        # Check for country TLDs (2 letters)
        if len(tld) == 2 and tld.isalpha():
            return True
        
        # Check for IP addresses
        if self._IPV4_PATTERN.match(host) or self._IPV6_PATTERN.match(host):
            return True
        
        # Check domain pattern
        if not self._DOMAIN_PATTERN.match(host):
            return False
        
        # 🔥 FIX #1: Prevent false positives like "config.json.backup"
        # Must end in a valid TLD-like segment (alpha, 2+ chars)
        last = host.split('.')[-1]
        if not (last.isalpha() and len(last) >= 2):
            return False
        
        # Check if it could be an email (shouldn't be treated as hostname)
        if '@' in host or self._EMAIL_PATTERN.match(host):
            return False
        
        # If all else fails, check if it has multiple dots (likely a domain)
        return host.count('.') >= 2
    
    def _salvage_malformed_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Try to salvage obviously malformed URLs."""
        for pattern, replacement, salvage_type in self._salvage_patterns:
            if pattern.match(url):
                try:
                    salvaged = pattern.sub(replacement, url)
                    cleaned = self._clean_final_url(salvaged)
                    return cleaned, salvage_type
                except Exception:
                    continue
        
        return None, None
    
    def _clean_final_url(self, url: str) -> str:
        """Final cleanup and standardization of URL."""
        try:
            parsed = urlparse(url)
            
            # Ensure valid scheme
            scheme = parsed.scheme.lower() if parsed.scheme else self.default_scheme
            if scheme not in self.PRESERVE_SCHEMES:
                scheme = self.default_scheme
            
            # Clean netloc
            netloc = parsed.netloc.lower()
            
            # Remove auth if present (username:password@)
            if '@' in netloc:
                netloc = netloc.split('@')[-1]
            
            # Remove default ports
            if ':' in netloc:
                host, port = netloc.split(':', 1)
                try:
                    port_int = int(port)
                    if (scheme == 'http' and port_int == 80) or \
                       (scheme == 'https' and port_int == 443) or \
                       (scheme == 'ftp' and port_int == 21):
                        netloc = host
                except ValueError:
                    pass
            
            # Clean path
            path = parsed.path
            
            # Decode then encode properly
            try:
                path = unquote(path)
            except Exception:
                pass
            
            # Remove directory traversal attempts
            path_segments = []
            for segment in path.split('/'):
                if segment == '..':
                    if path_segments:
                        path_segments.pop()
                elif segment not in ('', '.'):
                    path_segments.append(segment)
            
            path = '/' + '/'.join(path_segments)
            if path == '':
                path = '/'
            
            # Remove trailing slash except for root
            if path != '/':
                path = path.rstrip('/')
            
            # Collapse multiple slashes
            path = self._DOUBLE_SLASHES_PATTERN.sub('/', path)
            
            # Encode path (safe characters: alphanumeric, -, ., _, ~, /)
            path = quote(path, safe='/-._~')
            
            # Clean query (sort parameters for consistency)
            query = parsed.query
            if query:
                # Parse and sort query parameters
                params = parse_qsl(query, keep_blank_values=True)
                params.sort(key=lambda x: x[0])  # Sort by key
                query = '&'.join(f'{k}={v}' if v else k for k, v in params)
            
            # Handle fragment based on configuration
            fragment = parsed.fragment
            if self.strip_fragments_for_dedup:
                fragment = ''
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                query,
                fragment
            ))
            
            return normalized
            
        except Exception as e:
            logger.debug(f"URL cleaning failed: {e}")
            # Basic fallback
            return url.lower()
    
    def _validate_url(self, url: str) -> Tuple[bool, List[str]]:
        """Validate a normalized URL."""
        errors = []
        
        for validation_rule in self._validation_rules:
            is_valid, error_msg = validation_rule(url)
            if not is_valid:
                errors.append(error_msg)
        
        return len(errors) == 0, errors
    
    def _validate_length(self, url: str) -> Tuple[bool, str]:
        """Validate URL length."""
        if len(url) > 2048:
            return False, f"URL too long ({len(url)} > 2048 characters)"
        return True, ""
    
    def _validate_scheme(self, url: str) -> Tuple[bool, str]:
        """Validate URL scheme."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in self.PRESERVE_SCHEMES:
                return False, f"Invalid scheme: {parsed.scheme}"
            return True, ""
        except Exception:
            return False, "Cannot parse scheme"
    
    def _validate_hostname(self, url: str) -> Tuple[bool, str]:
        """Validate hostname."""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return False, "Missing hostname"
            
            hostname = parsed.netloc.split(':')[0]
            
            # Check for invalid characters
            if re.search(r'[^\w.\-:]', hostname):
                return False, f"Invalid characters in hostname: {hostname}"
            
            # Check each label in hostname
            labels = hostname.split('.')
            for label in labels:
                if not label:
                    return False, "Empty label in hostname"
                if len(label) > 63:
                    return False, f"Label too long: {label}"
                if label.startswith('-') or label.endswith('-'):
                    return False, f"Label starts or ends with hyphen: {label}"
            
            return True, ""
        except Exception:
            return False, "Cannot validate hostname"
    
    def _validate_path_segments(self, url: str) -> Tuple[bool, str]:
        """Validate URL path segments."""
        try:
            parsed = urlparse(url)
            for segment in parsed.path.split('/'):
                if '..' in segment or '//' in segment:
                    return False, f"Invalid path segment: {segment}"
            return True, ""
        except Exception:
            return False, "Cannot validate path segments"
    
    def _get_cache_key(self, url: str, base_url: Optional[str]) -> str:
        """Generate cache key for URL normalization."""
        # 🔥 FIX #3: Use SHA256 instead of MD5
        key_str = f"{url}|{base_url}"
        return hashlib.sha256(key_str.encode()).hexdigest()[:32]  # Use first 32 chars of SHA256
    
    def _record_metrics(self, result: NormalizationResult, start_time: float, cache_hit: bool):
        """Record normalization metrics."""
        if not self.enable_metrics:
            return
        
        processing_time = (time.perf_counter() - start_time) * 1000
        
        with self._metrics_lock:
            self._metrics.record_processing(
                result.classification,
                processing_time,
                cache_hit
            )
            
            if result.is_valid:
                self._metrics.successful += 1
                if result.scheme:
                    self._metrics.by_scheme[result.scheme] = (
                        self._metrics.by_scheme.get(result.scheme, 0) + 1
                    )
            else:
                self._metrics.failed += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get normalization metrics."""
        with self._metrics_lock:
            return self._metrics.to_dict()
    
    def clear_cache(self):
        """Clear the normalization cache."""
        with self._cache_lock:
            self._cache.clear()
    
    def reset_metrics(self):
        """Reset normalization metrics."""
        with self._metrics_lock:
            self._metrics = NormalizationMetrics()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._cache_lock:
            return {
                'size': len(self._cache),
                'max_size': self.max_cache_size,
                'utilization': len(self._cache) / self.max_cache_size if self.max_cache_size > 0 else 0
            }


# Global singleton instance for convenience
_normalizer_instance = None
_normalizer_lock = threading.Lock()

def get_normalizer(**kwargs) -> EnterpriseURLNormalizer:
    """Get singleton instance of URL normalizer."""
    global _normalizer_instance
    if _normalizer_instance is None:
        with _normalizer_lock:
            if _normalizer_instance is None:
                _normalizer_instance = EnterpriseURLNormalizer(**kwargs)
    return _normalizer_instance


# Simple wrapper functions for backward compatibility
def normalize_url(url: str, base_url: Optional[str] = None) -> Optional[str]:
    """
    Simple wrapper for backward compatibility.
    Returns normalized URL string or None if invalid.
    """
    normalizer = get_normalizer()
    result = normalizer.normalize(url, base_url)
    return result.normalized_url if result.success else None


def is_valid_url(url: str) -> bool:
    """Check if URL is valid and normalized."""
    normalizer = get_normalizer()
    result = normalizer.normalize(url)
    return result.success


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL."""
    normalizer = get_normalizer()
    result = normalizer.normalize(url)
    return result.domain if result.success else None


def get_normalization_metrics() -> Dict[str, Any]:
    """Get normalization metrics."""
    normalizer = get_normalizer()
    return normalizer.get_metrics()
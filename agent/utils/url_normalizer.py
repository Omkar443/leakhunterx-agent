"""
Universal URL normalization for web security scanning.
Handles all edge cases: escaped slashes, protocol-relative, embedded hosts, etc.
"""

import re
import logging
from urllib.parse import urlparse, urljoin, urlunparse
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

class URLNormalizer:
    """
    Universal URL normalizer that handles all common edge cases in web scanning.
    Production-grade with comprehensive error handling.
    """
    
    # Common TLDs for hostname detection
    COMMON_TLDS = {
        'com', 'net', 'org', 'io', 'co', 'ai', 'dev', 'app', 'tech',
        'cloud', 'online', 'store', 'shop', 'site', 'website', 'xyz',
        'info', 'biz', 'me', 'us', 'uk', 'ca', 'au', 'in', 'de', 'fr'
    }
    
    @staticmethod
    def normalize_url(raw_url: str, base_url: Optional[str] = None) -> Tuple[Optional[str], str, Dict[str, Any]]:
        """
        Normalize any URL format to a standard absolute URL.
        
        Args:
            raw_url: The URL to normalize (can be any format)
            base_url: Base URL for resolving relative URLs
            
        Returns:
            Tuple of (normalized_url, classification, metadata)
            classification can be: 'absolute', 'protocol_relative', 'relative', 
                                 'embedded_host', 'malformed', 'empty', 'invalid'
            metadata contains debug info about the normalization
        """
        metadata = {
            'original': raw_url,
            'transformations': [],
            'warnings': []
        }
        
        if not raw_url or not isinstance(raw_url, str):
            metadata['classification'] = 'empty'
            return None, 'empty', metadata
        
        # Clean input
        original = raw_url
        raw_url = raw_url.strip()
        if not raw_url:
            metadata['classification'] = 'empty'
            return None, 'empty', metadata
        
        # Track transformations
        transformations = []
        
        # Step 1: Decode JavaScript escapes (\/ → /)
        if '\\/' in raw_url:
            transformations.append('decoded_js_escapes')
            raw_url = raw_url.replace('\\\\/', '/')  # Handle double escapes
            raw_url = raw_url.replace('\\/', '/')
        
        # Step 2: Collapse multiple slashes (except after protocol)
        # Pattern: collapse 2+ slashes unless they're after ://
        if '//' in raw_url and not raw_url.startswith('//'):
            # Find and collapse multiple slashes in path
            parts = raw_url.split('://', 1)
            if len(parts) == 2:
                scheme, rest = parts
                # Collapse 2+ slashes in path
                rest = re.sub(r'/{2,}', '/', rest)
                raw_url = f"{scheme}://{rest}"
                transformations.append('collapsed_multiple_slashes')
        
        # Step 3: Handle protocol-relative URLs (//example.com/path)
        if raw_url.startswith('//'):
            normalized = 'https:' + raw_url
            normalized = URLNormalizer._clean_final_url(normalized)
            metadata.update({
                'classification': 'protocol_relative',
                'transformations': transformations + ['added_https_scheme'],
                'normalized': normalized
            })
            return normalized, 'protocol_relative', metadata
        
        # Step 4: Already absolute HTTP/HTTPS URL
        if raw_url.startswith(('http://', 'https://')):
            normalized = URLNormalizer._clean_final_url(raw_url)
            metadata.update({
                'classification': 'absolute',
                'transformations': transformations,
                'normalized': normalized
            })
            return normalized, 'absolute', metadata
        
        # Step 5: Check for embedded hostname in path
        embedded_match = URLNormalizer._extract_embedded_host(raw_url)
        if embedded_match:
            host, path = embedded_match
            normalized = f'https://{host}/{path}' if path else f'https://{host}'
            normalized = URLNormalizer._clean_final_url(normalized)
            transformations.append('extracted_embedded_host')
            metadata.update({
                'classification': 'embedded_host',
                'embedded_host': host,
                'original_path': path,
                'transformations': transformations,
                'normalized': normalized
            })
            return normalized, 'embedded_host', metadata
        
        # Step 6: Relative URL - need base_url
        if base_url:
            try:
                normalized = urljoin(base_url, raw_url)
                normalized = URLNormalizer._clean_final_url(normalized)
                transformations.append('resolved_relative_url')
                metadata.update({
                    'classification': 'relative',
                    'base_url': base_url,
                    'transformations': transformations,
                    'normalized': normalized
                })
                return normalized, 'relative', metadata
            except Exception as e:
                metadata['warnings'].append(f'urljoin failed: {str(e)}')
                logger.debug(f"urljoin failed for base='{base_url}', url='{raw_url}': {e}")
        
        # Step 7: Try to salvage malformed URLs
        salvaged, salvage_type = URLNormalizer._salvage_malformed_url(raw_url)
        if salvaged:
            transformations.append(f'salvaged_{salvage_type}')
            metadata.update({
                'classification': f'malformed_salvaged_{salvage_type}',
                'transformations': transformations,
                'normalized': salvaged
            })
            return salvaged, 'malformed_salvaged', metadata
        
        # Step 8: Final attempt - treat as path if it starts with /
        if raw_url.startswith('/'):
            if base_url:
                try:
                    normalized = urljoin(base_url, raw_url)
                    normalized = URLNormalizer._clean_final_url(normalized)
                    transformations.append('treated_as_absolute_path')
                    metadata.update({
                        'classification': 'absolute_path',
                        'transformations': transformations,
                        'normalized': normalized
                    })
                    return normalized, 'absolute_path', metadata
                except Exception:
                    pass
        
        metadata.update({
            'classification': 'invalid',
            'transformations': transformations,
            'warnings': metadata.get('warnings', []) + ['no_valid_normalization_found']
        })
        return None, 'invalid', metadata
    
    @staticmethod
    def _extract_embedded_host(url: str) -> Optional[Tuple[str, str]]:
        """
        Extract embedded hostname from a path-like string.
        
        Example:
            /static.xx.fbcdn.net/path → ('static.xx.fbcdn.net', 'path')
            static.xx.fbcdn.net/path → ('static.xx.fbcdn.net', 'path')
        """
        # Remove leading slash if present
        clean = url.lstrip('/')
        
        # Split by first slash
        parts = clean.split('/', 1)
        potential_host = parts[0]
        
        # Check if this looks like a hostname
        if '.' in potential_host:
            # Basic hostname validation
            host_parts = potential_host.split('.')
            if len(host_parts) >= 2:
                # Check if last part looks like a TLD
                last_part = host_parts[-1].lower()
                if (len(last_part) <= 6 or 
                    last_part in URLNormalizer.COMMON_TLDS or
                    re.match(r'^[a-z]{2,6}$', last_part)):
                    path = parts[1] if len(parts) > 1 else ''
                    return potential_host, path
        
        return None
    
    @staticmethod
    def _clean_final_url(url: str) -> str:
        """
        Final cleanup of normalized URL with comprehensive sanitization.
        """
        try:
            parsed = urlparse(url)
            
            # Ensure scheme
            scheme = parsed.scheme or 'https'
            if scheme not in ('http', 'https'):
                scheme = 'https'
            
            # Normalize netloc (lowercase, remove default ports, strip auth)
            netloc = parsed.netloc.lower()
            
            # Remove auth if present
            if '@' in netloc:
                netloc = netloc.split('@')[-1]
            
            # Remove default ports
            if ':' in netloc:
                host, port = netloc.split(':', 1)
                if port in ('80', '443'):
                    netloc = host
            
            # Clean path (remove trailing slash except root, collapse slashes)
            path = parsed.path
            
            # Collapse multiple slashes
            path = re.sub(r'/{2,}', '/', path)
            
            # Remove trailing slash except for root
            if path != '/':
                path = path.rstrip('/') or '/'
            
            # Clean query and fragment
            query = parsed.query
            fragment = parsed.fragment
            
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
            logger.debug(f"URL cleaning failed for '{url}': {e}")
            # Fallback: basic cleaning
            url_lower = url.lower()
            url_lower = re.sub(r'/{2,}', '/', url_lower)
            return url_lower.rstrip('/')
    
    @staticmethod
    def _salvage_malformed_url(url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Try to salvage obviously malformed but salvageable URLs.
        
        Returns:
            Tuple of (salvaged_url, salvage_type) or (None, None)
        """
        # Common patterns in JavaScript
        patterns = [
            # Looks like URL but missing protocol (www.example.com/path)
            (r'^(www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.*)$', r'https://\1', 'missing_protocol_www'),
            # Domain without www (example.com/path)
            (r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.*)$', r'https://\1', 'missing_protocol'),
            # Just a domain
            (r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', r'https://\1', 'domain_only'),
        ]
        
        for pattern, replacement, salvage_type in patterns:
            match = re.match(pattern, url)
            if match:
                try:
                    salvaged = re.sub(pattern, replacement, url)
                    cleaned = URLNormalizer._clean_final_url(salvaged)
                    return cleaned, salvage_type
                except Exception:
                    continue
        
        return None, None
    
    @staticmethod
    def classify_failure_status(status_code: int, url: str, error_msg: str = "") -> Tuple[str, Dict[str, Any]]:
        """
        Classify HTTP failure reasons for professional reporting.
        
        Returns:
            Tuple of (classification, metadata)
        """
        metadata = {
            'status_code': status_code,
            'url': url,
            'error_message': error_msg[:100] if error_msg else ''
        }
        
        if status_code == 0:
            return 'network_error', metadata
        elif status_code in (400, 405):
            return 'origin_bound', metadata
        elif status_code in (401, 403):
            return 'protected_resource', metadata
        elif status_code == 404:
            return 'not_found', metadata
        elif status_code == 429:
            return 'rate_limited', metadata
        elif status_code in (301, 302, 307, 308):
            return 'redirect', metadata
        elif 500 <= status_code < 600:
            return 'server_error', metadata
        else:
            return 'unexpected_error', metadata
    
    @staticmethod
    def should_retry_failure(classification: str, attempt: int, max_retries: int) -> bool:
        """
        Determine if a failed request should be retried based on classification.
        """
        # Never retry these
        no_retry_classes = {'origin_bound', 'protected_resource', 'not_found'}
        if classification in no_retry_classes:
            return False
        
        # Retry server errors and rate limits
        if classification in {'server_error', 'rate_limited'}:
            return attempt < max_retries - 1
        
        # Retry network errors
        if classification == 'network_error':
            return attempt < max_retries - 1
        
        # Don't retry others by default
        return False
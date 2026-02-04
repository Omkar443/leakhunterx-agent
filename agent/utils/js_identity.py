"""
JS Identity & Variant Tracking Utilities

Purpose:
- Provide stable, universal JS identity independent of URL versioning
- Detect content changes safely (B2: track JS variants)
- Support hash replacement strategy
- Work across CDNs, SPAs, and any target

This module contains NO crawling or networking logic.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, unquote, parse_qs, urlencode, urlunparse


# ─────────────────────────────────────────────
# 🔐 JS Identity Registry
# ─────────────────────────────────────────────

class JSIdentityRegistry:
    """
    Tracks JS identity → content hash mapping for a scan.

    Behavior:
    - First time identity seen → store hash
    - Same identity + same hash → no-op
    - Same identity + different hash → variant detected (replace hash)
    """

    def __init__(self) -> None:
        self._identity_to_hash: Dict[str, str] = {}
        self.variant_count: int = 0

    def check_and_update(self, identity: str, content_hash: str) -> str:
        """
        Check identity against stored hash and update registry.

        Returns:
            - "new"       → first time this identity is seen
            - "unchanged" → same identity, same content
            - "variant"   → same identity, different content (hash replaced)
        """
        existing = self._identity_to_hash.get(identity)

        if existing is None:
            self._identity_to_hash[identity] = content_hash
            return "new"

        if existing == content_hash:
            return "unchanged"

        # Variant detected → replace hash
        self._identity_to_hash[identity] = content_hash
        self.variant_count += 1
        return "variant"

    def reset(self) -> None:
        """Clear registry (used between scans)."""
        self._identity_to_hash.clear()
        self.variant_count = 0

    def get_stats(self) -> Dict[str, int]:
        """Return registry statistics."""
        return {
            "total_identities": len(self._identity_to_hash),
            "variant_count": self.variant_count
        }


# ─────────────────────────────────────────────
# 🧬 Identity & Hash Helpers
# ─────────────────────────────────────────────

def compute_content_hash(content: bytes) -> str:
    """
    Compute SHA256 hash of JS content.

    Always use content hash — never URL hash.
    """
    return hashlib.sha256(content).hexdigest()


def compute_js_identity(js_url: str) -> str:
    """
    Compute a stable JS identity from URL.

    Identity format:
        js::<canonical_host>::<canonical_path>::<safe_query>

    Query params and cache-busting tokens are handled safely.
    """
    # Parse and normalize
    parsed = urlparse(js_url)
    
    host = canonicalize_host(parsed.netloc)
    path = canonicalize_path(parsed.path)
    query = filter_js_query_params(parsed.query)
    
    # Build identity
    safe_query = query if query else ""
    return f"js::{host}::{path}::{safe_query}"


# ─────────────────────────────────────────────
# 🌍 Canonicalization Helpers (UNIVERSAL)
# ─────────────────────────────────────────────

# Version patterns: /v1/, /v2.3/, /v4i7M54/, /123abc/
_VERSION_SEGMENT_RE = re.compile(r'/(?:v\d+(?:[._-]\d+)*|v[0-9a-zA-Z._-]{1,20})/', re.IGNORECASE)

# Hash-like strings in filenames (8+ hex chars)
_HASH_LIKE_RE = re.compile(r'[a-f0-9]{8,}', re.IGNORECASE)

# CDN host normalization patterns
_CDN_HOST_PATTERNS = [
    (re.compile(r'^static\.(?:[a-z]{2})\.fbcdn\.net$'), 'static.fbcdn.net'),
    (re.compile(r'^([a-z0-9]+-)?cdn\.shopify\.com$'), 'cdn.shopify.com'),
    # Add other CDNs as needed, but be conservative
]

# Framework-specific path patterns
_FRAMEWORK_PATTERNS = [
    # Next.js: /_next/static/chunks/app-abc123.js → /_next/static/chunks/app.js
    (re.compile(r'/_next/static/(?:chunks|css)/([^/]+?)(?:-[a-f0-9]{8,})?(\.\w+)$'), r'/_next/static/\1\2'),
    
    # Vite/Rollup: /assets/index-abc123.js → /assets/index.js
    (re.compile(r'/assets/([^/]+?)(?:-[a-f0-9]{8,})?(\.\w+)$'), r'/assets/\1\2'),
    
    # Webpack chunks: main.abc123.chunk.js → main.chunk.js
    (re.compile(r'/([^/]+?)\.(?:[a-f0-9]{8,})\.(chunk\.js)$'), r'/\1.\2'),
]

# Query params to KEEP (meaningful params)
_SAFE_QUERY_PARAMS = {'module', 'nomodule', 'async', 'defer', 'type', 'crossorigin'}

# Query params to REMOVE (cache-busting)
_CACHE_PARAMS = {'v', 'version', 'ts', 't', '_', 'cache', 'cb', 'rand', 'random'}


def canonicalize_host(host: str) -> str:
    """
    Normalize host safely for CDNs and mirrors.
    
    Rules:
    1. Lowercase
    2. Strip trailing dots
    3. Apply CDN-specific normalization (conservative)
    4. Never strip too much — preserve uniqueness
    """
    if not host:
        return ""
    
    host = host.lower().rstrip(".")
    
    # Apply CDN patterns
    for pattern, replacement in _CDN_HOST_PATTERNS:
        if pattern.match(host):
            return replacement
    
    return host


def canonicalize_path(path: str) -> str:
    """
    Canonicalize JS path to remove versioning & noise.
    
    UNIVERSAL rules for:
    - CDNs (Facebook, Cloudflare, Akamai)
    - SPAs (Next.js, Vite, Webpack)
    - Any framework
    
    Returns normalized path with leading slash.
    """
    if not path:
        return "/"
    
    # Decode URL encoding
    path = unquote(path)
    
    # Remove version directories
    path = _VERSION_SEGMENT_RE.sub("/", path)
    
    # Apply framework-specific patterns
    for pattern, replacement in _FRAMEWORK_PATTERNS:
        path = pattern.sub(replacement, path)
    
    # Remove hash-like strings from filename (most frameworks)
    if "." in path.split("/")[-1]:  # Has extension
        dir_parts = path.rsplit("/", 1)
        if len(dir_parts) == 2:
            dirname, filename = dir_parts
            # Remove hash-like sequences
            filename = _HASH_LIKE_RE.sub("", filename)
            # Clean up resulting double dots
            filename = re.sub(r'\.{2,}', '.', filename)
            # Remove trailing dots before extension
            filename = re.sub(r'(?<=\.)\.+(?=\.\w+$)', '', filename)
            path = f"{dirname}/{filename}"
    
    # Collapse duplicate slashes
    path = re.sub(r'/{2,}', '/', path)
    
    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path
    
    # Remove trailing slash unless it's root
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    
    return path


def filter_js_query_params(query_string: str) -> str:
    """
    Filter query parameters to keep meaningful ones, remove cache-busting.
    
    Returns filtered query string or empty string.
    """
    if not query_string:
        return ""
    
    try:
        params = parse_qs(query_string, keep_blank_values=True)
        filtered = {}
        
        for key, values in params.items():
            key_lower = key.lower()
            
            # Keep safe params
            if key_lower in _SAFE_QUERY_PARAMS:
                filtered[key] = values[0] if values else ""
            # Remove cache params
            elif key_lower in _CACHE_PARAMS:
                continue
            # Keep other params (conservative — they might matter)
            else:
                filtered[key] = values[0] if values else ""
        
        return urlencode(filtered) if filtered else ""
    except Exception:
        # If parsing fails, return empty (safe fallback)
        return ""


# ─────────────────────────────────────────────
# 🧪 Optional Diagnostic Helper
# ─────────────────────────────────────────────

def explain_identity(js_url: str) -> dict:
    """
    Debug helper — explains how identity was derived.
    
    Useful for diagnostics & testing.
    """
    parsed = urlparse(js_url)
    filtered_query = filter_js_query_params(parsed.query)
    
    return {
        "original_url": js_url,
        "host": parsed.netloc,
        "canonical_host": canonicalize_host(parsed.netloc),
        "original_path": parsed.path,
        "canonical_path": canonicalize_path(parsed.path),
        "original_query": parsed.query,
        "filtered_query": filtered_query,
        "identity": compute_js_identity(js_url),
    }


# ─────────────────────────────────────────────
# 📊 Quick Tests (will be removed in production)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Test cases covering different scenarios
    test_urls = [
        "https://static.xx.fbcdn.net/rsrc.php/v3/y4/r/abc123.js",
        "https://static.xy.fbcdn.net/rsrc.php/v3i7M54/y4/r/abc123.js",
        "https://cdn.shopify.com/s/files/v123456/app.js?v=789",
        "https://example.com/_next/static/chunks/app-abc123def.js",
        "https://example.com/assets/main-xyz789.js",
        "https://example.com/static/js/main.abc123.chunk.js",
        "https://example.com/js/app.js?module=true&v=1.2.3",
        "https://example.com/js/app.js?_=1234567890",
    ]
    
    for url in test_urls:
        print(f"\nURL: {url}")
        print(f"Identity: {compute_js_identity(url)}")
        for key, value in explain_identity(url).items():
            if key not in ["original_url", "identity"]:
                print(f"  {key}: {value}")
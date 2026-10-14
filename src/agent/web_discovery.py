"""Literal module discovery without executing source or guessing bundle names.

All requests still pass the existing scope, DNS, TLS and redirect policies.
Bare package specifiers require browser/import-map resolution and are not URLs.
"""
import re
from urllib.parse import urljoin

from .utils.pipeline import normalize_target

MAX_DISCOVERED_RESOURCES = 20000
_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"\bimport\s*(?:\(\s*)?[\"']([^\"'\r\n]{1,2048})[\"']",
    r"\b(?:import|export)\s+[^;\r\n]{0,512}?\bfrom\s*[\"']([^\"'\r\n]{1,2048})[\"']",
    r"\b(?:require|importScripts)\s*\(\s*[\"']([^\"'\r\n]{1,2048})[\"']",
    r"\bnew\s+(?:Worker|SharedWorker)\s*\(\s*[\"']([^\"'\r\n]{1,2048})[\"']",
    r"\bnew\s+URL\s*\(\s*[\"']([^\"'\r\n]{1,2048}\.(?:js|mjs|cjs)(?:\?[^\"'\r\n]*)?)[\"']\s*,\s*import\.meta\.url",
))


def module_urls(content, base_url):
    """Yield literal HTTP module/worker references; the caller enforces scope."""
    for pattern in _PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1)
            if not value.startswith(('./', '../', '/', 'https://', 'http://')):
                continue
            try:
                yield normalize_target(urljoin(base_url, value))
            except ValueError:
                continue


def discover_modules(content, base_url, context):
    scope = getattr(context, 'scope_check', None)
    if not callable(scope):
        return  # Never introduce network scope from an unbound analyzer.
    urls = context.shared_state.setdefault('discovered_module_urls', set())
    for url in module_urls(content, base_url):
        if not scope(url) or url in urls:
            continue
        if len(urls) >= MAX_DISCOVERED_RESOURCES:
            context.shared_state['dependency_discovery_limited'] = True
            break
        urls.add(url)

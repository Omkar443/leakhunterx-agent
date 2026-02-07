"""
Utils package for LeakHunterX Agent
"""
from .helpers import (
    now_ts,
    generate_scan_id,
    # REMOVE normalize_url from here - it's in helpers.py but we want enterprise version
    is_same_domain,
    safe_join_url,
    sha256_text,
    read_json_safe,
    atomic_write_json,
    ensure_dir,
    run_blocking,
    safe_await,
    secure_hash,
    create_event,
    emit_compatible_event
)

# ADD: Import enterprise version
from .url_normalizer import normalize_url

__all__ = [
    'now_ts',
    'generate_scan_id',
    'normalize_url',  # Now correctly points to enterprise version
    'is_same_domain',
    'safe_join_url',
    'sha256_text',
    'read_json_safe',
    'atomic_write_json',
    'ensure_dir',
    'run_blocking',
    'safe_await',
    'secure_hash',
    'create_event',
    'emit_compatible_event'
]
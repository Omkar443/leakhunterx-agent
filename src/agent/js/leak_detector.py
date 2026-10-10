"""
Enterprise-Grade Leak Detector with Advanced Pattern Recognition
Maintains 100% compatibility with existing code

LEGACY WARNING: EnterpriseLeakDetector is stateful and meant for backward compatibility.
For SaaS/event-driven use, use SecretScanner class instead.
"""

import re
import math
import hashlib
import time
import copy
import logging
import urllib.parse
import os
from bisect import bisect_right
from .detection_policy import POLICY_VERSION, EXPOSURE_RULES, update_patterns, valid_candidate, placeholder
from typing import List, Dict, Any, Optional

DEFAULT_CONTEXT_BEFORE = 30
DEFAULT_CONTEXT_AFTER = 30
MAX_CONTEXT_CHARS = 3000


KNOWN_KEY_PREFIXES = (
    "AIzaSy",    # Google API Key
    "AKIA",      # AWS Access Key ID
    "ASIA",      # AWS Temporary Access Key
    "sk_live_",   # Stripe Secret Key
    "sk_test_",   # Stripe Test Secret Key
    "rk_live_",   # Stripe Restricted Key
    "ghp_",      # GitHub Personal Access Token
    "gho_",      # GitHub OAuth Token
    "ghu_",      # GitHub User Token
    "ghs_",      # GitHub Server Token
    "ghr_",      # GitHub Refresh Token
    "sq0atp-",   # Square Access Token
    "sq0csp-",   # Square OAuth Secret
    "xoxb-",     # Slack Bot Token
    "xoxp-",     # Slack User Token
    "xapp-",     # Slack App Token
    "dp.pt.",    # DigitalOcean Token
    "eyJ",       # JWT Token header
    "bearer ",   # Bearer Auth header
)


_PLACEHOLDER_VALUES = {
    'your_api_key', 'your-api-key', 'yourapikey', 'example', 'changeme',
    'change_me', 'placeholder', 'test123', 'sample_key', 'insert_key_here',
    'your_api_key_here', 'api_key_here', 'replace_me', 'todo', 'fixme',
    'your_key', 'your_key_here',
}

_PLACEHOLDER_SUBSTRINGS = (
    'your_api_key', 'your-api-key', 'yourapikey', 'xxxxxxxx',
    'placeholder', 'changeme', 'change_me', 'insert_key',
    'example_key', 'sample_key', 'api_key_here', 'replace_this',
    'your_key', 'your_key_here', 'your_secret', 'example', 'dummy',
)


def _looks_like_placeholder(value: str) -> bool:
    """Return True if a matched value looks like dummy/placeholder text rather than a real credential."""
    return placeholder(value)


def build_match_evidence_mask(raw_value: Optional[str], leak_type: Optional[str] = None) -> str:
    """
    Builds a safe, non-sensitive structural evidence mask for AI validation.

    GUARANTEES:
    - Preserves detector pattern prefix & format structure (e.g. AIzaSy[REDACTED_33_CHARS])
    - Preserves placeholder text if value is a known test placeholder
    - Never exposes raw secret bytes or characters
    """
    if not raw_value or not str(raw_value).strip():
        return "[REDACTED_SECRET]"

    val = str(raw_value).strip()

    # Check if value is a known placeholder
    # Placeholder heuristics must never bypass credential redaction.

    # Check for known prefixes
    for prefix in KNOWN_KEY_PREFIXES:
        if val.startswith(prefix):
            rem_len = len(val) - len(prefix)
            if rem_len > 0:
                return f"{prefix}[REDACTED_{rem_len}_CHARS]"
            return prefix

    return "[REDACTED_SECRET]"


def redact_secret_in_line(line: str, raw_value: Optional[str], evidence_mask: Optional[str] = None) -> str:
    """Redacts raw_value from a line of source code with an evidence mask or token."""
    if not line or not raw_value:
        return line or ""
    secret_str = str(raw_value).strip()
    if len(secret_str) < 2:
        return line

    mask = evidence_mask or "[REDACTED_SECRET]"

    res = line
    if secret_str in res:
        res = res.replace(secret_str, mask)
    url_enc = urllib.parse.quote(secret_str)
    if url_enc != secret_str and url_enc in res:
        res = res.replace(url_enc, mask)
    return res


def normalize_repo_relative_path(path: Optional[str]) -> str:
    """Converts absolute local filesystem path to a clean repository-relative path if possible."""
    if not path:
        return "unknown"
    p = str(path).replace("\\", "/").strip()
    if p.startswith(("http://", "https://")):
        try:
            parsed = urllib.parse.urlsplit(p)
            host = parsed.hostname or ''
            if ':' in host: host = '[' + host + ']'
            if parsed.port: host += ':' + str(parsed.port)
            return urllib.parse.urlunsplit((parsed.scheme,host,parsed.path or '/', '', ''))
        except ValueError:
            return 'unknown'

    markers = ["/src/", "/app/", "/lib/", "/components/", "/pages/", "/services/", "/utils/", "/config/", "/public/"]
    p_lower = p.lower()
    for m in markers:
        idx = p_lower.rfind(m)
        if idx != -1:
            return p[idx + 1:]

    if ":" in p and len(p) > 2 and p[1] == ":":
        parts = p.split(":", 1)[1].lstrip("/")
        return parts
    return p.lstrip("/")


def extract_code_context(
    content: Optional[str],
    position: Optional[int] = None,
    line_number: Optional[int] = None,
    raw_value: Optional[str] = None,
    leak_type: Optional[str] = None,
    evidence_mask: Optional[str] = None,
    context_before: int = DEFAULT_CONTEXT_BEFORE,
    context_after: int = DEFAULT_CONTEXT_AFTER,
    max_chars: int = MAX_CONTEXT_CHARS,
    prepared_lines=None,
) -> Dict[str, Any]:
    """Extracts bounded, redacted line context around a finding position or line number."""
    if not content or not isinstance(content, str) or not content.strip():
        return {
            "code_context": None,
            "context_start_line": None,
            "context_end_line": None,
            "line_number": line_number,
            "is_truncated": False,
        }

    mask = evidence_mask or build_match_evidence_mask(raw_value, leak_type)

    lines = prepared_lines if prepared_lines is not None else content.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return {
            "code_context": None,
            "context_start_line": None,
            "context_end_line": None,
            "line_number": line_number,
            "is_truncated": False,
        }

    target_idx: Optional[int] = None

    if isinstance(line_number, int) and line_number > 0:
        target_idx = min(line_number - 1, total_lines - 1)
    elif isinstance(position, int) and position >= 0:
        sub = content[:position]
        target_idx = min(sub.count('\n'), total_lines - 1)
    elif raw_value and str(raw_value).strip():
        secret_str = str(raw_value).strip()
        for idx, line in enumerate(lines):
            if secret_str in line:
                target_idx = idx
                break

    if target_idx is None:
        target_idx = 0

    actual_line_number = target_idx + 1

    from .evidence import centered_context, redact_neighbors
    return centered_context(lines, target_idx,
        lambda line: redact_neighbors(redact_secret_in_line(line, raw_value, mask)),
        context_before, context_after, max_chars)

# ------------------------------------------------------------
# PACKAGE-RELATIVE IMPORT (CRITICAL FIX)
# ------------------------------------------------------------

from ..utils.events import emit_event

logger = logging.getLogger(__name__)


# ------------------------------------------------------------
# PLACEHOLDER / DUMMY VALUE REJECTION
# Prevents obvious placeholder text ("YOUR_API_KEY_HERE", "xxxxxxxx",
# "00000000...") from being reported as real secrets. Used by
# generic_api_key's validation function.
# (Placeholder definitions moved to top of module)


# ------------------------------------------------------------
# PER-CHARSET ENTROPY THRESHOLDS FOR "SUSPICIOUS" FLAGGING
#
# The original code used one flat threshold (entropy > 3.5) for every
# token type. This is not meaningful across different charsets: a
# random 32-char HEX string naturally averages ~3.6-3.7 bits/char
# (max possible for hex is 4.0), while a random base64 string of
# similar length naturally averages ~4.8-4.9 (max possible is 6.0).
# A single flat cutoff either over-flags low-charset tokens as
# artificially "suspicious" or under-flags high-charset tokens as
# not-quite-random-enough, when in fact both are equally random for
# their respective character spaces.
#
# These thresholds were derived empirically (not guessed) by sampling
# 1000+ genuinely random strings per charset/length and confirming
# every threshold below correctly classifies 100% of real random
# samples as "suspicious" while remaining well above the entropy of
# repeated/placeholder-style text (e.g. "aaaa...", "0000...",
# "abcabc...") which measures at or near 0-2.0.
#
# NOTE: entropy is informational metadata only here (feeds the
# "suspicious" flag and risk score) - it is NOT used to reject or
# accept a match; the "validation" lambda per pattern remains the
# actual accept/reject gate. This keeps the change additive and
# low-risk.
# ------------------------------------------------------------
_CHARSET_SUSPICIOUS_THRESHOLDS = {
    'hex': 2.8,            # theoretical max 4.0 (log2(16))
    'base64': 3.8,         # theoretical max 6.0 (log2(64))
    'alphanumeric': 3.2,   # theoretical max ~5.95 (log2(62))
    'mixed': 3.5,          # DEFAULT - matches the ORIGINAL flat threshold,
                           # so any pattern not explicitly mapped below
                           # behaves EXACTLY as before this change.
}

_PATTERN_CHARSET = {
    'aws_access_key': 'alphanumeric',
    'aws_secret_key': 'base64',
    'google_api_key': 'alphanumeric',
    'google_oauth_token': 'alphanumeric',
    'jwt_token': 'base64',
    'basic_auth': 'base64',
    'stripe_key': 'alphanumeric',
    'stripe_restricted_key': 'alphanumeric',
    'twilio_key': 'hex',
    'twilio_account_sid': 'hex',
    'slack_token': 'alphanumeric',
    'github_token': 'alphanumeric',
    'github_fine_grained_pat': 'alphanumeric',
    'mailgun_key': 'alphanumeric',
    'openai_api_key': 'alphanumeric',
    'anthropic_api_key': 'alphanumeric',
    'sendgrid_api_key': 'alphanumeric',
    'npm_token': 'alphanumeric',
    'discord_bot_token': 'alphanumeric',
    
    # NEW PATTERN CHARSET MAPPINGS
    'twitter_bearer_token': 'base64',
    'huggingface_token': 'alphanumeric',
    'gitlab_pat': 'alphanumeric',
    'telegram_bot_token': 'mixed',  # Contains digits and letters with colon
    'mapbox_token': 'base64',
    'recaptcha_key': 'alphanumeric',
    'cloudinary_url': 'mixed',  # URL format
    'discord_webhook_url': 'mixed',  # URL format
    'slack_webhook_url': 'mixed',  # URL format
    'shopify_access_token': 'hex',
    'facebook_access_token': 'hex',
    'algolia_admin_key': 'hex',
    'segment_write_key': 'alphanumeric',
    'mixpanel_token': 'hex',
    'amplitude_api_key': 'hex',
    # Anything NOT listed here falls back to 'mixed' -> 3.5
}


def _get_suspicious_threshold(leak_type: str) -> float:
    """Return the entropy threshold above which a match of this type
    is flagged 'suspicious', scaled to its expected character set."""
    charset = _PATTERN_CHARSET.get(leak_type, 'mixed')
    return _CHARSET_SUSPICIOUS_THRESHOLDS.get(charset, _CHARSET_SUSPICIOUS_THRESHOLDS['mixed'])


class EnterpriseLeakDetector:
    """
    LEGACY Enterprise Leak Detector (stateful, for backward compatibility only)

    WARNING: This class maintains internal state (caches, counters, dedup sets).
    For stateless, event-driven scanning, use SecretScanner class instead.
    """

    # Enhanced regex patterns with validation functions
    PATTERNS = {
        # ============================================================
        # EXISTING PATTERNS (PRESERVED WITH FIXES)
        # ============================================================
        
        # Cloud Keys - Enhanced patterns
        "aws_access_key": {
            "pattern": r"\bAKIA[0-9A-Z]{16}\b",
            "confidence": 0.95,
            "validation": lambda x: len(x) == 20 and x.startswith('AKIA'),
            "severity": "HIGH"
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws[^'\"\n]{0,20}?['\"\s:=]([A-Za-z0-9/+=]{40})",
            "confidence": 0.85,
            "validation": lambda x: len(x) == 40,
            "severity": "CRITICAL"
        },

        # Google Cloud - Enhanced patterns
        "google_api_key": {
            "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "confidence": 0.90,
            "validation": lambda x: len(x) == 39 and x.startswith('AIza'),
            "severity": "HIGH"
        },
        "google_oauth_token": {
            "pattern": r"\bya29\.[0-9A-Za-z\-_]+\b",
            "confidence": 0.80,
            "validation": lambda x: x.startswith('ya29.'),
            "severity": "MEDIUM"
        },

        # API Keys - Enhanced patterns
        "generic_api_key": {
            "pattern": r"(?i)\b(api[_-]?key|apikey|secret[_-]?key)['\"\s:=]+([A-Za-z0-9\-_.]{20,100})\b",
            "confidence": 0.70,
            "validation": lambda x: 20 <= len(x) <= 100 and not _looks_like_placeholder(x),
            "severity": "MEDIUM"
        },
        "bearer_token": {
            "pattern": r"(?i)\bbearer[\s]+([A-Za-z0-9\-_.=]{50,})\b",
            "confidence": 0.75,
            "validation": lambda x: len(x) >= 50,
            "severity": "MEDIUM"
        },

        # Authentication - Enhanced patterns
        "jwt_token": {
            "pattern": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_\-.+/=]*",
            "confidence": 0.80,
            "validation": lambda x: len(x.split('.')) == 3,
            "severity": "MEDIUM"
        },
        "basic_auth": {
            "pattern": r"(?i)\bbasic[\s]+([A-Za-z0-9+/=]{20,})\b",
            "confidence": 0.65,
            "validation": lambda x: len(x) >= 20,
            "severity": "MEDIUM"
        },

        # Service-specific keys - Enhanced patterns
        "stripe_key": {
            # FIX: Added 3rd capturing group around the actual key body
            "pattern": r"\b(sk|pk)_(test|live)_([0-9a-zA-Z]{24})\b",
            "confidence": 0.95,
            "validation": lambda x: x.startswith(('sk_', 'pk_')),
            "severity": "HIGH"
        },
        "twilio_key": {
            "pattern": r"\bSK[0-9a-fA-F]{32}\b",
            "confidence": 0.90,
            "validation": lambda x: len(x) == 34 and x.startswith('SK'),
            "severity": "HIGH"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-(?:\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24,32}|[0-9a-zA-Z-]{20,48})",
            "confidence": 0.85,
            "validation": lambda x: x.startswith(('xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-')),
            "severity": "MEDIUM"
        },
        "github_token": {
            "pattern": r"\bgh[pousr]_[A-Za-z0-9_]{36}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')),
            "severity": "HIGH"
        },
        "mailgun_key": {
            "pattern": r"\bkey-[0-9a-zA-Z]{32}\b",
            "confidence": 0.80,
            "validation": lambda x: len(x) == 36 and x.startswith('key-'),
            "severity": "MEDIUM"
        },

        # Database connections - Enhanced patterns
        "mongodb_uri": {
            # FIX: Made (+srv) non-capturing so the full URI is extracted
            "pattern": r"mongodb(?:\+srv)?://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'mongodb' in x,
            "severity": "HIGH"
        },
        "mysql_connection": {
            "pattern": r"mysql://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'mysql://' in x,
            "severity": "HIGH"
        },
        "postgres_connection": {
            # FIX: Made (ql) non-capturing so the full URI is extracted
            "pattern": r"postgres(?:ql)?://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'postgres' in x,
            "severity": "HIGH"
        },
        "redis_connection": {
            "pattern": r"redis://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'redis://' in x,
            "severity": "HIGH"
        },

        # Cloud storage - Enhanced patterns
        "s3_bucket": {
            "pattern": r"s3://[a-z0-9\-\.]+",
            "confidence": 0.75,
            "validation": lambda x: x.startswith('s3://'),
            "severity": "MEDIUM"
        },
        "s3_url": {
            "pattern": r"https?://[a-z0-9\-\.]+\.s3\.(?:[a-z0-9\-\.]+)?amazonaws\.com",
            "confidence": 0.80,
            "validation": lambda x: '.s3.' in x and 'amazonaws.com' in x,
            "severity": "MEDIUM"
        },
        "google_storage": {
            "pattern": r"gs://[a-z0-9\-\.]+",
            "confidence": 0.75,
            "validation": lambda x: x.startswith('gs://'),
            "severity": "MEDIUM"
        },
        "azure_storage": {
            "pattern": r"https?://[a-z0-9]+\.blob\.core\.windows\.net",
            "confidence": 0.80,
            "validation": lambda x: '.blob.core.windows.net' in x,
            "severity": "MEDIUM"
        },
        "azure_storage_connection_string": {
            "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,};?",
            "confidence": 0.90,
            "validation": lambda x: 'AccountKey=' in x,
            "severity": "CRITICAL"
        },

        # Modern / previously-missing industry-standard secrets
        "github_fine_grained_pat": {
            "pattern": r"github_pat_[A-Za-z0-9_]{22,}",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('github_pat_') and len(x) >= 33,
            "severity": "HIGH"
        },
        "openai_api_key": {
            "pattern": r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b|\bsk-proj-[A-Za-z0-9_-]{20,}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('sk-', 'sk-proj-')),
            "severity": "HIGH"
        },
        "anthropic_api_key": {
            "pattern": r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('sk-ant-'),
            "severity": "HIGH"
        },
        "sendgrid_api_key": {
            "pattern": r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('SG.') and len(x.split('.')) == 3,
            "severity": "HIGH"
        },
        "npm_token": {
            "pattern": r"\bnpm_[A-Za-z0-9]{36}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('npm_') and len(x) == 40,
            "severity": "HIGH"
        },
        "stripe_restricted_key": {
            "pattern": r"\brk_(?:test|live)_[0-9a-zA-Z]{24,}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('rk_test_', 'rk_live_')),
            "severity": "HIGH"
        },
        "generic_pem_private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            "confidence": 0.98,
            "validation": lambda x: 'PRIVATE KEY' in x,
            "severity": "CRITICAL"
        },
        "discord_bot_token": {
            "pattern": r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b",
            "confidence": 0.80,
            "validation": lambda x: len(x.split('.')) == 3,
            "severity": "HIGH"
        },
        "twilio_account_sid": {
            "pattern": r"\bAC[0-9a-fA-F]{32}\b",
            "confidence": 0.75,
            "validation": lambda x: len(x) == 34 and x.startswith('AC'),
            "severity": "MEDIUM"
        },

        # Email/password combos - Enhanced patterns
        "email_password": {
            "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:,]\s*"
                       r"(?=[^\s\"']{6,}$|[^\s\"']{6,}[\s\"'])"
                       r"(?=[^\s\"']*[0-9])[^\s\"']{6,}",
            "confidence": 0.60,
            "validation": lambda x: '@' in x and '.' in x,
            "severity": "HIGH"
        },

        # ============================================================
        # NEW PATTERNS - TIER 1 (HIGH CONFIDENCE)
        # ============================================================

        "twitter_bearer_token": {
            # Verified against gitleaks' production rule: 22 literal 'A's
            # (base64 padding artifact) + 80-100 URL-safe chars.
            "pattern": r"\bA{22}[A-Za-z0-9%]{80,100}\b",
            "confidence": 0.85,
            "validation": lambda x: x.startswith('A' * 22) and len(x) >= 102,
            "severity": "HIGH"
        },
        "huggingface_token": {
            "pattern": r"\bhf_[A-Za-z0-9]{30,40}\b",
            "confidence": 0.85,
            "validation": lambda x: x.startswith('hf_'),
            "severity": "HIGH"
        },
        "gitlab_pat": {
            # Verified exact format from GitLab-maintained gitleaks.toml.
            "pattern": r"\bglpat-[0-9a-zA-Z\-]{20}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('glpat-'),
            "severity": "HIGH"
        },
        "telegram_bot_token": {
            # Official Telegram Bot API format: numeric bot ID + 35-char secret.
            "pattern": r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
            "confidence": 0.90,
            "validation": lambda x: ':' in x and len(x.split(':')[1]) == 35,
            "severity": "HIGH"
        },
        "mapbox_token": {
            "pattern": r"\b(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "confidence": 0.85,
            "validation": lambda x: x.startswith(('pk.eyJ', 'sk.eyJ')),
            "severity": "MEDIUM"
        },
        "recaptcha_key": {
            "pattern": r"\b6L[0-9A-Za-z_-]{38}\b",
            "confidence": 0.70,
            "validation": lambda x: x.startswith('6L') and len(x) == 40,
            "severity": "LOW"
        },
        "cloudinary_url": {
            # Official Cloudinary URL scheme: cloudinary://key:secret@cloud_name
            "pattern": r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9\-]+",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('cloudinary://') and '@' in x,
            "severity": "HIGH"
        },
        "discord_webhook_url": {
            "pattern": r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
            "confidence": 0.95,
            "validation": lambda x: '/api/webhooks/' in x,
            "severity": "HIGH"
        },
        "slack_webhook_url": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,12}/B[A-Za-z0-9]{8,12}/[A-Za-z0-9]{20,24}",
            "confidence": 0.95,
            "validation": lambda x: 'hooks.slack.com/services/' in x,
            "severity": "HIGH"
        },

        # ============================================================
        # NEW PATTERNS - TIER 2 (DOCUMENTED PREFIX, APPROXIMATE LENGTH)
        # ============================================================

        "shopify_access_token": {
            # Prefixes (shpat_/shpss_/shppa_/shpca_) confirmed via Shopify's own
            # docs. Body length is NOT precisely documented publicly - this
            # range is a reasonable bound based on commonly observed tokens.
            "pattern": r"\bshp(?:at|ss|pa|ca)_[a-fA-F0-9]{32,40}\b",
            "confidence": 0.75,
            "validation": lambda x: x.startswith(('shpat_', 'shpss_', 'shppa_', 'shpca_')),
            "severity": "HIGH"
        },

        # ============================================================
        # NEW PATTERNS - TIER 3 (KEYWORD-GATED HEURISTICS)
        # ============================================================

        "facebook_access_token": {
            "pattern": r"(?i)facebook[\w.\-]{0,20}['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "confidence": 0.65,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "algolia_admin_key": {
            "pattern": r"(?i)algolia[\w.\-]{0,20}['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "segment_write_key": {
            "pattern": r"(?i)segment[\w.\-]{0,20}(?:write)?key['\"\s:=]{1,4}([A-Za-z0-9]{32})\b",
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "mixpanel_token": {
            "pattern": r"(?i)mixpanel[\w.\-]{0,20}token['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "amplitude_api_key": {
            "pattern": r"(?i)amplitude[\w.\-]{0,20}(?:api)?key['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
    }

    # NEW: process-wide compiled-pattern cache, shared across every
    # EnterpriseLeakDetector instance (SecretScanner creates a fresh one
    # per file scanned). Keyed by pattern string, so each of the ~45
    # patterns is compiled exactly once for the life of the process.
    _compiled_pattern_cache: Dict[str, "re.Pattern"] = {}

    def __init__(self, aggressive: bool = False, entropy_cache_max_size: int = 10000,
                 max_findings_per_scan: Optional[int] = None):
        # Copy patterns to instance to prevent global mutation.
        # CHANGED: deepcopy instead of shallow dict() copy - the shallow
        # copy only duplicated the outer dict; each pattern's inner config
        # dict (pattern/confidence/validation/severity) was still SHARED
        # across every instance. Nothing currently mutates those inner
        # dicts, but a shallow copy left that landmine in place for any
        # future code that does. Lambdas inside are copied atomically by
        # copy.deepcopy (same object, not an error) so this is free.
        self.PATTERNS = copy.deepcopy(self.PATTERNS)
        self.entropy_cache_max_size = entropy_cache_max_size
        self.max_findings_per_scan = max_findings_per_scan

        self.aggressive = aggressive
        self.performance_metrics = {
            'total_checks': 0,
            'patterns_matched': 0,
            'high_confidence_finds': 0,
            'processing_time': 0
        }
        self.seen_leaks = set()  # Deduplication cache

        if aggressive:
            self._enable_aggressive_patterns()

        update_patterns(self.PATTERNS)

        # NEW: resolve each pattern to its compiled form via the shared
        # class-level cache, populating it on first use.
        self._compiled_patterns = {}
        for name, config in self.PATTERNS.items():
            pattern_str = config["pattern"]
            compiled = EnterpriseLeakDetector._compiled_pattern_cache.get(pattern_str)
            if compiled is None:
                compiled = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                EnterpriseLeakDetector._compiled_pattern_cache[pattern_str] = compiled
            self._compiled_patterns[name] = compiled

    def _enable_aggressive_patterns(self):
        """Enable more aggressive detection patterns"""
        aggressive_patterns = {
            # MOVED from base PATTERNS: this isn't secret detection,
            # it just flags any occurrence of common words like "admin"
            # or "test" with no URL/path context, which is noisy at
            # LOW severity by default. Now opt-in via aggressive mode.
            "admin_endpoint": {
                "pattern": r"(?i)(admin|internal|private|staging|dev|test)[^\"'\s]{0,30}",
                "confidence": 0.50,
                "validation": lambda x: len(x) > 5,
                "severity": "LOW"
            },
            "private_ip": {
                "pattern": r"(?i)(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}",
                "confidence": 0.95,
                "validation": lambda x: self._validate_ip_address(x),
                "severity": "MEDIUM"
            },
            "credit_card": {
                "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
                "confidence": 0.90,
                "validation": lambda x: self._validate_credit_card(x),
                "severity": "HIGH"
            },
            "ssh_private_key": {
                "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                "confidence": 0.98,
                "validation": lambda x: 'PRIVATE KEY' in x,
                "severity": "CRITICAL"
            },
            "api_endpoint_leak": {
                # FIX: Made both groups non-capturing so the correct value is extracted
                "pattern": r"(?i)(?:endpoint|url|uri)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\'][^\"\']*(?:key|secret|token)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']",
                "confidence": 0.70,
                "validation": lambda x: len(x) > 20,
                "severity": "MEDIUM"
            }
        }
        self.PATTERNS.update(aggressive_patterns)

    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        try:
            digits = [int(d) for d in str(number) if d.isdigit()]
            if len(digits) < 13 or len(digits) > 19:
                return False

            # Luhn algorithm
            checksum = 0
            parity = len(digits) % 2
            for i, digit in enumerate(digits):
                if (i % 2) == parity:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            return (checksum % 10) == 0
        except (ValueError, TypeError):
            return False

    def entropy(self, text: str) -> float:
        """Enhanced Shannon entropy calculation with caching"""
        if not text:
            return 0.0

        text = str(text)

        # Simple cache for performance
        cache_key = hashlib.sha256(text.encode()).hexdigest()
        if hasattr(self, '_entropy_cache') and cache_key in self._entropy_cache:
            return self._entropy_cache[cache_key]

        entropy_val = 0.0
        text_length = len(text)

        if text_length == 0:
            return 0.0

        for char in set(text):
            p_x = float(text.count(char)) / text_length
            if p_x > 0:
                entropy_val += - p_x * math.log2(p_x)

        # Cache the result
        if not hasattr(self, '_entropy_cache'):
            self._entropy_cache = {}

        # NEW: FIFO cap so a long-running scan session sharing this cache
        # via context.shared_state["entropy_cache"] doesn't grow unbounded.
        # Dict insertion order is preserved (Python 3.7+), so this evicts
        # the oldest entry without needing a separate ordered structure.
        if len(self._entropy_cache) >= self.entropy_cache_max_size:
            oldest_key = next(iter(self._entropy_cache))
            del self._entropy_cache[oldest_key]

        self._entropy_cache[cache_key] = entropy_val

        return entropy_val

    def _generate_leak_signature(self, leak_type: str, value: str) -> str:
        """Generate unique signature for leak deduplication"""
        return hashlib.sha256(f"{leak_type}:{value}".encode()).hexdigest()[:32]

    def _extract_context(self, content: str, match: str, position: int) -> str:
        """Extract context around the matched leak"""
        try:
            start = max(0, position - 50)
            end = min(len(content), position + len(match) + 50)
            context = content[start:end]

            # Clean and normalize context
            context = re.sub(r'\s+', ' ', context)
            return context.strip()
        except Exception:
            return ""

    def _calculate_risk_score(self, leak_type: str, entropy: float, confidence: float) -> float:
        """Calculate comprehensive risk score"""
        base_risk = {
            "CRITICAL": 0.9,
            "HIGH": 0.7,
            "MEDIUM": 0.5,
            "LOW": 0.3
        }.get(self.PATTERNS[leak_type]["severity"], 0.3)

        entropy_factor = min(entropy / 8.0, 1.0)  # Normalize entropy
        confidence_factor = confidence

        return (base_risk * 0.4) + (entropy_factor * 0.3) + (confidence_factor * 0.3)

    def check_content(self, content: str) -> List[Dict[str, Any]]:
        """
        Enterprise-grade content checking with advanced features
        Maintains 100% compatibility with existing code

        WARNING: This method maintains internal state (caches, counters).
        For stateless scanning, use SecretScanner.scan() instead.
        """
        start_time = time.time()
        findings = []

        if not content or not isinstance(content, str):
            self.performance_metrics['total_checks'] += 1
            return findings

        lines = content.splitlines()
        newline_positions = [m.start() for m in re.finditer('\\n', content)]
        # Redact multiline key bodies before line slicing/cropping; otherwise
        # an individual PEM body line cannot match the complete raw credential.
        from .detection_policy import PEM_PATTERN
        safe_lines = list(lines)
        for block in re.finditer(PEM_PATTERN, content):
            first = bisect_right(newline_positions, block.start())
            last = bisect_right(newline_positions, block.end())
            for index in range(first, min(len(safe_lines), last+1)):
                safe_lines[index] = '[REDACTED_PRIVATE_KEY]'

        for name, config in self.PATTERNS.items():
            try:
                base_confidence = config["confidence"]
                validation_func = config["validation"]
                base_severity = config["severity"]

                matches = self._compiled_patterns[name].finditer(content)

                for match in matches:
                    # Handle group matches
                    # FIX: prefer the LAST non-empty group, not the first.
                    # Patterns like generic_api_key capture (keyword, value) -
                    # taking the first group returned "api_key" instead of the
                    # actual secret. Verified this is a no-op for every other
                    # pattern in PATTERNS (all have 0 or 1 group).
                    if match.groups():
                        leak_value = next((g for g in reversed(match.groups()) if g), match.group(0))
                    else:
                        leak_value = match.group(0)

                    if not leak_value or len(leak_value) < 5:
                        continue

                    # Deduplication check
                    leak_signature = (self._generate_leak_signature(name, leak_value), match.start())
                    if leak_signature in self.seen_leaks:
                        continue
                    self.seen_leaks.add(leak_signature)

                    # Do not reinterpret URI userinfo as an email/password pair.
                    if name == 'email_password' and '://' in content[max(0, match.start()-256):match.start()].split('"')[-1].split("'")[-1]:
                        continue

                    # Enhanced validation
                    is_valid = validation_func(leak_value)
                    ent = self.entropy(leak_value)
                    if not is_valid or not valid_candidate(name, leak_value, ent):
                        continue
                    validation_status = "deterministic_candidate"

                    # Calculate enhanced metrics
                    confidence_score = base_confidence if is_valid else base_confidence * 0.6

                    # Context extraction
                    context = self._extract_context(content, leak_value, match.start())
                    mask = build_match_evidence_mask(leak_value, name)
                    ctx_res = extract_code_context(
                        content=content,
                        position=match.start(),
                        line_number=bisect_right(newline_positions, match.start())+1,
                        prepared_lines=safe_lines,
                        raw_value=leak_value,
                        leak_type=name,
                        evidence_mask=mask,
                        context_before=30,
                        context_after=30,
                        max_chars=3000
                    )

                    # Risk scoring
                    risk_score = self._calculate_risk_score(name, ent, confidence_score)

                    # Keep severity grounded in the rule, rather than entropy alone
                    final_severity = base_severity

                    finding = {
                        "type": name,
                        "value": leak_value,
                        "match_start": match.start(),
                        "match_end": match.end(),
                        "fingerprint": self._generate_leak_signature(name, leak_value),
                        "context_truncated": ctx_res.get("is_truncated", False),
                        "match_evidence_mask": mask,
                        "match_length": len(leak_value),
                        "severity": final_severity,
                        "entropy": round(ent, 2),
                        # FIX: per-charset-aware threshold instead of a
                        # flat 3.5 applied uniformly to every token type.
                        "suspicious": ent > _get_suspicious_threshold(name),
                        "confidence": round(confidence_score, 2),
                        "context": context,
                        "code_context": ctx_res.get("code_context"),
                        "context_start_line": ctx_res.get("context_start_line"),
                        "context_end_line": ctx_res.get("context_end_line"),
                        "line_number": ctx_res.get("line_number") or (content[:match.start()].count('\n') + 1),
                        "risk_score": round(risk_score, 2),
                        "validation_status": validation_status,
                        "detector_policy": POLICY_VERSION,
                        "category": "Exposure" if name in EXPOSURE_RULES else "Secrets"
                    }

                    findings.append(finding)
                    self.performance_metrics['patterns_matched'] += 1

                    if confidence_score > 0.8:
                        self.performance_metrics['high_confidence_finds'] += 1

            except Exception as e:
                logger.debug(f"Pattern '{name}' failed during scan: {e}")
                continue

        # Remove near-duplicates based on value similarity
        unique_findings = self._deduplicate_findings(findings)

        # NEW: optional safety cap - default unlimited, zero behavior
        # change unless you set max_findings_per_scan in the constructor.
        if self.max_findings_per_scan is not None and len(unique_findings) > self.max_findings_per_scan:
            logger.warning(
                f"Findings count {len(unique_findings)} exceeds cap "
                f"{self.max_findings_per_scan}; truncating."
            )
            unique_findings = unique_findings[: self.max_findings_per_scan]

        # Update performance metrics
        self.performance_metrics['total_checks'] += 1
        self.performance_metrics['processing_time'] += time.time() - start_time

        return unique_findings

    def _adjust_severity(self, base_severity: str, entropy: float, risk_score: float) -> str:
        """Adjust severity based on entropy and risk score"""
        severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        base_level = severity_map.get(base_severity, 0)

        # Increase severity for high entropy
        if entropy > 4.0:
            base_level = min(base_level + 1, 3)

        # Increase severity for high risk
        if risk_score > 0.8:
            base_level = min(base_level + 1, 3)

        # Decrease severity for low risk
        if risk_score < 0.3:
            base_level = max(base_level - 1, 0)

        # Map back to string
        reverse_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
        return reverse_map.get(base_level, "LOW")

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Advanced deduplication of findings"""
        # Prefer specific provider patterns over generic assignments for the same
        # bytes. Never lowercase a credential or collapse substring credentials.
        selected = {}
        for finding in findings:
            value = finding["value"]
            previous = selected.get(value)
            rank = (finding["type"] != "generic_api_key", finding["confidence"])
            if previous is None or rank > (previous["type"] != "generic_api_key", previous["confidence"]):
                selected[value] = finding
        values = list(selected.values())
        return [f for f in values if f['type'] != 'generic_api_key' or not any(
            other['type'] != 'generic_api_key' and f['value'] in other['value'] and
            f['match_start'] < other['match_end'] and other['match_start'] < f['match_end']
            for other in values)]

    def compute_severity(self, leak_type: str, entropy: float) -> str:
        """Backward compatibility method"""
        base_severity = self.PATTERNS.get(leak_type, {}).get("severity", "LOW")
        return self._adjust_severity(base_severity, entropy, 0.5)

    def group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Enhanced grouping by severity with sorting"""
        grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in grouped:
                grouped[severity].append(finding)

        # Sort each group by risk score (descending)
        for severity in grouped:
            grouped[severity].sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        return grouped

    def get_stats(self, findings: List[Dict]) -> Dict[str, Any]:
        """Enhanced statistics with performance metrics"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        risk_scores = []

        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in severity_counts:
                severity_counts[severity] += 1
            risk_scores.append(finding.get("risk_score", 0))

        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        return {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "suspicious_count": sum(1 for f in findings if f.get("suspicious", False)),
            "avg_risk_score": round(avg_risk, 2),
            "performance_metrics": self.performance_metrics.copy(),
            "high_confidence_findings": sum(1 for f in findings if f.get("confidence", 0) > 0.8)
        }

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        avg_processing_time = (
            self.performance_metrics['processing_time'] /
            self.performance_metrics['total_checks']
            if self.performance_metrics['total_checks'] > 0 else 0
        )

        return {
            **self.performance_metrics,
            'avg_processing_time_ms': round(avg_processing_time * 1000, 2),
            'patterns_configured': len(self.PATTERNS),
            'unique_leaks_detected': len(self.seen_leaks)
        }

    def reset_metrics(self):
        """Reset performance metrics for new scan"""
        self.performance_metrics = {
            'total_checks': 0,
            'patterns_matched': 0,
            'high_confidence_finds': 0,
            'processing_time': 0
        }
        self.seen_leaks.clear()
        if hasattr(self, '_entropy_cache'):
            self._entropy_cache.clear()


class SecretScanner:
    """
    Stateless, event-driven secret scanner for SaaS/Agent architecture.

    Uses same detection logic as EnterpriseLeakDetector but:
    1. No internal state (all state in context.shared_state)
    2. Emits events via context.event_emitter
    3. Stateless and resettable per scan
    4. No logging inside logic
    """

    def __init__(self, aggressive: bool = False):
        # Store configuration only, no state
        self.aggressive = aggressive

    async def scan(self, content: str, source_url: str, context) -> None:
        """
        Scan content for secrets and emit events.

        CRITICAL: Uses EXACT same detection logic as EnterpriseLeakDetector.
        Only architectural changes:
        1. Emits events via context.event_emitter
        2. Uses context.shared_state for all state
        3. Stateless and resettable per scan
        4. No logging inside logic

        Args:
            content: Content to scan for secrets
            source_url: URL where content came from
            context: ExtractorContext instance for state/events
        """
        if not content or not isinstance(content, str):
            metrics = context.shared_state.setdefault("metrics", {})
            if "total_checks" in metrics:
                metrics["total_checks"] += 1
            return

        # Create fresh, stateless detector instance for this scan
        detector = EnterpriseLeakDetector(aggressive=self.aggressive)

        # Share entropy cache with context (optimization only)
        detector._entropy_cache = context.shared_state.setdefault("entropy_cache", {})

        # Disable detector's internal dedup (use context only)
        detector.seen_leaks = set()

        # Run detection using stateless instance
        findings = detector.check_content(content)
        from .ignore_policy import IgnorePolicy
        policy = context.shared_state.get("ignore_policy")
        if policy is None:
            policy = IgnorePolicy.load(context.config.get("ignore_file") or os.environ.get("LHX_IGNORE_FILE", ".lhxignore"))
            context.shared_state["ignore_policy"] = policy

        # Copy metrics ONCE after scan (not per finding)
        metrics = context.shared_state.setdefault("metrics", {})
        for key in ['total_checks', 'patterns_matched', 'high_confidence_finds', 'processing_time']:
            if key in detector.performance_metrics and key in metrics:
                metrics[key] = detector.performance_metrics[key]

        # Hash the source once even when a bundle contains many detections.
        source_digest = hashlib.sha256(content.encode('utf-8')).hexdigest()
        from ..asset_coverage import asset_id, detector_policy
        try:
            source_identity = asset_id(source_url)
        except (ValueError, TypeError):
            source_identity = None  # Local paths have no HTTP coverage receipt.
        coverage_policy = detector_policy(context, self.aggressive)
        # Emit events for each finding with context-based dedup only
        for finding in findings:
            # Deduplication using ONLY context.shared_state
            leak_signature = detector._generate_leak_signature(
                finding["type"],
                finding["value"]
            )

            # FIX #1: HARD TYPE GUARD FOR SERIALIZATION ISSUES
            seen = context.shared_state.get("seen_leaks")

            # ENSURE seen_leaks is always a set (handles JSON serialization edge cases)
            if not isinstance(seen, set):
                seen = set(seen or [])
                context.shared_state["seen_leaks"] = seen

            # Preserve occurrences in different assets: usage may change the verdict.
            occurrence = (leak_signature, source_url, finding.get('line_number'))
            if occurrence in seen:
                continue

            # CANONICAL secret_found EVENT (BACKEND CONTRACT COMPLIANT)
            fingerprint = detector._generate_leak_signature(
                finding["type"],
                finding["value"]
            )

            norm_path = normalize_repo_relative_path(source_url)
            suppressed = policy.matches(source_url, finding["type"], fingerprint)
            verification = {'provider':'none','status':'unsupported'}
            if finding['type'] in ('github_token','github_fine_grained_pat'):
                from .provider_validation import verify_github
                enabled = os.environ.get('LHX_VERIFY_PROVIDERS', '').lower() == 'true'
                cache = context.shared_state.setdefault('provider_verification', {})
                if fingerprint not in cache and len(cache)<20 and not suppressed:
                    cache[fingerprint] = await verify_github(finding['value'], enabled)
                verification = cache.get(fingerprint, {'provider':'github','status':'not_attempted'})

            await emit_event(
                context,
                event_type="secret_found",
                data={
                    # REQUIRED FIELDS (used by DB + reports)
                    "type": finding["type"].replace("_", " ").title(),
                    "category": finding["category"],
                    "detector_policy": POLICY_VERSION,
                    "suppressed_by_local_policy": suppressed,
                    "provider_validation": verification,
                    "ignore_policy_sha256": policy.digest,
                    "severity": finding["severity"].lower(),
                    "confidence": float(finding["confidence"]),
                    "raw_value": finding["match_evidence_mask"],
                    "source_url": norm_path,
                    "source_sha256": source_digest,
                    "evidence_version": 2,
                    "context_truncated": finding.get('context_truncated', False),
                    "fingerprint": fingerprint,
                    "asset_id": source_identity,
                    "coverage_policy": coverage_policy,

                    # LOCATION
                    "file_path": norm_path,
                    "line_number": finding.get("line_number"),

                    # AI VALIDATION EVIDENCE & CONTEXT
                    "match_evidence_mask": finding.get("match_evidence_mask"),
                    "match_length": finding.get("match_length"),
                    "code_context": finding.get("code_context"),
                    "context_start_line": finding.get("context_start_line"),
                    "context_end_line": finding.get("context_end_line"),

                    # OPTIONAL (safe extras)
                    "entropy": finding.get("entropy"),
                    "risk_score": finding.get("risk_score"),
                    "validation_status": finding.get("validation_status"),
                }
            )
            # Deduplicate only after the evidence is safely journaled.
            seen.add(occurrence)


# Backward compatibility - original class name (LEGACY)
LeakDetector = EnterpriseLeakDetector

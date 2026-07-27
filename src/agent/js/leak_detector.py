"""
Enterprise-Grade Leak Detector with Advanced Pattern Recognition
Maintains 100% compatibility with existing code

LEGACY WARNING: EnterpriseLeakDetector is stateful and meant for backward compatibility.
For SaaS/event-driven use, use SecretScanner class instead.

DETECTION MODEL
---------------
Three complementary layers, in decreasing precision:

  1. VENDOR PATTERNS - unambiguous, self-identifying prefixes/structures
     (AKIA..., AIza..., ghp_..., sk-ant-..., xoxb-..., etc). These are
     reported with high confidence and are never filtered by value
     heuristics, because the prefix itself IS the proof.

  2. KEYWORD-GATED GENERIC PATTERNS - `apiKey: "..."`, `API_SECRET=...`,
     `"x-api-key": "..."`. Catches every vendor we have no prefix for.
     The captured value passes through _is_plausible_secret() to strip
     placeholders, URLs, filenames, mime types, CSS, template
     interpolations, version strings and dictionary words.

  3. HIGH-ENTROPY NEAR-KEYWORD (aggressive mode) - a long random-looking
     token that sits within a short window of a secret-ish keyword but
     didn't match a structural pattern. Deliberately context-gated:
     unrestricted entropy scanning over minified/webpack JS produces a
     false-positive flood (chunk hashes, SRI digests, inlined base64
     assets, mangled identifiers).

Each pattern declares which regex group holds the secret via "group"
(default 0 = whole match). The previous "take the last non-empty group"
heuristic silently broke multi-group patterns - e.g. stripe_key
`(sk|pk)_(test|live)_([0-9a-zA-Z]{24})` yielded only the 24-char body,
so its `startswith(('sk_','pk_'))` validator always failed and every
real Stripe key was downgraded to "suspicious".

Patterns are also no longer compiled with a blanket re.IGNORECASE.
Case-sensitive prefixes are load-bearing (AKIA, AIza, SG., ghp_, xoxb-);
folding case turned them into sloppy matchers. Patterns that genuinely
want case-insensitivity carry an inline (?i).
"""

import re
import math
import hashlib
import time
import copy
import logging
from typing import List, Dict, Any, Optional

# ------------------------------------------------------------
# PACKAGE-RELATIVE IMPORT (CRITICAL FIX)
# ------------------------------------------------------------

from ..utils.events import emit_event

logger = logging.getLogger(__name__)


# ------------------------------------------------------------
# PLACEHOLDER / DUMMY VALUE REJECTION
# Prevents obvious placeholder text ("YOUR_API_KEY_HERE", "xxxxxxxx",
# "00000000...") from being reported as real secrets. Used by the
# generic (keyword-gated) patterns' validation function.
# ------------------------------------------------------------
_PLACEHOLDER_VALUES = {
    'your_api_key', 'your-api-key', 'yourapikey', 'example', 'changeme',
    'change_me', 'placeholder', 'test123', 'sample_key', 'insert_key_here',
    'your_api_key_here', 'api_key_here', 'replace_me', 'todo', 'fixme',
    'none', 'null', 'nil', 'undefined', 'true', 'false', 'empty', 'unset',
    'default', 'dummy', 'fake', 'mock', 'invalid', 'unknown', 'n/a', 'na',
    'password', 'secret', 'apikey', 'api_key', 'token', 'xxx', 'test',
    'notasecret', 'not_a_secret', 'redacted', 'hidden', 'masked',
}

_PLACEHOLDER_SUBSTRINGS = (
    'your_api_key', 'your-api-key', 'yourapikey', 'xxxxxxxx',
    'placeholder', 'changeme', 'change_me', 'insert_key',
    'example_key', 'sample_key', 'api_key_here', 'replace_this',
    'your-token', 'your_token', 'yourtoken', 'dummy_key', 'fake_key',
    'test_key_', 'lorem', 'ipsum', 'foobar', 'deadbeef',
    '<your', 'enter_your', 'putyour', 'put_your', 'my_secret',
)


def _looks_like_placeholder(value: str) -> bool:
    """Return True if a matched value looks like dummy/placeholder text
    rather than a real credential."""
    v = value.lower().strip().strip('\'"`')

    if v in _PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r'x{8,}', v):
        return True
    if re.fullmatch(r'0{8,}', v):
        return True
    if re.fullmatch(r'1{8,}', v):
        return True
    if re.fullmatch(r'[a-z]{0,3}(1234567890|123456789)[a-z]{0,3}', v):
        return True
    if any(sub in v for sub in _PLACEHOLDER_SUBSTRINGS):
        return True
    # A single character repeated for the whole value ("aaaaaaaa...").
    if len(set(v)) <= 2 and len(v) >= 8:
        return True

    return False


# ------------------------------------------------------------
# GENERIC-VALUE PLAUSIBILITY GATE
#
# Applies ONLY to the keyword-gated generic patterns and the
# high-entropy scan. Vendor patterns (AKIA/AIza/ghp_/...) bypass this
# entirely - their prefix is stronger evidence than any heuristic.
#
# The goal is recall-first: reject only things that are provably NOT
# credentials (URLs, filenames, mime types, CSS, template placeholders,
# semver, plain prose), never "this doesn't look random enough".
# ------------------------------------------------------------

_FILE_EXTENSION_RE = re.compile(
    r'\.(?:js|jsx|mjs|cjs|ts|tsx|css|scss|sass|less|html?|json|xml|svg|'
    r'png|jpe?g|gif|webp|avif|ico|bmp|woff2?|ttf|otf|eot|map|md|txt|csv|'
    r'php|py|rb|go|java|c|cpp|sh|yml|yaml|toml|ini|lock|mp3|mp4|webm|'
    r'ogg|wav|pdf|zip|gz|tar)$',
    re.IGNORECASE,
)

_MIME_PREFIX_RE = re.compile(
    r'^(?:text|image|audio|video|font|application|multipart|message)/',
    re.IGNORECASE,
)

_SEMVER_RE = re.compile(r'^[v]?\d+\.\d+(\.\d+)*(-[A-Za-z0-9.]+)?$')

_DATE_LIKE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}.*)?$')

# Interpolation / templating markers - the value is computed at runtime,
# so whatever we captured is a template, not a credential.
_TEMPLATE_MARKERS = ('${', '{{', '<%', '%>', '#{', '{%', '$(')

_SRI_PREFIXES = ('sha256-', 'sha384-', 'sha512-')

# Words that show up constantly as the RHS of `token:` / `type:` /
# `secret:` in real front-end code and are never credentials.
_NON_SECRET_LITERALS = {
    'bearer', 'basic', 'digest', 'oauth', 'jwt', 'none', 'null', 'true',
    'false', 'undefined', 'function', 'object', 'string', 'number',
    'boolean', 'default', 'required', 'optional', 'enabled', 'disabled',
    'production', 'development', 'staging', 'localhost', 'anonymous',
    'authorization', 'content-type', 'application/json', 'utf-8', 'utf8',
    'get', 'post', 'put', 'delete', 'patch', 'head', 'options',
}


def _shannon(text: str) -> float:
    """Plain Shannon entropy in bits/char. Module-level so the value
    gate can use it without needing a detector instance."""
    if not text:
        return 0.0
    length = len(text)
    total = 0.0
    for char in set(text):
        p_x = text.count(char) / length
        if p_x > 0:
            total -= p_x * math.log2(p_x)
    return total


def _charset_classes(value: str) -> int:
    """How many of {lowercase, uppercase, digit, symbol} appear."""
    return sum((
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ))


def _is_plausible_secret(value: str, min_length: int = 8) -> bool:
    """
    Recall-first gate for generically-matched values.

    Returns False only for values that are structurally something other
    than a credential. Anything ambiguous is allowed through and lands
    at a lower confidence rather than being dropped.
    """
    if not value:
        return False

    v = value.strip().strip('\'"`')

    if len(v) < min_length or len(v) > 512:
        return False

    if _looks_like_placeholder(v):
        return False

    lowered = v.lower()

    if lowered in _NON_SECRET_LITERALS:
        return False

    # Runtime-interpolated template, not a literal secret.
    if any(marker in v for marker in _TEMPLATE_MARKERS):
        return False

    # Subresource-integrity digests.
    if lowered.startswith(_SRI_PREFIXES):
        return False

    # URLs, protocol-relative URLs, absolute/relative paths.
    if re.match(r'^[a-z][a-z0-9+.\-]{1,20}://', lowered):
        return False
    if v.startswith(('/', './', '../', '//', '\\', '~')):
        return False
    if v.startswith('data:') or v.startswith('#'):
        return False

    # Filenames and mime types.
    if _FILE_EXTENSION_RE.search(v):
        return False
    if _MIME_PREFIX_RE.match(v):
        return False

    # Version strings and timestamps.
    if _SEMVER_RE.match(v):
        return False
    if _DATE_LIKE_RE.match(v):
        return False

    # Short all-digit values are ids/ports/timestamps, not keys. Long
    # ones can be genuine (some vendors issue numeric keys), so they stay
    # - the sequential/repeated-digit placeholder check above already
    # removes the obvious dummies like "12345678901234567890".
    if v.isdigit() and len(v) < 16:
        return False

    # Whitespace inside a quoted value means prose, not a token.
    if any(c.isspace() for c in v):
        return False

    # An all-letter value with no digits and no separators, short enough
    # to be an identifier or an English word, is almost certainly not a
    # key. Long all-letter strings (>= 32) stay - some vendors issue them.
    if v.isalpha() and len(v) < 32:
        return False

    # snake_case / kebab-case / dotted identifiers with no digits read as
    # config keys ("content_type", "user.profile.name"), not secrets.
    if re.fullmatch(r'[A-Za-z]+([._\-][A-Za-z]+)+', v):
        return False

    # Near-zero entropy ("abababab", "aaaa1111") is never a real key.
    if _shannon(v) < 1.8:
        return False

    return True


# ------------------------------------------------------------
# GENERIC SECRET KEYWORDS
#
# Drives the keyword-gated patterns. Ordered longest-first inside each
# alternation so `secret_access_key` wins over `secret` and we capture
# the full keyword rather than a prefix of it.
# ------------------------------------------------------------
_STRONG_KEYWORD = (
    r"(?:"
    r"secret[_\-]?access[_\-]?key|aws[_\-]?secret[_\-]?access[_\-]?key|"
    r"x[_\-]?api[_\-]?key|api[_\-]?key|apikey|api[_\-]?secret|apisecret|"
    r"api[_\-]?token|apitoken|access[_\-]?key[_\-]?id|access[_\-]?key|"
    r"accesskey|access[_\-]?token|accesstoken|auth[_\-]?token|authtoken|"
    r"auth[_\-]?key|app[_\-]?secret|appsecret|app[_\-]?key|appkey|"
    r"application[_\-]?key|client[_\-]?secret|clientsecret|"
    r"consumer[_\-]?secret|consumer[_\-]?key|secret[_\-]?key|secretkey|"
    r"private[_\-]?key|privatekey|encryption[_\-]?key|signing[_\-]?key|"
    r"master[_\-]?key|session[_\-]?key|refresh[_\-]?token|"
    r"bearer[_\-]?token|id[_\-]?token|service[_\-]?key|"
    r"subscription[_\-]?key|account[_\-]?key|shared[_\-]?key|"
    r"secret[_\-]?token|security[_\-]?token|sas[_\-]?token"
    r")"
)

# Weaker keywords: real signal, but far more likely to be a benign field
# name too ("token" in a parser, "password" in a form label). Reported at
# lower confidence.
_WEAK_KEYWORD = (
    r"(?:token|secret|password|passwd|pwd|credential|credentials|"
    r"authorization|auth|passphrase|client[_\-]?id)"
)

# Separator between keyword and value: `:`, `=`, `=>`, `:=`, optionally
# with the keyword itself quoted (JSON / header-object style).
_ASSIGN = r"""["'`]?\s*(?::|=>|:=|=)\s*"""


# ------------------------------------------------------------
# PER-CHARSET ENTROPY THRESHOLDS FOR "SUSPICIOUS" FLAGGING
#
# One flat threshold (entropy > 3.5) is not meaningful across charsets:
# a random 32-char HEX string averages ~3.6-3.7 bits/char (max 4.0),
# while random base64 of similar length averages ~4.8-4.9 (max 6.0). A
# single cutoff either over-flags low-charset tokens or under-flags
# high-charset ones, when both are equally random for their alphabet.
#
# NOTE: entropy is informational metadata only - it feeds the
# "suspicious" flag and risk score, and is NOT an accept/reject gate.
# The per-pattern "validation" lambda remains the accept/reject gate.
# ------------------------------------------------------------
_CHARSET_SUSPICIOUS_THRESHOLDS = {
    'hex': 2.8,            # theoretical max 4.0 (log2(16))
    'base64': 3.8,         # theoretical max 6.0 (log2(64))
    'alphanumeric': 3.2,   # theoretical max ~5.95 (log2(62))
    'mixed': 3.5,          # DEFAULT
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
    'twitter_bearer_token': 'base64',
    'huggingface_token': 'alphanumeric',
    'gitlab_pat': 'alphanumeric',
    'telegram_bot_token': 'mixed',
    'mapbox_token': 'base64',
    'recaptcha_key': 'alphanumeric',
    'cloudinary_url': 'mixed',
    'discord_webhook_url': 'mixed',
    'slack_webhook_url': 'mixed',
    'shopify_access_token': 'hex',
    'facebook_access_token': 'hex',
    'algolia_admin_key': 'hex',
    'segment_write_key': 'alphanumeric',
    'mixpanel_token': 'hex',
    'amplitude_api_key': 'hex',
    'generic_api_key': 'mixed',
    'generic_secret_assignment': 'mixed',
    'high_entropy_secret': 'base64',
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

    Pattern config keys:
        pattern     - regex source
        group       - which group holds the secret (0 = whole match)
        confidence  - base confidence when validation passes
        validation  - callable(value) -> bool
        severity    - CRITICAL | HIGH | MEDIUM | LOW
        generic     - True if the match relies on a keyword rather than a
                      self-identifying prefix; these additionally pass
                      through _is_plausible_secret()
    """

    PATTERNS = {
        # ============================================================
        # CLOUD PROVIDERS
        # ============================================================
        "aws_access_key": {
            "pattern": r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
            "confidence": 0.95,
            "validation": lambda x: len(x) == 20,
            "severity": "HIGH"
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws[^'\"\n]{0,20}?['\"\s:=]([A-Za-z0-9/+=]{40})",
            "group": 1,
            "confidence": 0.85,
            "validation": lambda x: len(x) == 40,
            "severity": "CRITICAL"
        },
        "google_api_key": {
            "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "confidence": 0.90,
            "validation": lambda x: len(x) == 39 and x.startswith('AIza'),
            "severity": "HIGH"
        },
        "google_oauth_token": {
            "pattern": r"\bya29\.[0-9A-Za-z\-_]{8,}",
            "confidence": 0.85,
            "validation": lambda x: x.startswith('ya29.'),
            "severity": "HIGH"
        },
        "google_oauth_client_secret": {
            "pattern": r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('GOCSPX-'),
            "severity": "HIGH"
        },
        "gcp_service_account_key": {
            "pattern": r"\"type\"\s*:\s*\"service_account\"",
            "confidence": 0.90,
            "validation": lambda x: 'service_account' in x,
            "severity": "CRITICAL"
        },
        "firebase_cloud_messaging_key": {
            "pattern": r"\bAAAA[A-Za-z0-9_\-]{7,}:APA91b[A-Za-z0-9_\-]{130,}\b",
            "confidence": 0.90,
            "validation": lambda x: ':APA91b' in x,
            "severity": "HIGH"
        },
        "azure_storage_connection_string": {
            "pattern": r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{20,};?",
            "confidence": 0.90,
            "validation": lambda x: 'AccountKey=' in x,
            "severity": "CRITICAL"
        },

        # ============================================================
        # SOURCE CONTROL / PACKAGE REGISTRIES
        # ============================================================
        "github_token": {
            "pattern": r"\bgh[pousr]_[A-Za-z0-9_]{36}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith(('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')),
            "severity": "HIGH"
        },
        "github_fine_grained_pat": {
            "pattern": r"\bgithub_pat_[A-Za-z0-9_]{22,}",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('github_pat_') and len(x) >= 33,
            "severity": "HIGH"
        },
        "gitlab_pat": {
            "pattern": r"\bglpat-[0-9A-Za-z\-_]{20,}",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('glpat-'),
            "severity": "HIGH"
        },
        "npm_token": {
            "pattern": r"\bnpm_[A-Za-z0-9]{36}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('npm_') and len(x) == 40,
            "severity": "HIGH"
        },
        "pypi_upload_token": {
            "pattern": r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}",
            "confidence": 0.95,
            "validation": lambda x: x.startswith('pypi-'),
            "severity": "HIGH"
        },
        "atlassian_api_token": {
            "pattern": r"\bATATT3[A-Za-z0-9_\-=]{100,}",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('ATATT3'),
            "severity": "HIGH"
        },

        # ============================================================
        # AI / LLM PROVIDERS
        # ============================================================
        "openai_api_key": {
            "pattern": r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"
                       r"|\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('sk-'),
            "severity": "HIGH"
        },
        "anthropic_api_key": {
            "pattern": r"\bsk-ant-(?:api\d{2}|admin\d{2})-[A-Za-z0-9_\-]{20,}",
            "confidence": 0.95,
            "validation": lambda x: x.startswith('sk-ant-'),
            "severity": "HIGH"
        },
        "huggingface_token": {
            "pattern": r"\bhf_[A-Za-z0-9]{30,40}\b",
            "confidence": 0.88,
            "validation": lambda x: x.startswith('hf_'),
            "severity": "HIGH"
        },
        "groq_api_key": {
            "pattern": r"\bgsk_[A-Za-z0-9]{40,}",
            "confidence": 0.88,
            "validation": lambda x: x.startswith('gsk_'),
            "severity": "HIGH"
        },
        "cohere_api_key": {
            "pattern": r"(?i)cohere[\w.\-]{0,20}['\"\s:=]{1,4}([A-Za-z0-9]{40})\b",
            "group": 1,
            "confidence": 0.65,
            "validation": lambda x: len(x) == 40,
            "severity": "MEDIUM"
        },

        # ============================================================
        # PAYMENTS
        # ============================================================
        "stripe_key": {
            # Body length is 10-99 (matches gitleaks' production rule).
            # The previous {24,} floor missed Stripe's shorter legacy and
            # test keys entirely.
            "pattern": r"\b[sp]k_(?:test|live)_[0-9a-zA-Z]{10,99}",
            "confidence": 0.95,
            "validation": lambda x: x.startswith(('sk_', 'pk_')),
            "severity": "HIGH"
        },
        "stripe_restricted_key": {
            "pattern": r"\brk_(?:test|live)_[0-9a-zA-Z]{10,99}",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('rk_test_', 'rk_live_')),
            "severity": "HIGH"
        },
        "square_access_token": {
            "pattern": r"\b(?:sq0atp|sq0csp)-[0-9A-Za-z_\-]{22,43}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('sq0atp-', 'sq0csp-')),
            "severity": "HIGH"
        },
        "paypal_braintree_token": {
            "pattern": r"\baccess_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
            "confidence": 0.95,
            "validation": lambda x: x.startswith('access_token$'),
            "severity": "HIGH"
        },
        "razorpay_key": {
            "pattern": r"\brzp_(?:test|live)_[A-Za-z0-9]{14,}",
            "confidence": 0.85,
            "validation": lambda x: x.startswith('rzp_'),
            "severity": "MEDIUM"
        },
        "flutterwave_secret_key": {
            "pattern": r"\bFLWSECK[_\-][A-Za-z0-9]{12,}",
            "confidence": 0.90,
            "validation": lambda x: x.upper().startswith('FLWSECK'),
            "severity": "HIGH"
        },

        # ============================================================
        # COMMUNICATION / MESSAGING
        # ============================================================
        "slack_token": {
            "pattern": r"xox[baprse]-(?:\d{10,13}-\d{10,13}-[a-zA-Z0-9]{24,32}|[0-9a-zA-Z\-]{20,48})",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-', 'xoxe-')),
            "severity": "HIGH"
        },
        "slack_app_token": {
            "pattern": r"\bxapp-\d-[A-Za-z0-9]+-\d+-[a-f0-9]{64}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('xapp-'),
            "severity": "HIGH"
        },
        "slack_webhook_url": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,12}/B[A-Za-z0-9]{8,12}/[A-Za-z0-9]{20,24}",
            "confidence": 0.95,
            "validation": lambda x: 'hooks.slack.com/services/' in x,
            "severity": "HIGH"
        },
        "discord_bot_token": {
            "pattern": r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b",
            "confidence": 0.80,
            "validation": lambda x: len(x.split('.')) == 3,
            "severity": "HIGH"
        },
        "discord_webhook_url": {
            "pattern": r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
            "confidence": 0.95,
            "validation": lambda x: '/api/webhooks/' in x,
            "severity": "HIGH"
        },
        "telegram_bot_token": {
            "pattern": r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
            "confidence": 0.90,
            "validation": lambda x: ':' in x and len(x.split(':')[1]) == 35,
            "severity": "HIGH"
        },
        "twilio_key": {
            "pattern": r"\bSK[0-9a-fA-F]{32}\b",
            "confidence": 0.88,
            "validation": lambda x: len(x) == 34 and x.startswith('SK'),
            "severity": "HIGH"
        },
        "twilio_account_sid": {
            "pattern": r"\bAC[0-9a-fA-F]{32}\b",
            "confidence": 0.75,
            "validation": lambda x: len(x) == 34 and x.startswith('AC'),
            "severity": "MEDIUM"
        },
        "sendgrid_api_key": {
            "pattern": r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            "confidence": 0.95,
            "validation": lambda x: x.startswith('SG.') and len(x.split('.')) == 3,
            "severity": "HIGH"
        },
        "mailgun_key": {
            "pattern": r"\bkey-[0-9a-zA-Z]{32}\b",
            "confidence": 0.85,
            "validation": lambda x: len(x) == 36 and x.startswith('key-'),
            "severity": "HIGH"
        },
        "mailchimp_api_key": {
            "pattern": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
            "confidence": 0.90,
            "validation": lambda x: '-us' in x,
            "severity": "HIGH"
        },
        "postmark_server_token": {
            "pattern": r"(?i)postmark[\w.\-]{0,20}['\"\s:=]{1,4}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
            "group": 1,
            "confidence": 0.70,
            "validation": lambda x: len(x) == 36,
            "severity": "MEDIUM"
        },
        "twitter_bearer_token": {
            "pattern": r"\bA{22}[A-Za-z0-9%]{80,100}\b",
            "confidence": 0.85,
            "validation": lambda x: x.startswith('A' * 22),
            "severity": "HIGH"
        },

        # ============================================================
        # SAAS / PLATFORM
        # ============================================================
        "shopify_access_token": {
            "pattern": r"\bshp(?:at|ss|pa|ca)_[a-fA-F0-9]{32}\b",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('shpat_', 'shpss_', 'shppa_', 'shpca_')),
            "severity": "HIGH"
        },
        "linear_api_key": {
            "pattern": r"\blin_api_[A-Za-z0-9]{40,}",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('lin_api_'),
            "severity": "HIGH"
        },
        "notion_integration_token": {
            "pattern": r"\b(?:secret_|ntn_)[A-Za-z0-9]{40,}",
            "confidence": 0.85,
            "validation": lambda x: x.startswith(('secret_', 'ntn_')),
            "severity": "HIGH"
        },
        "postman_api_key": {
            "pattern": r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
            "confidence": 0.95,
            "validation": lambda x: x.startswith('PMAK-'),
            "severity": "HIGH"
        },
        "newrelic_api_key": {
            "pattern": r"\bNRAK-[A-Z0-9]{27}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('NRAK-'),
            "severity": "HIGH"
        },
        "planetscale_token": {
            "pattern": r"\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_\-\.]{32,}",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('pscale_'),
            "severity": "HIGH"
        },
        "supabase_service_key": {
            "pattern": r"\bsbp_[a-f0-9]{40}\b",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('sbp_'),
            "severity": "HIGH"
        },
        "doppler_token": {
            "pattern": r"\bdp\.(?:pt|st|ct|sa|scim)\.[A-Za-z0-9]{40,}",
            "confidence": 0.92,
            "validation": lambda x: x.startswith('dp.'),
            "severity": "HIGH"
        },
        "sentry_dsn": {
            "pattern": r"https://[a-f0-9]{32}(?::[a-f0-9]{32})?@[a-z0-9.\-]*sentry\.io/\d+",
            "confidence": 0.85,
            "validation": lambda x: 'sentry.io/' in x,
            "severity": "MEDIUM"
        },
        "cloudinary_url": {
            "pattern": r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9\-]+",
            "confidence": 0.90,
            "validation": lambda x: x.startswith('cloudinary://') and '@' in x,
            "severity": "HIGH"
        },
        "mapbox_token": {
            "pattern": r"\b(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
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
        "airtable_api_key": {
            "pattern": r"\b(?:key[A-Za-z0-9]{14}|pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b",
            "confidence": 0.80,
            "validation": lambda x: x.startswith(('key', 'pat')),
            "severity": "HIGH"
        },
        "algolia_admin_key": {
            "pattern": r"(?i)algolia[\w.\-]{0,20}['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "group": 1,
            "confidence": 0.65,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "facebook_access_token": {
            # Scoped inline flag (?i:...) rather than a global (?i) - a
            # global flag is only legal at position 0, so putting it on
            # the second alternation branch made the whole pattern fail
            # to compile and silently disabled this rule.
            "pattern": r"\bEAA[A-Za-z0-9]{90,}"
                       r"|(?i:facebook[\w.\-]{0,20}['\"\s:=]{1,4})([a-f0-9]{32})\b",
            "group": "auto",
            "confidence": 0.70,
            "validation": lambda x: len(x) == 32 or x.startswith('EAA'),
            "severity": "MEDIUM"
        },
        "segment_write_key": {
            "pattern": r"(?i)segment[\w.\-]{0,20}(?:write)?key['\"\s:=]{1,4}([A-Za-z0-9]{32})\b",
            "group": 1,
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "mixpanel_token": {
            "pattern": r"(?i)mixpanel[\w.\-]{0,20}token['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "group": 1,
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "amplitude_api_key": {
            "pattern": r"(?i)amplitude[\w.\-]{0,20}(?:api)?key['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "group": 1,
            "confidence": 0.60,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },
        "datadog_api_key": {
            "pattern": r"(?i)datadog[\w.\-]{0,20}(?:api)?key['\"\s:=]{1,4}([a-f0-9]{32})\b",
            "group": 1,
            "confidence": 0.65,
            "validation": lambda x: len(x) == 32,
            "severity": "MEDIUM"
        },

        # ============================================================
        # AUTHENTICATION PRIMITIVES
        # ============================================================
        "jwt_token": {
            "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]*",
            "confidence": 0.80,
            "validation": lambda x: len(x.split('.')) == 3,
            "severity": "MEDIUM"
        },
        "bearer_token": {
            "pattern": r"(?i)\bbearer\s+([A-Za-z0-9\-_.=+/]{20,})",
            "group": 1,
            "confidence": 0.75,
            "validation": lambda x: len(x) >= 20 and not _looks_like_placeholder(x),
            "severity": "MEDIUM"
        },
        "basic_auth": {
            "pattern": r"(?i)\bbasic\s+([A-Za-z0-9+/=]{20,})",
            "group": 1,
            "confidence": 0.70,
            "validation": lambda x: len(x) >= 20 and not _looks_like_placeholder(x),
            "severity": "MEDIUM"
        },
        "generic_pem_private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
            "confidence": 0.98,
            "validation": lambda x: 'PRIVATE KEY' in x,
            "severity": "CRITICAL"
        },

        # ============================================================
        # DATABASE / CONNECTION STRINGS
        # ============================================================
        "mongodb_uri": {
            "pattern": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
            "confidence": 0.85,
            "validation": lambda x: 'mongodb' in x,
            "severity": "HIGH"
        },
        "mysql_connection": {
            "pattern": r"mysql://[^\s\"'<>]+",
            "confidence": 0.85,
            "validation": lambda x: 'mysql://' in x,
            "severity": "HIGH"
        },
        "postgres_connection": {
            "pattern": r"postgres(?:ql)?://[^\s\"'<>]+",
            "confidence": 0.85,
            "validation": lambda x: 'postgres' in x,
            "severity": "HIGH"
        },
        "redis_connection": {
            "pattern": r"redis(?:s)?://[^\s\"'<>]+",
            "confidence": 0.85,
            "validation": lambda x: 'redis' in x,
            "severity": "HIGH"
        },
        "amqp_connection": {
            "pattern": r"amqps?://[^\s\"'<>:]+:[^\s\"'<>@]+@[^\s\"'<>]+",
            "confidence": 0.85,
            "validation": lambda x: '@' in x,
            "severity": "HIGH"
        },

        # ============================================================
        # CLOUD STORAGE (informational, not credentials)
        # ============================================================
        "s3_bucket": {
            "pattern": r"s3://[a-z0-9\-\.]+",
            "confidence": 0.75,
            "validation": lambda x: x.startswith('s3://'),
            "severity": "LOW"
        },
        "s3_url": {
            "pattern": r"https?://[a-z0-9\-\.]+\.s3\.(?:[a-z0-9\-\.]+)?amazonaws\.com",
            "confidence": 0.80,
            "validation": lambda x: '.s3.' in x and 'amazonaws.com' in x,
            "severity": "LOW"
        },
        "google_storage": {
            "pattern": r"gs://[a-z0-9\-\.]+",
            "confidence": 0.75,
            "validation": lambda x: x.startswith('gs://'),
            "severity": "LOW"
        },
        "azure_storage": {
            "pattern": r"https?://[a-z0-9]+\.blob\.core\.windows\.net",
            "confidence": 0.80,
            "validation": lambda x: '.blob.core.windows.net' in x,
            "severity": "LOW"
        },

        # ============================================================
        # GENERIC KEYWORD-GATED PATTERNS
        #
        # These are what catch the long tail: any vendor we have no
        # prefix rule for, plus the target's own internal keys. Matches
        # here go through _is_plausible_secret() on top of the lambda.
        # ============================================================
        "generic_api_key": {
            # `apiKey: "..."`, `"x-api-key": "..."`, `API_SECRET = '...'`
            "pattern": r"(?i)(?<![A-Za-z0-9_])" + _STRONG_KEYWORD + _ASSIGN +
                       r"""["'`]([^"'`\s]{8,200})["'`]""",
            "group": 1,
            "generic": True,
            "confidence": 0.75,
            "validation": lambda x: _is_plausible_secret(x, min_length=8),
            "severity": "HIGH"
        },
        "generic_api_key_unquoted": {
            # env-file / query-string style: `API_KEY=abc123`, `?api_key=abc`
            "pattern": r"(?i)(?<![A-Za-z0-9_])" + _STRONG_KEYWORD +
                       r"\s*[:=]\s*([A-Za-z0-9+/=_\-\.]{16,200})(?![A-Za-z0-9+/=_\-\.])",
            "group": 1,
            "generic": True,
            "confidence": 0.65,
            "validation": lambda x: _is_plausible_secret(x, min_length=16),
            "severity": "MEDIUM"
        },
        "generic_secret_assignment": {
            # Weaker keywords (token/secret/password). Lower confidence,
            # longer minimum value to compensate for the weaker gate.
            "pattern": r"(?i)(?<![A-Za-z0-9_])" + _WEAK_KEYWORD + _ASSIGN +
                       r"""["'`]([^"'`\s]{12,200})["'`]""",
            "group": 1,
            "generic": True,
            "confidence": 0.55,
            "validation": lambda x: _is_plausible_secret(x, min_length=12),
            "severity": "MEDIUM"
        },

        # ============================================================
        # CREDENTIAL PAIRS
        # ============================================================
        "email_password": {
            "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:,]\s*"
                       r"(?=[^\s\"']{6,}$|[^\s\"']{6,}[\s\"'])"
                       r"(?=[^\s\"']*[0-9])[^\s\"']{6,}",
            "confidence": 0.60,
            "validation": lambda x: '@' in x and '.' in x,
            "severity": "HIGH"
        },
    }

    # Process-wide compiled-pattern cache, shared across every
    # EnterpriseLeakDetector instance (SecretScanner creates a fresh one
    # per file scanned). Keyed by pattern string, so each pattern is
    # compiled exactly once for the life of the process.
    _compiled_pattern_cache: Dict[str, "re.Pattern"] = {}

    # Window (chars either side) searched for a secret-ish keyword when
    # deciding whether a high-entropy token is worth reporting.
    _ENTROPY_CONTEXT_WINDOW = 90

    _ENTROPY_CONTEXT_KEYWORDS = (
        'key', 'secret', 'token', 'password', 'passwd', 'pwd', 'auth',
        'credential', 'apikey', 'access', 'private', 'signature', 'sign',
        'bearer', 'session', 'cert', 'salt', 'hash', 'jwt', 'oauth',
    )

    def __init__(self, aggressive: bool = False, entropy_cache_max_size: int = 10000,
                 max_findings_per_scan: Optional[int] = None):
        # Copy patterns to instance to prevent global mutation. deepcopy
        # (not a shallow dict copy) so each pattern's inner config dict is
        # per-instance too. Lambdas are copied atomically by deepcopy.
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

        # Resolve each pattern to its compiled form via the shared
        # class-level cache, populating it on first use.
        #
        # NOTE: no blanket re.IGNORECASE - case-sensitive prefixes
        # (AKIA/AIza/SG./ghp_) are load-bearing. Patterns that want
        # case-insensitivity carry an inline (?i).
        self._compiled_patterns = {}
        for name, config in self.PATTERNS.items():
            pattern_str = config["pattern"]
            compiled = EnterpriseLeakDetector._compiled_pattern_cache.get(pattern_str)
            if compiled is None:
                try:
                    compiled = re.compile(pattern_str, re.MULTILINE)
                except re.error as e:
                    logger.error(f"Pattern '{name}' failed to compile, skipping: {e}")
                    continue
                EnterpriseLeakDetector._compiled_pattern_cache[pattern_str] = compiled
            self._compiled_patterns[name] = compiled

    def _enable_aggressive_patterns(self):
        """
        Enable higher-recall detection.

        The old `admin_endpoint` rule was removed: it matched any
        occurrence of "admin"/"test"/"dev" with no URL or credential
        context, which is not secret detection at all and flooded every
        scan with LOW-severity noise (aggressive mode is on by default
        in config, so this shipped to every user).
        """
        aggressive_patterns = {
            "private_ip": {
                "pattern": r"(?i)\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}\b",
                "confidence": 0.90,
                "validation": lambda x: self._validate_ip_address(x),
                "severity": "LOW"
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

        cache_key = hashlib.sha256(text.encode()).hexdigest()
        if hasattr(self, '_entropy_cache') and cache_key in self._entropy_cache:
            return self._entropy_cache[cache_key]

        entropy_val = _shannon(text)

        if not hasattr(self, '_entropy_cache'):
            self._entropy_cache = {}

        # FIFO cap so a long-running scan session sharing this cache via
        # context.shared_state["entropy_cache"] doesn't grow unbounded.
        # Dict insertion order is preserved (3.7+), so this evicts the
        # oldest entry without a separate ordered structure.
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
        }.get(self.PATTERNS.get(leak_type, {}).get("severity", "LOW"), 0.3)

        entropy_factor = min(entropy / 8.0, 1.0)
        confidence_factor = confidence

        return (base_risk * 0.4) + (entropy_factor * 0.3) + (confidence_factor * 0.3)

    def _extract_match_value(self, match, config: Dict[str, Any]) -> str:
        """
        Pull the secret out of a match according to the pattern's declared
        "group".

        0            -> whole match (default)
        int          -> that group, falling back to the whole match
        "auto"       -> last non-empty group (for patterns that alternate
                        between a prefix branch and a keyword branch)
        """
        group_spec = config.get("group", 0)

        if group_spec == "auto":
            groups = match.groups()
            if groups:
                for g in reversed(groups):
                    if g:
                        return g
            return match.group(0)

        if isinstance(group_spec, int) and group_spec > 0:
            try:
                value = match.group(group_spec)
                if value:
                    return value
            except (IndexError, re.error):
                pass
            return match.group(0)

        return match.group(0)

    def _scan_high_entropy(self, content: str) -> List[Dict[str, Any]]:
        """
        Aggressive-mode layer 3: long random-looking tokens that sit near
        a secret-ish keyword but matched no structural pattern.

        Context-gating is deliberate. Unrestricted entropy scanning over
        minified/webpack bundles yields overwhelming false positives -
        chunk hashes, SRI digests, inlined base64 assets and mangled
        identifiers are all high-entropy and none are credentials.
        """
        findings = []
        candidate_re = re.compile(r"""["'`]([A-Za-z0-9+/=_\-]{24,120})["'`]""")

        for match in candidate_re.finditer(content):
            value = match.group(1)

            if not _is_plausible_secret(value, min_length=24):
                continue

            # Needs real randomness AND a mixed alphabet. Pure-hex build
            # hashes (a common FP) fail the class check below.
            ent = self.entropy(value)
            if ent < 3.4 or _charset_classes(value) < 2:
                continue

            # All-hex of a common digest length is almost always a build
            # artifact / etag / SRI, not a key.
            if re.fullmatch(r'[a-f0-9]+', value.lower()) and len(value) in (32, 40, 64, 128):
                continue

            window_start = max(0, match.start() - self._ENTROPY_CONTEXT_WINDOW)
            window_end = min(len(content), match.end() + self._ENTROPY_CONTEXT_WINDOW)
            window = content[window_start:window_end].lower()

            if not any(kw in window for kw in self._ENTROPY_CONTEXT_KEYWORDS):
                continue

            findings.append({
                "name": "high_entropy_secret",
                "value": value,
                "start": match.start(1),
                "entropy": ent,
            })

        return findings

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

        for name, config in self.PATTERNS.items():
            compiled = self._compiled_patterns.get(name)
            if compiled is None:
                continue

            try:
                base_confidence = config["confidence"]
                validation_func = config["validation"]
                base_severity = config["severity"]
                is_generic = config.get("generic", False)

                for match in compiled.finditer(content):
                    leak_value = self._extract_match_value(match, config)

                    if not leak_value or len(leak_value) < 5:
                        continue

                    # Generic (keyword-gated) matches must additionally
                    # survive the value-plausibility gate. Vendor patterns
                    # skip it - their prefix is stronger evidence.
                    if is_generic and not _is_plausible_secret(leak_value):
                        continue

                    leak_signature = self._generate_leak_signature(name, leak_value)
                    if leak_signature in self.seen_leaks:
                        continue
                    self.seen_leaks.add(leak_signature)

                    is_valid = bool(validation_func(leak_value))
                    validation_status = "validated" if is_valid else "suspicious"

                    ent = self.entropy(leak_value)
                    confidence_score = base_confidence if is_valid else base_confidence * 0.6

                    context = self._extract_context(content, leak_value, match.start())
                    risk_score = self._calculate_risk_score(name, ent, confidence_score)
                    final_severity = self._adjust_severity(base_severity, ent, risk_score)

                    findings.append({
                        "type": name,
                        "value": leak_value[:200],
                        "severity": final_severity,
                        "entropy": round(ent, 2),
                        "suspicious": ent > _get_suspicious_threshold(name),
                        "confidence": round(confidence_score, 2),
                        "context": context,
                        "line_number": content[:match.start()].count('\n') + 1,
                        "risk_score": round(risk_score, 2),
                        "validation_status": validation_status
                    })

                    self.performance_metrics['patterns_matched'] += 1

                    if confidence_score > 0.8:
                        self.performance_metrics['high_confidence_finds'] += 1

            except Exception as e:
                logger.debug(f"Pattern '{name}' failed during scan: {e}")
                continue

        # Layer 3: context-gated high-entropy sweep (aggressive only).
        if self.aggressive:
            try:
                for hit in self._scan_high_entropy(content):
                    name = hit["name"]
                    leak_value = hit["value"]

                    leak_signature = self._generate_leak_signature(name, leak_value)
                    if leak_signature in self.seen_leaks:
                        continue
                    self.seen_leaks.add(leak_signature)

                    ent = hit["entropy"]
                    confidence_score = 0.5
                    risk_score = (0.5 * 0.4) + (min(ent / 8.0, 1.0) * 0.3) + (confidence_score * 0.3)

                    findings.append({
                        "type": name,
                        "value": leak_value[:200],
                        "severity": "MEDIUM",
                        "entropy": round(ent, 2),
                        "suspicious": True,
                        "confidence": round(confidence_score, 2),
                        "context": self._extract_context(content, leak_value, hit["start"]),
                        "line_number": content[:hit["start"]].count('\n') + 1,
                        "risk_score": round(risk_score, 2),
                        "validation_status": "heuristic"
                    })
                    self.performance_metrics['patterns_matched'] += 1
            except Exception as e:
                logger.debug(f"High-entropy sweep failed: {e}")

        unique_findings = self._deduplicate_findings(findings)

        # Optional safety cap - default unlimited.
        if self.max_findings_per_scan is not None and len(unique_findings) > self.max_findings_per_scan:
            logger.warning(
                f"Findings count {len(unique_findings)} exceeds cap "
                f"{self.max_findings_per_scan}; truncating."
            )
            unique_findings = unique_findings[: self.max_findings_per_scan]

        self.performance_metrics['total_checks'] += 1
        self.performance_metrics['processing_time'] += time.time() - start_time

        return unique_findings

    def _adjust_severity(self, base_severity: str, entropy: float, risk_score: float) -> str:
        """Adjust severity based on entropy and risk score"""
        severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        base_level = severity_map.get(base_severity, 0)

        if entropy > 4.0:
            base_level = min(base_level + 1, 3)

        if risk_score > 0.8:
            base_level = min(base_level + 1, 3)

        if risk_score < 0.3:
            base_level = max(base_level - 1, 0)

        reverse_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
        return reverse_map.get(base_level, "LOW")

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings, keeping the highest-confidence report per
        distinct secret value.

        CHANGED: the previous implementation dropped any finding whose
        value was a substring of an already-seen value. That is wrong for
        secret detection - a short real key legitimately appears inside a
        longer unrelated match (e.g. a bare token inside a connection
        string), and the O(n^2) substring scan silently deleted genuine
        findings depending purely on iteration order. Now dedup is exact
        on the value, and when the same value is matched by two patterns
        the higher-confidence (more specific) one wins.
        """
        best_by_value: Dict[str, Dict] = {}

        for finding in findings:
            key = finding["value"].strip()
            existing = best_by_value.get(key)

            if existing is None:
                best_by_value[key] = finding
                continue

            # Prefer higher confidence; tie-break on severity rank.
            severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            new_score = (
                finding.get("confidence", 0),
                severity_rank.get(finding.get("severity"), 0),
            )
            old_score = (
                existing.get("confidence", 0),
                severity_rank.get(existing.get("severity"), 0),
            )
            if new_score > old_score:
                best_by_value[key] = finding

        return list(best_by_value.values())

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

        # Copy metrics ONCE after scan (not per finding)
        metrics = context.shared_state.setdefault("metrics", {})
        for key in ['total_checks', 'patterns_matched', 'high_confidence_finds', 'processing_time']:
            if key in detector.performance_metrics and key in metrics:
                metrics[key] = detector.performance_metrics[key]

        # Emit events for each finding with context-based dedup only
        for finding in findings:
            leak_signature = detector._generate_leak_signature(
                finding["type"],
                finding["value"]
            )

            # HARD TYPE GUARD FOR SERIALIZATION ISSUES: ensure seen_leaks
            # is always a set (handles JSON round-trip edge cases).
            seen = context.shared_state.get("seen_leaks")
            if not isinstance(seen, set):
                seen = set(seen or [])
                context.shared_state["seen_leaks"] = seen

            if leak_signature in seen:
                continue

            seen.add(leak_signature)

            metrics["secrets_found"] = metrics.get("secrets_found", 0) + 1

            # CANONICAL secret_found EVENT (BACKEND CONTRACT COMPLIANT)
            await emit_event(
                context,
                event_type="secret_found",
                data={
                    # REQUIRED FIELDS (used by DB + reports)
                    "type": finding["type"].replace("_", " ").title(),
                    # Raw machine-readable rule name. The pretty "type"
                    # above is for display; consumers that need to key off
                    # the detector rule use this.
                    "finding_type": finding["type"],
                    "category": "Secrets",
                    "severity": finding["severity"].lower(),
                    "confidence": float(finding["confidence"]),
                    "raw_value": finding["value"],
                    "fingerprint": leak_signature,

                    # LOCATION
                    "source_url": source_url,
                    "file_path": source_url,
                    "line_number": finding.get("line_number"),

                    # OPTIONAL (safe extras)
                    "context": finding.get("context"),
                    "entropy": finding.get("entropy"),
                    "risk_score": finding.get("risk_score"),
                    "validation_status": finding.get("validation_status"),
                }
            )


# Backward compatibility - original class name (LEGACY)
LeakDetector = EnterpriseLeakDetector

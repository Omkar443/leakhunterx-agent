"""
LeakHunterX Configuration System

Production-grade configuration with validation, environment loading,
and secret redaction.

LOCKED VERSION - Production ready.
"""

import os
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, ClassVar, Union
from enum import Enum
import json


class AgentMode(Enum):
    """Agent operating mode"""
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"


@dataclass
class AgentConfig:
    """
    Agent configuration (SaaS-safe, env-driven)

    IMPORTANT DESIGN RULES:
    - agent_secret is NOT required at startup
    - backend mode supports self-registration
    - secrets are runtime-acquired, not config-required
    """

    # ------------------------------------------------------------
    # Core
    # ------------------------------------------------------------
    mode: AgentMode = AgentMode.DEVELOPMENT
    agent_id: Optional[str] = None
    agent_secret: Optional[str] = None   # NOT required at startup
    agent_api_key: Optional[str] = None  # DEPRECATED (never used)

    # Backend
    backend_url: str = field(default="https://backend-leakhunterx-staging.onrender.com")

    # ------------------------------------------------------------
    # Scan behavior
    # ------------------------------------------------------------
    scan_timeout: int = 3600
    crawl_timeout: int = 300
    analysis_timeout: int = 30
    max_depth: int = 3

    artifact_batch_size: int = 50
    heartbeat_interval: int = 60
    state_save_interval: int = 10

    # ------------------------------------------------------------
    # Crawler behavior
    # NEW: previously read via config.get(...) with hardcoded
    # fallback defaults scattered across crawler.py — now declared
    # in one place so they're documented, env-configurable, and
    # consistent. Values match the hardened defaults already applied
    # in crawler.py directly.
    # ------------------------------------------------------------
    crawler_concurrency: int = 5
    crawler_delay: float = 0.1
    request_timeout: int = 30
    max_pages: int = 500

    # NEW: was defaulting to False in crawler.py but True in
    # js_analyzer.py — declaring it here means both modules now
    # receive the SAME explicit value from this single source,
    # eliminating that inconsistency.
    verify_ssl: bool = False

    # ------------------------------------------------------------
    # Circuit breaker (shared by crawler.py + js_analyzer.py)
    # NEW: matches the relaxed defaults already applied directly
    # in crawler.py / js_analyzer.py / domain_manager.py.
    # ------------------------------------------------------------
    circuit_breaker_max_failures: int = 5
    circuit_breaker_reset_timeout: int = 60

    # ------------------------------------------------------------
    # JS analysis behavior
    # NEW: previously only configurable via hardcoded fallback
    # defaults inside js_analyzer.py.
    # ------------------------------------------------------------
    js_fetch_timeout: int = 30
    js_fetch_retries: int = 3
    max_js_file_size: int = 15 * 1024 * 1024  # 15MB
    max_connections: int = 100
    max_connections_per_host: int = 10
    content_cache_size: int = 100
    extraction_timeout: int = 60
    js_concurrency_limit: int = 5
    aggressive_secrets: bool = True

    # ------------------------------------------------------------
    # Logging & System
    # ------------------------------------------------------------
    log_level: str = "INFO"
    log_format: str = "json"
    enable_debug_logs: bool = False

    hostname: str = field(default_factory=lambda: os.environ.get("HOSTNAME", "unknown"))
    platform: str = field(default_factory=lambda: os.environ.get("PLATFORM", "unknown"))
    data_dir: str = "./data"

    # ------------------------------------------------------------
    # Environment mapping
    # ------------------------------------------------------------
    ENV_PREFIX: ClassVar[str] = "LHX_"

    ENV_MAPPINGS: ClassVar[Dict[str, str]] = {
        "MODE": "mode",
        "AGENT_ID": "agent_id",
        "AGENT_SECRET": "agent_secret",   # Optional override only
        "BACKEND_URL": "backend_url",

        "SCAN_TIMEOUT": "scan_timeout",
        "CRAWL_TIMEOUT": "crawl_timeout",
        "ANALYSIS_TIMEOUT": "analysis_timeout",
        "MAX_DEPTH": "max_depth",
        "ARTIFACT_BATCH_SIZE": "artifact_batch_size",
        "HEARTBEAT_INTERVAL": "heartbeat_interval",
        "STATE_SAVE_INTERVAL": "state_save_interval",

        "CRAWLER_CONCURRENCY": "crawler_concurrency",
        "CRAWLER_DELAY": "crawler_delay",
        "REQUEST_TIMEOUT": "request_timeout",
        "MAX_PAGES": "max_pages",
        "VERIFY_SSL": "verify_ssl",

        "CIRCUIT_BREAKER_MAX_FAILURES": "circuit_breaker_max_failures",
        "CIRCUIT_BREAKER_RESET_TIMEOUT": "circuit_breaker_reset_timeout",

        "JS_FETCH_TIMEOUT": "js_fetch_timeout",
        "JS_FETCH_RETRIES": "js_fetch_retries",
        "MAX_JS_FILE_SIZE": "max_js_file_size",
        "MAX_CONNECTIONS": "max_connections",
        "MAX_CONNECTIONS_PER_HOST": "max_connections_per_host",
        "CONTENT_CACHE_SIZE": "content_cache_size",
        "EXTRACTION_TIMEOUT": "extraction_timeout",
        "JS_CONCURRENCY_LIMIT": "js_concurrency_limit",
        "AGGRESSIVE_SECRETS": "aggressive_secrets",

        "LOG_LEVEL": "log_level",
        "LOG_FORMAT": "log_format",
        "ENABLE_DEBUG_LOGS": "enable_debug_logs",
        "DATA_DIR": "data_dir",
    }

    # ------------------------------------------------------------
    # Loader
    # ------------------------------------------------------------
    @classmethod
    def from_env(cls) -> "AgentConfig":
        config = cls()

        for env_key, attr in cls.ENV_MAPPINGS.items():
            full_key = f"{cls.ENV_PREFIX}{env_key}"
            if full_key not in os.environ:
                continue

            raw_value = os.environ[full_key]
            current_value = getattr(config, attr)

            if isinstance(current_value, bool):
                value = raw_value.lower() in ("1", "true", "yes", "on")
            elif isinstance(current_value, int):
                try:
                    value = int(raw_value)
                except ValueError:
                    continue
            # NEW: float coercion (needed for crawler_delay). Must be
            # checked AFTER bool (bool is a subclass of int in Python,
            # but the isinstance(current_value, bool) branch above
            # already intercepts real bools first, so this doesn't
            # change any existing field's behavior) and AFTER int,
            # since no existing field is a float.
            elif isinstance(current_value, float):
                try:
                    value = float(raw_value)
                except ValueError:
                    continue
            elif isinstance(current_value, AgentMode):
                try:
                    value = AgentMode(raw_value.lower())
                except ValueError:
                    continue
            else:
                value = raw_value

            setattr(config, attr, value)

        config._auto_configure()
        config.validate()
        return config

    def _auto_configure(self) -> None:
        if self.mode == AgentMode.PRODUCTION:
            self.log_format = "json"
            self.enable_debug_logs = False
        else:
            self.enable_debug_logs = True

    # ------------------------------------------------------------
    # Validation (NO SECRET ENFORCEMENT)
    # ------------------------------------------------------------
    def validate(self) -> None:
        if not isinstance(self.mode, AgentMode):
            raise ValueError("Invalid agent mode")

        if self.scan_timeout <= 0:
            raise ValueError("scan_timeout must be positive")
        if self.crawl_timeout <= 0:
            raise ValueError("crawl_timeout must be positive")
        if self.analysis_timeout <= 0:
            raise ValueError("analysis_timeout must be positive")
        if self.max_depth <= 0:
            raise ValueError("max_depth must be positive")
        if self.artifact_batch_size <= 0:
            raise ValueError("artifact_batch_size must be positive")
        if self.heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")
        if self.state_save_interval <= 0:
            raise ValueError("state_save_interval must be positive")

        # NEW: validation for newly-exposed crawler/JS-analysis settings
        if self.crawler_concurrency <= 0:
            raise ValueError("crawler_concurrency must be positive")
        if self.crawler_delay < 0:
            raise ValueError("crawler_delay cannot be negative")
        if self.request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        if self.max_pages <= 0:
            raise ValueError("max_pages must be positive")
        if self.circuit_breaker_max_failures <= 0:
            raise ValueError("circuit_breaker_max_failures must be positive")
        if self.circuit_breaker_reset_timeout <= 0:
            raise ValueError("circuit_breaker_reset_timeout must be positive")
        if self.js_fetch_timeout <= 0:
            raise ValueError("js_fetch_timeout must be positive")
        if self.js_fetch_retries <= 0:
            raise ValueError("js_fetch_retries must be positive")
        if self.max_js_file_size <= 0:
            raise ValueError("max_js_file_size must be positive")
        if self.max_connections <= 0:
            raise ValueError("max_connections must be positive")
        if self.max_connections_per_host <= 0:
            raise ValueError("max_connections_per_host must be positive")
        if self.content_cache_size <= 0:
            raise ValueError("content_cache_size must be positive")
        if self.extraction_timeout <= 0:
            raise ValueError("extraction_timeout must be positive")
        if self.js_concurrency_limit <= 0:
            raise ValueError("js_concurrency_limit must be positive")

        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_log_levels:
            raise ValueError(f"Invalid log_level: {self.log_level}")

        valid_formats = {"json", "text", "simple"}
        if self.log_format.lower() not in valid_formats:
            raise ValueError(f"Invalid log_format: {self.log_format}")

        if not self.data_dir:
            raise ValueError("data_dir cannot be empty")

        # NO agent_secret validation here
        # Registration + StateManager owns identity lifecycle

    # ------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------
    def to_dict(self, redact_secrets: bool = True) -> Dict[str, Any]:
        data = asdict(self)
        data["mode"] = self.mode.value

        if redact_secrets:
            if data.get("agent_secret"):
                data["agent_secret"] = "***REDACTED***"
            if data.get("agent_api_key"):
                data["agent_api_key"] = "***REDACTED***"

        return data

    def __str__(self) -> str:
        return json.dumps(self.to_dict(redact_secrets=True), indent=2)
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

    # ─────────────────────────────────────────────
    # Core
    # ─────────────────────────────────────────────
    mode: AgentMode = AgentMode.DEVELOPMENT
    agent_id: Optional[str] = None
    agent_secret: Optional[str] = None   # ❌ NOT required at startup
    agent_api_key: Optional[str] = None  # ⚠️ DEPRECATED (never used)

    # Backend
    backend_url: str = field(default="https://backend-leakhunterx-staging.onrender.com")

    # ─────────────────────────────────────────────
    # Scan behavior
    # ─────────────────────────────────────────────
    scan_timeout: int = 3600
    crawl_timeout: int = 300
    analysis_timeout: int = 30
    max_depth: int = 3

    artifact_batch_size: int = 50
    heartbeat_interval: int = 60
    state_save_interval: int = 10

    # ─────────────────────────────────────────────
    # Logging & System
    # ─────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "json"
    enable_debug_logs: bool = False

    hostname: str = field(default_factory=lambda: os.environ.get("HOSTNAME", "unknown"))
    platform: str = field(default_factory=lambda: os.environ.get("PLATFORM", "unknown"))
    data_dir: str = "./data"

    # ─────────────────────────────────────────────
    # Environment mapping
    # ─────────────────────────────────────────────
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

        "LOG_LEVEL": "log_level",
        "LOG_FORMAT": "log_format",
        "ENABLE_DEBUG_LOGS": "enable_debug_logs",
        "DATA_DIR": "data_dir",
    }

    # ─────────────────────────────────────────────
    # Loader
    # ─────────────────────────────────────────────
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

    # ─────────────────────────────────────────────
    # Validation (NO SECRET ENFORCEMENT)
    # ─────────────────────────────────────────────
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

        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_log_levels:
            raise ValueError(f"Invalid log_level: {self.log_level}")

        valid_formats = {"json", "text", "simple"}
        if self.log_format.lower() not in valid_formats:
            raise ValueError(f"Invalid log_format: {self.log_format}")

        if not self.data_dir:
            raise ValueError("data_dir cannot be empty")

        # 🚫 NO agent_secret validation here
        # Registration + StateManager owns identity lifecycle

    # ─────────────────────────────────────────────
    # Serialization
    # ─────────────────────────────────────────────
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

import asyncio
from typing import Dict, Any, Optional, Set

class ExtractorContext:
    """
    Single source of truth for ALL shared mutable scan state.
    NO other module may assume keys exist.
    """

    def __init__(
        self,
        scan_id: str,
        config: dict,
        event_emitter,
        seen_artifact_hashes: Optional[Set[str]] = None,
        **kwargs
    ):
        self.scan_id = scan_id
        self.config = config
        self.event_emitter = event_emitter

        # Control flags
        self.should_stop = asyncio.Event()
        self.should_pause = asyncio.Event()
        self.should_pause.clear()

        # Artifact dedupe
        self.seen_artifact_hashes = seen_artifact_hashes or set()

        # 🔑 SINGLE, CANONICAL SHARED STATE
        self.shared_state: Dict[str, Any] = {
            # JS analysis
            "content_hashes": set(),
            "processed_content_hashes": set(),
            "analysis_cache": {},
            "content_cache": {},
            "entropy_cache": {},
            "seen_leaks": set(),

            # Circuit breaker
            "circuit_breaker": {},

            # Metrics (ALL must exist)
            "metrics": {
                "files_analyzed": 0,
                "secrets_found": 0,
                "endpoints_found": 0,
                "duplicates_skipped": 0,
                "cache_hits": 0,
                "content_downloaded": 0,
            },
        }

    def ensure_metrics(self) -> Dict[str, int]:
        """Return metrics dict with guaranteed keys."""
        metrics = self.shared_state.setdefault("metrics", {})
        metrics.setdefault("files_analyzed", 0)
        metrics.setdefault("secrets_found", 0)
        metrics.setdefault("endpoints_found", 0)
        metrics.setdefault("duplicates_skipped", 0)
        metrics.setdefault("cache_hits", 0)
        metrics.setdefault("content_downloaded", 0)
        return metrics

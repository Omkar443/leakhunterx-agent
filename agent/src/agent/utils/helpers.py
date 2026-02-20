"""
Shared utility functions for LeakHunterX.
Pure, stateless, dependency-light utilities.
"""

import platform
import psutil
import asyncio
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Dict, Optional, Union
from urllib.parse import urljoin, urlparse, urlunparse
from .url_normalizer import normalize_url as enterprise_normalize_url


# ========================
# 1️⃣ Time & ID helpers
# ========================

def now_ts() -> int:
    """Get current timestamp as integer seconds since epoch."""
    return int(time.time())


def generate_scan_id(prefix: str = "scan") -> str:
    """
    Generate a unique scan ID with timestamp and UUID.
    
    Args:
        prefix: Prefix for the scan ID
        
    Returns:
        Unique scan ID in format: {prefix}_{timestamp}_{uuid_short}
    """
    timestamp = now_ts()
    unique_id = uuid.uuid4().hex[:12]  # 12 chars for readability
    return f"{prefix}_{timestamp}_{unique_id}"


# ========================
# 2️⃣ URL helpers
# ========================

def normalize_url(url: str) -> str:
    """
    Normalize URL using the enterprise normalizer.
    Wrapper for backward compatibility.
    """
    result = enterprise_normalize_url(url)
    return result.normalized_url if result.success else url
            

def is_same_domain(url: str, base_domain: str) -> bool:
    """
    Check if URL belongs to the same domain as base domain.
    
    Args:
        url: URL to check
        base_domain: Base domain to compare against
        
    Returns:
        True if same domain, False otherwise
    """
    try:
        url_domain = urlparse(normalize_url(url)).netloc
        base_domain_clean = urlparse(normalize_url(base_domain)).netloc
        
        # Remove port if present for comparison
        url_domain_no_port = url_domain.split(':')[0]
        base_domain_no_port = base_domain_clean.split(':')[0]
        
        return url_domain_no_port == base_domain_no_port
        
    except Exception:
        return False


def safe_join_url(base: str, path: str) -> str:
    """
    Safely join base URL with path, handling edge cases.
    
    Args:
        base: Base URL
        path: Path to join
        
    Returns:
        Joined URL, or empty string on error
    """
    if not base:
        return path if path else ""
    
    try:
        # If path is already absolute, return it
        if urlparse(path).scheme:
            return normalize_url(path)
        
        # Join and normalize
        joined = urljoin(base.rstrip('/') + '/', path.lstrip('/'))
        return normalize_url(joined)
        
    except Exception:
        # Fallback: simple string join
        base_clean = base.rstrip('/')
        path_clean = path.lstrip('/')
        return normalize_url(f"{base_clean}/{path_clean}")


# ========================
# 3️⃣ File & directory helpers
# ========================

def ensure_dir(path: Union[str, Path]) -> None:
    """
    Ensure directory exists, create if it doesn't.
    
    Args:
        path: Directory path (will create parent directories too)
    """
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError):
        # Silent fail - caller should handle if critical
        pass


def read_json_safe(path: Union[str, Path]) -> Dict[str, Any]:
    """
    Safely read JSON file, return empty dict on any error.
    
    Args:
        path: Path to JSON file
        
    Returns:
        Dictionary from JSON, or empty dict on error
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError):
        return {}


def atomic_write_json(path: Union[str, Path], data: Dict[str, Any]) -> None:
    """
    Atomically write JSON data to file using temp file rename.
    
    Args:
        path: Destination file path
        data: Dictionary data to write
    """
    path_obj = Path(path)
    temp_path = path_obj.parent / f".{path_obj.name}.{uuid.uuid4().hex}.tmp"
    
    try:
        # Ensure parent directory exists
        ensure_dir(path_obj.parent)
        
        # Write to temp file
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()  # Ensure data is written to OS buffer
        
        # Atomic rename
        temp_path.replace(path_obj)
        
    except Exception:
        # Clean up temp file on error
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise
    finally:
        # Ensure temp file is cleaned up
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


# ========================
# 4️⃣ Async safety helpers
# ========================

async def run_blocking(func: callable, *args, **kwargs) -> Any:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args, **kwargs)



async def safe_await(task: Awaitable, timeout: Optional[int] = None) -> Optional[Any]:
    """
    Safely await a task with optional timeout and error suppression.
    
    Args:
        task: Awaitable task
        timeout: Timeout in seconds (None for no timeout)
        
    Returns:
        Task result or None on timeout/error
    """
    try:
        if timeout is not None:
            return await asyncio.wait_for(task, timeout=timeout)
        else:
            return await task
    except (asyncio.TimeoutError, asyncio.CancelledError):
        return None
    except Exception:
        # Suppress all other exceptions
        return None


# ========================
# 5️⃣ Hash / fingerprint helpers
# ========================

def sha256_text(text: str) -> str:
    """
    Calculate SHA256 hash of text (UTF-8 encoded).
    
    Args:
        text: Input text
        
    Returns:
        SHA256 hex digest
    """
    if not text:
        return hashlib.sha256(b"").hexdigest()
    
    return hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()



# ========================
# 6 Add after sha256_text() function:
# ========================
def secure_hash(data: str, truncate: bool = True) -> str:
    """Generate secure SHA256 hash."""
    if not data:
        return ""
    hash_result = hashlib.sha256(data.encode('utf-8', errors='ignore')).hexdigest()
    return hash_result[:32] if truncate else hash_result

async def emit_compatible_event(emitter, event_dict: dict, scan_id: str):
    event = dict(event_dict)

    if "scan_id" not in event:
        event["scan_id"] = scan_id

    if not hasattr(emitter, "emit"):
        raise TypeError("Emitter must have an async .emit() method")

    await emitter.emit(event)


def get_version() -> str:
    """
    Return agent version.
    Single source of truth for versioning.
    """
    return "1.0"



def create_event(event_type: str, scan_id: str, **kwargs) -> dict:
    return {
        "event_type": event_type,
        "scan_id": scan_id,
        "timestamp": now_ts(),
        "data": kwargs
    }




# ========================
# 7️⃣ System metrics helpers (AGENT ONLY)
# ========================

def collect_system_metrics() -> Dict[str, Any]:
    """
    Collect real-time system metrics for agent heartbeat.
    Must be called from the running agent process.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()

        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory_percent": round(memory.percent, 2),
            "disk_percent": round(disk.percent, 2),
            "network_kbps": int((net.bytes_sent + net.bytes_recv) / 1024),
            "uptime_seconds": int(time.time() - psutil.boot_time()),
        }

    except Exception:
        # Never crash agent because of metrics
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "network_kbps": 0,
            "uptime_seconds": 0,
        }


def collect_system_info() -> Dict[str, str]:
    """
    Collect static system information.
    Used for Agent UI (hardware, OS).
    """
    try:
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "unknown",
        }
    except Exception:
        return {
            "os": "unknown",
            "os_version": "unknown",
            "architecture": "unknown",
            "processor": "unknown",
        }

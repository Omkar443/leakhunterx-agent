"""
Persistent scan state manager for LeakHunterX.
Atomic, crash-safe, async-safe state management.
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid


class ScanStatus(str, Enum):
    """Valid scan states with strict transitions."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


# Valid state transitions
VALID_TRANSITIONS = {
    ScanStatus.PENDING: {ScanStatus.RUNNING, ScanStatus.FAILED},
    ScanStatus.RUNNING: {ScanStatus.PAUSED, ScanStatus.COMPLETED, ScanStatus.FAILED},
    ScanStatus.PAUSED: {ScanStatus.RUNNING, ScanStatus.FAILED},
    ScanStatus.COMPLETED: set(),  # Terminal state
    ScanStatus.FAILED: set(),    # Terminal state
}


@dataclass
class ScanState:
    """Scan state container with strict transition validation."""
    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    created_at: int = field(default_factory=lambda: int(datetime.utcnow().timestamp()))
    updated_at: int = field(default_factory=lambda: int(datetime.utcnow().timestamp()))
    progress: Dict[str, Any] = field(default_factory=dict)
    cursor: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "progress": self.progress,
            "cursor": self.cursor,
            "error": self.error
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanState":
        """Create ScanState from dictionary."""
        return cls(
            scan_id=data["scan_id"],
            status=ScanStatus(data["status"]),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            progress=data.get("progress", {}),
            cursor=data.get("cursor", {}),
            error=data.get("error")
        )
    
    def validate_transition(self, new_status: ScanStatus) -> None:
        """Raise StateTransitionError for invalid transitions."""
        if new_status not in VALID_TRANSITIONS.get(self.status, set()):
            raise StateTransitionError(
                f"Cannot transition from {self.status} to {new_status}"
            )



@dataclass
class AgentState:
    """
    Persistent agent runtime state.
    Single agent per machine (MVP-safe).
    """
    agent_id: Optional[str] = None  # ✅ Phase 2: Server-issued agent identity
    agent_secret: Optional[str] = None  # ✅ Phase 2: Server-issued agent secret
    started_at: Optional[int] = None  # ✅ Added for monotonic uptime
    state: str = "disconnected"  # connected | scanning | updating | disconnected
    last_heartbeat: Optional[int] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    network_kbps: int = 0
    scans_completed: int = 0
    data_processed_mb: int = 0
    uptime_seconds: int = 0
    version: str = "unknown"
    mode: str = "local"

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        return cls(**data)



class StateTransitionError(Exception):
    """Invalid state transition attempted."""
    pass


class StateManagerError(Exception):
    """Base exception for state manager errors."""
    pass


class StateManager:
    """
    Persistent, atomic, async-safe scan state manager.
    
    Features:
        - One JSON file per scan_id
        - Atomic writes via temp file rename
        - Async locks per scan_id
        - Crash-safe state loading
        - Strict state transitions

    """
    
    def __init__(self, state_dir: Optional[str] = None):
        """
        Initialize state manager.
        
        Args:
            state_dir: Directory to store state files. Defaults to ~/.leakhunterx/state/
        """
        if state_dir is None:
            state_dir = os.path.expanduser("~/.leakhunterx/state")
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        # Per-scan_id locks for async safety
        self._scan_locks: Dict[str, asyncio.Lock] = {}
        self._manager_lock = asyncio.Lock()
        
        # ✅ OPTIONAL: Agent state lock for future thread safety
        self._agent_lock = asyncio.Lock()



    async def clear_scan_state(self, scan_id: str) -> bool:
        """Backward-compatible cleanup alias"""
        return await self.delete(scan_id)

    async def save_async(self, *args) -> None:
        """
        Backward-compatible async save.

        Supports:
            save_async(state)
            save_async(scan_id, state)
        """
        if len(args) == 1:
            state = args[0]
        elif len(args) == 2:
            _, state = args
        else:
            raise TypeError("save_async expects 1 or 2 arguments")

        await self._write_state(state)


    def save(self, *args) -> None:
        if len(args) == 1:
            state = args[0]
        elif len(args) == 2:
            _, state = args
        else:
            raise TypeError("save expects 1 or 2 arguments")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._write_state(state))
        else:
            # Fire-and-forget fallback
            loop.create_task(self._write_state(state))


    def save_scan_state(self, scan_id: str, state: dict) -> None:
        """
        Persist scan state (sync wrapper).

        Transition validation is handled centrally in _write_state().
        """
        self.save(scan_id, state)


    async def save_scan_state_async(self, scan_id: str, state: dict) -> None:
        """
        Persist scan state asynchronously.

        Transition validation is handled centrally in _write_state().
        """
        await self.save_async(scan_id, state)


    
    async def _get_lock(self, scan_id: str) -> asyncio.Lock:
        """
        Get or create a lock for a scan_id in an async-safe way.
        """
        # ✅ Validate scan_id format
        if not scan_id or len(scan_id) > 64:
            raise StateManagerError("Invalid scan_id")
            
        async with self._manager_lock:
            lock = self._scan_locks.get(scan_id)
            if not lock:
                lock = asyncio.Lock()
                self._scan_locks[scan_id] = lock
            return lock

    
    def _get_state_path(self, scan_id: str) -> Path:
        """Get path for scan state file."""
        return self.state_dir / f"scan_{scan_id}.json"
    
    def _get_agent_state_path(self) -> Path:
        return self.state_dir / "agent_state.json"

    
    def _get_temp_path(self, scan_id: str) -> Path:
        """Get path for temporary state file."""
        return self.state_dir / f"scan_{scan_id}.{uuid.uuid4().hex}.tmp"
    
    async def _load_unlocked(self, scan_id: str) -> Optional[ScanState]:
        """
        Load scan state without acquiring a lock.
        For internal use only.
        """
        state_path = self._get_state_path(scan_id)
        if not state_path.exists():
            return None
        
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Validate required fields
            required_fields = {"scan_id", "status", "created_at", "updated_at"}
            if not all(field in data for field in required_fields):
                raise StateManagerError(f"Missing required fields in state file for {scan_id}")
            
            # Validate status
            try:
                ScanStatus(data["status"])
            except ValueError:
                raise StateManagerError(f"Invalid status in state file for {scan_id}: {data['status']}")
            
            return ScanState.from_dict(data)
            
        except json.JSONDecodeError as e:
            raise StateManagerError(f"Corrupted state file for {scan_id}: {e}")
        except (KeyError, TypeError) as e:
            raise StateManagerError(f"Invalid state data for {scan_id}: {e}")
        except OSError as e:
            raise StateManagerError(f"Failed to read state for {scan_id}: {e}")
    
    async def _write_state(self, state: ScanState | dict) -> None:
        """
        Atomic write of state to disk.

        Accepts ScanState or partial dict (backward compatible).
        """

        # 🔑 Normalize input
        if isinstance(state, dict):
            try:
                scan_id = state.get("scan_id")
                if not scan_id:
                    raise StateManagerError("State dict missing scan_id")

                # ✅ FIX: Use unlocked loader to avoid nested locking
                existing = await self._load_unlocked(scan_id)

                if existing:
                    # Merge incoming fields
                    IMMUTABLE_FIELDS = {"scan_id", "created_at"}
                    
                    for key, value in state.items():
                        if not hasattr(existing, key):
                            continue

                        if key in IMMUTABLE_FIELDS:
                            continue  # Skip immutable fields

                        if key == "status":
                            new_status = (
                                value
                                if isinstance(value, ScanStatus)
                                else ScanStatus(value)
                            )

                            # ✅ IDENTITY TRANSITION — IGNORE
                            if existing.status == new_status:
                                continue

                            # 🔒 Validate real transitions only
                            existing.validate_transition(new_status)
                            existing.status = new_status

                        else:
                            setattr(existing, key, value)

                    state = existing

                else:
                    # Create new state safely
                    raw_status = state.get("status", ScanStatus.PENDING)
                    status = (
                        raw_status
                        if isinstance(raw_status, ScanStatus)
                        else ScanStatus(raw_status)
                    )

                    state = ScanState(
                        scan_id=scan_id,
                        status=status,
                        progress=state.get("progress", {}),
                        cursor=state.get("cursor", {}),
                        error=state.get("error"),
                    )

            except Exception as e:
                raise StateManagerError(f"Invalid state dict provided: {e}")

        if not isinstance(state, ScanState):
            raise StateManagerError(
                f"_write_state expected ScanState or dict, got {type(state)}"
            )

        # ✅ Safety check: Prevent DoS via huge progress payloads
        if len(json.dumps(state.progress)) > 50_000:
            raise StateManagerError("Progress payload too large")
        
        # ✅ OPTIONAL: Cursor size cap for symmetry with progress
        if len(json.dumps(state.cursor)) > 20_000:
            raise StateManagerError("Cursor payload too large")

        # ✅ FIX: Acquire lock before writing
        scan_id = state.scan_id
        lock = await self._get_lock(scan_id)

        async with lock:
            temp_path = self._get_temp_path(scan_id)
            state_path = self._get_state_path(scan_id)

            # Update timestamp
            state.updated_at = int(datetime.utcnow().timestamp())

            try:
                temp_path.parent.mkdir(parents=True, exist_ok=True)

                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(state.to_dict(), f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())

                os.replace(temp_path, state_path)

            except (OSError, IOError) as e:
                try:
                    if temp_path.exists():
                        temp_path.unlink()
                except OSError:
                    pass

                raise StateManagerError(
                    f"Failed to write state for scan_id={state.scan_id}: {e}"
                )

    
    async def create_scan(self, scan_id: str) -> ScanState:
        """
        Create a new scan state.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            Created ScanState
            
        Raises:
            StateManagerError: If scan already exists
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state_path = self._get_state_path(scan_id)
            if state_path.exists():
                raise StateManagerError(f"Scan {scan_id} already exists")
            
            state = ScanState(scan_id=scan_id)
            await self._write_state(state)
            return state
    
    async def load(self, scan_id: str) -> Optional[ScanState]:
        """
        Load existing scan state.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            ScanState if exists, None otherwise
            
        Raises:
            StateManagerError: If state file is corrupted
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state_path = self._get_state_path(scan_id)
            if not state_path.exists():
                return None
            
            try:
                with open(state_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Validate required fields
                required_fields = {"scan_id", "status", "created_at", "updated_at"}
                if not all(field in data for field in required_fields):
                    raise StateManagerError(f"Missing required fields in state file for {scan_id}")
                
                # Validate status
                try:
                    ScanStatus(data["status"])
                except ValueError:
                    raise StateManagerError(f"Invalid status in state file for {scan_id}: {data['status']}")
                
                return ScanState.from_dict(data)
                
            except json.JSONDecodeError as e:
                raise StateManagerError(f"Corrupted state file for {scan_id}: {e}")
            except (KeyError, TypeError) as e:
                raise StateManagerError(f"Invalid state data for {scan_id}: {e}")
            except OSError as e:
                raise StateManagerError(f"Failed to read state for {scan_id}: {e}")
    
    async def update_progress(self, scan_id: str, **kwargs: Any) -> ScanState:
        """
        Update scan progress metrics.
        
        Args:
            scan_id: Scan identifier
            **kwargs: Progress metrics to update
            
        Returns:
            Updated ScanState
            
        Raises:
            StateManagerError: If scan doesn't exist or update fails
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state = await self._load_or_error(scan_id)
            
            # ✅ Safety check: Prevent DoS via huge progress payloads
            # Create a copy to check size without modifying original
            test_progress = state.progress.copy()
            test_progress.update(kwargs)
            if len(json.dumps(test_progress)) > 50_000:
                raise StateManagerError("Progress payload would exceed size limit")
            
            # Update progress dict
            state.progress.update(kwargs)
            
            await self._write_state(state)
            return state
    
    async def update_cursor(self, scan_id: str, **kwargs: Any) -> ScanState:
        """
        Update scan cursor position.
        
        Args:
            scan_id: Scan identifier
            **kwargs: Cursor data to update
            
        Returns:
            Updated ScanState
            
        Raises:
            StateManagerError: If scan doesn't exist or update fails
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state = await self._load_or_error(scan_id)
            
            # ✅ Safety check: Prevent DoS via huge cursor payloads
            # Create a copy to check size without modifying original
            test_cursor = state.cursor.copy()
            test_cursor.update(kwargs)
            if len(json.dumps(test_cursor)) > 20_000:
                raise StateManagerError("Cursor payload would exceed size limit")
            
            # Update cursor dict
            state.cursor.update(kwargs)
            
            await self._write_state(state)
            return state
    
    async def pause(self, scan_id: str) -> ScanState:
        """
        Pause a running scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Updated ScanState
            
        Raises:
            StateTransitionError: If scan cannot be paused
            StateManagerError: If scan doesn't exist or update fails
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state = await self._load_or_error(scan_id)
            
            # Validate and transition
            state.validate_transition(ScanStatus.PAUSED)
            state.status = ScanStatus.PAUSED
            
            await self._write_state(state)
            return state
    
    async def resume(self, scan_id: str) -> ScanState:
        """
        Resume a paused scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Updated ScanState
            
        Raises:
            StateTransitionError: If scan cannot be resumed
            StateManagerError: If scan doesn't exist or update fails
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state = await self._load_or_error(scan_id)
            
            # Validate and transition
            state.validate_transition(ScanStatus.RUNNING)
            state.status = ScanStatus.RUNNING
            
            await self._write_state(state)
            return state
    
    async def complete(self, scan_id: str) -> ScanState:
        """
        Mark a scan as completed.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Updated ScanState
            
        Raises:
            StateTransitionError: If scan cannot be completed
            StateManagerError: If scan doesn't exist or update fails
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state = await self._load_or_error(scan_id)
            
            # Validate and transition
            state.validate_transition(ScanStatus.COMPLETED)
            state.status = ScanStatus.COMPLETED
            
            await self._write_state(state)
            return state
    
    async def fail(self, scan_id: str, reason: str) -> ScanState:
        """
        Mark a scan as failed with error reason.
        
        Args:
            scan_id: Scan identifier
            reason: Failure reason
            
        Returns:
            Updated ScanState
            
        Raises:
            StateTransitionError: If scan cannot be failed
            StateManagerError: If scan doesn't exist or update fails
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state = await self._load_or_error(scan_id)
            
            # Validate and transition
            state.validate_transition(ScanStatus.FAILED)
            state.status = ScanStatus.FAILED
            state.error = reason
            
            await self._write_state(state)
            return state
    
    async def delete(self, scan_id: str) -> bool:
        """
        Delete scan state file.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            True if deleted, False if didn't exist
            
        Raises:
            StateManagerError: If deletion fails
        """
        state_path = self._get_state_path(scan_id)
        
        if not state_path.exists():
            # Clean up lock even if file doesn't exist
            async with self._manager_lock:
                if scan_id in self._scan_locks:
                    del self._scan_locks[scan_id]
            return False
        
        lock = await self._get_lock(scan_id)
        async with lock:
            try:
                state_path.unlink()
                return True
                
            except OSError as e:
                raise StateManagerError(f"Failed to delete state for {scan_id}: {e}")
            finally:
                # Always clean up lock
                async with self._manager_lock:
                    if scan_id in self._scan_locks:
                        del self._scan_locks[scan_id]
    
    async def list_scans(self) -> List[ScanState]:
        """
        List all scan states.
        
        Returns:
            List of ScanState objects
            
        Raises:
            StateManagerError: If reading any state fails
        """
        scan_states: List[ScanState] = []
        
        try:
            # Find all scan state files
            for state_file in self.state_dir.glob("scan_*.json"):
                # Extract scan_id from filename
                filename = state_file.stem
                if filename.startswith("scan_"):
                    scan_id = filename[5:]  # Remove "scan_" prefix
                    
                    try:
                        state = await self.load(scan_id)
                        if state:
                            scan_states.append(state)
                    except StateManagerError:
                        # Skip corrupted files
                        continue
                        
        except OSError as e:
            raise StateManagerError(f"Failed to list scans: {e}")
        
        # Sort by creation time (newest first)
        scan_states.sort(key=lambda s: s.created_at, reverse=True)
        return scan_states
    
    async def _load_or_error(self, scan_id: str) -> ScanState:
        """
        Load scan state or raise error if not found.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            ScanState if exists
            
        Raises:
            StateManagerError: If scan doesn't exist
        """
        state = await self.load(scan_id)
        if state is None:
            raise StateManagerError(f"Scan {scan_id} not found")
        return state
    
    async def get_status(self, scan_id: str) -> Optional[ScanStatus]:
        """
        Get scan status without loading full state.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            ScanStatus if exists, None otherwise
        """
        lock = await self._get_lock(scan_id)
        async with lock:
            state_path = self._get_state_path(scan_id)
            if not state_path.exists():
                return None
            
            try:
                with open(state_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                return ScanStatus(data.get("status"))
                
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                # If we can't read the status, treat as non-existent
                return None
    
    async def cleanup_old_scans(self, max_age_days: int = 30) -> int:
        """
        Clean up scan states older than specified days.
        
        Args:
            max_age_days: Maximum age in days (default: 30)
            
        Returns:
            Number of scans cleaned up
        """
        cleanup_count = 0
        cutoff_time = int(datetime.utcnow().timestamp()) - (max_age_days * 24 * 60 * 60)
        
        try:
            scans = await self.list_scans()
            for state in scans:
                if state.created_at < cutoff_time:
                    try:
                        if await self.delete(state.scan_id):
                            cleanup_count += 1
                    except StateManagerError:
                        # Skip if deletion fails
                        continue
                        
        except StateManagerError:
            return cleanup_count
        
        return cleanup_count
    
    def get_state_dir(self) -> Path:
        """
        Get the state directory path.
        
        Returns:
            Path to state directory
        """
        return self.state_dir
    
    async def close(self) -> None:
        """
        Clean up resources.
        """
        async with self._manager_lock:
            self._scan_locks.clear()

    
    async def update_agent_state(self, data: Dict[str, Any]) -> None:
        """
        Persist agent heartbeat + metrics.
        Called by /agent/heartbeat.
        SAFE: Merges with existing state to preserve agent_id/agent_secret.
        """
        # ✅ OPTIONAL: Use agent lock for thread safety (future-proofing)
        async with self._agent_lock:
            path = self._get_agent_state_path()

            # ✅ Allow only known AgentState fields (defensive)
            allowed_fields = AgentState().__dict__.keys()
            filtered_data = {k: v for k, v in data.items() if k in allowed_fields}

            # ✅ Load existing state (preserves agent_id/agent_secret)
            existing = await self.load_agent_state()
            state = existing or AgentState()

            # ✅ Merge incoming data (only overwrite if value is not None)
            for key, value in filtered_data.items():
                if hasattr(state, key) and value is not None:
                    setattr(state, key, value)

            # ✅ Update heartbeat timestamp server-side (authoritative)
            state.last_heartbeat = int(datetime.utcnow().timestamp())
            
            # ✅ Update uptime if started_at exists
            if state.started_at:
                state.uptime_seconds = (
                    int(datetime.utcnow().timestamp()) - state.started_at
                )

            # ✅ Ensure sane defaults (but preserve existing values)
            if not state.version or state.version == "unknown":
                state.version = filtered_data.get("version", "unknown")
            if not state.mode or state.mode == "local":
                state.mode = filtered_data.get("mode", "local")

            # ✅ Atomic write (crash-safe)
            temp = path.with_suffix(".tmp")
            with open(temp, "w", encoding="utf-8") as f:
                json.dump(state.to_dict(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp, path)



    async def load_agent_state(self) -> Optional[AgentState]:
        """
        Load persisted agent state.
        """
        # ✅ OPTIONAL: Use agent lock for thread safety (future-proofing)
        async with self._agent_lock:
            path = self._get_agent_state_path()
            if not path.exists():
                return None

            try:
                with open(path, "r", encoding="utf-8") as f:
                    return AgentState.from_dict(json.load(f))
            except Exception:
                return None
    
    async def is_agent_connected(self, timeout_seconds: int = 15) -> bool:
        state = await self.load_agent_state()
        if not state or not state.last_heartbeat:
            return False

        return (int(datetime.utcnow().timestamp()) - state.last_heartbeat) <= timeout_seconds

    async def is_agent_paired(self) -> bool:
        """
        Check if agent identity is already persisted.
        """
        state = await self.load_agent_state()
        return bool(
            state
            and state.agent_id
            and state.agent_secret
        )

    async def save_agent_identity(
        self,
        agent_id: str,
        agent_secret: str,
    ) -> None:
        """
        Persist agent identity after successful pairing.
        """
        # ✅ OPTIONAL: Use agent lock for thread safety (future-proofing)
        async with self._agent_lock:
            existing = await self.load_agent_state()

            state = existing or AgentState()

            state.agent_id = agent_id
            state.agent_secret = agent_secret
            state.started_at = int(datetime.utcnow().timestamp())  # ✅ Set start time
            state.state = "connected"
            state.last_heartbeat = int(datetime.utcnow().timestamp())

            path = self._get_agent_state_path()
            temp = path.with_suffix(".tmp")

            with open(temp, "w", encoding="utf-8") as f:
                json.dump(state.to_dict(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp, path)

    async def get_agent_credentials(self) -> Optional[Dict[str, str]]:
        """
        Return agent credentials for HTTP auth headers.
        """
        state = await self.load_agent_state()
        if not state or not state.agent_id or not state.agent_secret:
            return None

        return {
            "X-Agent-Id": state.agent_id,
            "X-Agent-Secret": state.agent_secret,
        }


# Factory function for convenience
def create_state_manager(state_dir: Optional[str] = None) -> StateManager:
    """
    Create and return a StateManager instance.
    
    Args:
        state_dir: Optional custom state directory
        
    Returns:
        StateManager instance
    """
    return StateManager(state_dir)
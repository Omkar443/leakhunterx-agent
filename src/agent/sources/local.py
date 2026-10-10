"""Descriptor-relative traversal; symlinks, devices and changed files fail closed."""
import hashlib
import os
import stat
from pathlib import PurePosixPath
from agent.local.registry import PROFILES
from agent.sources.base import Artifact
from agent.js.ignore_policy import IgnorePolicy

TEXT_SUFFIXES = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.xml', '.toml',
                '.py', '.java', '.kt', '.go', '.rs', '.php', '.rb', '.sh', '.bash', '.env', '.ini', '.conf',
                '.config', '.properties', '.tf', '.tfvars', '.pem', '.key', '.txt', '.sql', '.html', '.vue', '.svelte'}
SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv', '.idea', '.next', 'dist', 'build', 'coverage'}


class LocalSource:
    def __init__(self, root, profile='standard', cancelled=lambda: False):
        self.root = str(root)
        if profile not in PROFILES: raise ValueError('Unsupported profile')
        self.limits = PROFILES[profile]
        self.cancelled = cancelled
        self.root_fd = None
        self.windows = None
        self.failures = 0
        self.skipped = 0
        self.visited = 0
        self.bytes_read = 0
        self.limited = False
        self.policy = IgnorePolicy()
        self._metadata_only = False

    def prepare(self):
        # Native Windows junction-safe handle traversal is a separate verified
        # implementation. Never silently substitute a race-prone string walk.
        if os.name == 'nt':
            from agent.local.windows_fs import WindowsRoot
            self.windows = WindowsRoot(self.root)
        elif os.name != 'posix' or os.open not in os.supports_dir_fd:
            raise RuntimeError('Secure local filesystem traversal is not available on this runtime')
        else:
            from pathlib import Path
            root = Path(self.root)
            if not root.is_absolute(): root = root.absolute()
            fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in root.parts[1:]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                self.root_fd = fd
            except BaseException:
                os.close(fd)
                raise
        try:
            raw = self.read('.lhxignore', 65536)
        except FileNotFoundError:
            return
        # Parse bytes already opened relative to the authorized root, avoiding
        # IgnorePolicy.load's path-based open race.
        self.policy = IgnorePolicy.parse(raw.decode('utf-8'))

    def read(self, locator, maximum):
        if self.windows:
            with self.windows.file(locator) as file_fd:
                return self._read_fd(file_fd, maximum)
        parts = PurePosixPath(locator).parts
        if not parts or any(part in ('..', '.', '') for part in parts) or PurePosixPath(locator).is_absolute() or '\\' in locator:
            raise ValueError('Invalid relative artifact path')
        fd = os.dup(self.root_fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                return self._read_fd(file_fd, maximum)
            finally:
                os.close(file_fd)
        finally:
            os.close(fd)

    def _read_fd(self, file_fd, maximum):
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode): raise ValueError('Artifact is not a regular file')
        if before.st_nlink > 1: raise ValueError('Hard-linked artifacts are excluded')
        if before.st_size > maximum: raise OverflowError('Artifact exceeds scan limits')
        chunks = []
        remaining = maximum + 1
        while remaining:
            if self.cancelled(): raise InterruptedError('Scan cancelled')
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk: break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b''.join(chunks)
        after = os.fstat(file_fd)
        if len(content) > maximum: raise OverflowError('Artifact exceeds scan limits')
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise OSError('Artifact changed while being read')
        return content

    def artifacts(self):
        if self.root_fd is None and self.windows is None: raise RuntimeError('Source is not prepared')
        yield from self._walk(self.root_fd, '', 0)

    def enumerate(self):
        self._metadata_only = True
        try: yield from self.artifacts()
        finally: self._metadata_only = False

    def read_artifact(self, locator):
        raw = self.read(locator, self.limits['max_file_bytes'])
        if self.bytes_read + len(raw) > self.limits['max_bytes']:
            self.limited = True
            raise OverflowError('Project exceeds scan byte limits')
        self.bytes_read += len(raw)
        if b'\x00' in raw[:8192]:
            self.skipped += 1
            self.limited = True
            return None
        try: content = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            self.skipped += 1
            self.limited = True
            return None
        path = PurePosixPath(locator)
        return Artifact(hashlib.sha256(locator.encode()).hexdigest(), 'LOCAL', locator, 'text/plain', path.suffix.lstrip('.'), len(raw), hashlib.sha256(raw).hexdigest(), content)

    def _walk(self, directory_fd, prefix, depth):
        if depth > 64:
            self.limited = True
            return
        # Streaming traversal: never materialize an entire project directory.
        with os.scandir(str(self.windows.root / prefix) if self.windows else directory_fd) as entries:
            for entry in entries:
                if self.cancelled(): raise InterruptedError('Scan cancelled')
                self.visited += 1
                if self.visited > self.limits['max_files']:
                    self.limited = True
                    return
                locator = prefix + entry.name
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        self.skipped += 1
                        self.limited = True
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if entry.name in SKIP_DIRS or self.policy.matches(locator + '/', '', ''):
                            continue
                        if self.windows:
                            with self.windows.directory(locator): yield from self._walk(None, locator + '/', depth + 1)
                        else:
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                            try: yield from self._walk(child, locator + '/', depth + 1)
                            finally: os.close(child)
                        if self.visited > self.limits['max_files']: return
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        self.skipped += 1
                        self.limited = True
                        continue
                    path = PurePosixPath(locator)
                    if not (path.suffix.lower() in TEXT_SUFFIXES or path.name.startswith('.env') or path.name in ('Dockerfile', 'Makefile', 'id_rsa', 'id_ed25519')):
                        continue
                    if self.policy.matches(locator, '', ''): continue
                    if info.st_size > self.limits['max_file_bytes']:
                        self.skipped += 1
                        self.limited = True
                        continue
                    if self._metadata_only:
                        yield Artifact(hashlib.sha256(locator.encode()).hexdigest(), 'LOCAL', locator, 'text/plain', path.suffix.lstrip('.'), info.st_size, '', '')
                    else:
                        artifact = self.read_artifact(locator)
                        if artifact is not None: yield artifact
                except (PermissionError, FileNotFoundError, OSError, ValueError, OverflowError):
                    self.failures += 1

    def cleanup(self):
        if self.windows:
            self.windows.close()
            self.windows = None
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None

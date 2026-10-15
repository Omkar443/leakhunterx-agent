"""Owner-private SQLite registry and checkpoints, independent of cloud access."""
import json
import os
import secrets
import sqlite3
import stat
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path

from agent.utils.secret_path import get_agent_secret_path

PROFILES = {'quick': {'max_files': 10000, 'max_bytes': 100_000_000, 'max_file_bytes': 1_000_000},
            'standard': {'max_files': 100000, 'max_bytes': 500_000_000, 'max_file_bytes': 5_000_000},
            'deep': {'max_files': 200000, 'max_bytes': 1_000_000_000, 'max_file_bytes': 10_000_000}}


class Registry:
    def __init__(self, path=None):
        self.path = Path(path) if path else get_agent_secret_path().parent / 'agent.db'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path is None and os.name == 'posix' and not self.path.parent.is_symlink() and self.path.parent.stat().st_uid == os.getuid():
            os.chmod(self.path.parent, 0o700)
        if os.name == 'nt':
            from agent.local.windows_fs import protect_private_path
            protect_private_path(self.path.parent)
        info = self.path.parent.lstat()
        if stat.S_ISLNK(info.st_mode) or (os.name == 'posix' and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
            raise ValueError('Registry directory must be private and owned by the current user')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (os.name == 'posix' and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
                raise ValueError('Registry file must be private and owned by the current user')
        finally:
            os.close(fd)
        if os.name == 'nt': protect_private_path(self.path)
        with self.connect() as db:
            # Readers (heartbeats/configuration) must not block checkpoint commits.
            # The private parent and database permissions also protect WAL sidecars.
            if db.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() != 'wal':
                raise ValueError('Local checkpoint storage requires WAL support')
            columns = {row[1] for row in db.execute('PRAGMA table_info(targets)')}
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if {'source_type','repository_url','app_managed'} <= columns and {'targets','scans','files','github_snapshots'} <= tables:
                return  # Existing registries need no schema write lock per heartbeat.
            db.executescript('''
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
                    project_id TEXT, dashboard_allowed INTEGER NOT NULL DEFAULT 0,
                    profile TEXT NOT NULL DEFAULT 'standard', config_version INTEGER NOT NULL DEFAULT 1,
                    key BLOB NOT NULL, key_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY, target_id TEXT NOT NULL, scope TEXT NOT NULL,
                    status TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TEXT,
                    FOREIGN KEY(target_id) REFERENCES targets(id));
                CREATE TABLE IF NOT EXISTS files (
                    scan_id TEXT NOT NULL, locator TEXT NOT NULL, digest TEXT NOT NULL,
                    size INTEGER NOT NULL, findings TEXT NOT NULL,
                    PRIMARY KEY(scan_id, locator), FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE);
            ''')
            db.execute('BEGIN IMMEDIATE')
            columns = {row[1] for row in db.execute('PRAGMA table_info(targets)')}
            if 'source_type' not in columns: db.execute("ALTER TABLE targets ADD COLUMN source_type TEXT NOT NULL DEFAULT 'LOCAL'")
            if 'repository_url' not in columns: db.execute('ALTER TABLE targets ADD COLUMN repository_url TEXT')
            if 'app_managed' not in columns: db.execute('ALTER TABLE targets ADD COLUMN app_managed INTEGER NOT NULL DEFAULT 0')
            db.execute('''CREATE TABLE IF NOT EXISTS github_snapshots (
                scan_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, repository_url TEXT NOT NULL,
                branch TEXT NOT NULL, commit_sha TEXT NOT NULL, FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE)''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def scan_lock(self):
        fd = os.open(self.path.parent / 'scan.lock', os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.name == 'posix':
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                if not os.fstat(fd).st_size: os.write(fd, b'0')
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            yield
        finally:
            os.close(fd)

    def add(self, path, name=None, project_id=None, profile='standard'):
        root = Path(path).expanduser().resolve(strict=True)
        if not root.is_dir() or profile not in PROFILES:
            raise ValueError('Choose an existing directory and supported profile')
        name = name or root.name
        if not isinstance(name,str): raise ValueError('Use a display name')
        name = name.strip()
        if not 1 <= len(name) <= 80 or any(ord(c) < 32 or ord(c)==127 or c in '/\\' for c in name):
            raise ValueError('Display name must be 1–80 characters without paths or control characters')
        identifier = str(uuid.uuid4())
        if project_id: project_id = str(uuid.UUID(project_id))
        with self.connect() as db:
            if db.execute('SELECT count(*) FROM targets').fetchone()[0] >= 100: raise ValueError('Local target registration limit reached')
            db.execute('INSERT INTO targets(id,name,path,project_id,profile,key,key_id) VALUES(?,?,?,?,?,?,?)',
                       (identifier, name, str(root), project_id, profile, secrets.token_bytes(32), str(uuid.uuid4())))
        return self.get(identifier)

    def get(self, identifier):
        with self.connect() as db:
            row = db.execute('SELECT * FROM targets WHERE id=?', (str(identifier),)).fetchone()
        if not row: raise ValueError('Local target not registered')
        return dict(row)

    def add_repository(self, url, name=None, project_id=None, profile='standard'):
        from agent.sources.github import repository_url, private_directory
        url = repository_url(url)
        if profile not in PROFILES: raise ValueError('Unsupported profile')
        identifier = str(uuid.uuid4())
        name = name or url.rsplit('/',1)[-1]
        if not isinstance(name,str) or not 1 <= len(name.strip()) <= 80 or any(ord(c)<32 or ord(c)==127 or c in '/\\' for c in name): raise ValueError('Invalid repository display name')
        if project_id: project_id = str(uuid.UUID(project_id))
        root = self.path.parent / 'repositories' / identifier
        with self.connect() as db:
            if db.execute('SELECT count(*) FROM targets').fetchone()[0] >= 100: raise ValueError('Target registration limit reached')
            if db.execute("SELECT id FROM targets WHERE source_type='GITHUB' AND repository_url=? AND project_id IS ?",(url,project_id)).fetchone(): raise ValueError('Repository already registered for this project')
            private_directory(private_directory(root.parent) / identifier)
            db.execute('INSERT INTO targets(id,name,path,project_id,profile,key,key_id,source_type,repository_url) VALUES(?,?,?,?,?,?,?,?,?)',
                (identifier,name.strip(),str(root),project_id,profile,secrets.token_bytes(32),str(uuid.uuid4()),'GITHUB',url))
        return self.get(identifier)

    def list(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT * FROM targets ORDER BY created_at,id')]

    def find_path(self, path):
        root = str(Path(path).expanduser().resolve(strict=True))
        return next((target for target in self.list() if target['path'] == root), None)

    def update(self, identifier, *, allowed=None, path=None, project_id=None, profile=None):
        target = self.get(identifier)
        if path is not None:
            if target['source_type'] == 'GITHUB': raise ValueError('Repository location is managed by the agent')
            root = Path(path).expanduser().resolve(strict=True)
            if not root.is_dir(): raise ValueError('Choose an existing directory')
            target['path'] = str(root)
        if project_id is not None: target['project_id'] = str(uuid.UUID(project_id))
        if profile is not None:
            if profile not in PROFILES: raise ValueError('Unsupported scan profile')
            target['profile'] = profile
        if allowed is not None: target['dashboard_allowed'] = int(bool(allowed))
        # Location moves preserve target identity and keyed finding identities.
        with self.connect() as db:
            db.execute('UPDATE targets SET path=?,project_id=?,dashboard_allowed=?,profile=?,config_version=config_version+1 WHERE id=?',
                       (target['path'], target['project_id'], target['dashboard_allowed'], target['profile'], str(identifier)))
        return self.get(identifier)

    def remove(self, identifier):
        target = self.get(identifier)
        with self.scan_lock() if target['source_type']=='GITHUB' else nullcontext():
            if target['source_type']=='GITHUB':
                from agent.sources.github import discard_repository
                discard_repository(self,target)
            with self.connect() as db:
                # Local project files stay intact; GitHub caches are agent owned.
                db.execute('UPDATE targets SET dashboard_allowed=0,project_id=NULL WHERE id=?', (str(identifier),))
                db.execute('DELETE FROM scans WHERE target_id=?', (str(identifier),))
                db.execute('DELETE FROM targets WHERE id=?', (str(identifier),))

    def metadata(self, source_type='LOCAL'):
        # Explicit allowlist: no path, key, file contents or local checkpoint data.
        return [dict(id=t['id'], project_id=t['project_id'], display_name=t['name'], profile=t['profile'],
                     config_version=t['config_version'], remote_scan_allowed=bool(t['dashboard_allowed']),
                     availability='available' if Path(t['path']).is_dir() else 'missing',
                     **({'repository_url':t['repository_url']} if source_type=='GITHUB' else {}))
                for t in self.list() if t['project_id'] and t['source_type']==source_type and not t['app_managed']]

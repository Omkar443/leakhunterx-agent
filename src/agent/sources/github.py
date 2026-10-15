"""Pinned GitHub snapshots. Git, credentials and all repository content stay local.

Only tracked blobs from the current default branch are read. No checkout,
hooks, filters, submodules, LFS, history or repository code is executed.
"""
import base64
import os
from pathlib import Path, PurePosixPath
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import time
import unicodedata
from contextlib import contextmanager
from urllib.parse import urlsplit

from agent.local.registry import PROFILES
from agent.local.failures import GitHubScanError


def repository_url(value):
    if not isinstance(value, str) or len(value) > 300: raise ValueError('Invalid GitHub repository')
    url = urlsplit(value)
    if (url.scheme != 'https' or url.netloc.lower() != 'github.com' or url.query or url.fragment
            or url.username or url.password): raise ValueError('Use a GitHub HTTPS repository URL without credentials')
    parts = url.path.strip('/').split('/')
    if len(parts) != 2: raise ValueError('Use a repository URL, not a branch, file or pull request')
    owner, repo = parts
    if repo.endswith('.git'): repo = repo[:-4]
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})', owner) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', repo) or repo in ('.', '..'):
        raise ValueError('Invalid GitHub repository name')
    return f'https://github.com/{owner.lower()}/{repo.lower()}'


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise ValueError('Unsafe repository cache')
    if os.name == 'posix':
        if info.st_uid != os.getuid() or info.st_mode & 0o077: raise ValueError('Repository cache must be owner private')
    else:
        from agent.local.windows_fs import protect_private_path
        protect_private_path(path)
    return path


def git_command(root, args, *, network=False, cancelled=lambda:False, limit=16_000_000, timeout=90, credential=None, use_local_credential=True):
    executable = shutil.which('git')
    if not executable: raise GitHubScanError('github_git_unavailable')
    # Never inherit arbitrary GIT_CONFIG/GIT_TRACE/askpass/helper overrides.
    env = {k:v for k,v in os.environ.items() if k in ('PATH','SystemRoot','SYSTEMROOT','WINDIR','TMP','TEMP','TMPDIR','SSL_CERT_FILE','SSL_CERT_DIR')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0', GIT_LFS_SKIP_SMUDGE='1')
    token = credential or ((os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')) if use_local_credential else None)
    if network and token:
        if len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token): raise ValueError('Invalid local GitHub credential')
        encoded = base64.b64encode(f'x-access-token:{token}'.encode()).decode()
        env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraHeader', GIT_CONFIG_VALUE_0=f'Authorization: Basic {encoded}')
    command = [executable, '-c','core.hooksPath='+os.devnull,'-c','credential.helper=',
        '-c','protocol.allow=never','-c','protocol.https.allow=always','-c','http.followRedirects=false',
        '-c','http.lowSpeedLimit=1024','-c','http.lowSpeedTime=20','-c','fetch.fsckObjects=true',
        '-c','transfer.fsckObjects=true','-c','init.templateDir=', *args]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
            start_new_session=os.name=='posix',
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        started = time.monotonic()
        try:
            while process.poll() is None:
                if cancelled(): raise InterruptedError('Scan cancelled')
                if time.monotonic()-started > timeout: raise GitHubScanError('github_acquisition_timeout')
                if os.fstat(out.fileno()).st_size > limit or os.fstat(err.fileno()).st_size > 1_000_000:
                    raise GitHubScanError('github_download_limit')
                # Bound downloaded packs, including Git temporary packfiles.
                if network and sum(p.stat().st_size for p in Path(root).rglob('*') if p.is_file() and not p.is_symlink()) > 256_000_000:
                    raise GitHubScanError('github_download_limit')
                time.sleep(.05 if network else .005)
            if process.returncode: raise GitHubScanError('github_acquisition_failed')
            if os.fstat(out.fileno()).st_size > limit: raise GitHubScanError('github_download_limit')
            out.seek(0)
            return out.read(limit+1)
        finally:
            if process.poll() is None:
                if os.name=='posix': os.killpg(process.pid, signal.SIGKILL)
                else:
                    # Git may have spawned its HTTPS helper; stop the owned tree.
                    try:
                        subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
                    except (OSError,subprocess.TimeoutExpired): pass
                    if process.poll() is None: process.kill()
                process.wait(timeout=10)


def remove_cache_tree(root):
    """Windows Git packs are read-only; remove only verified cache files."""
    root = Path(root).absolute()
    def retry_readonly(action, path, error):
        candidate=Path(path).absolute()
        candidate.relative_to(root)
        info=candidate.lstat()
        if (os.name!='nt' or not isinstance(error[1],PermissionError)
                or action not in (os.unlink,os.remove) or not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)):
            raise error[1]
        os.chmod(candidate,stat.S_IREAD|stat.S_IWRITE)
        action(candidate)
    shutil.rmtree(root,onerror=retry_readonly)


@contextmanager
def acquisition_store(registry, target):
    """Each attempt owns its Git locks; checkpoints retain pins, not lock state.

    A killed fetch/history lookup can leave shallow.lock behind. Never reuse or
    unlink another attempt's locks. Resume fetches the same persisted commit
    into a new private object store, while redacted file checkpoints are reused.
    """
    from uuid import UUID
    cache = private_directory(private_directory(registry.path.parent / 'repositories') / str(UUID(target['id'])))
    path = private_directory(tempfile.mkdtemp(prefix='git-attempt-', dir=cache))
    try:
        yield path
    finally:
        # All subprocesses belonging to this attempt have been reaped by
        # git_command before this context closes. Never follow a substituted link.
        if path.is_symlink() or path.resolve().parent != cache.resolve():
            raise GitHubScanError('github_cache_unavailable')
        try:
            remove_cache_tree(path)
        except OSError:
            # A cleanup failure must not turn a completed scan into a failure;
            # a later attempt never reuses this directory.
            import logging
            logging.getLogger(__name__).warning('Private Git acquisition cleanup deferred')


def discard_snapshot(registry, target_id, scan_id):
    """Remove only an owned, terminal snapshot; keep interrupted pins resumable."""
    from uuid import UUID
    target_id, scan_id = str(UUID(target_id)), str(UUID(scan_id))
    base = registry.path.parent / 'repositories'
    root = base / target_id / 'snapshots' / scan_id
    if not root.exists(): return
    for directory in (base, base/target_id, base/target_id/'snapshots', root):
        private_directory(directory)
    # Each directory is owner-private, and rmtree never follows contained links.
    remove_cache_tree(root)
    with registry.connect() as db:
        active = db.execute("SELECT 1 FROM scans WHERE target_id=? AND status IN ('running','interrupted') LIMIT 1",(target_id,)).fetchone()
    objects = base/target_id/'objects.git'
    if not active and objects.exists():
        private_directory(objects)
        remove_cache_tree(objects)


def discard_repository(registry, target):
    """Forget owned Git objects and interrupted snapshots on deregistration."""
    from uuid import UUID
    base = registry.path.parent / 'repositories'
    root = base / str(UUID(target['id']))
    if Path(target['path']).absolute() != root.absolute():
        raise ValueError('Repository cache location mismatch')
    if not root.exists(): return
    for directory in (base, root): private_directory(directory)
    remove_cache_tree(root)


def snapshot(registry, target, scan_id, *, resume=False, profile='standard', cancelled=lambda:False, runner=None, object_store=None):
    runner = runner or git_command
    url = repository_url(target['repository_url'])
    parent = private_directory(registry.path.parent / 'repositories')
    cache = private_directory(parent / target['id'])
    objects = private_directory(object_store if object_store is not None else cache / 'objects.git')
    snapshots = private_directory(cache / 'snapshots')
    root = private_directory(snapshots / scan_id)
    runner(objects, ['init','--bare','.'], cancelled=cancelled)
    with registry.connect() as db:
        previous = db.execute('SELECT * FROM github_snapshots WHERE scan_id=?', (scan_id,)).fetchone()
    if resume and not previous: raise ValueError('Pinned repository checkpoint unavailable')
    if previous:
        if previous['target_id'] != target['id'] or previous['repository_url'] != url: raise ValueError('Repository checkpoint mismatch')
        branch, commit = previous['branch'], previous['commit_sha']
        pin=target.get('commit_pin')
        if pin is not None and (not isinstance(pin,dict) or pin.get('commit_sha')!=commit or pin.get('branch')!=branch):raise ValueError('Requested commit differs from the recovery checkpoint')
    else:
        head = runner(objects, ['ls-remote','--symref',url,'HEAD'], network=True, cancelled=cancelled, limit=4096).decode('ascii')
        branch_match = re.search(r'^ref: refs/heads/([^\t\n]+)\tHEAD$', head, re.M)
        sha_match = re.search(r'^([a-f0-9]{40}|[a-f0-9]{64})\tHEAD$', head, re.M)
        if not branch_match or not sha_match: raise RuntimeError('Repository default branch unavailable')
        branch, commit = branch_match[1], sha_match[1]
        pin=target.get('commit_pin')
        if pin is not None:
            if (not isinstance(pin,dict) or set(pin)!={'commit_sha','branch'} or pin.get('branch')!=branch
                    or not isinstance(pin.get('commit_sha'),str) or not re.fullmatch(r'[a-f0-9]{40}(?:[a-f0-9]{24})?',pin['commit_sha'])
                    or pin['commit_sha']!=commit):raise ValueError('Requested commit is no longer the authorized default-branch head')
            commit=pin['commit_sha']
        if len(branch)>255 or not re.fullmatch(r'[A-Za-z0-9_./-]+',branch) or '..' in branch or branch.startswith(('-', '/')): raise ValueError('Unsupported default branch name')
        with registry.connect() as db:
            db.execute('INSERT INTO github_snapshots(scan_id,target_id,repository_url,branch,commit_sha) VALUES(?,?,?,?,?)', (scan_id,target['id'],url,branch,commit))
    # Persist the SHA before fetching. An interrupted download must not silently
    # scan a newer default-branch head after a restart or credential refresh.
    present=False
    if previous:
        try: present=runner(objects,['rev-parse','--verify',commit+'^{commit}'],cancelled=cancelled,limit=256).decode().strip()==commit
        except RuntimeError: pass
    if not present:
        runner(objects,['fetch','--depth=1','--no-tags','--no-recurse-submodules',url,commit],network=True,cancelled=cancelled,timeout=120)
    resolved = runner(objects,['rev-parse','--verify',commit+'^{commit}'],cancelled=cancelled,limit=256).decode().strip()
    if resolved != commit: raise RuntimeError('Repository snapshot could not be pinned')
    limits = PROFILES[profile]
    from agent.sources.local import TEXT_SUFFIXES, SKIP_DIRS
    tree = runner(objects,['ls-tree','-rlz',commit],cancelled=cancelled,limit=32_000_000)
    total = count = 0
    limited = False
    destinations = set()
    for entry in tree.split(b'\0'):
        if not entry: continue
        if cancelled(): raise InterruptedError('Scan cancelled')
        header, raw_path = entry.split(b'\t',1)
        mode, kind, oid, size = header.split()
        try: path = raw_path.decode('utf-8')
        except UnicodeError:
            limited = True
            continue
        parts = PurePosixPath(path).parts
        if (not parts or any(p in ('.','..','.git') for p in parts) or path.startswith('/') or '\\' in path or ':' in path
                or any(ord(c)<32 or ord(c)==127 for c in path) or len(path)>1024):
            limited = True
            continue
        normalized = '/'.join(unicodedata.normalize('NFC',p).casefold().rstrip(' .') for p in parts)
        reserved = {'con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),*(f'lpt{i}' for i in range(1,10))}
        if normalized in destinations or any(p.endswith((' ','.')) or p.split('.')[0].casefold() in reserved for p in parts):
            limited = True  # Do not overwrite blobs on case-insensitive filesystems.
            continue
        destinations.add(normalized)
        if mode not in (b'100644',b'100755') or kind != b'blob':
            limited = True  # symlinks/submodules are never followed
            continue
        if any(part in SKIP_DIRS for part in parts[:-1]): continue
        source_path=PurePosixPath(path)
        if not (source_path.suffix.lower() in TEXT_SUFFIXES or source_path.name.startswith('.env')
                or source_path.name in ('.lhxignore','Dockerfile','Makefile','id_rsa','id_ed25519')): continue
        length = int(size)
        if count >= limits['max_files'] or total+length > limits['max_bytes']:
            limited = True
            break
        if length > limits['max_file_bytes']:
            limited = True
            continue
        destination = root.joinpath(*parts)
        # Owner-private snapshot directories contain regular blobs only.
        for ancestor in [destination.parent,*destination.parents]:
            if ancestor == root.parent: break
            if ancestor.exists() and ancestor.is_symlink(): raise ValueError('Unsafe snapshot path')
        destination.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        if destination.is_symlink() or (destination.exists() and not destination.is_file()): raise ValueError('Unsafe snapshot file')
        content = runner(objects,['cat-file','blob',oid.decode('ascii')],cancelled=cancelled,limit=limits['max_file_bytes'])
        if len(content) != length: raise RuntimeError('Repository blob integrity mismatch')
        if content.startswith(b'version https://git-lfs.github.com/spec/v1\n'):
            limited = True
        fd = os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream: stream.write(content)
        count += 1
        total += length
    return str(root), dict(repository_url=url,branch=branch,commit_sha=commit), limited

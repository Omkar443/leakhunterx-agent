"""Bounded local operator policy. Never load policies from a scanned website."""
from dataclasses import dataclass
from fnmatch import fnmatchcase
import hashlib
from pathlib import Path
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class IgnorePolicy:
    paths: tuple = ()
    rules: tuple = ()
    fingerprints: tuple = ()
    digest: str = ''

    @classmethod
    def load(cls, path='.lhxignore'):
        source = Path(path)
        if not source.exists(): return cls()
        if source.is_symlink() or source.stat().st_size > 65536: raise ValueError('Unsafe or oversized .lhxignore file')
        text = source.read_text(encoding='utf-8')
        paths, rules, fingerprints = [], [], []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            if len(line)>512 or len(paths)+len(rules)+len(fingerprints)>=256: raise ValueError('.lhxignore rule limit exceeded')
            if line.startswith('rule:'):
                rule = line[5:]
                if not re.fullmatch(r'[a-z][a-z0-9_]{0,79}',rule): raise ValueError('Invalid ignore rule ID')
                rules.append(rule)
            elif line.startswith(('finding:','test:')):
                fp = line.split(':',1)[1]
                if not re.fullmatch(r'[a-f0-9]{32,64}',fp): raise ValueError('Ignore findings require a fingerprint, never a raw credential')
                fingerprints.append(fp)
            else:
                pattern = line.removeprefix('path:').replace('\\','/').lstrip('/')
                if '..' in pattern.split('/') or ':' in pattern: raise ValueError('Invalid ignored path')
                paths.append(pattern)
        return cls(tuple(paths),tuple(rules),tuple(fingerprints),hashlib.sha256(text.encode()).hexdigest())

    def matches(self, path, rule, fingerprint):
        path = urlsplit(path).path.lstrip('/') if path.startswith(('http://','https://')) else path.replace('\\','/').lstrip('/')
        return rule in self.rules or fingerprint in self.fingerprints or any(fnmatchcase(path, p) or fnmatchcase(path, '**/'+p) for p in self.paths)

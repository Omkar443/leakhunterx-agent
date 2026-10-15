"""Bounded agent-side origin proof. Never publish history content or credentials."""
import time
import hashlib
from agent.correlation import normalized_secret


class OriginTracer:
    def __init__(self,registry,target,metadata,cancelled,runner=None,object_store=None):
        from agent.sources.github import git_command
        self.root=object_store if object_store is not None else registry.path.parent/'repositories'/target['id']/'objects.git'
        self.pin=metadata['commit_sha']; self.url=metadata['repository_url']
        self.runner=runner or git_command; self.cancelled=cancelled
        self.started=None; self.commits=None; self.cache={}; self.checked=0

    def trace(self,locator,detector,value):
        unknown={'status':'not_established','reason':'history_limit','last_containing_commit':self.pin}
        if self.cancelled(): raise InterruptedError('Scan cancelled')
        if self.checked>=20: return unknown
        self.checked+=1
        if self.started is None: self.started=time.monotonic()
        if time.monotonic()-self.started>20: return unknown
        try:
            def call(args,**kwargs):
                remaining=20-(time.monotonic()-self.started)
                if remaining<=0:raise TimeoutError('Origin budget reached')
                kwargs['timeout']=min(kwargs.get('timeout',2),remaining)
                return self.runner(self.root,args,**kwargs)
            if self.commits is None:
                # The exact authorized pinned SHA is the sole history root.
                # An unavailable history must never fail a current-source scan.
                call(['fetch','--depth=32','--no-tags','--no-recurse-submodules',self.url,self.pin],
                    network=True,cancelled=self.cancelled,timeout=15,limit=4096)
                raw=call(['rev-list','--first-parent','--max-count=32',self.pin],cancelled=self.cancelled,timeout=2,limit=4096)
                self.commits=raw.decode('ascii').splitlines()
            secret=normalized_secret(detector,value)
            def contains(commit):
                key=(commit,locator,hashlib.sha256(secret.encode()).digest())
                if key not in self.cache:
                    try:
                        content=call(['show',commit+':'+locator],cancelled=self.cancelled,limit=2_000_000,timeout=2).decode('utf8',errors='replace')
                        self.cache[key]=secret in normalized_secret(detector,content)
                    except RuntimeError:
                        # Verify the tree before declaring a missing file absent.
                        found=call(['ls-tree','-z',commit,'--',locator],cancelled=self.cancelled,timeout=2,limit=4096)
                        if found: raise
                        self.cache[key]=False
                return self.cache[key]
            for commit in self.commits:
                if time.monotonic()-self.started>20: return unknown
                if not contains(commit): break
                parents=call(['cat-file','-p',commit],cancelled=self.cancelled,timeout=2,limit=65536).decode('utf8',errors='replace')
                parent_ids=[line.split(' ',1)[1] for line in parents.splitlines() if line.startswith('parent ')]
                if len(parent_ids)>16:return unknown
                if not parent_ids:
                    # cat-file retains true parent headers even at shallow roots.
                    return {'status':'proved','introduced_commit':commit,'last_containing_commit':self.pin,'method':'all_parents_absent_v1'}
                if all(not contains(parent) for parent in parent_ids):
                    return {'status':'proved','introduced_commit':commit,'last_containing_commit':self.pin,'method':'all_parents_absent_v1'}
            return unknown
        except InterruptedError: raise
        except TimeoutError:return unknown
        except (OSError,RuntimeError,ValueError,UnicodeError):
            return {'status':'not_established','reason':'history_unavailable','last_containing_commit':self.pin}

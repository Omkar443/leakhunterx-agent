"""Real Git commits and detector; transport replaced only with a local fixture."""
import json
import os
import subprocess
from uuid import uuid4
import pytest
from agent.local.registry import Registry
from agent.local.scanner import scan_local, local_delta, result
from agent.sources.github import git_command, repository_url, snapshot

SECRET='ghp_'+'b7Tf9pQ2jK4vC6xD8mF0sH3nR5wY1zA9uE7g'


def git(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.DEVNULL).decode().strip()


@pytest.fixture
def repository(tmp_path,monkeypatch):
    root=tmp_path/'fixture';root.mkdir()
    git(root,'init','-b','main');git(root,'config','user.email','fixture@example.invalid');git(root,'config','user.name','Fixture')
    (root/'config.js').write_text(f'// PRIVATE_SOURCE_MARKER\nconst githubToken="{SECRET}";')
    git(root,'add','.');git(root,'commit','-m','Baseline')
    private=tmp_path/'private';private.mkdir(mode=0o700)
    registry=Registry(private/'agent.db');target=registry.add_repository('https://github.com/example/fixture',project_id=str(uuid4()))
    def runner(cache,args,**kwargs):
        kwargs['network']=False
        return git_command(cache,['-c','protocol.file.allow=always',*[str(root) if arg==target['repository_url'] else arg for arg in args]],**kwargs)
    monkeypatch.setattr('agent.sources.github.git_command',runner)
    return registry,target,root


def test_default_branch_pinned_delta_and_private_payload(repository):
    registry,target,root=repository
    events=[]
    first=scan_local(registry,target,on_event=lambda k,d:events.append((k,d)))
    assert first['status']=='completed' and first['complete'] and first['findings_count']==1
    assert first['commit_sha']==git(root,'rev-parse','HEAD') and first['branch']=='main' and first['source_type']=='GITHUB'
    assert not (registry.path.parent/'repositories'/target['id']/'snapshots'/first['scan_id']).exists()
    payload=json.dumps(events)
    assert all(v not in payload for v in (SECRET,'PRIVATE_SOURCE_MARKER','githubToken',str(root)))
    assert all('key' not in t and 'path' not in t for t in registry.metadata('GITHUB'))
    (root/'config.js').write_text(f'\n\nconst githubToken="{SECRET}";')
    git(root,'add','.');git(root,'commit','-m','Line shift')
    second=scan_local(registry,target)
    assert second['commit_sha']!=first['commit_sha'] and len(local_delta(registry,second['scan_id'])['existing'])==1
    (root/'config.js').write_text('const githubToken=process.env.GITHUB_TOKEN;')
    git(root,'add','.');git(root,'commit','-m','Remove fixture credential')
    third=scan_local(registry,target)
    assert len(local_delta(registry,third['scan_id'])['resolved'])==1
    assert not result(registry,third['scan_id'])['findings']


def test_resume_is_same_commit_despite_head_change(repository):
    registry,target,root=repository
    def interrupt(kind,data):
        if kind=='secret_found': raise KeyboardInterrupt()
    first=scan_local(registry,target,on_event=interrupt)
    assert first['status']=='interrupted'
    assert (registry.path.parent/'repositories'/target['id']/'snapshots'/first['scan_id']).exists()
    (root/'config.js').write_text('const x=42;');git(root,'add','.');git(root,'commit','-m','Moving HEAD')
    resumed=scan_local(registry,target,scan_id=first['scan_id'],resume=True)
    assert resumed['complete'] and resumed['commit_sha']==first['commit_sha'] and resumed['findings_count']==1


@pytest.mark.skipif(os.name!='posix',reason='Fixture symlink')
def test_symlink_is_never_followed_and_resolution_remains_deferred(repository):
    registry,target,root=repository
    (root/'escape.js').symlink_to('/etc/passwd');git(root,'add','.');git(root,'commit','-m','Link fixture')
    outcome=scan_local(registry,target)
    assert outcome['status']=='completed' and not outcome['complete']
    assert local_delta(registry,outcome['scan_id'])['status']=='unavailable'


@pytest.mark.parametrize('url',['https://token@github.com/o/r','http://github.com/o/r','https://github.com.evil.invalid/o/r','https://github.com/o/r/tree/main','https://github.com/o/r?token=x','file:///tmp/repo','git@github.com:o/r','https://github.com/o/..'])
def test_credentials_and_non_repository_locators_rejected(url):
    with pytest.raises(ValueError): repository_url(url)


def test_cancelled_fetch_cannot_continue(repository):
    registry,target,_=repository
    with pytest.raises(InterruptedError): snapshot(registry,target,str(uuid4()),cancelled=lambda:True)


def test_local_authorization_never_enters_command_arguments_or_cache(repository,monkeypatch):
    registry,target,root=repository
    token='LOCAL_AUTHORIZATION_FIXTURE_ONLY'
    monkeypatch.setenv('GH_TOKEN',token)
    calls=[];popen=subprocess.Popen
    def capture(command,**kwargs):
        calls.append((command,kwargs.get('env',{})))
        return popen(command,**kwargs)
    monkeypatch.setattr(subprocess,'Popen',capture)
    git_command(root,['-c','protocol.file.allow=always','ls-remote',str(root),'HEAD'],network=True)
    git_command(root,['rev-parse','HEAD'])
    assert len(calls)==2 and token not in json.dumps([command for command,_ in calls])
    assert calls[0][1]['GIT_CONFIG_KEY_0']=='http.https://github.com/.extraHeader'
    assert 'GIT_CONFIG_VALUE_0' not in calls[1][1] and 'GH_TOKEN' not in calls[1][1]
    assert token not in git(root,'config','--list')


@pytest.mark.skipif(os.name!='posix',reason='Case-sensitive Git tree/device-name fixture requires Unix')
def test_cross_platform_path_collisions_cannot_claim_full_coverage(repository):
    registry,target,root=repository
    (root/'Config.js').write_text('const x=42;')
    (root/'CON.txt').write_text('reserved device fixture')
    git(root,'add','.');git(root,'commit','-m','Filesystem edge cases')
    summary=scan_local(registry,target)
    assert summary['status']=='completed' and not summary['complete']
    assert local_delta(registry,summary['scan_id'])['status']=='unavailable'


def test_deregister_removes_interrupted_repository_source_only(repository):
    registry,target,root=repository
    def interrupt(kind,data):
        if kind=='secret_found': raise KeyboardInterrupt()
    outcome=scan_local(registry,target,on_event=interrupt)
    assert outcome['status']=='interrupted'
    cache=registry.path.parent/'repositories'/target['id']
    assert cache.exists()
    registry.remove(target['id'])
    assert not cache.exists() and (root/'config.js').exists()
    with pytest.raises(ValueError): registry.get(target['id'])


def test_vendor_and_lhxignore_use_existing_local_policy(repository):
    registry,target,root=repository
    (root/'node_modules').mkdir()
    (root/'node_modules'/'vendor.js').write_text(f'const githubToken="{SECRET}";')
    (root/'ignored.js').write_text(f'const githubToken="{SECRET}";')
    (root/'.lhxignore').write_text('ignored.js\n')
    git(root,'add','.');git(root,'commit','-m','Ignore policy fixture')
    outcome=scan_local(registry,target)
    assert outcome['status']=='completed' and outcome['findings_count']==1
    findings=result(registry,outcome['scan_id'])['findings']
    assert all(f['file_path']=='config.js' for f in findings)


def test_completed_runtime_replays_pinned_redacted_evidence_after_source_cleanup(repository,monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock
    from agent.local.runtime import LocalScanOrchestrator
    from agent.orchestrator import ScanStatus
    registry,target,root=repository
    target=registry.update(target['id'],allowed=True)
    summary=scan_local(registry,target)
    assert summary['complete'] and not (registry.path.parent/'repositories'/target['id']/'objects.git').exists()
    (root/'config.js').write_text('const x=42;');git(root,'add','.');git(root,'commit','-m','Move HEAD after delivery loss')
    monkeypatch.setattr('agent.local.runtime.Registry',lambda:registry)
    emitter=AsyncMock()
    job=dict(scan_id=summary['scan_id'],target_id=target['id'],target='github://'+target['id'],
             source_type='GITHUB',profile='standard',config_version=target['config_version'])
    runtime=LocalScanOrchestrator(job,emitter);runtime._recovering=True
    asyncio.run(runtime.start_scan())
    events=[call.args[0] for call in emitter.emit.await_args_list]
    assert runtime.status==ScanStatus.COMPLETED
    completion=next(e for e in events if e['event_type']=='scan_completed')
    assert completion['data']['commit_sha']==summary['commit_sha'] and completion['data']['findings_count']==1
    assert len([e for e in events if e['event_type']=='secret_found'])==1
    assert SECRET not in json.dumps(events) and 'PRIVATE_SOURCE_MARKER' not in json.dumps(events)


def test_runtime_cancellation_during_git_acquisition_is_cancelled_not_failed(repository,monkeypatch):
    import asyncio
    from unittest.mock import AsyncMock
    from agent.local.runtime import LocalScanOrchestrator
    from agent.orchestrator import ScanStatus
    registry,target,_=repository
    target=registry.update(target['id'],allowed=True)
    monkeypatch.setattr('agent.local.runtime.Registry',lambda:registry)
    def interrupted(*args,**kwargs):raise InterruptedError('Scan cancelled')
    monkeypatch.setattr('agent.sources.github.snapshot',interrupted)
    emitter=AsyncMock()
    job=dict(scan_id=str(uuid4()),target_id=target['id'],target='github://'+target['id'],
             source_type='GITHUB',profile='standard',config_version=target['config_version'])
    runtime=LocalScanOrchestrator(job,emitter)
    asyncio.run(runtime.start_scan())
    assert runtime.status==ScanStatus.STOPPED
    assert emitter.emit.await_args.args[0]['event_type']=='scan_stopped'

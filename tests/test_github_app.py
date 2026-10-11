import asyncio
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import httpx
import pytest
from agent.local.registry import Registry
from agent.local.github_app import register_assignment,prepare_assignment,TemporaryGitAccess
from test_github_sources import repository,git


def assignment():
    tid=str(uuid4())
    return dict(scan_id=str(uuid4()),target_id=tid,target='github://'+tid,source_type='GITHUB',config_version=1,profile='standard',
        github_app=dict(repository_url='https://github.com/example/repository',repository_id=77,project_id=str(uuid4())))


def test_managed_registration_idempotent_private_and_scope_safe(tmp_path):
    registry=Registry(tmp_path/'private'/'agent.db');job=assignment()
    first=register_assignment(registry,job);second=register_assignment(registry,job)
    assert first['key']==second['key'] and first['key_id']==second['key_id']
    assert not registry.metadata('GITHUB') and len(registry.list())==1
    with pytest.raises(ValueError):register_assignment(registry,{**job,'github_app':{**job['github_app'],'repository_url':'https://github.com/example/other'}})
    with pytest.raises(ValueError):register_assignment(registry,{**job,'config_version':0})
    with pytest.raises(ValueError):register_assignment(registry,{**job,'github_app':{**job['github_app'],'token':'DO_NOT_STORE'}})
    registry.update(job['target_id'],allowed=False)
    with pytest.raises(ValueError):register_assignment(registry,{**job,'config_version':10})


def test_access_delivery_token_memory_only_and_cross_scope_rejected(tmp_path):
    registry=Registry(tmp_path/'private'/'agent.db');job=assignment()
    token='ghs_'+'a'*40
    async def execute():
        requests=[]
        def transport(request):
            requests.append(request)
            return httpx.Response(200,json=dict(token=token,expires_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),repository_url=job['github_app']['repository_url']))
        async with httpx.AsyncClient(base_url='https://backend.invalid',transport=httpx.MockTransport(transport)) as client:
            runner=await prepare_assignment(client,job,registry)
        assert len(requests)==1 and requests[0].method=='POST'
        assert token not in registry.path.read_bytes().decode('latin1')
        runner.clear();assert runner.token is None
        with pytest.raises(RuntimeError):runner(tmp_path,[],network=True)
    asyncio.run(execute())


def test_managed_access_never_falls_back_to_local_pat(monkeypatch,tmp_path):
    from agent.local import github_app
    seen=[]
    monkeypatch.setenv('GH_TOKEN','legacy-private-token')
    monkeypatch.setattr(github_app,'git_command',lambda *args,**kwargs:seen.append(kwargs))
    runner=TemporaryGitAccess('ghs_'+'x'*40,datetime.now(timezone.utc)+timedelta(hours=1))
    runner(tmp_path,[],network=True)
    assert seen[0]['credential'].startswith('ghs_') and seen[0]['use_local_credential'] is False


def test_restart_during_download_retains_original_commit(repository):
    from agent.local.scanner import scan_local
    from agent.sources import github
    registry,target,root=repository
    original=git(root,'rev-parse','HEAD');scan_id=str(uuid4())
    actual=github.git_command
    def interrupted(cache,args,**kwargs):
        if args[0]=='fetch':
            with registry.connect() as db:assert db.execute('SELECT commit_sha FROM github_snapshots WHERE scan_id=?',(scan_id,)).fetchone()[0]==original
            raise KeyboardInterrupt()
        return actual(cache,args,**kwargs)
    with pytest.raises(KeyboardInterrupt):scan_local(registry,target,scan_id=scan_id,github_runner=interrupted)
    (root/'config.js').write_text('const safe=42;');git(root,'add','.');git(root,'commit','-m','Head moved')
    outcome=scan_local(registry,target,scan_id=scan_id)
    assert outcome['status']=='completed' and outcome['commit_sha']==original and outcome['findings_count']==1

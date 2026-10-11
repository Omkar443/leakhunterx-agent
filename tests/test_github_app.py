import asyncio
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import httpx
import pytest
from agent.local.registry import Registry
from agent.local.github_app import register_assignment,prepare_assignment,TemporaryGitAccess
from agent.local.failures import GitHubScanError
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
        assert 40<=requests[0].extensions['timeout']['read']<=60
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


@pytest.mark.parametrize('detail,code', [
    ('GitHub App signing configuration is unavailable','github_signing_unavailable'),
    ('GitHub App requires only read-only Contents and Metadata permissions','github_permissions_invalid'),
    ('Reconnect GitHub to restore authorization','github_authorization_unavailable'),
])
def test_permanent_access_errors_do_not_retry_or_persist_credentials(tmp_path, detail, code):
    registry=Registry(tmp_path/'private'/'agent.db'); job=assignment(); calls=[]
    async def execute():
        def respond(request):
            calls.append(request)
            return httpx.Response(503,json={'detail':detail,'token':'PRIVATE_PROVIDER_TOKEN'})
        async with httpx.AsyncClient(base_url='https://backend.invalid',transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(GitHubScanError) as caught:
                await prepare_assignment(client,job,registry)
            assert caught.value.reason==code and 'PRIVATE_PROVIDER_TOKEN' not in str(caught.value)
    asyncio.run(execute())
    assert len(calls)==1 and registry.list()==[]


def test_transient_access_recovery_and_unknown_body_never_leaks(monkeypatch,tmp_path):
    from agent.local import github_app
    from unittest.mock import AsyncMock
    monkeypatch.setattr(github_app.asyncio,'sleep',AsyncMock())
    registry=Registry(tmp_path/'private'/'agent.db'); job=assignment(); calls=[]
    async def execute():
        def respond(request):
            calls.append(request)
            if len(calls)<3: return httpx.Response(503,json={'detail':'PRIVATE_PROVIDER_TOKEN'})
            return httpx.Response(200,json=dict(token='ghs_'+'a'*40,expires_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),repository_url=job['github_app']['repository_url']))
        async with httpx.AsyncClient(base_url='https://backend.invalid',transport=httpx.MockTransport(respond)) as client:
            access=await prepare_assignment(client,job,registry)
            access.clear()
        async with httpx.AsyncClient(base_url='https://backend.invalid',transport=httpx.MockTransport(lambda _:httpx.Response(403,json={'detail':'PRIVATE_PROVIDER_TOKEN'}))) as client:
            with pytest.raises(GitHubScanError) as caught: await prepare_assignment(client,job,registry)
            assert 'PRIVATE_PROVIDER_TOKEN' not in str(caught.value)
            assert caught.value.reason=='github_authorization_unavailable'
    asyncio.run(execute())
    assert len(calls)==3


@pytest.mark.parametrize('value', [[], {'token':'PRIVATE_PROVIDER_TOKEN'}, {'detail':['PRIVATE_PROVIDER_TOKEN']}])
def test_invalid_access_response_is_safe_and_never_creates_target(tmp_path,value):
    registry=Registry(tmp_path/'private'/'agent.db')
    async def execute():
        async with httpx.AsyncClient(base_url='https://backend.invalid',transport=httpx.MockTransport(lambda _:httpx.Response(200,json=value))) as client:
            with pytest.raises(GitHubScanError) as caught: await prepare_assignment(client,assignment(),registry)
            assert caught.value.reason=='github_response_invalid' and 'PRIVATE_PROVIDER_TOKEN' not in str(caught.value)
    asyncio.run(execute())
    assert registry.list()==[]


def test_access_error_contract_uses_only_allowlisted_codes():
    from agent.local.failures import access_failure
    response=httpx.Response(503,headers={'X-LHX-GitHub-Error':'github_signing_unavailable'},json={'detail':'PRIVATE_PROVIDER_TOKEN'})
    assert access_failure(response).reason=='github_signing_unavailable'
    response=httpx.Response(503,headers={'X-LHX-GitHub-Error':'PRIVATE_PROVIDER_TOKEN'},json={'detail':'PRIVATE_PROVIDER_TOKEN'})
    assert access_failure(response).reason=='github_access_unavailable'
    assert 'PRIVATE_PROVIDER_TOKEN' not in str(access_failure(response))

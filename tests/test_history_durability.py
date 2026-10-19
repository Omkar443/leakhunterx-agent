import asyncio
import hashlib
import json
import time
from uuid import uuid4
import httpx
import pytest
from agent.local.registry import Registry
from agent.history.state import HistoryState
from agent.history.recovery import ArchiveRecovery,RecoveryPolicy
from agent.history.archive import ArchiveClient,ArchiveError
from agent.history.discovery import ArchiveDiscovery,DiscoveryPolicy
from agent.history.cache import ArchiveCache

CONFIG={'from_date':'2024-01-01','to_date':'2024-12-31','include_subdomains':True,'max_captures':10,'policy_version':1}
HEADER=['timestamp','original','mimetype','statuscode','digest']
ROW=['20240601120000','https://example.com/app.js','application/javascript','200','digest']
CAPTURE={'original_url':ROW[1],'requested_timestamp':ROW[0]}

def state(tmp_path):
    registry=Registry(tmp_path/'private'/'agent.db');identifier=str(uuid4())
    with registry.connect() as db:
        db.execute('CREATE TABLE history_jobs(scan_id TEXT PRIMARY KEY)')
        db.execute('INSERT INTO history_jobs VALUES(?)',(identifier,))
    return HistoryState(registry,identifier,'a'*64)

def test_recovery_resumes_original_attempt_and_reuses_only_completed_metadata(tmp_path):
    saved=state(tmp_path);calls=[];messages=[]
    async def operation():
        calls.append(1)
        if len(calls)==1:raise ArchiveError('archive_unavailable',failure_reason='archive_service_unavailable')
        return [[CAPTURE],False]
    async def notify(phase,value):messages.append(value)
    async def run():
        recovery=ArchiveRecovery(saved,lambda:False,lambda:time.time()+100,notify,RecoveryPolicy(first_backoff=0))
        assert await recovery.execute('discovery',operation,'discovery',cache_result=True)==[[CAPTURE],False]
        resumed=ArchiveRecovery(HistoryState(saved.registry,saved.scan_id,saved.scope),lambda:False,lambda:time.time()+100,notify)
        assert await resumed.execute('discovery',operation,'discovery',cache_result=True)==[[CAPTURE],False]
        assert len(calls)==2 and [item['state'] for item in messages]==['retrieving','waiting','retrieving']
    asyncio.run(run())

def test_exhausted_retry_allowance_survives_restart(tmp_path):
    saved=state(tmp_path);calls=[]
    async def operation():calls.append(1);raise ArchiveError('archive_unavailable',failure_reason='archive_network_error')
    async def notify(*args):pass
    async def run():
        for _ in range(2):
            recovery=ArchiveRecovery(saved,lambda:False,lambda:time.time()+100,notify,RecoveryPolicy(first_backoff=0))
            with pytest.raises(ArchiveError):await recovery.execute('discovery',operation,'discovery')
        assert len(calls)==3
    asyncio.run(run())

def test_retry_after_longer_than_assignment_does_not_trigger_early_retry(tmp_path):
    calls=[]
    async def operation():calls.append(1);raise ArchiveError('rate_limited',retry_after=1000)
    async def notify(*args):pass
    async def run():
        recovery=ArchiveRecovery(state(tmp_path),lambda:False,lambda:time.time()+10,notify,RecoveryPolicy(first_backoff=0))
        with pytest.raises(ArchiveError):await recovery.execute('discovery',operation,'discovery')
        assert len(calls)==1
    asyncio.run(run())


def test_cancel_during_persisted_retry_wait_never_starts_a_request(tmp_path):
    saved=state(tmp_path);cancelled=[False]
    saved.put('recovery:discovery',{'attempt':1,'retry_at':time.time()+10,'reason':'archive_timeout'})
    async def operation():raise AssertionError('Request must not start')
    async def notify(*args):pass
    async def run():
        recovery=ArchiveRecovery(saved,lambda:cancelled[0],lambda:time.time()+100,notify)
        task=asyncio.create_task(recovery.execute('discovery',operation,'discovery'))
        await asyncio.sleep(.01);cancelled[0]=True
        with pytest.raises(InterruptedError):await asyncio.wait_for(task,timeout=1)
        assert saved.get('recovery:discovery')['attempt']==1
    asyncio.run(run())

def test_index_cursor_survives_interrupted_second_page(tmp_path):
    saved=state(tmp_path);calls=[]
    def handler(request):
        calls.append(request)
        if len(calls)==1:return httpx.Response(200,json=[HEADER,ROW,[],['cursor']])
        if len(calls)==2:raise httpx.ReadTimeout('temporary',request=request)
        assert request.url.params['resumeKey']=='cursor'
        return httpx.Response(200,json=[HEADER])
    async def run():
        query={'url':'example.com','limit':500}
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            archive=ArchiveClient(client,'https://example.com/',CONFIG,checkpoint=saved)
            with pytest.raises(ArchiveError):await archive.index(query)
            resumed=ArchiveClient(client,'https://example.com/',CONFIG,checkpoint=saved)
            rows,limited=await resumed.index(query)
        assert len(rows)==1 and not limited and len(calls)==3
    asyncio.run(run())

def test_discovery_resume_does_not_repeat_completed_category(tmp_path):
    saved=state(tmp_path);calls=[]
    def handler(request):calls.append(request);return httpx.Response(200,json=[HEADER,ROW])
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            archive=ArchiveClient(client,'https://example.com/',CONFIG,checkpoint=saved)
            with pytest.raises(ArchiveError):await ArchiveDiscovery(archive,DiscoveryPolicy(max_requests=1)).discover()
            rows,limited=await ArchiveDiscovery(archive).discover()
        assert len(rows)==1 and not limited and len(calls)==3
        assert len({str(request.url) for request in calls})==3
    asyncio.run(run())

def test_scope_change_cannot_reuse_checkpoint(tmp_path):
    saved=state(tmp_path);saved.put('value',{'data':1})
    with pytest.raises(ValueError):HistoryState(saved.registry,saved.scan_id,'b'*64).get('value')

def cache(saved,key=b'x'*32,scope='a'*64):
    return ArchiveCache(saved.registry,'target',scope,key,'https://example.com/',CONFIG)

def result(content='const secret = "private";'):
    return content,ROW[0],hashlib.sha256(content.encode()).hexdigest(),len(content.encode())

def test_archive_artifacts_are_encrypted_and_bound_to_scope_and_key(tmp_path):
    saved=state(tmp_path);first=cache(saved);first.put(CAPTURE,result())
    assert first.get(CAPTURE)==result()
    assert cache(saved,scope='b'*64).get(CAPTURE) is None
    with saved.registry.connect() as db:
        encrypted=db.execute('SELECT payload FROM history_cache').fetchone()[0]
        assert b'private' not in encrypted
    assert cache(saved,key=b'y'*32).get(CAPTURE) is None

def test_cache_expiration_and_storage_budget(tmp_path):
    saved=state(tmp_path);first=cache(saved);first.put(CAPTURE,result())
    with saved.registry.connect() as db:db.execute('UPDATE history_cache SET expires=0')
    assert first.get(CAPTURE) is None
    first.MAX_BYTES=400
    for index in range(10):first.put({**CAPTURE,'original_url':f'https://example.com/{index}.js'},result('safe'))
    with saved.registry.connect() as db:
        assert db.execute('SELECT coalesce(sum(length(payload)),0) FROM history_cache').fetchone()[0]<=400

def test_tampered_ciphertext_is_a_cache_miss(tmp_path):
    saved=state(tmp_path);first=cache(saved);first.put(CAPTURE,result())
    with saved.registry.connect() as db:db.execute('UPDATE history_cache SET payload=?',(b'corrupt',))
    assert first.get(CAPTURE) is None

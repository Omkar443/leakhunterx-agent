"""Archive outage recovery stays bounded, scoped and honest about coverage."""
import asyncio
import io
import json
from unittest.mock import AsyncMock
from uuid import uuid4
import httpx
import pytest
from agent.history.archive import ArchiveClient, ArchiveError
from agent.history.contracts import validate
from agent.history.discovery import ArchiveDiscovery, DiscoveryPolicy, DiscoveryBudget
from agent.history.failures import HISTORICAL_FAILURES
from agent.history.runtime import HistoricalScanOrchestrator
from agent.local.registry import Registry
from agent.terminal_ui import AgentWorkspace

OPTIONS = {'from_date': '2024-01-01', 'to_date': '2024-12-31', 'include_subdomains': True, 'max_captures': 2, 'policy_version': 1}
HEADER = ['timestamp', 'original', 'mimetype', 'statuscode', 'digest']
CAPTURE = ['20240601120000', 'https://example.com/app.js', 'application/javascript', '200', 'digest']

@pytest.fixture(autouse=True)
def no_retry_sleep(monkeypatch):
    monkeypatch.setattr('agent.history.archive.asyncio.sleep', AsyncMock())
    from agent.history.recovery import RecoveryPolicy
    monkeypatch.setattr('agent.history.recovery.RecoveryPolicy',lambda:RecoveryPolicy(first_backoff=0))

def test_partition_recovery_preserves_full_authorized_scope_and_date_coverage():
    requests = []
    def handler(request):
        requests.append(request)
        assert request.url.host == 'web.archive.org'
        assert request.url.params['matchType'] == 'domain'
        assert request.url.params['url'] == 'example.com'
        if request.url.params['from']=='20240101' and request.url.params['to']=='20241231235959':
            return httpx.Response(503, text='private provider body')
        return httpx.Response(200, json=[HEADER, CAPTURE, CAPTURE,
            ['20240601120000', 'https://outside.com/private.js', 'application/javascript', '200', 'd'],
            ['20250601120000', 'https://example.com/future.js', 'application/javascript', '200', 'd'],
            ['20240601120000', 'https://example.com/image.png', 'image/png', '200', 'd']])
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            captures, limited = await ArchiveClient(client, 'https://example.com/', OPTIONS).discover()
        assert len(captures) == 1 and not limited
        assert captures[0]['original_url'] == CAPTURE[1]
        assert len(requests) == 9
        for category in ArchiveDiscovery.FILTERS:
            ranges=[(request.url.params['from'],request.url.params['to']) for request in requests
                    if category in request.url.params.get_list('filter')]
            assert ranges==[('20240101','20241231235959'),('20240101','20240701235959'),('20240702','20241231235959')]
    asyncio.run(run())

@pytest.mark.parametrize('status,code', [(429, 'archive_rate_limited'), (403, 'archive_access_denied')])
def test_provider_restriction_does_not_trigger_retry_storm(status, code):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(status, text='private response')
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ArchiveError) as failure:
                await ArchiveClient(client, 'https://example.com/', OPTIONS).discover()
        assert failure.value.failure_reason == code and len(requests) == 1
        assert 'private' not in str(failure.value)
    asyncio.run(run())

def test_all_queries_unavailable_remains_failed_and_bounded():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(503, text='sensitive upstream details')
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ArchiveError) as failure:
                await ArchiveClient(client, 'https://example.com/', OPTIONS).discover()
        assert failure.value.failure_reason == 'archive_service_unavailable' and len(requests) == 4
    asyncio.run(run())

def test_timeout_is_distinct_and_never_becomes_an_empty_success():
    def handler(request): raise httpx.ReadTimeout('private connection details', request=request)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ArchiveError) as failure:
                await ArchiveClient(client, 'https://example.com/', OPTIONS).discover()
        assert failure.value.failure_reason == str(failure.value) == 'archive_timeout'
    asyncio.run(run())

def test_redirect_retry_preserves_original_query():
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path == '/cdx/search/cdx':
            assert request.url.params['url'] == 'example.com'
            return httpx.Response(302, headers={'location': '/index-result'})
        if len(calls) == 2: raise httpx.ReadTimeout('temporary failure', request=request)
        return httpx.Response(200, json=[HEADER, CAPTURE])
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            body,_,_=await ArchiveClient(client, 'https://example.com/', OPTIONS).read('https://web.archive.org/cdx/search/cdx',{'url':'example.com'})
        assert json.loads(body)==[HEADER,CAPTURE] and len(calls) == 4
    asyncio.run(run())

def assignment():
    target, scope = validate('https://example.com', OPTIONS)
    return {'scan_id': str(uuid4()), 'target_id': str(uuid4()), 'source_type': 'HISTORY', 'history_protocol':2, 'target': target, 'historical': OPTIONS, 'scope_fingerprint': scope}

class Emitter:
    def __init__(self): self.events = []
    async def emit(self, event): self.events.append(event)
    async def flush(self): pass

def test_runtime_restart_preserves_incomplete_partition_coverage(tmp_path):
    emitter = Emitter()
    def handler(request):
        assert request.url.host == 'web.archive.org'
        if '/cdx/' in request.url.path:
            filters=request.url.params.get_list('filter')
            return httpx.Response(200,json=[HEADER,CAPTURE]) if filters[-1]==ArchiveDiscovery.FILTERS[0] else httpx.Response(503)
        return httpx.Response(200, text='const version = "safe";', headers={'content-type': 'application/javascript'})
    async def run():
        job = assignment(); registry = Registry(tmp_path / 'private' / 'agent.db')
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            for _ in range(2):
                runner = HistoricalScanOrchestrator(job, emitter, registry, client)
                await runner.start_scan()
                assert runner.status.value == 'completed'
        completed = [event for event in emitter.events if event['event_type'] == 'scan_completed']
        assert len(completed) == 2 and all(event['data']['complete'] is False for event in completed)
        assert all(event['data']['discovery_limited'] is True for event in emitter.events if event['event_type']=='discovery_completed')
    asyncio.run(run())

def test_request_budget_retains_partial_evidence_but_never_claims_full_coverage():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=[HEADER,CAPTURE]))) as client:
            archive=ArchiveClient(client,'https://example.com/',OPTIONS)
            captures,limited=await ArchiveDiscovery(archive,DiscoveryPolicy(max_requests=1)).discover()
            assert len(captures)==1 and limited
            with pytest.raises(ArchiveError) as failure:
                await ArchiveDiscovery(archive,DiscoveryPolicy(max_requests=0)).discover()
            assert failure.value.failure_reason=='archive_discovery_incomplete'
    asyncio.run(run())

def test_redirects_cannot_bypass_the_discovery_request_budget():
    calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(302,headers={'location':'/another-index'})
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ArchiveError) as failure:
                await ArchiveClient(client,'https://example.com/',OPTIONS).read('https://web.archive.org/cdx/search/cdx',index=True,budget=DiscoveryBudget(DiscoveryPolicy(max_requests=1)))
        assert len(calls)==1 and failure.value.failure_reason=='archive_discovery_incomplete'
    asyncio.run(run())

def test_cancellation_interrupts_a_waiting_archive_request_and_closes_it():
    cancelled=False;closed=False
    async def handler(request):
        nonlocal closed
        try:await asyncio.Event().wait()
        finally:closed=True
    async def run():
        nonlocal cancelled
        loop=asyncio.get_running_loop()
        def cancel():
            nonlocal cancelled
            cancelled=True
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            loop.call_later(.01,cancel)
            with pytest.raises(InterruptedError):
                await asyncio.wait_for(ArchiveClient(client,'https://example.com/',OPTIONS,lambda:cancelled).read('https://web.archive.org/cdx/search/cdx'),timeout=1)
        assert closed
    asyncio.run(run())

def test_wall_clock_budget_cancels_stalled_response_without_hanging():
    async def handler(request):await asyncio.Event().wait()
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            archive=ArchiveClient(client,'https://example.com/',OPTIONS)
            with pytest.raises(ArchiveError) as failure:
                await asyncio.wait_for(ArchiveDiscovery(archive,DiscoveryPolicy(max_seconds=.02)).discover(),timeout=1)
            assert failure.value.failure_reason=='archive_discovery_incomplete'
    asyncio.run(run())

def test_empty_archive_index_is_not_reported_as_clean_completed_scan():
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=[]))) as client:
            with pytest.raises(ArchiveError) as failure:
                await ArchiveClient(client,'https://example.com/',OPTIONS).discover()
            assert failure.value.failure_reason=='archive_no_captures'
    asyncio.run(run())

def test_transient_network_retry_does_not_change_authorization_or_dates():
    calls=[]
    def handler(request):
        calls.append(request)
        if len(calls)==1:raise httpx.ConnectError('private transport information',request=request)
        return httpx.Response(200,json=[HEADER,CAPTURE])
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            captures,limited=await ArchiveClient(client,'https://example.com/',OPTIONS).discover()
        assert len(captures)==1 and not limited
        assert str(calls[0].url)==str(calls[1].url)
    asyncio.run(run())

def test_slow_script_index_does_not_starve_available_html_captures():
    categories=[]
    def handler(request):
        category=request.url.params.get_list('filter')[-1];categories.append(category)
        if category!=ArchiveDiscovery.FILTERS[2]:return httpx.Response(503)
        return httpx.Response(200,json=[HEADER,[CAPTURE[0],'https://example.com/','text/html','200','d']])
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            captures,limited=await ArchiveClient(client,'https://example.com/',OPTIONS).discover()
        assert len(captures)==1 and captures[0]['mime']=='text/html' and limited
        assert categories[:3]==list(ArchiveDiscovery.FILTERS)
    asyncio.run(run())

def test_rate_limit_during_capture_fetch_stops_remaining_replay_requests(tmp_path):
    replays=[];emitter=Emitter()
    def handler(request):
        if '/cdx/' in request.url.path:return httpx.Response(200,json=[HEADER,CAPTURE,[*CAPTURE[:1],'https://example.com/second.js',*CAPTURE[2:]]])
        replays.append(request)
        return httpx.Response(429)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            runner=HistoricalScanOrchestrator(assignment(),emitter,Registry(tmp_path/'agent.db'),client)
            with pytest.raises(ArchiveError):await runner.start_scan()
        assert len(replays)==3 and all(request.url.path.endswith('/https://example.com/app.js') for request in replays) and emitter.events[-1]['data']['reason']=='archive_rate_limited'
    asyncio.run(run())

def test_restart_preserves_specific_capture_failure_without_reuploading_source(tmp_path):
    emitter=Emitter();replays=[]
    def handler(request):
        if '/cdx/' in request.url.path:return httpx.Response(200,json=[HEADER,CAPTURE])
        replays.append(request)
        return httpx.Response(503,text='PRIVATE_RESPONSE_BODY')
    async def run():
        job=assignment();registry=Registry(tmp_path/'agent.db')
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            for _ in range(2):
                with pytest.raises(ArchiveError):await HistoricalScanOrchestrator(job,emitter,registry,client).start_scan()
        failures=[event['data']['reason'] for event in emitter.events if event['event_type']=='scan_failed']
        assert failures==['archive_service_unavailable']*2 and len(replays)==3
        assert 'PRIVATE_RESPONSE_BODY' not in json.dumps(emitter.events)
        with registry.connect() as db:
            assert 'PRIVATE_RESPONSE_BODY' not in db.execute('SELECT payload FROM history_artifacts').fetchone()[0]
    asyncio.run(run())

def test_local_scan_deadline_is_not_misreported_as_user_cancellation(tmp_path):
    emitter=Emitter()
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=[]))) as client:
            runner=HistoricalScanOrchestrator(assignment(),emitter,Registry(tmp_path/'agent.db'),client)
            runner._scan_timeout=-1
            with pytest.raises(InterruptedError):await runner.start_scan()
        assert emitter.events[-1]['event_type']=='scan_stopped'
        assert emitter.events[-1]['data']['reason']=='runtime_limit'
    asyncio.run(run())


def test_empty_persisted_manifest_cannot_become_a_clean_assessment(tmp_path):
    emitter=Emitter()
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _:httpx.Response(200,json=[]))) as client:
            runner=HistoricalScanOrchestrator(assignment(),emitter,Registry(tmp_path/'agent.db'),client)
            with runner.registry.connect() as db:db.execute('UPDATE history_jobs SET manifest=? WHERE scan_id=?',('[]',runner.scan_id))
            with pytest.raises(ArchiveError):await runner.start_scan()
        assert emitter.events[-1]['event_type']=='scan_failed'
        assert not any(event['event_type']=='scan_completed' for event in emitter.events)
    asyncio.run(run())


def test_detector_upgrade_cannot_silently_reuse_older_redacted_analysis(tmp_path):
    from agent.history.state import HistoryState
    emitter=Emitter()
    async def run():
        runner=HistoricalScanOrchestrator(assignment(),emitter,Registry(tmp_path/'agent.db'))
        HistoryState(runner.registry,runner.scan_id,runner.scope).put('detector_policy','detector-v3')
        with runner.registry.connect() as db:db.execute('INSERT INTO history_artifacts VALUES(?,?,?)',(runner.scan_id,0,'{}'))
        with pytest.raises(ArchiveError):await runner.start_scan()
        assert emitter.events[-1]['event_type']=='scan_failed'
        assert not any(event['event_type']=='scan_completed' for event in emitter.events)
    asyncio.run(run())

@pytest.mark.parametrize('status,code', [(503, 'archive_service_unavailable'), (429, 'archive_rate_limited'), (403, 'archive_access_denied')])
def test_runtime_delivers_safe_specific_failure_to_terminal_and_backend(tmp_path, status, code):
    emitter = Emitter()
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(status, text='PRIVATE_UPSTREAM_BODY'))) as client:
            runner = HistoricalScanOrchestrator(assignment(), emitter, Registry(tmp_path / 'agent.db'), client)
            with pytest.raises(ArchiveError): await runner.start_scan()
        assert emitter.events[-1]['data'] == {'reason': code}
        assert 'PRIVATE_UPSTREAM_BODY' not in json.dumps(emitter.events)
        ui = AgentWorkspace(stream=io.StringIO()); ui.terminal('failed', code)
        assert ui.failure_message == HISTORICAL_FAILURES[code]
    asyncio.run(run())

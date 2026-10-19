"""Historical progress and restart replay through the actual durable transport."""
import asyncio,json,sys
from pathlib import Path
from unittest.mock import AsyncMock
from agent.events.event_emitter import HTTPBatchEmitter
from agent.events.router_emitter import RouterEmitter
from agent.history.runtime import HistoricalScanOrchestrator
from agent.local.registry import Registry
from agent.events.outbox import DeliveryPending
from tests.test_historical_resilience import assignment
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'benchmarks'))

def transport(tmp_path):
    batch=HTTPBatchEmitter('http://127.0.0.1/unused',dlq_dir=tmp_path/'delivery')
    batch.flush=AsyncMock()  # Deliberate delivery backlog, no invented receipts.
    return RouterEmitter(AsyncMock(),batch),batch

def test_repeated_archive_progress_during_backlog_never_reuses_an_event_id(tmp_path,monkeypatch):
    clock=[1_800_000_000]
    monkeypatch.setattr('agent.history.runtime.time.time',lambda:clock[0])
    async def run():
        router,batch=transport(tmp_path)
        runner=HistoricalScanOrchestrator(assignment(),router,Registry(tmp_path/'agent.db'))
        data={'phase':'analysis','archive':{'state':'retrieving','provider':'wayback','attempt':1,'retry_at':0}}
        await runner.event('scan_progress',data)
        clock[0]+=2
        await runner.event('scan_progress',data)
        assert batch.outbox.count()==2 and not batch._evidence_failed
        _,events=batch.outbox.next_batch()
        assert len({event['event_id'] for event in events})==2
    asyncio.run(run())

@pytest.mark.parametrize('completion_offline',[False,True])
def test_fifty_captures_one_finding_partial_coverage_survives_delivery_backlog_and_restart(tmp_path,monkeypatch,completion_offline):
    from aiohttp import web
    import httpx
    from agent.history.contracts import validate
    # Synthesized credential is generated at test time; never issued by a provider.
    from catalog_fixtures import cases
    example=next(c for c in cases() if c['rule']=='pinecone_api_key_pcsk_2')
    async def run():
        online=[False];accepted=[];attempts=[]
        async def receive(request):
            payload=await request.json();attempts.append(payload['batch_id'])
            if not online[0]:return web.json_response({'detail':'Temporary outage'},status=503)
            accepted.extend(item['event'] for item in payload['events'])
            return web.json_response({'status':'accepted','received':len(payload['events']),'batch_id':payload['batch_id']},status=202)
        app=web.Application();app.router.add_post('/events',receive)
        server=web.AppRunner(app);await server.setup();site=web.TCPSite(server,'127.0.0.1',0);await site.start()
        endpoint=f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/events'
        batch=HTTPBatchEmitter(endpoint,dlq_dir=tmp_path/'http',max_retries=0)
        router=RouterEmitter(AsyncMock(),batch)
        class Delivery:
            async def emit(self,event):
                if event['event_type']=='scan_completed' and not completion_offline:online[0]=True
                await router.emit(event)
            async def flush(self):await router.flush()
        job=assignment();job['historical']['max_captures']=50
        _,job['scope_fingerprint']=validate(job['target'],job['historical'])
        registry=Registry(tmp_path/'history.db')
        captures=[{'original_url':f'https://example.com/app-{i}.js','requested_timestamp':'20240601120000','mime':'application/javascript'} for i in range(50)]
        def archive(request):
            index=int(request.url.path.rsplit('app-',1)[1].split('.')[0])
            body=b'\x00invalid archive bytes' if index>=44 else (example['content'].encode() if index==0 else b'const version = 1;')
            return httpx.Response(200,content=body,headers={'content-type':'application/javascript'})
        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(archive)) as client:
                runner=HistoricalScanOrchestrator(job,Delivery(),registry,client)
                with registry.connect() as db:db.execute('UPDATE history_jobs SET manifest=?,limited=1 WHERE scan_id=?',(json.dumps(captures),runner.scan_id))
                async def analyze(*args):return runner.analyze(args[0],args[1],args[2],map_content=args[3],map_provenance=args[4])
                runner.bounded_analysis=analyze
                if completion_offline:
                    with pytest.raises(DeliveryPending):await runner.start_scan()
                    with batch.outbox.connect() as db:queued=[json.loads(r[0]) for r in db.execute('SELECT payload FROM pending ORDER BY seq')]
                    assert queued[-1]['event_type']=='scan_completed'
                    assert not any(e['event_type']=='scan_failed' for e in queued)
                    online[0]=True
                    replay=HTTPBatchEmitter(endpoint,dlq_dir=tmp_path/'http',max_retries=0)
                    try:await replay.drain()
                    finally:await replay._session.close()
                    assert batch.outbox.count()==0
                    runner=HistoricalScanOrchestrator(job,Delivery(),registry,client)
                    await runner.start_scan()
                else:await runner.start_scan()
                await batch.drain()
                assert runner.status.value=='completed' and not batch._evidence_failed
                assert not any(e['event_type']=='scan_failed' for e in accepted)
                summary=next(e['data'] for e in accepted if e['event_type']=='js_analysis_summary')
                assert (summary['processed_files'],summary['successful_analyses'],summary['failed_analyses'],summary['findings_count'])==(50,44,6,1)
                assert all(e['data']['complete'] is False for e in accepted if e['event_type']=='scan_completed')
                # Same identity always means identical bytes, including timestamp.
                identities={}
                for event in accepted:
                    encoded=json.dumps(event,sort_keys=True)
                    assert identities.setdefault(event['event_id'],encoded)==encoded
                assert example['secret'] not in json.dumps(accepted)
        finally:
            if batch._delivery_task:await batch._delivery_task
            if batch._session:await batch._session.close()
            await server.cleanup()
    asyncio.run(run())

def test_journal_error_is_not_reclassified_as_invalid_archived_content(tmp_path):
    async def run():
        emitter=AsyncMock();emitter.emit.side_effect=ValueError('private internal details')
        runner=HistoricalScanOrchestrator(assignment(),emitter,Registry(tmp_path/'agent.db'))
        with pytest.raises(DeliveryPending,match='evidence delivery unavailable') as error:
            await runner.event('scan_progress',{'phase':'analysis'})
        assert 'private' not in str(error.value)
    asyncio.run(run())

def test_durable_evidence_replay_keeps_original_envelope_across_restart(tmp_path,monkeypatch):
    clock=[1_800_000_000]
    monkeypatch.setattr('agent.history.runtime.time.time',lambda:clock[0])
    async def run():
        router,batch=transport(tmp_path);job=assignment();registry=Registry(tmp_path/'agent.db')
        runner=HistoricalScanOrchestrator(job,router,registry)
        await runner.event('scan_started',{'source_type':'HISTORY'})
        before=batch.outbox.next_batch()
        clock[0]+=10
        restarted=HistoricalScanOrchestrator(job,router,registry)
        await restarted.event('scan_started',{'source_type':'HISTORY'})
        assert batch.outbox.next_batch()==before and batch.outbox.count()==1
        assert not batch._evidence_failed
    asyncio.run(run())

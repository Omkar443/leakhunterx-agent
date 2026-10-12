import asyncio,base64,json,hashlib
from uuid import uuid4
import httpx,pytest
from agent.history.archive import ArchiveClient,ArchiveError
from agent.history.contracts import validate
from agent.history.javascript import recover_sources,literal_assignments,source_map_reference,mapped_location
from agent.history.runtime import HistoricalScanOrchestrator
from agent.local.registry import Registry

OPTIONS={'from_date':'2020-01-01','to_date':'2026-01-01','include_subdomains':False,'max_captures':150,'policy_version':1}
TOKEN='ghp_'+'v7G9k3Q2s8N4b6Y1m5R0c9T7w2L8p4D6x1Z3'
BODY='const githubToken = "'+TOKEN+'"; fetch("https://api.github.com/user", {headers:{Authorization:"Bearer " + githubToken}});'


def test_source_map_recovers_real_source_and_does_not_follow_source_root():
    value={'version':3,'sourceRoot':'file:///etc/','sources':['config.ts'],'sourcesContent':[BODY],'mappings':'AAAA'}
    assert recover_sources(json.dumps(value))==[('config.ts',BODY)]
    inline='//# sourceMappingURL=data:application/json;base64,'+base64.b64encode(json.dumps(value).encode()).decode()
    assert recover_sources(source_map_reference(inline,'https://example.com/app.js'))==[('config.ts',BODY)]
    position=mapped_location(json.dumps(value),'config.ts',BODY,1,10)
    assert position['accuracy']=='nearest_segment' and position['generated_line']==1
    assert mapped_location(json.dumps(value),'config.ts',BODY,1,0)['accuracy']=='exact_segment'
    assert mapped_location(json.dumps(value),'config.ts',BODY,2,0) is None
    assert source_map_reference('const example="//# sourceMappingURL=other.map";','https://example.com/app.js') is None


def test_versioned_assets_allowed_but_secret_queries_are_not():
    from agent.history.contracts import url
    assert url('https://example.com/app.js?v=42')=='https://example.com/app.js?v=42'
    for value in ('https://example.com/app.js?token=secret','https://example.com:80/app.js','https://example.com/'+TOKEN):
        with pytest.raises(ValueError):url(value)


def test_large_minified_identifier_is_fast_without_losing_email_detection():
    import time
    from agent.js.leak_detector import EnterpriseLeakDetector
    started=time.perf_counter()
    detector=EnterpriseLeakDetector();findings=detector.check_content('/*'+'a'*100000+'*/'+BODY)
    assert time.perf_counter()-started<3 and any(f['type']=='github_token' for f in findings)
    email=EnterpriseLeakDetector().check_content('"person@example.com:V7u4F9k2R8m6S3x1"')
    assert any(f['type']=='email_password' for f in email)


@pytest.mark.parametrize('mapping',[{'version':2},{'version':3,'sources':['a'],'sourcesContent':['a','b']},{'version':3,'sections':[{'url':'file:///etc/passwd','offset':{'line':0,'column':0}}]},{'version':3,'sources':['a']*101,'sourcesContent':['']*101}])
def test_malformed_or_unbounded_maps_are_rejected(mapping):
    with pytest.raises(ValueError):recover_sources(json.dumps(mapping))


def test_static_reconstruction_is_bounded_and_ignores_comments_and_code_execution():
    assert list(literal_assignments('const githubToken = "ghp_" + "abc";'))==[('githubToken = "ghp_abc";',1)]
    assert not list(literal_assignments('// const token = "ghp_"+"abc";'))
    assert not list(literal_assignments('const token = dangerous() + "abc";'))
    assert not list(literal_assignments('const text = `const token = "a"+"b";`;'))


def test_analysis_deduplicates_bundle_and_map_without_secret_upload(tmp_path):
    registry=Registry(tmp_path/'private'/'agent.db');target,scope=validate('https://example.com',OPTIONS)
    assignment={'scan_id':str(uuid4()),'target_id':str(uuid4()),'source_type':'HISTORY','target':target,'historical':OPTIONS,'scope_fingerprint':scope}
    runner=HistoricalScanOrchestrator(assignment,None,registry=registry)
    text=BODY+'\n//# sourceMappingURL=app.js.map'
    mapping=json.dumps({'version':3,'sources':['src/config.ts'],'sourcesContent':[BODY],'mappings':'AAAA'})
    findings,digest,status=runner.analyze(text,'https://example.com/app.js','20240102120000',map_content=mapping)
    assert len(findings)==1 and status=='archived_recovered'
    assert findings[0]['historical']['evidence_kind']=='embedded_source'
    assert TOKEN not in json.dumps(findings) and BODY not in json.dumps(findings)
    assert findings[0]['semantic_evidence']['assignment']=='literal_assignment'
    assert findings[0]['raw_value']=='[REDACTED]'


def test_archive_discovery_scopes_dates_and_follows_pagination():
    count=0
    def handler(request):
        nonlocal count;count+=1
        assert request.url.host=='web.archive.org'
        header=['timestamp','original','mimetype','statuscode','digest']
        rows=[header,['20240102120000','https://example.com/app.js','application/javascript','200','d'],
            ['20240102120000','https://outside.com/app.js','application/javascript','200','d']]
        return httpx.Response(200,text=json.dumps(rows)+('\n\ncursor' if count==1 else ''),headers={'content-type':'application/json'})
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            items,limited=await ArchiveClient(client,'https://example.com/',OPTIONS).discover()
            assert len(items)==1 and count==4 and not limited
    asyncio.run(exercise())


def test_real_cdx_json_resume_shape_is_supported():
    count=0
    def handler(request):
        nonlocal count;count+=1
        rows=[['timestamp','original','mimetype','statuscode','digest'],['20240102120000','https://example.com/app.js','application/javascript','200','d']]
        if count==1:rows += [[],['resume-key']]
        return httpx.Response(200,json=rows)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            items,limited=await ArchiveClient(client,'https://example.com/',OPTIONS).discover()
            assert len(items)==1 and count==4 and not limited
    asyncio.run(run())


def test_compressed_response_budget_prevents_expansion_bombs():
    import gzip
    async def run():
        def handler(request):return httpx.Response(200,stream=httpx.ByteStream(gzip.compress(b'a'*1000000)),headers={'content-encoding':'gzip','content-type':'application/javascript'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ArchiveError) as error:await ArchiveClient(client,'https://example.com/',OPTIONS).read('https://web.archive.org/cdx/search/cdx',limit=1024)
            assert error.value.reason=='response_limit'
    asyncio.run(run())


@pytest.mark.parametrize('destination',['https://example.com/app.js','http://web.archive.org/a','https://127.0.0.1/a'])
def test_archive_redirect_never_falls_back_to_live_or_private_network(destination):
    async def exercise():
        def handler(request):return httpx.Response(302,headers={'location':destination})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ArchiveError) as error: await ArchiveClient(client,'https://example.com/',OPTIONS).fetch({'original_url':'https://example.com/app.js','requested_timestamp':'20240102120000'})
            assert error.value.reason=='scope_refused'
    asyncio.run(exercise())


def test_lifecycle_checkpoint_replay_is_redacted_and_archive_only(tmp_path):
    events=[];downloads=[]
    class Emitter:
        async def emit(self,event):events.append(event)
        async def flush(self):pass
    def handler(request):
        assert request.url.host=='web.archive.org';downloads.append(str(request.url))
        if '/cdx/' in request.url.path:
            return httpx.Response(200,json=[['timestamp','original','mimetype','statuscode','digest'],['20240102120000','https://example.com/app.js','application/javascript','200','d']])
        return httpx.Response(200,text=BODY,headers={'content-type':'application/javascript'})
    async def exercise():
        registry=Registry(tmp_path/'private'/'agent.db');target,scope=validate('https://example.com',OPTIONS)
        assignment={'scan_id':str(uuid4()),'target_id':str(uuid4()),'source_type':'HISTORY','target':target,'historical':OPTIONS,'scope_fingerprint':scope}
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            runner=HistoricalScanOrchestrator(assignment,Emitter(),registry,client);await runner.start_scan()
            assert runner.status.value=='completed'
            before=len(downloads);await HistoricalScanOrchestrator(assignment,Emitter(),registry,client).start_scan()
            assert len(downloads)==before
        assert TOKEN not in json.dumps(events)
        with registry.connect() as db:
            checkpoint=db.execute('SELECT payload FROM history_artifacts').fetchone()[0]
            assert TOKEN not in checkpoint and 'literal_assignment' in checkpoint
        assert len([e for e in events if e['event_type']=='scan_completed'])==2
        assert events[-2]['data']['successful_analyses']==1
    asyncio.run(exercise())

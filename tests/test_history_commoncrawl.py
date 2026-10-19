"""Verified archive bytes, provider isolation, recovery and redacted evidence."""
import asyncio
import base64
import hashlib
import io
import json
from uuid import uuid4
from unittest.mock import AsyncMock
import httpx
import pytest
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders
from agent.history.archive import ArchiveError
from agent.history.commoncrawl import CommonCrawlProvider
from agent.history.commoncrawl_record import validate_record
from agent.history.warc import parse_record,bounded_record
from agent.history.runtime import HistoricalScanOrchestrator
from agent.history.contracts import validate,MAX_BYTES
from agent.local.registry import Registry
from test_history_durability import state

OPTIONS={'from_date':'2024-01-01','to_date':'2024-12-31','include_subdomains':True,'max_captures':2,'policy_version':1}
ORIGINAL='https://example.com/app.js'
STAMP='20240601120000'
COLLECTION='CC-MAIN-2024-22'
FILENAME=f'crawl-data/{COLLECTION}/segments/1710000000.0/warc/example.warc.gz'
TOKEN='ghp_'+'v7G9k3Q2s8N4b6Y1m5R0c9T7w2L8p4D6x1Z3'
BODY=('const githubToken="'+TOKEN+'";').encode()

def warc(body=BODY,original=ORIGINAL):
    stream=io.BytesIO();writer=WARCWriter(stream,gzip=True)
    record=writer.create_warc_record(original,'response',payload=io.BytesIO(body),
        http_headers=StatusAndHeaders('200 OK',[('Content-Type','application/javascript; charset=utf-8'),('Content-Length',str(len(body)))],protocol='HTTP/1.1'),
        warc_headers_dict={'WARC-Date':'2024-06-01T12:00:00Z'})
    writer.write_record(record)
    return stream.getvalue(),base64.b32encode(hashlib.sha1(body).digest()).decode()


def exited_parser(pipe,args):
    pipe.close()


def test_crashed_parser_is_a_finite_capture_failure(tmp_path,monkeypatch):
    monkeypatch.setattr('agent.history.warc._worker',exited_parser)
    async def run():
        data,digest=warc()
        with pytest.raises(ArchiveError) as error:await asyncio.wait_for(bounded_record(data,ORIGINAL,STAMP,digest,lambda:False),timeout=5)
        assert error.value.failure_reason=='archive_invalid_response'
    asyncio.run(run())

def entry(data,digest):
    return {'url':ORIGINAL,'timestamp':STAMP,'mime':'application/javascript','status':'200','filename':FILENAME,'offset':'123','length':str(len(data)),'digest':digest}

def handler(data,digest,requests):
    def respond(request):
        requests.append(request)
        if request.url.host=='web.archive.org':return httpx.Response(503)
        if request.url.path=='/collinfo.json':return httpx.Response(200,json=[{'id':COLLECTION}])
        if request.url.host=='index.commoncrawl.org':
            assert request.url.params['matchType']=='domain' and request.url.params['url']=='example.com'
            return httpx.Response(200,content=json.dumps(entry(data,digest)).encode())
        assert request.url.host=='data.commoncrawl.org' and request.url.path=='/'+FILENAME
        assert request.headers['range']==f'bytes=123-{122+len(data)}'
        return httpx.Response(206,headers={'content-range':f'bytes 123-{122+len(data)}/9999999'},content=data)
    return respond

def test_warc_verifies_original_timestamp_payload_and_single_record():
    data,digest=warc()
    assert parse_record(data,ORIGINAL,STAMP,digest)==(BODY.decode(),STAMP,hashlib.sha256(BODY).hexdigest(),len(BODY))
    for original,stamp,checksum,payload in [(ORIGINAL,STAMP,'A'*32,data),('https://outside.com/app.js',STAMP,digest,data),(ORIGINAL,'20240602120000',digest,data),(ORIGINAL,STAMP,digest,data+data),(ORIGINAL,STAMP,digest,data[:-10])]:
        with pytest.raises(Exception):parse_record(payload,original,stamp,checksum)

def test_warc_decompression_budget_and_isolated_parser():
    data,digest=warc(b'a'*(MAX_BYTES+1))
    with pytest.raises(ValueError):parse_record(data,ORIGINAL,STAMP,digest)
    async def run():
        good,checksum=warc()
        assert (await bounded_record(good,ORIGINAL,STAMP,checksum,lambda:False))[0]==BODY.decode()
        with pytest.raises(InterruptedError):await bounded_record(good,ORIGINAL,STAMP,checksum,lambda:True)
    asyncio.run(run())

@pytest.mark.parametrize('change',[{'filename':'../private.warc.gz'},{'filename':'https://evil.com/file'},{'collection':'CC-MAIN-2024-23'},{'offset':True},{'length':MAX_BYTES+1},{'digest':'not-a-digest'}])
def test_archive_locators_cannot_escape_provider_or_budgets(change):
    data,digest=warc();record={key:entry(data,digest)[key] for key in ('filename','digest')}
    record.update(collection=COLLECTION,offset=123,length=len(data));record.update(change)
    with pytest.raises(ValueError):validate_record(record)

def test_discovery_range_fetch_and_restart_reuse(tmp_path):
    data,digest=warc();requests=[];saved=state(tmp_path)
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler(data,digest,requests))) as client:
            provider=CommonCrawlProvider(client,'https://example.com/',OPTIONS,lambda:False,saved)
            captures,limited=await provider.discover()
            assert limited and len(captures)==1
            assert (await provider.fetch(captures[0]))[0]==BODY.decode()
            assert await provider.discover()==(captures,True)
            assert len(requests)==3
    asyncio.run(run())

@pytest.mark.parametrize('status,headers,payload',[(200,{},b'data'),(302,{'location':'https://example.com'},b''),(206,{'content-range':'bytes 0-3/100'},b'data'),(206,{'content-range':'bytes 123-126/200'},b'bad')])
def test_range_fetch_rejects_redirects_wrong_ranges_and_truncation(tmp_path,status,headers,payload):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request:httpx.Response(status,headers=headers,content=payload))) as client:
            provider=CommonCrawlProvider(client,'https://example.com/',OPTIONS,lambda:False,state(tmp_path))
            with pytest.raises(ArchiveError):await provider.request('https://data.commoncrawl.org/'+FILENAME,record={'offset':123,'length':4,'filename':FILENAME,'collection':COLLECTION,'digest':'A'*32})
    asyncio.run(run())


@pytest.mark.parametrize('endpoint',['https://user:password@index.commoncrawl.org/collinfo.json','https://index.commoncrawl.org:8443/collinfo.json','http://index.commoncrawl.org/collinfo.json','https://127.0.0.1/collinfo.json','https://index.commoncrawl.org/arbitrary','https://data.commoncrawl.org/private'])
def test_provider_transport_refuses_unapproved_routes_before_network(tmp_path,endpoint):
    async def run():
        def network(request):raise AssertionError('Refused URL must not reach network')
        async with httpx.AsyncClient(transport=httpx.MockTransport(network)) as client:
            provider=CommonCrawlProvider(client,'https://example.com/',OPTIONS,lambda:False,state(tmp_path))
            with pytest.raises(ArchiveError):await provider.request(endpoint)
    asyncio.run(run())

def test_runtime_falls_back_without_claiming_full_coverage_or_uploading_source(tmp_path,monkeypatch):
    from agent.history.recovery import RecoveryPolicy
    monkeypatch.setattr('agent.history.recovery.RecoveryPolicy',lambda:RecoveryPolicy(first_backoff=0))
    target,scope=validate('https://example.com/',OPTIONS);events=[];data,digest=warc();requests=[]
    class Emitter:
        async def emit(self,event):events.append(event)
        async def flush(self):pass
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler(data,digest,requests))) as client:
            runner=HistoricalScanOrchestrator({'scan_id':str(uuid4()),'target_id':str(uuid4()),'source_type':'HISTORY','target':target,'historical':OPTIONS,'scope_fingerprint':scope,'history_protocol':2,'history_sources':['wayback','commoncrawl']},Emitter(),Registry(tmp_path/'private'/'agent.db'),client)
            await runner.start_scan()
        captures=[item['data'] for item in events if item['event_type']=='historical_capture']
        assert len(captures)==1 and captures[0]['archive_provider']=='commoncrawl' and captures[0]['outcome']=='analyzed'
        assert captures[0]['archive_record']['digest']==digest
        assert [item['data'] for item in events if item['event_type']=='scan_completed'][0]['complete'] is False
        assert any(item['data'].get('archive',{}).get('provider')=='commoncrawl' for item in events)
        assert any(item['event_type']=='secret_found' and item['data']['historical']['archive_record']['digest']==digest for item in events)
        assert TOKEN not in json.dumps(events)
    asyncio.run(run())

"""Common Crawl CDX discovery and bounded, verified WARC range acquisition."""
import json
import re
import zlib
from datetime import date,datetime,timedelta
from urllib.parse import urlsplit
import httpx
from agent.history.archive import ArchiveError,retry_after_seconds
from agent.history.commoncrawl_record import validate_record,COLLECTION
from agent.history.contracts import MAX_BYTES,MAX_INDEX_BYTES,MAX_SCAN_BYTES,permitted,url
from agent.history.discovery import ArchiveDiscovery
from agent.history.transport import bounded_await
from agent.history.warc import bounded_record


class CommonCrawlProvider:
    name='commoncrawl'
    MAX_COLLECTIONS=4
    MAX_INDEX_REQUESTS=16

    def __init__(self,client,target,config,cancelled,state,cache=None):
        self.client,self.target,self.config,self.cancelled,self.state,self.cache=client,target,config,cancelled,state,cache

    async def request(self,endpoint,*,params=None,record=None):
        parsed=urlsplit(endpoint);host=parsed.hostname
        if parsed.scheme!='https' or parsed.username or parsed.password or parsed.port not in (None,443) or parsed.fragment or parsed.query:raise ArchiveError('scope_refused')
        if record is not None:
            try:record=validate_record(record)
            except (ValueError,TypeError):raise ArchiveError('scope_refused') from None
            if host!='data.commoncrawl.org' or parsed.path!='/'+record['filename']:raise ArchiveError('scope_refused')
        elif host!='index.commoncrawl.org' or (parsed.path!='/collinfo.json' and not re.fullmatch(r'/CC-MAIN-\d{4}-\d{2}-index',parsed.path)):raise ArchiveError('scope_refused')
        async def response():
            headers={'Accept-Encoding':'identity'}
            expected=200
            if record:
                start,end=record['offset'],record['offset']+record['length']-1
                headers['Range']=f'bytes={start}-{end}';expected=206
            try:
                async with self.client.stream('GET',endpoint,params=params,headers=headers,follow_redirects=False,timeout=httpx.Timeout(20,connect=8)) as item:
                    if item.status_code==429:
                        raise ArchiveError('rate_limited',retry_after=retry_after_seconds(item.headers.get('retry-after','')))
                    if item.status_code>=500:raise ArchiveError('archive_unavailable',failure_reason='archive_service_unavailable',retry_after=retry_after_seconds(item.headers.get('retry-after','')))
                    if item.status_code==404 and not record:return b''
                    if item.status_code!=expected:raise ArchiveError('archive_unavailable',failure_reason='archive_access_denied' if item.status_code in (401,403) else 'archive_unavailable')
                    if record:
                        match=re.fullmatch(r'bytes (\d{1,16})-(\d{1,16})/(\d{1,20})',item.headers.get('content-range',''))
                        if not match or (int(match[1]),int(match[2]))!=(start,end) or int(match[3])<=end:raise ArchiveError('invalid_content')
                    encoding=item.headers.get('content-encoding','identity').lower().strip()
                    if encoding not in ('identity','gzip','deflate') or record and encoding!='identity':raise ArchiveError('invalid_content')
                    decoder=zlib.decompressobj(16+zlib.MAX_WBITS if encoding=='gzip' else zlib.MAX_WBITS) if encoding!='identity' else None
                    limit=record['length'] if record else MAX_INDEX_BYTES
                    body=bytearray();wire=0;previous=self.state.get('cc:wire_bytes') or 0
                    try:
                        async def chunks():
                            if item.is_stream_consumed:yield item.content
                            else:
                                async for chunk in item.aiter_raw():yield chunk
                        async for chunk in chunks():
                            if self.cancelled():raise InterruptedError()
                            wire+=len(chunk)
                            if wire>limit:raise ArchiveError('response_limit')
                            if previous+wire>MAX_SCAN_BYTES:raise ArchiveError('budget_limit')
                            if decoder:
                                try:chunk=decoder.decompress(chunk,limit-len(body)+1)
                                except zlib.error:raise ArchiveError('invalid_content') from None
                            if len(body)+len(chunk)>limit:raise ArchiveError('response_limit')
                            body.extend(chunk)
                        if decoder and (not decoder.eof or decoder.unused_data):raise ArchiveError('invalid_content')
                        if record and len(body)!=record['length']:raise ArchiveError('invalid_content')
                        return bytes(body)
                    finally:self.state.put('cc:wire_bytes',previous+wire)
            except httpx.TimeoutException:raise ArchiveError('archive_unavailable',failure_reason='archive_timeout') from None
            except httpx.HTTPError:raise ArchiveError('archive_unavailable',failure_reason='archive_network_error') from None
        return await bounded_await(response,self.cancelled,30)

    async def discover(self):
        selected=self.state.get('cc:collections')
        if selected is None:
            body=await self.request('https://index.commoncrawl.org/collinfo.json')
            try:catalog=json.loads(body)
            except (ValueError,UnicodeError,RecursionError):raise ArchiveError('invalid_content') from None
            if not isinstance(catalog,list) or len(catalog)>1000:raise ArchiveError('invalid_content')
            first=date.fromisoformat(self.config['from_date'])-timedelta(days=35)
            last=date.fromisoformat(self.config['to_date'])+timedelta(days=35)
            collections=[]
            for entry in catalog:
                identifier=entry.get('id') if isinstance(entry,dict) else None
                if not isinstance(identifier,str) or not COLLECTION.fullmatch(identifier):continue
                try:moment=datetime.strptime(identifier[8:]+'-1','%G-%V-%u').date()
                except ValueError:continue
                if first<=moment<=last:collections.append(identifier)
            collections=sorted(set(collections))
            if len(collections)>self.MAX_COLLECTIONS:
                collections=[collections[index*(len(collections)-1)//(self.MAX_COLLECTIONS-1)] for index in range(self.MAX_COLLECTIONS)]
            selected=collections;self.state.put('cc:collections',selected)
        if not isinstance(selected,list) or len(selected)>self.MAX_COLLECTIONS or any(not isinstance(item,str) or not COLLECTION.fullmatch(item) for item in selected):raise ArchiveError('invalid_content')
        pools=[];failure=None
        for collection in selected:
            if self.cancelled():raise InterruptedError()
            rows=self.state.get('cc:rows:'+collection)
            if rows is None:
                attempts=self.state.get('cc:index_requests') or 0
                if type(attempts) is not int or attempts>=self.MAX_INDEX_REQUESTS:raise ArchiveError('budget_limit')
                self.state.put('cc:index_requests',attempts+1)
                try:
                    body=await self.request('https://index.commoncrawl.org/'+collection+'-index',params={
                        'url':urlsplit(self.target).hostname,'matchType':'domain' if self.config['include_subdomains'] else 'host',
                        'output':'json','filter':'status:200','limit':500,
                        'from':self.config['from_date'].replace('-',''),'to':self.config['to_date'].replace('-','')+'235959'})
                    lines=body.splitlines()
                    if len(lines)>500:raise ArchiveError('response_limit')
                    rows=[]
                    for line in lines:
                        try:entry=json.loads(line)
                        except (ValueError,UnicodeError,RecursionError):raise ArchiveError('invalid_content') from None
                        if not isinstance(entry,dict):raise ArchiveError('invalid_content')
                        original,stamp,mime=entry.get('url'),entry.get('timestamp'),entry.get('mime')
                        if entry.get('status')!='200' or not permitted(original,self.target,self.config,stamp):continue
                        if not isinstance(mime,str) or len(mime)>512 or not any(kind in mime.lower() for kind in ('text/','javascript','json','xml','octet-stream')):continue
                        try:
                            if any(isinstance(entry.get(field),bool) or not str(entry.get(field,'')).isdigit() for field in ('offset','length')):raise ValueError()
                            if int(entry['length'])>MAX_BYTES:continue
                            locator=validate_record({'collection':collection,'filename':entry.get('filename'),'offset':int(entry['offset']),
                                'length':int(entry['length']),'digest':entry.get('digest')})
                        except (ValueError,TypeError,KeyError):raise ArchiveError('invalid_content') from None
                        rows.append({'original_url':url(original),'requested_timestamp':stamp,'mime':mime,
                                     'archive_provider':self.name,'archive_record':locator})
                    self.state.put('cc:rows:'+collection,rows)
                except ArchiveError as error:
                    if error.failure_reason in ('archive_rate_limited','archive_access_denied','archive_scope_refused'):raise
                    failure=error;continue
            if not isinstance(rows,list) or len(rows)>500:raise ArchiveError('invalid_content')
            for capture in rows:
                if not isinstance(capture,dict) or set(capture)!={'original_url','requested_timestamp','mime','archive_provider','archive_record'}:raise ArchiveError('invalid_content')
                validate_record(capture['archive_record'])
                if capture.get('archive_provider')!=self.name or not permitted(capture['original_url'],self.target,self.config,capture['requested_timestamp']):raise ArchiveError('invalid_content')
            pools.extend(rows)
        if not pools:raise failure or ArchiveError('archive_unavailable',failure_reason='archive_no_captures')
        unique={(item['original_url'],item['requested_timestamp']):item for item in pools}
        return ArchiveDiscovery.order(list(unique.values()))[:self.config['max_captures']],True

    async def fetch(self,capture):
        if self.cancelled():raise InterruptedError()
        locator=validate_record(capture['archive_record'])
        if capture.get('archive_provider')!=self.name or not permitted(capture['original_url'],self.target,self.config,capture['requested_timestamp']):raise ArchiveError('scope_refused')
        if self.cache:
            cached=self.cache.get(capture)
            if cached is not None:return cached
        body=await self.request('https://data.commoncrawl.org/'+locator['filename'],record=locator)
        result=await bounded_record(body,capture['original_url'],capture['requested_timestamp'],locator['digest'],self.cancelled)
        if self.cache:self.cache.put(capture,result)
        return result

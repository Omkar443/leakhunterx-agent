"""Only Internet Archive is contacted; never replay archived executable code."""
import asyncio
import json
import hashlib
import zlib
import re
import time
import math
from email.utils import parsedate_to_datetime
from contextlib import suppress
from urllib.parse import quote,urlsplit,urljoin
import httpx
from agent.history.contracts import MAX_BYTES,MAX_INDEX_BYTES,permitted,url
from agent.history.failures import CONTENT_FAILURES,HISTORICAL_FAILURES


class ArchiveError(Exception):
    def __init__(self,reason,*,failure_reason=None,retry_after=None):
        self.reason=reason
        code=failure_reason or CONTENT_FAILURES.get(reason,reason)
        self.failure_reason=code if code in HISTORICAL_FAILURES else 'archive_unavailable'
        self.retry_after=retry_after
        super().__init__(self.failure_reason)


def retry_after_seconds(value):
    if not isinstance(value,str) or len(value)>128:return None
    try:
        return min(3600,max(0,int(value))) if value.isdigit() else min(3600,max(0,math.ceil(parsedate_to_datetime(value).timestamp()-time.time()))) if value else None
    except (ValueError,TypeError,OverflowError):return None


class ArchiveClient:
    def __init__(self,client,target,config,cancelled=lambda:False,*,checkpoint=None,managed_retries=False):
        self.client,self.target,self.config,self.cancelled=client,target,config,cancelled
        self.checkpoint=checkpoint
        self.managed_retries=managed_retries

    async def read(self,endpoint,params=None,limit=MAX_BYTES,*,index=False,budget=None):
        if self.cancelled():raise InterruptedError()
        duration=min(30 if index else 60,budget.reserve() if budget else float('inf'))
        deadline=time.monotonic()+duration
        task=asyncio.create_task(self._read_with_retries(endpoint,params,limit,index=index,budget=budget))
        try:
            while True:
                if self.cancelled():raise InterruptedError()
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ArchiveError('archive_unavailable',failure_reason='archive_timeout')
                done,_=await asyncio.wait({task},timeout=min(.25,remaining))
                if done:return await task
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError,Exception):await task

    async def _read_with_retries(self,endpoint,params,limit,*,index,budget):
        attempts=1 if index or self.managed_retries else 3
        for attempt in range(attempts):
            if self.cancelled(): raise InterruptedError()
            try:
                location=endpoint;request_params=params
                for hop in range(5):
                    p=urlsplit(location)
                    if p.scheme!='https' or p.hostname!='web.archive.org' or p.port not in (None,443) or p.username or p.password: raise ArchiveError('scope_refused')
                    if budget and hop:budget.reserve()
                    async with self.client.stream('GET',location,params=request_params,follow_redirects=False,timeout=httpx.Timeout(30 if index else 15,connect=8)) as response:
                        if response.status_code in (301,302,303,307,308):
                            location=urljoin(location,response.headers.get('location',''));request_params=None;continue
                        retry_after=retry_after_seconds(response.headers.get('retry-after',''))
                        if response.status_code==429: raise ArchiveError('rate_limited',retry_after=retry_after)
                        if response.status_code in (401,403): raise ArchiveError('archive_unavailable',failure_reason='archive_access_denied')
                        if response.status_code>=500: raise ArchiveError('archive_unavailable',failure_reason='archive_service_unavailable',retry_after=retry_after)
                        if response.status_code!=200: raise ArchiveError('archive_unavailable')
                        encoding=response.headers.get('content-encoding','identity').lower().strip()
                        if encoding not in ('identity','gzip','deflate'):raise ArchiveError('invalid_content')
                        decoder=zlib.decompressobj(16+zlib.MAX_WBITS if encoding=='gzip' else zlib.MAX_WBITS) if encoding!='identity' else None
                        body=bytearray();wire_bytes=0
                        async def chunks():
                            if response.is_stream_consumed:
                                yield response.content  # Already-buffered custom clients remain bounded.
                            else:
                                async for piece in response.aiter_raw():yield piece
                        async for chunk in chunks():
                            if self.cancelled(): raise InterruptedError()
                            wire_bytes+=len(chunk)
                            if wire_bytes>limit:raise ArchiveError('response_limit')
                            try:chunk=decoder.decompress(chunk,limit-len(body)+1) if decoder else chunk
                            except zlib.error:raise ArchiveError('invalid_content') from None
                            if len(body)+len(chunk)>limit:raise ArchiveError('response_limit')
                            body.extend(chunk)
                        if decoder and (not decoder.eof or decoder.unused_data):raise ArchiveError('invalid_content')
                        return bytes(body),str(response.url),response.headers
                raise ArchiveError('archive_unavailable')
            except httpx.TimeoutException:
                error=ArchiveError('archive_unavailable',failure_reason='archive_timeout')
            except httpx.HTTPError:
                error=ArchiveError('archive_unavailable',failure_reason='archive_network_error')
            except ArchiveError as failure:
                error=failure
            if error.reason!='archive_unavailable' or error.failure_reason=='archive_access_denied' or attempt==attempts-1: raise error
            # Fixed bounded retry window; do not wait out long provider quotas.
            await asyncio.sleep(min(4,2**attempt))
        raise ArchiveError('archive_unavailable')

    async def index(self,query,*,budget=None):
        """Two bounded CDX pages with the same validation for every date partition."""
        pool=[];cursor=None
        query=dict(query)
        key=self.checkpoint.query_key(query) if self.checkpoint else None
        saved=self.checkpoint.get(key) if self.checkpoint else None
        pages=0
        if saved:
            pool=saved['rows'];cursor=saved['cursor'];pages=saved['pages']
            self.validate_checkpoint_rows(pool,query)
            if type(pages) is not int or not 0<=pages<=2 or type(saved['done']) is not bool or (cursor is not None and (not isinstance(cursor,str) or not cursor or len(cursor)>4096 or any(ord(c)<32 for c in cursor))):raise ArchiveError('invalid_content')
            if saved['done']:return pool,bool(cursor)
        for page in range(pages,2):
            if cursor:query['resumeKey']=cursor
            body,_,_=await self.read('https://web.archive.org/cdx/search/cdx',query,MAX_INDEX_BYTES,index=True,budget=budget)
            try:
                text=body.decode('utf-8').lstrip()
                rows,end=json.JSONDecoder().raw_decode(text)
            except (UnicodeError,ValueError,RecursionError):raise ArchiveError('invalid_content') from None
            cursor=text[end:].strip() or None
            if isinstance(rows,list) and len(rows)>=3 and rows[-2]==[] and isinstance(rows[-1],list) and len(rows[-1])==1:
                cursor=rows[-1][0];rows=rows[:-2]
            if cursor is not None and (not isinstance(cursor,str) or not cursor or len(cursor)>4096 or any(ord(c)<32 for c in cursor)):raise ArchiveError('invalid_content')
            if not isinstance(rows,list) or len(rows)>query['limit']+1:raise ArchiveError('invalid_content')
            if not rows:
                if self.checkpoint:self.checkpoint.put(key,{'rows':pool,'cursor':None,'pages':page+1,'done':True})
                break
            if rows[0]!=['timestamp','original','mimetype','statuscode','digest']:raise ArchiveError('invalid_content')
            for row in rows[1:]:
                if not isinstance(row,list) or len(row)!=5 or any(not isinstance(v,str) for v in row):raise ArchiveError('invalid_content')
                stamp,original,mime,status,digest=row
                if len(mime)>512:raise ArchiveError('invalid_content')
                if status!='200' or not permitted(original,self.target,self.config,stamp):continue
                if not query.get('from','')<=stamp<=query.get('to','99999999999999'):continue
                fields={'mimetype':mime,'original':original,'statuscode':status}
                if any(not re.fullmatch(pattern,fields[field]) for clause in query.get('filter',[])
                       for field,_,pattern in [clause.partition(':')] if field in fields):continue
                pool.append({'original_url':url(original),'requested_timestamp':stamp,'mime':mime})
            if self.checkpoint:self.checkpoint.put(key,{'rows':pool,'cursor':cursor,'pages':page+1,'done':not cursor or page==1})
            if not cursor:break
        return pool,bool(cursor)

    def validate_checkpoint_rows(self,rows,query,maximum=1000,*,providers=False):
        if not isinstance(rows,list) or len(rows)>maximum:raise ArchiveError('invalid_content')
        for row in rows:
            if not isinstance(row,dict):raise ArchiveError('invalid_content')
            required={'original_url','requested_timestamp','mime'}
            if providers and row.get('archive_provider')=='commoncrawl':
                from agent.history.commoncrawl_record import validate_record
                required|={'archive_provider','archive_record'}
                try:validate_record(row['archive_record'])
                except (ValueError,KeyError):raise ArchiveError('invalid_content') from None
            if set(row)!=required:raise ArchiveError('invalid_content')
            original,stamp,mime=row['original_url'],row['requested_timestamp'],row['mime']
            if not isinstance(stamp,str) or not isinstance(mime,str) or len(mime)>512 or not permitted(original,self.target,self.config,stamp):raise ArchiveError('invalid_content')
            if not query.get('from','')<=stamp<=query.get('to','99999999999999'):raise ArchiveError('invalid_content')

    async def discover(self):
        from agent.history.discovery import ArchiveDiscovery
        return await ArchiveDiscovery(self).discover()

    async def fetch(self,capture):
        original=capture['original_url'];stamp=capture['requested_timestamp']
        body,location,headers=await self.read('https://web.archive.org/web/'+stamp+'id_/'+quote(original,safe=':/%?&='))
        match=re.match(r'https://web\.archive\.org/web/(\d{14})(?:id_|im_|js_)?/(.+)',location)
        if not match: raise ArchiveError('invalid_content')
        actual,returned=match.groups()
        if returned!=original or not permitted(returned,self.target,self.config,actual): raise ArchiveError('scope_refused')
        content_type=headers.get('content-type','').lower()
        if not any(t in content_type for t in ('text/','javascript','json','xml','octet-stream')): raise ArchiveError('invalid_content')
        charset=re.search(r'charset=["\x27]?([a-zA-Z0-9_-]+)',content_type)
        encoding={'utf-8':'utf-8-sig','utf8':'utf-8-sig','us-ascii':'ascii','iso-8859-1':'latin-1','windows-1252':'cp1252'}.get(charset.group(1).lower() if charset else 'utf-8')
        if encoding is None:raise ArchiveError('invalid_content')
        try: content=body.decode(encoding)
        except UnicodeError: raise ArchiveError('invalid_content') from None
        if '\x00' in content or ('Wayback Machine' in content[:5000] and ('wb-autocomplete' in content[:5000] or 'Wayback Machine has not archived' in content)): raise ArchiveError('invalid_content')
        return content,actual,hashlib.sha256(body).hexdigest(),len(body)

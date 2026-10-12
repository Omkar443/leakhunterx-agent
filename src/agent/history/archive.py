"""Only Internet Archive is contacted; never replay archived executable code."""
import asyncio
import json
import hashlib
import zlib
import re
from urllib.parse import quote,urlsplit,urljoin
import httpx
from agent.history.contracts import MAX_BYTES,MAX_INDEX_BYTES,permitted,url


class ArchiveError(Exception):
    def __init__(self,reason): self.reason=reason;super().__init__(reason)


class ArchiveClient:
    def __init__(self,client,target,config,cancelled=lambda:False):
        self.client,self.target,self.config,self.cancelled=client,target,config,cancelled

    async def read(self,endpoint,params=None,limit=MAX_BYTES):
        for attempt in range(3):
            if self.cancelled(): raise InterruptedError()
            try:
                location=endpoint
                for _ in range(5):
                    p=urlsplit(location)
                    if p.scheme!='https' or p.hostname!='web.archive.org' or p.port not in (None,443) or p.username or p.password: raise ArchiveError('scope_refused')
                    async with self.client.stream('GET',location,params=params,follow_redirects=False,timeout=httpx.Timeout(15,connect=8)) as response:
                        if response.status_code in (301,302,303,307,308):
                            location=urljoin(location,response.headers.get('location',''));params=None;continue
                        if response.status_code==429: raise ArchiveError('rate_limited')
                        if response.status_code>=500: raise ArchiveError('archive_unavailable')
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
            except httpx.HTTPError:
                error=ArchiveError('archive_unavailable')
            except ArchiveError as failure:
                error=failure
            if error.reason not in ('archive_unavailable','rate_limited') or attempt==2: raise error
            # Fixed bounded retry window; do not wait out long provider quotas.
            await asyncio.sleep(min(4,2**attempt))
        raise ArchiveError('archive_unavailable')

    async def discover(self):
        root=urlsplit(self.target).hostname
        params={'url':root,'matchType':'domain' if self.config['include_subdomains'] else 'host','output':'json',
                'fl':'timestamp,original,mimetype,statuscode,digest','from':self.config['from_date'].replace('-',''),
                'to':self.config['to_date'].replace('-','')+'235959',
                'limit':500,'showResumeKey':'true','collapse':'digest'}
        # Root-page captures otherwise crowd every script out of a lexical CDX
        # page. Use separate bounded indexes for scripts, maps and HTML/text.
        filters=['mimetype:.*javascript.*',r'original:.*\.map(?:\?.*)?',
                 'mimetype:(text/html|text/plain|application/json|text/xml|application/xml|application/octet-stream)']
        pools=[];seen=set();limited=False;successes=0;last_error=None
        for category in filters:
            pool=[];cursor=None
            query={**params,'filter':['statuscode:200',category]}
            try:
                for _ in range(2):
                    if cursor:query['resumeKey']=cursor
                    body,_,_=await self.read('https://web.archive.org/cdx/search/cdx',query,MAX_INDEX_BYTES)
                    text=body.decode('utf-8')
                    try:rows,end=json.JSONDecoder().raw_decode(text.lstrip())
                    except (ValueError,RecursionError):raise ArchiveError('invalid_content') from None
                    cursor=text.lstrip()[end:].strip() or None
                    # Production CDX JSON includes [] and [resumeKey] inside JSON.
                    if isinstance(rows,list) and len(rows)>=3 and rows[-2]==[] and isinstance(rows[-1],list) and len(rows[-1])==1:
                        cursor=rows[-1][0];rows=rows[:-2]
                    if cursor is not None and (not isinstance(cursor,str) or not cursor or len(cursor)>4096 or any(ord(c)<32 for c in cursor)):raise ArchiveError('invalid_content')
                    if not isinstance(rows,list) or len(rows)>501:raise ArchiveError('invalid_content')
                    if not rows:break
                    if rows[0]!=['timestamp','original','mimetype','statuscode','digest']:raise ArchiveError('invalid_content')
                    for row in rows[1:]:
                        if not isinstance(row,list) or len(row)!=5 or any(not isinstance(v,str) for v in row):raise ArchiveError('invalid_content')
                        stamp,original,mime,status,digest=row
                        if status!='200' or not permitted(original,self.target,self.config,stamp):continue
                        original=url(original);identity=(original,stamp)
                        if identity in seen:continue
                        seen.add(identity);pool.append({'original_url':original,'requested_timestamp':stamp,'mime':mime})
                    if not cursor:break
                successes+=1;limited|=bool(cursor)
            except ArchiveError as error:last_error=error;limited=True
            # Spread captures across resources, then earliest/latest inspected
            # versions, before dense intermediate captures of one resource.
            groups={}
            for row in pool:groups.setdefault(row['original_url'],[]).append(row)
            ordered=[]
            for rows in groups.values():
                rows.sort(key=lambda r:r['requested_timestamp'])
                if len(rows)>2:rows[:]=[rows[0],rows[-1],*rows[1:-1]]
            while any(groups.values()):
                for name in sorted(groups):
                    if groups[name]:ordered.append(groups[name].pop(0))
            pools.append(ordered)
        if not successes and last_error:raise last_error
        maximum=self.config['max_captures'];selected=[]
        quotas=[max(1,int(maximum*.6)),max(1,int(maximum*.25)),max(1,int(maximum*.15))]
        for pool,quota in zip(pools,quotas):
            take=min(quota,len(pool),maximum-len(selected));selected.extend(pool[:take]);del pool[:take]
        for pool in pools:
            take=min(len(pool),maximum-len(selected));selected.extend(pool[:take]);del pool[:take]
        limited|=any(pools)
        if not selected and last_error:raise last_error
        selected.sort(key=lambda r:(r['requested_timestamp'],r['original_url']))
        return selected,limited

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

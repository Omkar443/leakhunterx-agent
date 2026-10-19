"""WARC parsing is isolated from the agent process and never executes content."""
import asyncio
import hashlib
import io
import multiprocessing
import time
import zlib
from datetime import datetime,timezone
import psutil
from agent.history.archive import ArchiveError
from agent.history.contracts import MAX_BYTES,url


def parse_record(data,original,stamp,digest):
    from warcio.archiveiterator import ArchiveIterator
    # Validate the gzip member's CRC/footer and size ourselves: WARC readers can
    # accept an intact payload from a truncated gzip member without its footer.
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:raise ValueError()
    decoder=zlib.decompressobj(16+zlib.MAX_WBITS)
    decoded=decoder.decompress(data,MAX_BYTES+65537)
    if len(decoded)>MAX_BYTES+65536 or not decoder.eof or decoder.unused_data:raise ValueError()
    iterator=ArchiveIterator(io.BytesIO(decoded),check_digests=True)
    record=next(iterator)
    if record.rec_type!='response' or url(record.rec_headers.get_header('WARC-Target-URI'))!=original:raise ValueError()
    moment=datetime.fromisoformat(record.rec_headers.get_header('WARC-Date').replace('Z','+00:00'))
    if moment.tzinfo is None:raise ValueError()
    actual=moment.astimezone(timezone.utc).strftime('%Y%m%d%H%M%S')
    if actual!=stamp or record.rec_headers.get_header('WARC-Payload-Digest','').upper()!='SHA1:'+digest:raise ValueError()
    if record.http_headers is None or record.http_headers.get_statuscode()!='200':raise ValueError()
    content_type=record.http_headers.get_header('Content-Type','').lower()
    if not any(kind in content_type for kind in ('text/','javascript','json','xml','octet-stream')):raise ValueError()
    body=record.content_stream().read(MAX_BYTES+1)
    if len(body)>MAX_BYTES:raise ValueError()
    if next(iterator,None) is not None or record.digest_checker.passed is not True:raise ValueError()
    import re
    match=re.search(r'charset=["\x27]?([a-zA-Z0-9_-]+)',content_type)
    encoding={'utf-8':'utf-8-sig','utf8':'utf-8-sig','us-ascii':'ascii','iso-8859-1':'latin-1','windows-1252':'cp1252'}.get(match[1] if match else 'utf-8')
    if encoding is None:raise ValueError()
    text=body.decode(encoding)
    if '\x00' in text:raise ValueError()
    return text,actual,hashlib.sha256(body).hexdigest(),len(body)


def _worker(pipe,args):
    try:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_AS,(192*1024*1024,192*1024*1024))
            resource.setrlimit(resource.RLIMIT_CPU,(8,8))
        except (ImportError,ValueError,OSError):pass
        pipe.send(parse_record(*args))
    except BaseException:pipe.send(None)
    finally:pipe.close()


async def bounded_record(data,original,stamp,digest,cancelled):
    context=multiprocessing.get_context('spawn');receiver,sender=context.Pipe(duplex=False)
    worker=context.Process(target=_worker,args=(sender,(data,original,stamp,digest)),daemon=True)
    worker.start();sender.close();started=time.monotonic()
    try:
        while worker.is_alive() and not receiver.poll():
            if cancelled():raise InterruptedError()
            if time.monotonic()-started>10:raise ArchiveError('invalid_content')
            try:
                if psutil.Process(worker.pid).memory_info().rss>192*1024*1024:raise ArchiveError('response_limit')
            except psutil.Error:pass
            await asyncio.sleep(.05)
        if cancelled():raise InterruptedError()
        try:result=receiver.recv() if receiver.poll() else None
        except (EOFError,OSError):result=None
        if result is None:raise ArchiveError('invalid_content')
        return result
    finally:
        if worker.is_alive():worker.terminate()
        await asyncio.to_thread(worker.join,2)
        if worker.is_alive():worker.kill();await asyncio.to_thread(worker.join,2)
        receiver.close()

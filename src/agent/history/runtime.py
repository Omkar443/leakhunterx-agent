"""Resumable archive manifests and redacted checkpoints using shared outbox/control."""
import asyncio
import base64
import hmac
import hashlib
import json
import secrets
import time
import multiprocessing
import psutil
from datetime import datetime,timezone
from uuid import UUID,uuid4
from urllib.parse import urlsplit
import httpx
from agent.local.registry import Registry
from agent.local.scanner import envelope,keyed
from agent.sources.base import Artifact
from agent.js.leak_detector import EnterpriseLeakDetector
from agent.orchestrator import ScanStatus
from agent.history.archive import ArchiveClient,ArchiveError
from agent.history.contracts import validate,MAX_SCAN_BYTES
from agent.history.javascript import source_map_reference,recover_sources,literal_assignments,mapped_location


def _analysis_worker(pipe,identity,content,original,actual,map_content,map_provenance):
    try:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
            resource.setrlimit(resource.RLIMIT_CPU,(25,25))
        except (ImportError,ValueError,OSError): pass
        runner=object.__new__(HistoricalScanOrchestrator);runner.identity=identity
        pipe.send(runner.analyze(content,original,actual,map_content=map_content,map_provenance=map_provenance))
    except BaseException: pipe.send(None)
    finally: pipe.close()


class HistoricalScanOrchestrator:
    def __init__(self,assignment,emitter,registry=None,client=None):
        if assignment.get('source_type')!='HISTORY': raise ValueError('Historical assignment required')
        self.scan_id=str(UUID(assignment['scan_id']));self.target_id=str(UUID(assignment['target_id']))
        self.target,self.scope=validate(assignment['target'],assignment['historical'])
        if self.scope!=assignment.get('scope_fingerprint'): raise ValueError('Historical scope mismatch')
        self.config=assignment['historical'];self.emitter=emitter;self.registry=registry or Registry();self.client=client
        self.correlation=assignment.get('correlation_identity');self.status=ScanStatus.PENDING
        self._shared_transport=True;self._backend_terminal_status=None;self._stop=False;self._scan_timeout=600;self.deadline=None
        if assignment.get('deadline_at'): self.deadline=datetime.fromisoformat(assignment['deadline_at'].replace('Z','+00:00')).timestamp()
        with self.registry.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS history_keys(target_id TEXT PRIMARY KEY,key BLOB NOT NULL,key_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS history_jobs(scan_id TEXT PRIMARY KEY,target_id TEXT NOT NULL,scope TEXT NOT NULL,manifest TEXT,status TEXT NOT NULL,limited INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS history_artifacts(scan_id TEXT NOT NULL,position INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(scan_id,position),FOREIGN KEY(scan_id) REFERENCES history_jobs(scan_id) ON DELETE CASCADE);''')
            db.execute('INSERT OR IGNORE INTO history_keys VALUES(?,?,?)',(self.target_id,secrets.token_bytes(32),str(uuid4())))
            key=db.execute('SELECT key,key_id FROM history_keys WHERE target_id=?',(self.target_id,)).fetchone()
            from agent.correlation import approved
            correlation=approved(self.correlation)
            if correlation:
                material=hmac.new(base64.urlsafe_b64decode(correlation['key']),('lhx-history-target-v1:'+self.target_id).encode(),hashlib.sha256).digest()
                key={'key':material,'key_id':str(UUID(hashlib.sha256(material).hexdigest()[:32]))}
            self.identity={'id':self.target_id,'key':key['key'],'key_id':key['key_id'],'source_type':'HISTORY','correlation_identity':self.correlation}
            job=db.execute('SELECT * FROM history_jobs WHERE scan_id=?',(self.scan_id,)).fetchone()
            if job and (job['target_id']!=self.target_id or job['scope']!=self.scope): raise ValueError('Historical checkpoint scope changed')
            db.execute("INSERT OR IGNORE INTO history_jobs(scan_id,target_id,scope,status) VALUES(?,?,?,'running')",(self.scan_id,self.target_id,self.scope))

    def cancelled(self):
        return self._stop or (self.deadline is not None and time.time()>=self.deadline)

    async def event(self,kind,data):
        identity=hashlib.sha256((self.scan_id+'|'+kind+'|'+json.dumps(data,sort_keys=True,separators=(',',':'))).encode()).hexdigest()
        await self.emitter.emit({'event_id':identity,'event_type':kind,'scan_id':self.scan_id,'timestamp':int(time.time()),'data':data})

    async def bounded_analysis(self,content,original,actual,map_content,map_provenance=None):
        context=multiprocessing.get_context('spawn');receiver,sender=context.Pipe(duplex=False)
        worker=context.Process(target=_analysis_worker,args=(sender,self.identity,content,original,actual,map_content,map_provenance),daemon=True)
        worker.start();sender.close();started=time.monotonic()
        try:
            while worker.is_alive() and not receiver.poll():
                if self.cancelled(): raise InterruptedError()
                if time.monotonic()-started>30: raise TimeoutError('Analysis budget exceeded')
                try:
                    if psutil.Process(worker.pid).memory_info().rss>512*1024*1024: raise ValueError('Analysis memory budget exceeded')
                except psutil.Error: pass
                await asyncio.sleep(.05)
            result=receiver.recv() if receiver.poll() else None
            if result is None: raise ValueError('Analysis unavailable')
            return result
        finally:
            if worker.is_alive(): worker.terminate()
            await asyncio.to_thread(worker.join,2)
            if worker.is_alive(): worker.kill();await asyncio.to_thread(worker.join,2)
            receiver.close()

    def analyze(self,content,original,actual,*,kind='archived_resource',map_content=None,map_provenance=None):
        digest=hashlib.sha256(content.encode()).hexdigest()
        candidates=[];map_status='not_present';mapping_attempts=0
        def detect(body,locator,evidence_kind,line_override=None,mapping=None):
            nonlocal mapping_attempts
            detector=EnterpriseLeakDetector()
            artifact=Artifact(digest,'HISTORY',locator,'application/javascript','javascript',len(body.encode()),hashlib.sha256(body.encode()).hexdigest(),body)
            for finding in detector.check_content(body)[:200]:
                safe=envelope(self.identity,artifact,finding)
                # Locations are source-free checkpoints; original public URL is
                # approved separately. Stable finding identity excludes capture time.
                safe['file_path']=safe['source_url']='archive/'+safe['source_hash']+'.js'
                safe['fingerprint']=keyed(self.identity['key'],'historical-secret-v1',safe['type'],safe['secret_fingerprint'])
                if line_override: safe['line_number']=line_override
                safe['historical']={'original_url':original,'requested_timestamp':actual,'actual_timestamp':actual,
                    'content_sha256':digest,'evidence_kind':evidence_kind}
                if line_override: safe['historical']['reconstruction']='static_string_concatenation'
                if evidence_kind=='embedded_source' and map_provenance:
                    safe['historical']['source_map']=map_provenance
                if mapping and mapping_attempts<10:
                    mapping_attempts+=1
                    offset=max(0,int(finding.get('match_start') or 0));prefix=body[body.rfind('\n',0,offset)+1:offset]
                    try:
                        location=mapped_location(mapping,locator,body,safe['line_number'],len(prefix.encode('utf-16-le'))//2)
                        if location: safe['historical']['mapping']=location
                    except (ValueError,TypeError,KeyError,RecursionError):pass
                candidates.append(safe)
        detect(content,original,kind)
        for reconstructed,line in literal_assignments(content):
            detect(reconstructed,original,kind,line)
        try:
            reference=source_map_reference(content,original)
            text=reference if reference and reference.startswith('{') else map_content
            if original.lower().endswith('.map'): text=content
            if text:
                sources=recover_sources(text)
                map_status=('embedded_recovered' if reference and reference.startswith('{') else 'archived_recovered') if sources else 'unavailable'
                for name,body in sources: detect(body,name,'embedded_source',mapping=text)
            elif reference: map_status='unavailable'
        except (ValueError,UnicodeError,RecursionError): map_status='invalid'
        # Prefer recovered source semantic observations over the encoded map/bundle
        # candidate; a secret repeated in source and bundle is one scan finding.
        unique={}
        for finding in candidates: unique[finding['fingerprint']]=finding
        return list(unique.values())[:200],digest,map_status

    async def start_scan(self):
        self.status=ScanStatus.RUNNING
        await self.event('scan_started',{'source_type':'HISTORY','target_id':self.target_id,'scope_fingerprint':self.scope,'fingerprint_key_id':self.identity['key_id']})
        started=time.monotonic()
        owned=self.client is None
        client=self.client or httpx.AsyncClient(headers={'User-Agent':'LeakHunterX-Historical/1','Accept-Encoding':'gzip, deflate'},limits=httpx.Limits(max_connections=2,max_keepalive_connections=2),trust_env=False)
        archive=ArchiveClient(client,self.target,self.config,lambda:self.cancelled() or time.monotonic()-started>=self._scan_timeout)
        try:
            with self.registry.connect() as db: job=dict(db.execute('SELECT * FROM history_jobs WHERE scan_id=?',(self.scan_id,)).fetchone())
            await self.event('discovery_started',{})
            if job['manifest'] is None:
                manifest,limited=await archive.discover()
                with self.registry.connect() as db: db.execute('UPDATE history_jobs SET manifest=?,limited=? WHERE scan_id=?',(json.dumps(manifest),int(limited),self.scan_id))
            else: manifest=json.loads(job['manifest']);limited=bool(job['limited'])
            await self.event('discovery_completed',{'routes_discovered':len(manifest),'total_files':len(manifest)})
            await self.event('crawling_started',{})
            await self.event('analysis_started',{'source_type':'HISTORY','total_files':len(manifest)})
            with self.registry.connect() as db: checkpoint={r['position']:json.loads(r['payload']) for r in db.execute('SELECT * FROM history_artifacts WHERE scan_id=?',(self.scan_id,))}
            emitted=set();ok=failed=timed_out=bytes_processed=0
            for position,capture in enumerate(manifest):
                if archive.cancelled(): raise InterruptedError()
                record=checkpoint.get(position)
                if record is None:
                    meta={'original_url':capture['original_url'],'requested_timestamp':capture['requested_timestamp'],'actual_timestamp':capture['requested_timestamp'],
                          'content_sha256':None,'evidence_kind':'archived_resource','outcome':'unavailable','reason':'archive_unavailable','bytes':0,'finding_fingerprints':[],'source_map_status':'not_present'}
                    findings=[]
                    try:
                        remaining=self.deadline-time.time() if self.deadline else 1000
                        if bytes_processed>=MAX_SCAN_BYTES or len(emitted)>=1000 or time.monotonic()-started>=min(480,max(1,self._scan_timeout-60)) or remaining<30: raise ArchiveError('budget_limit')
                        content,actual,raw_digest,size=await archive.fetch(capture)
                        if bytes_processed+size>MAX_SCAN_BYTES: raise ArchiveError('budget_limit')
                        map_content=None;map_provenance=None
                        # A declared external map is fetched from its own indexed
                        # capture at/before the bundle capture, never from live Web.
                        try: ref=source_map_reference(content,capture['original_url'])
                        except (ValueError,UnicodeError): ref=None
                        if ref and ref.startswith(('http://','https://')):
                            choices=[c for c in manifest if c['original_url']==ref and c['requested_timestamp']<=actual]
                            if choices:
                                choice=max(choices,key=lambda c:c['requested_timestamp'])
                                try:
                                    map_content,map_actual,map_digest,map_size=await archive.fetch(choice)
                                    if map_actual>actual or bytes_processed+size+map_size>MAX_SCAN_BYTES: map_content=None
                                    else:
                                        bytes_processed+=map_size
                                        map_provenance={'original_url':choice['original_url'],'actual_timestamp':map_actual,'content_sha256':map_digest,'association':'declared_nearest_prior_capture'}
                                except ArchiveError: pass
                        digest=raw_digest
                        # Redacted analysis may be reused only for identical bytes
                        # at the same original URL with no external map dependency.
                        cached=next((r for r in checkpoint.values() if (r['findings'] or not r['metadata']['finding_fingerprints']) and not (ref and ref.startswith(('http://','https://'))) and r['metadata']['original_url']==capture['original_url'] and r['metadata']['content_sha256']==digest and r['metadata']['outcome']=='analyzed'),None)
                        if cached:
                            findings=json.loads(json.dumps(cached['findings']));map_status=cached['metadata']['source_map_status']
                            for finding in findings: finding['historical']['actual_timestamp']=actual
                        else: findings,_,map_status=await self.bounded_analysis(content,capture['original_url'],actual,map_content,map_provenance)
                        for f in findings:
                            f['historical']['requested_timestamp']=capture['requested_timestamp']
                            f['historical']['content_sha256']=raw_digest
                        meta.update(actual_timestamp=actual,content_sha256=digest,outcome='analyzed',reason='none',bytes=size,
                            finding_fingerprints=[f['fingerprint'] for f in findings],source_map_status=map_status)
                        if map_provenance: meta['source_map']=map_provenance
                        content=None;map_content=None
                    except ArchiveError as error:
                        meta['reason']=error.reason
                        if error.reason=='budget_limit': meta['outcome']='excluded'
                    except TimeoutError: meta['reason']='analysis_timeout'
                    except (ValueError,UnicodeError,RecursionError,asyncio.TimeoutError): meta['reason']='invalid_content'
                    # One redacted envelope per identity across the manifest;
                    # capture references retain all occurrences without 300 copies
                    # of the same semantic payload in memory or on disk.
                    fresh=[f for f in findings if f['fingerprint'] not in emitted][:max(0,1000-len(emitted))]
                    record={'metadata':meta,'findings':fresh}
                    with self.registry.connect() as db: db.execute('INSERT OR IGNORE INTO history_artifacts VALUES(?,?,?)',(self.scan_id,position,json.dumps(record)))
                    checkpoint[position]=record
                meta=record['metadata'];bytes_processed+=meta['bytes']
                if meta['outcome']=='analyzed': ok+=1
                elif meta['reason']=='analysis_timeout': timed_out+=1
                else: failed+=1
                for finding in record['findings']:
                    if finding['fingerprint'] not in emitted and len(emitted)<1000:
                        await self.event('secret_found',finding);emitted.add(finding['fingerprint'])
                await self.event('historical_capture',meta)
                await self.event('scan_progress',{'phase':'analysis','processed_files':position+1,'total_files':len(manifest),'successful_analyses':ok,'failed_analyses':failed,'timed_out_analyses':timed_out,'analysis_limited':True})
            if manifest and not ok: raise ArchiveError('archive_unavailable')
            await self.event('js_analysis_summary',{'processed_files':len(manifest),'total_files':len(manifest),'successful_analyses':ok,'failed_analyses':failed,'timed_out_analyses':timed_out,'findings_count':len(emitted),'total_secrets_found':len(emitted),'analysis_limited':True})
            await self.event('scan_completed',{'source_type':'HISTORY','complete':not failed and not timed_out and not limited,'findings_count':len(emitted),'analysis_limited':True})
            await self.emitter.flush()
            with self.registry.connect() as db: db.execute("UPDATE history_jobs SET status='completed' WHERE scan_id=?",(self.scan_id,))
            self.status=ScanStatus.COMPLETED
        except (InterruptedError,asyncio.CancelledError):
            self._stop=True;self.status=ScanStatus.STOPPED
            if not self._backend_terminal_status:
                await self.event('scan_stopped',{'reason':'runtime_limit' if self.deadline and time.time()>=self.deadline else 'cancelled'})
                await self.emitter.flush()
            raise
        except BaseException as error:
            self.status=ScanStatus.ERROR
            await self.event('scan_failed',{'reason':'archive_unavailable' if isinstance(error,ArchiveError) else 'historical_analysis_unavailable'})
            await self.emitter.flush()
            raise
        finally:
            if owned: await client.aclose()

    async def stop_scan(self): self._stop=True
    async def cleanup(self): self._stop=True

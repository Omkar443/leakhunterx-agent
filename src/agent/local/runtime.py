"""Adapter to the existing assignment, heartbeat, cancellation and outbox loop."""
import asyncio
import threading
import time
from datetime import datetime, timezone
from uuid import UUID
from agent.local.registry import Registry
from agent.local.scanner import scan_local, result
from agent.orchestrator import ScanStatus


class LocalScanOrchestrator:
    def __init__(self, assignment, emitter, github_runner=None):
        self.github_runner=github_runner
        self.registry = Registry()
        self.target = self.registry.get(str(UUID(assignment['target_id'])))
        self.scan_id = str(UUID(assignment['scan_id']))
        self.profile = assignment.get('profile')
        self.source_type = self.target.get('source_type','LOCAL')
        scheme = 'github' if self.source_type=='GITHUB' else 'local'
        if (assignment.get('source_type','LOCAL') != self.source_type or assignment.get('target') != scheme+'://' + self.target['id'] or not self.target['dashboard_allowed']
                or not self.target['project_id'] or assignment.get('config_version') != self.target['config_version']
                or self.profile not in ('quick', 'standard', 'deep')
                or ('quick', 'standard', 'deep').index(self.profile) > ('quick', 'standard', 'deep').index(self.target['profile'])):
            raise ValueError('Local target not authorized for this assignment')
        self.emitter = emitter
        self.status = ScanStatus.PENDING
        self._stop = threading.Event()
        self._scan_timeout = 600
        self._shared_transport = True
        self._backend_terminal_status = None
        deadline = assignment.get('deadline_at')
        if deadline:
            self._scan_timeout = max(0, min(self._scan_timeout, (datetime.fromisoformat(deadline.replace('Z', '+00:00')) - datetime.now(timezone.utc)).total_seconds()))

    async def start_scan(self):
        loop = asyncio.get_running_loop()
        self.status = ScanStatus.RUNNING
        started = time.monotonic()
        def cancelled():
            if self._stop.is_set() or time.monotonic() - started >= self._scan_timeout: return True
            latest = self.registry.get(self.target['id'])
            return not latest['dashboard_allowed'] or latest['config_version'] != self.target['config_version']
        def event(kind, data):
            if self._stop.is_set(): return
            future = asyncio.run_coroutine_threadsafe(self.emitter.emit(
                {'event_type': kind, 'scan_id': self.scan_id, 'timestamp': int(time.time()), 'data': data}), loop)
            try:
                # Backpressure bounds privacy-safe events during network loss.
                future.result(timeout=60)
            except BaseException:
                future.cancel()
                self._stop.set()
                raise RuntimeError('Evidence delivery unavailable') from None
        with self.registry.connect() as db:
            checkpoint = db.execute('SELECT * FROM scans WHERE id=? AND target_id=?', (self.scan_id, self.target['id'])).fetchone()
        if getattr(self, '_recovering', False) and not checkpoint and self.source_type!='GITHUB':
            raise ValueError('Local recovery checkpoint is unavailable')
        if checkpoint:
            await self.emitter.emit({'event_type':'local_scan_resumed','scan_id':self.scan_id,'timestamp':int(time.time()),
                    'data':{'scope_fingerprint':checkpoint['scope']}})
        def execute():
            if cancelled():
                event('scan_stopped', {'reason':'cancelled'})
                return {'status':'cancelled'}
            if checkpoint and checkpoint['status'] == 'completed':
                snapshot = result(self.registry, self.scan_id)
                with self.registry.connect() as db:
                    files = db.execute('SELECT count(*) FROM files WHERE scan_id=?', (self.scan_id,)).fetchone()[0]
                repository = {}
                if self.source_type=='GITHUB':
                    with self.registry.connect() as db:
                        pin = db.execute('SELECT repository_url,branch,commit_sha FROM github_snapshots WHERE scan_id=?',(self.scan_id,)).fetchone()
                    if not pin: raise ValueError('Repository checkpoint unavailable')
                    repository = dict(pin)
                event('scan_started', dict(source_type=self.source_type, target_id=self.target['id'], scope_fingerprint=checkpoint['scope'], fingerprint_key_id=self.target['key_id'], **repository))
                event('discovery_completed', {'routes_discovered':files,'total_files':files})
                event('analysis_started', {'source_type':self.source_type,'total_files':files})
                for finding in snapshot['findings']:
                    if cancelled(): raise InterruptedError('Scan cancelled')
                    event('secret_found', finding)
                event('js_analysis_summary', {'processed_files':files,'total_files':files,'successful_analyses':files,'analysis_limited':not snapshot['complete']})
                event('scan_completed', {'source_type':self.source_type,'findings_count':len(snapshot['findings']),
                                        'complete':snapshot['complete'],'analysis_limited':not snapshot['complete'],**repository})
                return {'status':'completed'}
            return scan_local(self.registry, self.target, scan_id=self.scan_id, profile=self.profile,
                              resume=bool(checkpoint), cancelled=cancelled, on_event=event, github_runner=self.github_runner)
        worker = asyncio.create_task(asyncio.to_thread(execute))
        try:
            summary = await asyncio.shield(worker)
            self.status = (ScanStatus.COMPLETED if summary['status'] == 'completed' else
                           ScanStatus.STOPPED if summary['status'] == 'cancelled' else ScanStatus.ERROR)
            await self.emitter.flush()
        except asyncio.CancelledError:
            self._stop.set()
            # Let descriptor reads and bounded detector work stop before accepting
            # another assignment. A worker must not remain scanning in the background.
            await asyncio.shield(worker)
            self.status = ScanStatus.STOPPED
            raise
        except InterruptedError:
            # Git acquisition can be cancelled before a file checkpoint exists.
            self._stop.set()
            self.status = ScanStatus.STOPPED
            await self.emitter.emit({'event_type':'scan_stopped','scan_id':self.scan_id,
                                    'timestamp':int(time.time()),'data':{'reason':'cancelled'}})
            await self.emitter.flush()
        except BaseException:
            self._stop.set()
            self.status = ScanStatus.ERROR
            raise

    async def stop_scan(self):
        self._stop.set()
    async def cleanup(self):
        self._stop.set()
        if self.github_runner: self.github_runner.clear()


def target_heartbeat():
    registry = Registry()
    return {'capabilities': ['web-v1', 'local-v1', 'github-v1', 'github-app-v1'], 'local_targets': registry.metadata(), 'github_targets':registry.metadata('GITHUB')}

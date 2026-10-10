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
    def __init__(self, assignment, emitter):
        self.registry = Registry()
        self.target = self.registry.get(str(UUID(assignment['target_id'])))
        self.scan_id = str(UUID(assignment['scan_id']))
        self.profile = assignment.get('profile')
        if (assignment.get('target') != 'local://' + self.target['id'] or not self.target['dashboard_allowed']
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
        if getattr(self, '_recovering', False) and not checkpoint:
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
                event('scan_started', dict(source_type='LOCAL', target_id=self.target['id'], scope_fingerprint=checkpoint['scope'], fingerprint_key_id=self.target['key_id']))
                event('discovery_completed', {'routes_discovered':files,'total_files':files})
                event('analysis_started', {'total_files':files})
                for finding in snapshot['findings']:
                    if cancelled(): raise InterruptedError('Scan cancelled')
                    event('secret_found', finding)
                event('js_analysis_summary', {'processed_files':files,'total_files':files,'successful_analyses':files,'analysis_limited':not snapshot['complete']})
                event('scan_completed', {'complete':snapshot['complete'],'analysis_limited':not snapshot['complete']})
                return {'status':'completed'}
            return scan_local(self.registry, self.target, scan_id=self.scan_id, profile=self.profile,
                              resume=bool(checkpoint), cancelled=cancelled, on_event=event)
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
        except BaseException:
            self._stop.set()
            self.status = ScanStatus.ERROR
            raise

    async def stop_scan(self):
        self._stop.set()
    async def cleanup(self):
        self._stop.set()


def target_heartbeat():
    registry = Registry()
    return {'capabilities': ['web-v1', 'local-v1'], 'local_targets': registry.metadata()}

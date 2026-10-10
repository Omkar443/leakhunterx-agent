"""Shared deterministic detection with a deliberately source-free output envelope."""
import hashlib
import hmac
import json
import re
import time
import uuid
from agent.js.leak_detector import EnterpriseLeakDetector
from agent.js.detection_policy import POLICY_VERSION
from agent.sources.local import LocalSource, TEXT_SUFFIXES, SKIP_DIRS


def keyed(key, domain, *parts):
    return hmac.new(key, json.dumps([domain, *parts], separators=(',', ':'), ensure_ascii=True).encode(), hashlib.sha256).hexdigest()


def envelope(target, artifact, finding):
    rule = str(finding['type'])
    secret = str(finding.get('value', ''))
    secret_fp = keyed(target['key'], 'secret-v1', rule, secret)
    fingerprint = keyed(target['key'], 'finding-v1', rule, artifact.locator, secret_fp)
    safe_locator = artifact.locator.replace(secret,'[REDACTED]') if len(secret) >= 8 else artifact.locator
    # Context categories are computed locally; identifiers and surrounding code
    # cannot become an accidental upload, even with an unfamiliar detector.
    category = str(finding.get('category', 'Secrets'))
    severity = str(finding.get('severity', 'medium')).lower()
    if severity not in ('critical', 'high', 'medium', 'low', 'info'): severity = 'medium'
    line = max(1, int(finding.get('line_number') or 1))
    signals = {
        'credential_assignment': bool(re.search(r'[A-Za-z_$][\w$.-]*\s*[:=]\s*[\x27\x22]?\s*$', artifact.content[max(0, finding.get('match_start', 0)-256):finding.get('match_start', 0)])),
        'configuration_file': artifact.locator.rsplit('/', 1)[-1].startswith('.env') or artifact.language in ('json', 'yaml', 'yml', 'ini', 'conf', 'properties', 'tfvars'),
        'test_file': any(part in ('tests', 'test', 'fixtures', '__tests__') for part in artifact.locator.split('/')),
        'private_key': 'private' in rule.lower() and 'key' in rule.lower(),
    }
    semantic = '; '.join(f'{name}={str(value).lower()}' for name, value in signals.items())
    return dict(type=rule.replace('_', ' ').title(), category=category, severity=severity, confidence=float(finding.get('confidence', .5)),
                source_type='LOCAL', target_id=target['id'], file_path=safe_locator, line_number=line,
                source_url=safe_locator, raw_value='[REDACTED]', match_evidence_mask='[REDACTED]',
                match_length=len(secret), fingerprint=fingerprint, secret_fingerprint=secret_fp,
                fingerprint_key_id=target['key_id'], fingerprint_version='hmac-sha256-v1',
                source_hash=keyed(target['key'], 'content-v1', artifact.content_hash),
                evidence_version=2, detector_policy=POLICY_VERSION,
                code_context=f'Local semantic evidence only. {semantic}', context_truncated=True,
                semantic_context=signals, provider_validation={'provider': 'none', 'status': 'not_attempted'})


def scan_local(registry, target, **options):
    with registry.scan_lock():
        return _scan_local(registry, target, **options)


def _scan_local(registry, target, *, profile=None, scan_id=None, resume=False, cancelled=lambda: False, on_event=lambda kind, data: None):
    profile = profile or target['profile']
    if profile not in ('quick', 'standard', 'deep'): raise ValueError('Unsupported scan profile')
    if ('quick', 'standard', 'deep').index(profile) > ('quick', 'standard', 'deep').index(target['profile']):
        raise ValueError('Scan profile exceeds locally authorized limits')
    scan_id = str(uuid.UUID(scan_id)) if scan_id else str(uuid.uuid4())
    source = LocalSource(target['path'], profile, cancelled)
    started = time.monotonic()
    processed = findings_count = bytes_read = reused = 0
    status = 'failed'
    failure_code = None
    prepared = False
    checkpoint_opened = False
    scope = None
    try:
        if cancelled(): raise InterruptedError('Scan cancelled')
        source.prepare()
        prepared = True
        scope = hashlib.sha256(json.dumps(dict(version=POLICY_VERSION, profile=profile, ignore=source.policy.digest,
                      limits=source.limits, types=sorted(TEXT_SUFFIXES), excluded=sorted(SKIP_DIRS),
                      symlinks='deny', fingerprint_key=target['key_id']), sort_keys=True).encode()).hexdigest()
        with registry.connect() as db:
            existing = db.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            if existing:
                if not resume or existing['target_id'] != target['id'] or existing['scope'] != scope or existing['status'] not in ('running', 'interrupted'):
                    raise ValueError('Scan cannot be resumed with this target or scope')
                db.execute('UPDATE scans SET status=?,complete=0,finished_at=NULL WHERE id=?', ('running', scan_id))
            else:
                if resume: raise ValueError('Checkpoint unavailable')
                db.execute('INSERT INTO scans(id,target_id,scope,status) VALUES(?,?,?,?)', (scan_id, target['id'], scope, 'running'))
        checkpoint_opened = True
        on_event('scan_started', dict(source_type='LOCAL', target_id=target['id'], scope_fingerprint=scope, fingerprint_key_id=target['key_id']))
        on_event('discovery_started', {})
        with registry.connect() as db:
            db.execute('CREATE TEMP TABLE visited(locator TEXT PRIMARY KEY)')
            db.execute('CREATE TEMP TABLE candidates(locator TEXT PRIMARY KEY)')
            discovered = 0
            for metadata in source.enumerate():
                db.execute('INSERT INTO candidates VALUES(?)', (metadata.locator,))
                discovered += 1
                if discovered == 1 or discovered % 1000 == 0:
                    on_event('scan_progress', dict(phase='discovery', routes_discovered=discovered, source_type='LOCAL'))
            db.commit()
            if cancelled(): raise InterruptedError('Scan cancelled')
            on_event('discovery_completed', dict(routes_discovered=discovered, total_files=discovered))
            on_event('analysis_started', dict(source_type='LOCAL', total_files=discovered))
            for item in db.execute('SELECT locator FROM candidates ORDER BY locator'):
                if cancelled(): raise InterruptedError('Scan cancelled')
                try: artifact = source.read_artifact(item['locator'])
                except (OSError, ValueError, OverflowError):
                    source.failures += 1
                    continue
                if artifact is None: continue
                digest = keyed(target['key'], 'checkpoint-v1', artifact.content_hash)
                prior = db.execute('SELECT digest,findings FROM files WHERE scan_id=? AND locator=?', (scan_id, artifact.locator)).fetchone()
                if resume and prior and prior['digest'] == digest:
                    output = json.loads(prior['findings'])
                    reused += 1
                else:
                    detector = EnterpriseLeakDetector(max_findings_per_scan=1000)
                    output = []
                    seen = set()
                    for finding in detector.check_content(artifact.content):
                        record = envelope(target, artifact, finding)
                        if source.policy.matches(artifact.locator, finding['type'], record['fingerprint']) or record['fingerprint'] in seen:
                            continue
                        seen.add(record['fingerprint'])
                        output.append(record)
                    if getattr(detector, 'truncated', False): source.limited = True
                # Checkpoints store only the same redacted semantic envelopes.
                db.execute('INSERT OR REPLACE INTO files(scan_id,locator,digest,size,findings) VALUES(?,?,?,?,?)',
                           (scan_id, artifact.locator, digest, artifact.size, json.dumps(output)))
                db.execute('INSERT OR IGNORE INTO visited VALUES(?)', (artifact.locator,))
                processed += 1
                bytes_read += artifact.size
                findings_count += len(output)
                # Persist detected evidence before emitting it. Ordinary files
                # commit in small batches; recovery rehashes any uncommitted tail.
                if output or processed % 20 == 0: db.commit()
                for record in output: on_event('secret_found', record)
                if processed == 1 or processed % 20 == 0:
                    on_event('scan_progress', dict(phase='analysis', processed_files=processed, total_files=discovered, successful_analyses=processed, source_type='LOCAL'))
                if findings_count >= 10000:
                    source.limited = True
                    break
            # A changed/deleted file cannot leave stale detections in a resumed
            # local checkpoint. Cloud recovery must replay the final snapshot,
            # not provisional findings emitted before interruption.
            db.execute('DELETE FROM files WHERE scan_id=? AND locator NOT IN (SELECT locator FROM visited)', (scan_id,))
            if cancelled(): raise InterruptedError('Scan cancelled')
        status = 'completed'
    except InterruptedError:
        status = 'cancelled'
        failure_code = 'cancelled'
    except KeyboardInterrupt:
        status = 'interrupted'
        failure_code = 'interrupted'
    except (OSError, ValueError, RuntimeError, OverflowError):
        failure_code = 'local_scan_unavailable'
    finally:
        source.cleanup()
    if status == 'cancelled' and not checkpoint_opened and not resume:
        # Cancellation before reading the root still has a private terminal
        # record. An empty scope is explicitly ineligible as a Delta baseline.
        with registry.connect() as db:
            db.execute('INSERT OR IGNORE INTO scans(id,target_id,scope,status) VALUES(?,?,?,?)',
                       (scan_id, target['id'], scope or '', 'cancelled'))
    complete = bool(status == 'completed' and prepared and not source.failures and not source.limited)
    if checkpoint_opened:
        with registry.connect() as db:
            db.execute('UPDATE scans SET status=?,complete=?,finished_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?', (status, int(complete), scan_id, target['id']))
    summary = dict(scan_id=scan_id, target_id=target['id'], source_type='LOCAL', status=status,
                   scope_fingerprint=scope, complete=complete, processed_files=processed, findings_count=findings_count,
                   skipped_files=source.skipped, failed_files=source.failures, bytes_processed=bytes_read, reused_files=reused,
                   elapsed_seconds=round(time.monotonic()-started, 3), failure_code=failure_code)
    if status == 'completed':
        on_event('js_analysis_summary', dict(total_files=processed, processed_files=processed, successful_analyses=processed,
                      failed_analyses=source.failures, timed_out_analyses=0, analysis_limited=not complete))
        on_event('scan_completed', dict(summary, analysis_limited=not complete))
    else:
        on_event('scan_stopped' if status in ('cancelled', 'interrupted') else 'scan_failed', dict(reason=failure_code or 'scan_failed'))
    return summary


def result(registry, scan_id):
    with registry.connect() as db:
        scan = db.execute('SELECT * FROM scans WHERE id=?', (str(uuid.UUID(scan_id)),)).fetchone()
        if not scan: raise ValueError('Checkpoint unavailable')
        findings = [finding for row in db.execute('SELECT findings FROM files WHERE scan_id=? ORDER BY locator', (scan_id,)) for finding in json.loads(row['findings'])]
    return dict(scan_id=scan['id'], target_id=scan['target_id'], status=scan['status'], complete=bool(scan['complete']),
                scope_fingerprint=scan['scope'], findings=findings if scan['status'] == 'completed' else [])


def local_delta(registry, scan_id):
    current = result(registry, scan_id)
    if current['status'] != 'completed' or not current['complete']:
        return dict(status='unavailable', reason='complete_coverage_required')
    with registry.connect() as db:
        row = db.execute('SELECT id FROM scans WHERE target_id=? AND scope=? AND status=? AND complete=1 AND rowid < (SELECT rowid FROM scans WHERE id=?) ORDER BY rowid DESC LIMIT 1',
                         (current['target_id'], current['scope_fingerprint'], 'completed', scan_id)).fetchone()
    previous = result(registry, row['id']) if row else None
    now = {f['fingerprint'] for f in current['findings']}
    before = {f['fingerprint'] for f in previous['findings']} if previous else set()
    return dict(status='completed', previous_scan_id=previous['scan_id'] if previous else None,
                baseline=previous is None, new=sorted(now-before), existing=sorted(now&before), resolved=sorted(before-now))

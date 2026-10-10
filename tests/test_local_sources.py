import json
import os
from pathlib import Path
import pytest
from agent.local.registry import Registry
from agent.local.scanner import scan_local, result, local_delta
from agent.sources.local import LocalSource


@pytest.fixture
def local(tmp_path):
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    project = tmp_path / 'project'
    project.mkdir()
    registry = Registry(private / 'agent.db')
    return registry, registry.add(project, 'Example'), project


def secret_file(project, name='config.js'):
    secret = 'ghp_' + 'b7Tf9pQ2jK4vC6xD8mF0sH3nR5wY1zA9uE7g'
    (project / name).write_text(f'// PROPRIETARY_MARKER\nconst githubToken = "{secret}";\n', encoding='utf8')
    return secret


def test_private_envelope_and_network_independence(local, monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: (_ for _ in ()).throw(AssertionError('Network prohibited')))
    registry, target, project = local
    secret = secret_file(project)
    events = []
    summary = scan_local(registry, target, on_event=lambda kind, data: events.append((kind, data)))
    assert summary['complete'] and summary['processed_files'] == 1
    assert summary['findings_count'] >= 1
    payload = json.dumps(events)
    for marker in (secret, str(project), 'PROPRIETARY_MARKER', 'githubToken'):
        assert marker not in payload
    assert 'scan_progress' in [kind for kind, _ in events]
    assert not target['dashboard_allowed']
    assert str(project) not in json.dumps(registry.metadata())
    assert secret.encode() not in registry.path.read_bytes()


def test_delta_keyed_identity_line_shift_and_location_move(local, tmp_path):
    registry, target, project = local
    secret_file(project)
    first = scan_local(registry, target)
    before = (project/'config.js').read_text()
    (project/'config.js').write_text('\n\n' + before)
    second = scan_local(registry, target)
    delta = local_delta(registry, second['scan_id'])
    assert len(delta['existing']) == 1 and not delta['new'] and not delta['resolved']
    moved = tmp_path/'moved'
    project.rename(moved)
    updated = registry.update(target['id'], path=moved)
    third = scan_local(registry, updated)
    assert local_delta(registry, third['scan_id'])['existing'] == delta['existing']
    (moved/'config.js').write_text('const ordinary = 42;')
    fourth = scan_local(registry, updated)
    assert local_delta(registry, fourth['scan_id'])['resolved'] == delta['existing']
    registry.remove(target['id'])
    assert (moved/'config.js').exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX descriptor and device checks')
def test_path_escape_devices_ignore_and_source_mutation(local, tmp_path):
    registry, target, project = local
    secret = secret_file(tmp_path)
    (project/'escape.js').symlink_to(tmp_path/'config.js')
    (project/'cycle').symlink_to(project, target_is_directory=True)
    os.mkfifo(project/'device.js')
    (project/'.lhxignore').write_text('path:ignored/*\n')
    (project/'ignored').mkdir()
    secret_file(project/'ignored')
    (project/'safe.js').write_text('const x = 42;')
    source = LocalSource(project)
    source.prepare()
    try:
        with pytest.raises(ValueError): source.read('../config.js', 1000)
        with pytest.raises(OSError): source.read('escape.js', 1000)
        with pytest.raises(ValueError): source.read('device.js', 1000)
        assert [a.locator for a in source.artifacts()] == ['safe.js']
    finally: source.cleanup()
    summary = scan_local(registry, target)
    assert not summary['complete'] and summary['findings_count'] == 0


def test_interruption_resume_removes_deleted_and_changed_evidence(local):
    registry, target, project = local
    secret_file(project)
    (project/'other.js').write_text('const x = 42;')
    def interrupt(kind, data):
        if kind == 'secret_found': raise KeyboardInterrupt()
    summary = scan_local(registry, target, on_event=interrupt)
    assert summary['status'] == 'interrupted'
    assert not result(registry, summary['scan_id'])['findings']
    (project/'config.js').unlink()
    resumed = scan_local(registry, target, scan_id=summary['scan_id'], resume=True)
    assert resumed['complete'] and resumed['findings_count'] == 0
    assert not result(registry, summary['scan_id'])['findings']


def test_failed_cancelled_partial_never_become_baselines(local):
    registry, target, project = local
    secret_file(project)
    baseline = scan_local(registry, target)
    cancelled = scan_local(registry, target, cancelled=lambda: True)
    assert cancelled['status'] == 'cancelled'
    assert local_delta(registry, cancelled['scan_id'])['status'] == 'unavailable'
    (project/'huge.js').write_bytes(b'x' * 5_000_001)
    partial = scan_local(registry, target)
    assert partial['status'] == 'completed' and not partial['complete']
    assert local_delta(registry, partial['scan_id'])['status'] == 'unavailable'
    (project/'huge.js').unlink()
    final = scan_local(registry, target)
    assert local_delta(registry, final['scan_id'])['previous_scan_id'] == baseline['scan_id']


def test_binary_replacement_does_not_prove_resolution(local):
    registry, target, project = local
    secret_file(project)
    scan_local(registry, target)
    (project/'config.js').write_bytes(b'\x00binary content')
    partial = scan_local(registry, target)
    assert not partial['complete']
    assert local_delta(registry, partial['scan_id'])['status'] == 'unavailable'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX owner and mode checks')
def test_registry_permissions_and_invalid_ignore_fail_closed(local, tmp_path):
    registry, target, project = local
    assert registry.path.stat().st_mode & 0o077 == 0
    (project/'.lhxignore').write_text('path:../outside\n')
    assert scan_local(registry, target)['status'] == 'failed'
    public = tmp_path/'public'
    public.mkdir(mode=0o755)
    with pytest.raises(ValueError): Registry(public/'agent.db')

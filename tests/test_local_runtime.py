import asyncio
from uuid import uuid4
from unittest.mock import AsyncMock
import pytest
from agent.local.registry import Registry
from agent.local.scanner import scan_local
from agent.local.runtime import LocalScanOrchestrator
from agent.orchestrator import ScanStatus


def setup(tmp_path, monkeypatch):
    private=tmp_path/'private'; private.mkdir(mode=0o700); root=tmp_path/'project'; root.mkdir()
    registry=Registry(private/'agent.db'); target=registry.add(root,'App',project_id=str(uuid4()))
    target=registry.update(target['id'],allowed=True)
    monkeypatch.setattr('agent.local.runtime.Registry',lambda:registry)
    job=dict(scan_id=str(uuid4()),target_id=target['id'],target='local://'+target['id'],profile='standard',config_version=target['config_version'])
    return registry,target,root,job


def test_runtime_rechecks_consent_and_rejects_forged_profile(tmp_path, monkeypatch):
    registry,target,root,job=setup(tmp_path,monkeypatch)
    with pytest.raises(ValueError): LocalScanOrchestrator(dict(job,profile='deep'),AsyncMock())
    runtime=LocalScanOrchestrator(job,AsyncMock())
    registry.update(target['id'],allowed=False)
    asyncio.run(runtime.start_scan())
    assert runtime.status==ScanStatus.STOPPED


def test_completed_delivery_recovery_uses_original_snapshot_not_changed_files(tmp_path,monkeypatch):
    registry,target,root,job=setup(tmp_path,monkeypatch)
    (root/'config.js').write_text('const token="ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";')
    summary=scan_local(registry,target,scan_id=job['scan_id']); assert summary['complete']
    (root/'config.js').write_text('const token = process.env.TOKEN;')
    emitter=AsyncMock(); runtime=LocalScanOrchestrator(job,emitter); runtime._recovering=True
    asyncio.run(runtime.start_scan())
    events=[call.args[0] for call in emitter.emit.await_args_list]
    assert runtime.status==ScanStatus.COMPLETED
    assert events[0]['event_type']=='local_scan_resumed'
    assert len([e for e in events if e['event_type']=='secret_found'])==1
    assert all('ghp_' not in str(e) for e in events)


def test_one_heavy_scan_lock_is_shared_across_registry_instances(tmp_path,monkeypatch):
    registry,target,root,job=setup(tmp_path,monkeypatch)
    other=Registry(registry.path)
    with registry.scan_lock():
        with pytest.raises(OSError):
            with other.scan_lock(): pass

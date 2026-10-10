import os
from pathlib import Path
import pytest
import subprocess
from agent.sources.local import LocalSource

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Native Windows handle checks')


def test_ancestor_and_artifact_rename_blocked_while_open(tmp_path):
    root = tmp_path/'project'
    child = root/'src'
    child.mkdir(parents=True)
    artifact = child/'config.js'
    artifact.write_text('const x = 42;')
    source = LocalSource(root)
    source.prepare()
    try:
        with source.windows.file('src/config.js'):
            with pytest.raises(OSError): child.rename(root/'moved')
            with pytest.raises(OSError): artifact.rename(child/'moved.js')
        assert [item.locator for item in source.artifacts()] == ['src/config.js']
        with pytest.raises(ValueError): source.read('../outside.js', 100)
        with pytest.raises(ValueError): source.read('C:/outside.js', 100)
    finally: source.cleanup()
    child.rename(root/'moved')


def test_windows_hardlinks_are_not_scanned(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    outside = tmp_path/'secret.js'
    outside.write_text('const x = 42;')
    os.link(outside, root/'linked.js')
    source = LocalSource(root)
    source.prepare()
    try:
        assert list(source.artifacts()) == []
        assert source.failures == 1
    finally: source.cleanup()


def test_windows_junction_cannot_escape_registered_root(tmp_path):
    root=tmp_path/'project'; root.mkdir(); outside=tmp_path/'outside'; outside.mkdir()
    (outside/'secret.js').write_text('PRIVATE_OUTSIDE_MARKER')
    created=subprocess.run(['cmd','/c','mklink','/J',str(root/'linked'),str(outside)],capture_output=True)
    assert created.returncode==0
    source=LocalSource(root); source.prepare()
    try:
        assert list(source.artifacts())==[]
        assert source.failures or source.skipped
    finally: source.cleanup()

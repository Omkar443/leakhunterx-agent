import os
from pathlib import Path
import subprocess
import pytest
from agent import service


def test_unit_supervises_unprivileged_runtime_without_secrets():
    unit = service.render_unit('/home/operator/agent env/bin/python', 'https://backend-leakhunterx.onrender.com')
    assert ' -m agent agent --backend ' in unit
    for setting in ('Restart=on-failure', 'UMask=0077', 'KillSignal=SIGTERM', 'NoNewPrivileges=yes'):
        assert setting in unit
    assert 'User=root' not in unit and 'Secret' not in unit


def test_systemd_paths_escape_specifiers_and_quotes():
    assert service.quote('/tmp/a%"b') == '"/tmp/a%%\\"b"'
    with pytest.raises(ValueError):
        service.quote('/tmp/a\nExecStart=bad')


def test_atomic_install_preserves_unmanaged_units(tmp_path):
    path = tmp_path / 'unit'
    path.write_text('unmanaged')
    with pytest.raises(ValueError):
        service.write_unit(path, service.MARKER)
    assert path.read_text() == 'unmanaged'
    path.unlink()
    service.write_unit(path, service.MARKER)
    assert path.read_text() == service.MARKER
    if os.name == 'posix':
        assert path.stat().st_mode & 0o777 == 0o600


def test_symlink_not_overwritten(tmp_path):
    target = tmp_path / 'original'
    target.write_text('preserved')
    path = tmp_path / 'unit'
    path.symlink_to(target)
    with pytest.raises(ValueError):
        service.write_unit(path, service.MARKER)
    assert target.read_text() == 'preserved'


def test_non_linux_fails_cleanly(monkeypatch):
    monkeypatch.setattr(service.sys, 'platform', 'win32')
    with pytest.raises(SystemExit) as error:
        service.manage('install')
    assert error.value.code == 1


def test_stop_disables_autostart_without_shell(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(service.sys, 'platform', 'linux')
    monkeypatch.setattr(service.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(service.shutil, 'which', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(service.subprocess, 'run', lambda argv, **kw: calls.append((argv, kw)))
    service.manage('stop')
    assert calls[0][0] == ['/usr/bin/systemctl', '--user', 'disable', '--now', service.UNIT]
    assert 'shell' not in calls[0][1]

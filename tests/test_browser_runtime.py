import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

from agent import browser_runtime as runtime


def test_frozen_worker_reuses_bundle_without_tokens_or_environment_hooks(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, '_MEIPASS', str(tmp_path), raising=False)
    monkeypatch.setenv('LHX_AGENT_SECRET', 'never-forward')
    monkeypatch.setenv('HTTPS_PROXY', 'never-forward')
    monkeypatch.setenv('PYTHONPATH', '/untrusted')
    monkeypatch.setenv('PLAYWRIGHT_BROWSERS_PATH', '/untrusted-cache')
    monkeypatch.setenv('_PYI_APPLICATION_HOME_DIR', str(tmp_path))
    monkeypatch.setenv('_PYI_PARENT_PROCESS_LEVEL', '1')
    environment = runtime.worker_environment()
    assert environment['_PYI_APPLICATION_HOME_DIR'] == str(tmp_path)
    assert environment['_PYI_PARENT_PROCESS_LEVEL'] == '1'
    assert environment['PLAYWRIGHT_BROWSERS_PATH'].startswith(str(tmp_path))
    assert not any(key in environment for key in ('LHX_AGENT_SECRET', 'HTTPS_PROXY', 'PYTHONPATH'))
    assert runtime.worker_command() == [sys.executable, '--lhx-browser-worker']
    installer = Mock(); monkeypatch.setattr(runtime, '_install_browser', installer)
    runtime.prepare_browser_runtime(SimpleNamespace(browser_rendering='on'))
    installer.assert_not_called()


def test_python_start_provisions_browser_automatically_without_credentials(monkeypatch):
    monkeypatch.setenv('LHX_AGENT_SECRET', 'never-forward')
    installer = Mock(return_value=0)
    monkeypatch.setattr(runtime, '_install_browser', installer)
    runtime.prepare_browser_runtime(SimpleNamespace(browser_rendering='on'))
    assert installer.call_args.args[0] == [sys.executable, '-m', 'playwright', 'install', '--only-shell', 'chromium']
    assert 'LHX_AGENT_SECRET' not in installer.call_args.args[1]
    installer.reset_mock()
    runtime.prepare_browser_runtime(SimpleNamespace(browser_rendering='off'))
    installer.assert_not_called()


def test_provisioning_failure_is_clear_and_does_not_break_http_scanning(monkeypatch, capsys):
    monkeypatch.setattr(runtime, '_install_browser', Mock(side_effect=subprocess.TimeoutExpired('installer', 180)))
    runtime.prepare_browser_runtime(SimpleNamespace(browser_rendering='on'))
    assert 'HTTP crawling remains active' in capsys.readouterr().out


def test_lhx_agent_alias_delegates_to_existing_assignment_loop(monkeypatch):
    from agent import cli
    from agent import lhx_agent
    monkeypatch.setattr(sys, 'argv', ['lhx', 'agent'])
    arguments = []
    monkeypatch.setattr(lhx_agent, 'main', lambda: arguments.append(sys.argv[1:]))
    cli.run()
    assert arguments == [['run']]
    assert sys.argv == ['lhx', 'agent']


def test_worker_entry_never_enters_registration_or_assignment_code(monkeypatch):
    import lhx_agent_entry
    from agent import browser_worker, cli
    worker = Mock(); runner = Mock()
    monkeypatch.setattr(sys, 'argv', ['agent-binary', '--lhx-browser-worker'])
    monkeypatch.setattr(browser_worker, 'main', worker)
    monkeypatch.setattr(cli, 'run', runner)
    lhx_agent_entry.main()
    worker.assert_called_once(); runner.assert_not_called()


def test_first_start_timeout_reaps_owned_downloader_children(monkeypatch):
    child = SimpleNamespace(pid=2, create_time=lambda: 1, kill=Mock())
    process = SimpleNamespace(pid=1, returncode=None)
    process.poll = lambda: process.returncode
    process.kill = Mock(side_effect=lambda: setattr(process, 'returncode', -9))
    def wait(timeout=None):
        if timeout is not None: raise subprocess.TimeoutExpired('installer', timeout)
        return process.returncode
    process.wait = Mock(side_effect=wait)
    monkeypatch.setattr(runtime.subprocess, 'Popen', Mock(return_value=process))
    monkeypatch.setattr(runtime.psutil, 'Process', lambda _: SimpleNamespace(children=lambda **__: [child]))
    ticks = iter([0, 1, 181]); monkeypatch.setattr(runtime.time, 'monotonic', lambda: next(ticks))
    try:
        runtime._install_browser(['installer'], {})
        assert False, 'timeout must propagate to the startup fallback'
    except subprocess.TimeoutExpired:
        pass
    child.kill.assert_called_once(); process.kill.assert_called_once()


def test_bundled_registration_starts_same_process_in_run_mode(monkeypatch):
    from agent import pair_agent, lhx_agent
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'argv', ['binary', 'pair'])
    arguments = []
    monkeypatch.setattr(lhx_agent, 'main', lambda: arguments.append(sys.argv[1:]))
    restart = Mock(); monkeypatch.setattr(pair_agent.os, 'execv', restart)
    pair_agent.exec_agent()
    assert arguments == [['run']]
    assert sys.argv == ['binary', 'pair']
    restart.assert_not_called()


def test_source_entry_uses_matching_project_environment_instead_of_old_system_python(monkeypatch):
    import importlib.metadata
    import lhx_agent_entry as entry
    monkeypatch.setattr(importlib.metadata, 'version', lambda _: '1.55.0')
    monkeypatch.setattr(entry.Path, 'is_file', lambda _: True)
    monkeypatch.setattr(entry.subprocess, 'run', Mock(return_value=SimpleNamespace(returncode=0, stdout='1.63.0\n')))
    monkeypatch.setattr(sys, 'argv', ['lhx_agent_entry.py', 'run'])
    monkeypatch.setattr(sys, 'executable', '/usr/bin/python3')
    restart = Mock(); monkeypatch.setattr(entry.os, 'execv', restart)
    entry.select_project_runtime()
    assert '.venv' in restart.call_args.args[0]
    assert restart.call_args.args[1][-1] == 'run'


def test_browser_failure_diagnostics_never_print_raw_installer_output(monkeypatch, capsys):
    def launch(*args, **kwargs):
        kwargs['stdout'].write(b'CERT_HAS_EXPIRED https://user:secret@proxy.example')
        return SimpleNamespace(poll=lambda:1, returncode=1, wait=lambda:None)
    monkeypatch.setattr(runtime.subprocess, 'Popen', launch)
    assert runtime._install_browser(['installer'], {}) == 1
    output = capsys.readouterr().out
    assert 'certificate verification failed' in output
    assert 'secret' not in output and 'proxy.example' not in output

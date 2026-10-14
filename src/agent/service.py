"""Opt-in per-user systemd supervision; never copies secrets or invokes a shell."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

UNIT = 'leakhunterx-agent.service'
MARKER = '# Managed by lhx service; credentials stay in the user profile.'


def quote(value):
    if any(ord(c) < 32 for c in value):
        raise ValueError('Control characters are not allowed in service paths')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def render_unit(executable, backend):
    return f'''{MARKER}
[Unit]
Description=LeakHunterX local scanning agent
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart={quote(executable)} -m agent agent --backend {quote(backend)}
WorkingDirectory=%h
Environment=PYTHONUNBUFFERED=1
UMask=0077
Restart=on-failure
RestartSec=15
TimeoutStopSec=60
KillSignal=SIGTERM
KillMode=control-group
NoNewPrivileges=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
'''


def write_unit(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.read_text().startswith(MARKER)):
        raise ValueError('Refusing to overwrite an unmanaged service')
    fd, temporary = tempfile.mkstemp(prefix='.lhx-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def manage(action, backend=None):
    try:
        if sys.platform != 'linux' or os.geteuid() == 0:
            raise ValueError('Use this command on Linux as the registered, non-root agent user; do not use sudo')
        systemctl = shutil.which('systemctl')
        if not systemctl:
            raise ValueError('systemd is not available; use lhx agent in the foreground')
        config_home = Path(os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config'))
        if not config_home.is_absolute():
            raise ValueError('XDG_CONFIG_HOME must be an absolute path')
        path = config_home / 'systemd/user' / UNIT
        def control(*args):
            return subprocess.run([systemctl, '--user', *args], check=True, timeout=90)
        if action == 'install':
            from agent.lhx_agent import load_agent_credentials
            from agent.config.config import AgentConfig
            from agent.cli import _https_backend
            load_agent_credentials()  # Fail before changing files if not registered.
            origin = _https_backend(backend or AgentConfig.from_env().backend_url)
            if getattr(sys, 'frozen', False):
                raise ValueError('Install the PyPI package in a persistent virtual environment for service support')
            # Check the user manager without printing its potentially sensitive environment.
            subprocess.run([systemctl, '--user', 'show-environment'], stdout=subprocess.DEVNULL,
                           check=True, timeout=15)
            write_unit(path, render_unit(sys.executable, origin))
            control('daemon-reload')
            print('Service installed; no start requested. Stop any foreground agent, then run lhx service start (or restart an existing service).')
        elif action == 'uninstall':
            if not path.exists() or path.is_symlink() or not path.read_text().startswith(MARKER):
                raise ValueError('No managed service to uninstall')
            control('disable', '--now', UNIT)
            path.unlink()
            control('daemon-reload')
            print('Service removed. Registration, credentials and scan state retained.')
        elif action == 'logs':
            journal = shutil.which('journalctl')
            if not journal:
                raise ValueError('journalctl is unavailable')
            subprocess.run([journal, '--user', '-u', UNIT, '-n', '100', '--no-pager'], check=True, timeout=30)
        elif action == 'start':
            control('enable', '--now', UNIT)
        elif action == 'stop':
            control('disable', '--now', UNIT)
        else:
            control(action, UNIT)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        message = str(exc) if isinstance(exc, ValueError) else 'Service operation failed. Check your user systemd session and lhx service logs.'
        print(message, file=sys.stderr)
        raise SystemExit(1) from None

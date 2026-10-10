"""Browser provisioning at startup, and credential-free worker launch."""
import os
from pathlib import Path
import subprocess
import sys
import time
import tempfile

import psutil

WORKER_FLAG = '--lhx-browser-worker'


def configure_bundled_browser():
    if getattr(sys, 'frozen', False):
        # The browser version travels with its matching Playwright driver.
        # Ignore user cache overrides in released executables.
        os.environ['PLAYWRIGHT_BROWSERS_PATH'] = str(
            Path(sys._MEIPASS) / 'playwright' / 'driver' / 'package' / '.local-browsers')


def worker_command():
    if getattr(sys, 'frozen', False):
        return [sys.executable, WORKER_FLAG]
    return [sys.executable, '-m', 'agent.browser_worker']


def worker_environment():
    safe_keys = {'PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'SYSTEMROOT', 'WINDIR',
                 'TEMP', 'TMP', 'LOCALAPPDATA', 'PLAYWRIGHT_BROWSERS_PATH', 'LD_LIBRARY_PATH'}
    environment = {key: value for key, value in os.environ.items() if key in safe_keys}
    if getattr(sys, 'frozen', False):
        # Bootloader-owned state must survive for workers to reuse the unpacked
        # bundle rather than unpacking Chromium again on every scan.
        environment.update({key: value for key, value in os.environ.items() if key.startswith('_PYI_')})
        environment['PLAYWRIGHT_BROWSERS_PATH'] = str(
            Path(sys._MEIPASS) / 'playwright' / 'driver' / 'package' / '.local-browsers')
    else:
        environment['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
    return environment


def prepare_browser_runtime(config):
    """Released bundles need no downloads. Python installs provision once.

    Playwright's installer checks its versioned cache before downloading. This
    runs at startup, outside a scan, with a bounded timeout and no agent tokens.
    Never installs packages, invokes sudo, or disables Chromium's sandbox.
    """
    if config.browser_rendering == 'off':
        return
    configure_bundled_browser()
    if getattr(sys, 'frozen', False):
        return
    print('  Browser    preparing headless runtime (cached after first start)', flush=True)
    try:
        code = _install_browser(
            [sys.executable, '-m', 'playwright', 'install', '--only-shell', 'chromium'],
            worker_environment())
        if code == 0:
            print('  Browser    ready · enabled alongside HTTP crawling', flush=True)
            return
    except subprocess.TimeoutExpired:
        print('  Browser    preparation exceeded 180 seconds; check download connectivity.', flush=True)
    except OSError:
        print('  Browser    installer could not start; check the Python installation.', flush=True)
    print('  Browser    unavailable; HTTP crawling remains active. Browser coverage will be reported.', flush=True)


def _install_browser(command, environment):
    """Bound first-run provisioning and reap owned downloader descendants."""
    # Capture diagnostics on disk to avoid pipe deadlocks or unbounded RAM.
    output = tempfile.TemporaryFile()
    try:
        process = subprocess.Popen(command, env=environment, stdout=output,
                               stderr=output,
                               **({'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}))
    except BaseException:
        output.close()
        raise
    children = {}
    deadline = time.monotonic() + 180
    try:
        while process.poll() is None:
            try:
                for child in psutil.Process(process.pid).children(recursive=True):
                    children[(child.pid, child.create_time())] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(command, 180)
            try:
                process.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                pass
        if process.returncode != 0:
            output.seek(max(0, output.tell() - 16384))
            diagnostic = output.read(16384).decode('utf-8', errors='replace').lower()
            # Never echo raw installer logs (paths, proxy URLs or credentials).
            reason = ('Playwright is missing from this Python environment' if 'no module named playwright' in diagnostic
                      else 'browser download certificate verification failed' if any(code in diagnostic for code in ('certificate', 'cert_'))
                      else 'browser download could not reach its server' if any(code in diagnostic for code in ('enotfound', 'econn', 'etimedout', 'download failed', 'failed to download'))
                      else 'browser installation failed')
            print(f'  Browser    {reason}.', flush=True)
        return process.returncode
    finally:
        for child in reversed(list(children.values())):
            try: child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        if process.poll() is None:
            process.kill()
        process.wait()
        output.close()

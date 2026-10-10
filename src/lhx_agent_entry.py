#!/usr/bin/env python3
"""
LeakHunterX PyInstaller Entry Point
"""

import sys
import multiprocessing
import os
from pathlib import Path
import subprocess


def select_project_runtime():
    """Source checkout launches use its installed environment when needed.

    Never installs into or alters system Python. Frozen distributions already
    carry their own dependencies. Only the checkout's fixed .venv is eligible.
    """
    if getattr(sys, 'frozen', False):
        return
    from importlib.metadata import version, PackageNotFoundError
    required = '1.63.0'
    try:
        if version('playwright') == required:
            return
    except PackageNotFoundError:
        pass
    root = Path(__file__).resolve().parent.parent
    candidate = root / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not candidate.is_file() or not (root / '.venv/pyvenv.cfg').is_file():
        return
    if os.path.abspath(sys.executable) == str(candidate):
        return
    try:
        check = subprocess.run([str(candidate), '-I', '-c',
            'import importlib.metadata as m; print(m.version("playwright"))'],
            capture_output=True, text=True, timeout=10)
        if check.returncode == 0 and check.stdout.strip() == required:
            print('  Runtime    using the installed project environment', flush=True)
            os.execv(str(candidate), [str(candidate), str(Path(__file__).resolve()), *sys.argv[1:]])
    except (OSError, subprocess.TimeoutExpired):
        return

def main() -> None:
    # 🔑 REQUIRED for Windows + PyInstaller
    multiprocessing.freeze_support()

    select_project_runtime()

    # Frozen workers reuse this executable, never enter pairing/assignment code.
    if sys.argv[1:] == ['--lhx-browser-worker']:
        from agent.browser_runtime import configure_bundled_browser
        configure_bundled_browser()
        from agent.browser_worker import main as browser_main
        browser_main()
        return

    from agent.cli import run
    run()

if __name__ == "__main__":
    main()

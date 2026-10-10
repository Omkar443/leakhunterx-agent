#!/usr/bin/env python3
"""Build the standalone lhx-agent binary for the current platform.

    python packaging/build.py

Picks the right spec for the host OS and drops the result in dist/.
PyInstaller cannot cross-compile: run this on Windows for the .exe and on
Linux (or the release workflow) for the ELF binary.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPECS = {
    "win32": "lhx-agent-windows-x64.spec",
    "linux": "lhx-agent-linux-x64.spec",
}


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def main() -> int:
    spec = SPECS.get(sys.platform)
    if spec is None:
        print(f"Unsupported platform for the binary build: {sys.platform}")
        return 1

    if not _module_available('playwright'):
        print('Build dependencies missing. Install the agent and PyInstaller first.')
        return 1
    environment = {**os.environ, 'PLAYWRIGHT_BROWSERS_PATH': '0'}
    # Embed only headless Chromium and its matching driver, never depend on
    # the builder's user browser cache or download anything on end-user scans.
    install = subprocess.run(
        [sys.executable, '-m', 'playwright', 'install', '--only-shell', 'chromium'],
        cwd=ROOT, env=environment, timeout=600)
    if install.returncode:
        return install.returncode

    # The console script is not always on PATH (user-site installs on Windows),
    # so fall back to the module runner.
    if _module_available("PyInstaller"):
        runner = [sys.executable, "-m", "PyInstaller"]
    else:
        print("pyinstaller not found. Install it with: pip install pyinstaller")
        return 1

    cmd = [
        *runner,
        str(Path("packaging") / spec),
        "--noconfirm",
        "--clean",
        "--distpath",
        "dist",
        "--workpath",
        "build",
    ]
    print("$ " + " ".join(cmd))
    result = subprocess.run(cmd, cwd=ROOT, env=environment)
    if result.returncode != 0:
        return result.returncode

    filename = 'lhx-agent-windows-x64.exe' if sys.platform == 'win32' else 'lhx-agent-linux-x64'
    produced = [ROOT / 'dist' / filename]
    print("\nBuilt:")
    for path in produced:
        print(f"  {path}  ({path.stat().st_size / 1_048_576:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

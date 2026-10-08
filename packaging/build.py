#!/usr/bin/env python3
"""Build the standalone lhx-agent binary for the current platform.

    python packaging/build.py

Picks the right spec for the host OS and drops the result in dist/.
PyInstaller cannot cross-compile: run this on Windows for the .exe and on
Linux (or the release workflow) for the ELF binary.
"""

from __future__ import annotations

import importlib.util
import shutil
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

    # The console script is not always on PATH (user-site installs on Windows),
    # so fall back to the module runner.
    if shutil.which("pyinstaller"):
        runner = ["pyinstaller"]
    elif _module_available("PyInstaller"):
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
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        return result.returncode

    produced = sorted(p for p in (ROOT / "dist").iterdir() if p.is_file())
    print("\nBuilt:")
    for path in produced:
        print(f"  {path}  ({path.stat().st_size / 1_048_576:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

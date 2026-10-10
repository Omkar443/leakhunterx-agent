# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Linux x64 single-file build.

Build from the repo root on a Linux host (PyInstaller cannot cross-compile):
    pyinstaller packaging/lhx-agent-linux-x64.spec --noconfirm
Output:
    dist/lhx-agent-linux-x64

ELF binaries carry no embedded icon; the desktop icon comes from
packaging/lhx-agent.desktop + assets/lhx-agent.png, which install.sh places
into the XDG icon/applications directories.
"""

a = Analysis(
    ['../src/lhx_agent_entry.py'],
    pathex=['src'],
    binaries=[],
    datas=[('../assets/lhx-agent.png', 'assets')],
    hiddenimports=[
        'agent',
        'agent.cli',
        'agent.lhx_agent',
        'agent.browser_worker',
        'playwright.async_api',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='lhx-agent-linux-x64',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

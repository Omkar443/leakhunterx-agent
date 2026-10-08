<p align="center">
  <img src="assets/lhx-agent.png" alt="LeakHunterX" width="128">
</p>

# LeakHunterX Agent

Lightweight open-source security scanning agent for LeakHunterX SaaS.

## Features

- Secure backend communication
- JS leak detection
- Endpoint discovery
- Cross-platform (Linux, Windows, macOS)

## Installation

### pip (any platform, needs Python 3.9+)

```bash
pip install lhx-agent
```

Then:

```bash
lhx-agent pair
```

### Standalone binary — no Python required

Linux:

```bash
curl -fsSL https://download.leakhunterx.com/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://download.leakhunterx.com/install.ps1 | iex
```

Or download the file directly from the
[releases page](https://github.com/Omkar443/leakhunterx-agent/releases):

| Platform    | File                        |
| ----------- | --------------------------- |
| Windows x64 | `lhx-agent-windows-x64.exe` |
| Linux x64   | `lhx-agent-linux-x64`       |

The Windows executable ships with the LeakHunterX icon embedded. ELF binaries
cannot embed an icon, so on Linux the installer registers `lhx-agent.png` plus
a `.desktop` entry and the icon shows up in the application menu.

## Building the binaries yourself

```bash
pip install -r requirements.txt pyinstaller
```

```bash
python packaging/build.py
```

`build.py` selects the spec for the host OS and writes the result to `dist/`.
PyInstaller cannot cross-compile, so the Windows `.exe` must be built on
Windows and the Linux binary on Linux — the `Release` GitHub Actions workflow
does both on a tag push and attaches them to the release.

## Development

```bash
pip install -e .
```

## License

MIT

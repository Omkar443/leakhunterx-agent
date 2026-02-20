# LeakHunterX Agent

Lightweight open-source security scanning agent for LeakHunterX SaaS.

## Features

- Secure backend communication
- JS leak detection
- Endpoint discovery
- Cross-platform (Linux, Windows, macOS)

## Installation

### One-liner (Linux/macOS)
curl -L https://download.leakhunterx.com/install.sh | bash

### One-liner (Windows PowerShell)
iwr -Uri https://download.leakhunterx.com/install.ps1 -OutFile install.ps1; .\install.ps1

## Manual Installation

pip install .

lhx-agent pair

## Development

pip install -e .

## License

MIT

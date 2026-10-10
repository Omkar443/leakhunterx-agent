#!/usr/bin/env bash
# LeakHunterX Agent installer (Linux).
#
#   curl -fsSL https://download.leakhunterx.com/install.sh | bash
#
# Override the version or download host with LHX_VERSION / LHX_BASE_URL.
set -euo pipefail

VERSION="${LHX_VERSION:-v1.0.0}"
BASE_URL="${LHX_BASE_URL:-https://github.com/Omkar443/leakhunterx-agent/releases/download/$VERSION}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) FILE="lhx-agent-linux-x64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    echo "Install with pip instead: pip install lhx-agent" >&2
    exit 1
    ;;
esac

# System-wide when run as root, per-user otherwise.
if [ "$(id -u)" -eq 0 ]; then
  BIN_DIR="/usr/local/bin"
  ICON_DIR="/usr/share/icons/hicolor/512x512/apps"
  DESKTOP_DIR="/usr/share/applications"
else
  BIN_DIR="$HOME/.local/bin"
  ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
  DESKTOP_DIR="$HOME/.local/share/applications"
fi

mkdir -p "$BIN_DIR" "$ICON_DIR" "$DESKTOP_DIR"

echo "Downloading $FILE ($VERSION)..."
curl -fsSL -o "$BIN_DIR/lhx-agent" "$BASE_URL/$FILE"
chmod +x "$BIN_DIR/lhx-agent"
ln -sfn lhx-agent "$BIN_DIR/lhx"

# ELF binaries carry no embedded icon, so register one through XDG instead.
if curl -fsSL -o "$ICON_DIR/lhx-agent.png" "$BASE_URL/lhx-agent.png" 2>/dev/null; then
  cat > "$DESKTOP_DIR/lhx-agent.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=LeakHunterX Agent
GenericName=Security Scanning Agent
Comment=Pair and run LeakHunterX security scans from the terminal
Exec=lhx-agent
Icon=lhx-agent
Terminal=true
Categories=Development;Security;Network;
Keywords=security;scanner;secrets;leak;
DESKTOP
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
  fi
else
  rm -f "$ICON_DIR/lhx-agent.png"
fi

echo "LeakHunterX Agent installed to $BIN_DIR/lhx-agent"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Add it to your PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
echo "Register once: lhx-agent pair"
echo "Start later: lhx agent (HTTP crawling + bundled headless rendering)"

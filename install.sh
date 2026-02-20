#!/usr/bin/env bash
set -e

VERSION="v1.0.0"
ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]; then
  FILE="lhx-agent-linux-x64"
else
  echo "Unsupported architecture"
  exit 1
fi

curl -L -o /usr/local/bin/lhx-agent \
  https://github.com/YOUR_USERNAME/leakhunterx-agent/releases/download/$VERSION/$FILE

chmod +x /usr/local/bin/lhx-agent

echo "LeakHunterX Agent installed."
echo "Run: lhx-agent pair"

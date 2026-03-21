#!/usr/bin/env python3
"""
LeakHunterX Agent Bootstrap
-------------------------------------------------
• Validates existing agent credentials
• Detects revocation automatically
• Re-pairs only when required
• Cross-platform secure secret storage
• Seamlessly launches agent after pairing
• Clean Ctrl+C handling (no tracebacks)
• Safe for systemd / Docker / supervisors

Supported OS:
- Linux
- macOS
- Windows
"""

from __future__ import annotations

import os
import sys
import json
import time
import platform
import re
import httpx
from pathlib import Path
from typing import Dict, Optional


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
BACKEND_URL = "https://backend-leakhunterx-staging.onrender.com"
AGENT_VERSION = "1.0.0"
REQUEST_TIMEOUT = 15


# ─────────────────────────────────────────────
# Cross-platform secret path resolution
# ─────────────────────────────────────────────
# Use shared secret path helper to avoid path mismatch
try:
    # Try to import from agent utils
    from agent.utils.secret_path import get_agent_secret_path
    SECRET_PATH = get_agent_secret_path()
except ImportError:
    # Fallback for direct script execution
    def get_secret_path() -> Path:
        system = platform.system().lower()

        if system == "windows":
            base = Path(os.environ.get("APPDATA", Path.home()))
            return base / "LeakHunterX" / "agent_secret.json"

        if system == "darwin":
            return (
                Path.home()
                / "Library"
                / "Application Support"
                / "LeakHunterX"
                / "agent_secret.json"
            )

        return Path.home() / ".leakhunterx" / "agent_secret.json"
    
    SECRET_PATH = get_secret_path()


# ─────────────────────────────────────────────
# Platform normalization
# ─────────────────────────────────────────────
def get_platform_info() -> Dict[str, str]:
    sys_platform = sys.platform.lower()

    if sys_platform.startswith("linux"):
        platform_name = "linux"
    elif sys_platform.startswith("win"):
        platform_name = "windows"
    elif sys_platform.startswith("darwin"):
        platform_name = "macos"
    else:
        platform_name = sys_platform

    system = platform.system()
    os_name = "Linux" if system == "Linux" else system

    release = platform.release()
    match = re.match(r"(\d+)\.", release)
    os_release = f"{match.group(1)}.x" if match else release

    return {
        "platform": platform_name,
        "os": os_name,
        "os_release": os_release,
    }


# ─────────────────────────────────────────────
# Secret handling
# ─────────────────────────────────────────────
def save_secret(agent_id: str, agent_secret: str) -> None:
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "agent_id": agent_id,
        "agent_secret": agent_secret,
        "created_at": int(time.time()),
        "backend_url": BACKEND_URL,
        "version": AGENT_VERSION,
    }

    with open(SECRET_PATH, "w") as f:
        json.dump(payload, f, indent=2)

    try:
        os.chmod(SECRET_PATH.parent, 0o700)
        os.chmod(SECRET_PATH, 0o600)
    except Exception:
        pass


def load_secret() -> Optional[Dict[str, str]]:
    try:
        with open(SECRET_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return None


def delete_secret() -> None:
    try:
        SECRET_PATH.unlink()
    except Exception:
        pass


# ─────────────────────────────────────────────
# Agent credential validation
# ─────────────────────────────────────────────
def validate_agent(agent_id: str, agent_secret: str) -> bool:
    try:
        resp = httpx.get(
            f"{BACKEND_URL}/api/v1/agent/status",
            headers={
                "X-Agent-Id": agent_id,
                "X-Agent-Secret": agent_secret,
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        return resp.status_code == 200

    except httpx.RequestError:
        print("⚠️  Backend unreachable — using cached credentials")
        return True


# ─────────────────────────────────────────────
# Agent execution
# ─────────────────────────────────────────────
def exec_agent() -> None:
    """
    Launch agent safely across platforms.

    IMPORTANT:
    - Windows + PyInstaller onefile CANNOT execv (temp dir is deleted)
    - Must continue in the same process
    """

    print("\n🚀 Launching LeakHunterX Agent...\n")

    # Detect PyInstaller onefile on Windows
    is_windows = platform.system().lower() == "windows"
    is_frozen = getattr(sys, "frozen", False)

    if is_windows and is_frozen:
        # ✅ SAFE PATH: in-process launch
        from agent.lhx_agent import main as agent_main
        agent_main()
        return

    # ✅ Normal behavior (Linux, macOS, non-frozen)
    executable = sys.executable
    argv0 = sys.argv[0]

    os.execv(executable, [executable, argv0, "run"])



# ─────────────────────────────────────────────
# Pairing flow (Ctrl+C SAFE)
# ─────────────────────────────────────────────
def pair_agent(pairing_token: Optional[str] = None) -> None:
    print("\n🔑 Agent pairing required")

    try:
        if not pairing_token:
            pairing_token = input("Paste pairing token: ").strip()
    except KeyboardInterrupt:
        print("\n\n⛔ Pairing cancelled by user")
        print("👋 Exiting LeakHunterX Agent")
        sys.exit(130)

    if not pairing_token:
        print("❌ Pairing token cannot be empty")
        sys.exit(1)

    hostname = platform.node() or "unknown-host"
    platform_info = get_platform_info()

    payload = {
        "pairing_token": pairing_token,
        "agent_name": hostname,
        "hostname": hostname,
        "platform": platform_info["platform"],
        "os": platform_info["os"],
        "os_release": platform_info["os_release"],
        "version": AGENT_VERSION,
    }

    print("\n📡 Registering agent with LeakHunterX backend...")

    try:
        resp = httpx.post(
            f"{BACKEND_URL}/api/v1/agents/pair",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    except httpx.RequestError as e:
        print(f"❌ Backend unreachable during pairing: {e}")
        sys.exit(1)

    if resp.status_code not in (200, 201):
        print(f"❌ Pairing failed [{resp.status_code}]")
        print(resp.text)
        sys.exit(1)

    data = resp.json()
    agent_id = data.get("agent_id")
    agent_secret = data.get("agent_secret")

    if not agent_id or not agent_secret:
        print("❌ Invalid backend response during pairing")
        sys.exit(1)

    save_secret(agent_id, agent_secret)

    print("\n✅ Agent successfully paired")
    print(f"   Agent ID : {agent_id}")
    print(f"   Secret   : {SECRET_PATH}")

    exec_agent()


# ─────────────────────────────────────────────
# Main bootstrap (final safety net)
# ─────────────────────────────────────────────
def main() -> None:
    try:
        print("\n🛡️  LeakHunterX Security Agent Bootstrap")
        print(f"Version {AGENT_VERSION}")
        print("=" * 48)

        secret = load_secret()

        if secret:
            print("🔍 Existing agent credentials found")

            agent_id = secret.get("agent_id")
            agent_secret = secret.get("agent_secret")

            if agent_id and agent_secret and validate_agent(agent_id, agent_secret):
                print("✅ Agent authorization verified")
                exec_agent()

            print("⚠️  Agent credentials invalid or revoked")
            print("🔁 Re-pairing required")
            delete_secret()

        pair_agent()

    except KeyboardInterrupt:
        print("\n\n⛔ Interrupted by user")
        print("👋 Exiting LeakHunterX Agent")
        sys.exit(130)


if __name__ == "__main__":
    main()
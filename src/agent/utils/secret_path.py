import os
import platform
from pathlib import Path

def get_agent_secret_path() -> Path:
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

    # Linux / Unix
    return Path.home() / ".leakhunterx" / "agent_secret.json"

#!/usr/bin/env python3
"""
LeakHunterX PyInstaller Entry Point
"""

import sys
import multiprocessing

def main() -> None:
    # 🔑 REQUIRED for Windows + PyInstaller
    multiprocessing.freeze_support()

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

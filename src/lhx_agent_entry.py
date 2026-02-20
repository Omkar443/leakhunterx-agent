#!/usr/bin/env python3
"""
LeakHunterX PyInstaller Entry Point
"""

import sys
import multiprocessing

def main() -> None:
    # 🔑 REQUIRED for Windows + PyInstaller
    multiprocessing.freeze_support()

    from agent.cli import run
    run()

if __name__ == "__main__":
    main()

"""
LeakHunterX Agent CLI entry point.

This file contains NO business logic.
It only delegates execution to agent.lhx_agent.main().
"""

import sys


def run() -> None:
    from agent.lhx_agent import main
    previous = sys.argv
    try:
        if sys.argv[1:2] == ['agent']:
            sys.argv = [previous[0], 'run', *previous[2:]]
        main()
    finally:
        sys.argv = previous

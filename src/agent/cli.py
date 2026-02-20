"""
LeakHunterX Agent CLI entry point.

This file contains NO business logic.
It only delegates execution to agent.lhx_agent.main().
"""

from agent.lhx_agent import main


def run() -> None:
    main()

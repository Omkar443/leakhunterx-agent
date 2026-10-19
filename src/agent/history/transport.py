"""Shared cancellation/deadline boundary for archive provider operations."""
import asyncio
import time
from contextlib import suppress
from agent.history.archive import ArchiveError


async def bounded_await(operation,cancelled,seconds):
    if cancelled():raise InterruptedError()
    deadline=time.monotonic()+seconds
    task=asyncio.create_task(operation())
    try:
        while True:
            if cancelled():raise InterruptedError()
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ArchiveError('archive_unavailable',failure_reason='archive_timeout')
            done,_=await asyncio.wait({task},timeout=min(.25,remaining))
            if done:return await task
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError,Exception):await task

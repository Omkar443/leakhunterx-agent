"""Archive provider boundary; capture acquisition never falls back to live URLs."""
from typing import Protocol
from agent.history.archive import ArchiveClient
from agent.history.archive import ArchiveError


class ArchiveProvider(Protocol):
    name: str
    async def discover(self): ...
    async def fetch(self,capture): ...


class WaybackProvider:
    name='wayback'

    def __init__(self,client: ArchiveClient,cache=None):
        self.client,self.cache=client,cache

    async def discover(self):return await self.client.discover()

    async def fetch(self,capture):
        if self.client.cancelled():raise InterruptedError()
        if capture.get('archive_provider','wayback')!=self.name or 'archive_record' in capture:raise ArchiveError('scope_refused')
        if self.cache:
            cached=self.cache.get(capture)
            if cached is not None:return cached
        result=await self.client.fetch(capture)
        if self.cache:self.cache.put(capture,result)
        return result

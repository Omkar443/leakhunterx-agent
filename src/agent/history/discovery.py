"""Bounded CDX discovery with exact-scope recovery by inclusive date partitions.

Transport, parsing and redirection checks stay in ArchiveClient. This planner
only changes query dates, never the host, subdomain authorization or source.
"""
from collections import deque
import asyncio
from dataclasses import dataclass
from datetime import date, timedelta
import time
from urllib.parse import urlsplit

from agent.history.archive import ArchiveError


@dataclass(frozen=True)
class DiscoveryPolicy:
    max_requests: int = 24
    max_seconds: float = 180
    consecutive_failures: int = 4
    transport_retries: int = 1


class DiscoveryBudget:
    def __init__(self, policy, checkpoint=None):
        self.policy = policy
        self.deadline = time.monotonic() + policy.max_seconds
        self.checkpoint=checkpoint
        self.requests = (checkpoint.get('index_requests') or 0) if checkpoint else 0
        if type(self.requests) is not int or not 0<=self.requests<=policy.max_requests:raise ArchiveError('invalid_content')

    def reserve(self):
        remaining = self.deadline - time.monotonic()
        if self.requests >= self.policy.max_requests or remaining <= 0:
            raise ArchiveError('budget_limit', failure_reason='archive_discovery_incomplete')
        self.requests += 1
        if self.checkpoint:self.checkpoint.put('index_requests',self.requests)
        return remaining


class ArchiveDiscovery:
    FILTERS = (
        'mimetype:.*javascript.*', r'original:.*\.map(?:\?.*)?',
        'mimetype:(text/html|text/plain|application/json|text/xml|application/xml|application/octet-stream)',
    )
    RECOVERABLE = {'archive_timeout', 'archive_service_unavailable'}

    def __init__(self, archive, policy=None):
        self.archive = archive
        self.policy = policy or DiscoveryPolicy()
        self.budget = DiscoveryBudget(self.policy,archive.checkpoint)

    def restore(self,start,end):
        saved=self.archive.checkpoint.get('discovery') if self.archive.checkpoint else None
        if not saved:return ([[] for _ in self.FILTERS],deque((index,start,end) for index in range(len(self.FILTERS))),False)
        if set(saved)!={'pools','pending','limited'} or type(saved['limited']) is not bool or len(saved['pools'])!=3 or len(saved['pending'])>64:
            raise ArchiveError('invalid_content')
        pools=[]
        for pool in saved['pools']:
            self.archive.validate_checkpoint_rows(pool,{},maximum=12000)
            pools.append(pool)
        pending=deque()
        for category,first,last in saved['pending']:
            first,last=date.fromisoformat(first),date.fromisoformat(last)
            if type(category) is not int or category not in range(3) or not start<=first<=last<=end:raise ArchiveError('invalid_content')
            pending.append((category,first,last))
        return pools,pending,saved['limited']

    def save(self,pools,pending,limited):
        if self.archive.checkpoint:self.archive.checkpoint.put('discovery',{'pools':pools,'pending':[(category,first.isoformat(),last.isoformat()) for category,first,last in pending],'limited':limited})

    def partial(self):
        config=self.archive.config
        pools,_,_=self.restore(date.fromisoformat(config['from_date']),date.fromisoformat(config['to_date']))
        if not any(pools):return None
        return self.select([self.order(pool) for pool in pools],config['max_captures'],True)

    async def discover(self):
        config = self.archive.config
        params = {'url': urlsplit(self.archive.target).hostname,
                  'matchType': 'domain' if config['include_subdomains'] else 'host',
                  'output': 'json', 'fl': 'timestamp,original,mimetype,statuscode,digest',
                  'limit': 500, 'showResumeKey': 'true', 'collapse': 'digest'}
        start, end = date.fromisoformat(config['from_date']), date.fromisoformat(config['to_date'])
        pools,pending,limited=self.restore(start,end)
        seen={(row['original_url'],row['requested_timestamp']) for pool in pools for row in pool}
        last_error = None
        consecutive_failures = 0; retries = {}
        # Breadth first across resource categories and then date partitions:
        # a slow JavaScript index must not starve available HTML or source maps.
        while pending:
            if self.archive.cancelled(): raise InterruptedError()
            category, first, last = pending.popleft()
            query = {**params, 'filter': ['statuscode:200', self.FILTERS[category]],
                     'from': first.strftime('%Y%m%d'), 'to': last.strftime('%Y%m%d') + '235959'}
            try:
                rows, more = await self.archive.index(query, budget=self.budget)
                limited |= more
                consecutive_failures = 0
                for row in rows:
                    identity = (row['original_url'], row['requested_timestamp'])
                    if identity not in seen:
                        seen.add(identity); pools[category].append(row)
            except ArchiveError as error:
                if error.failure_reason in ('archive_rate_limited', 'archive_access_denied', 'archive_scope_refused'):
                    raise
                consecutive_failures += 1
                if error.reason == 'budget_limit' or consecutive_failures >= self.policy.consecutive_failures:
                    last_error = error
                    pending.appendleft((category,first,last))
                    break
                if error.failure_reason in self.RECOVERABLE and first < last:
                    middle = first + (last - first) // 2
                    pending.extend([(category,first,middle),(category,middle+timedelta(days=1),last)])
                elif error.failure_reason=='archive_network_error' and retries.get((category,first,last),0)<self.policy.transport_retries:
                    retries[(category,first,last)]=retries.get((category,first,last),0)+1
                    await asyncio.sleep(.5)
                    pending.appendleft((category,first,last))
                else:
                    last_error = error
                    limited = True
            self.save(pools,pending,limited)
        self.save(pools,pending,limited)
        if pending and self.archive.checkpoint and last_error:raise last_error
        limited|=bool(pending)
        if not any(pools) and last_error:
            raise last_error
        if not any(pools):
            raise ArchiveError('archive_unavailable',failure_reason='archive_no_captures')
        return self.select([self.order(pool) for pool in pools], config['max_captures'], limited)

    @staticmethod
    def order(pool):
        groups = {}
        for row in pool: groups.setdefault(row['original_url'], []).append(row)
        for rows in groups.values():
            rows.sort(key=lambda row: row['requested_timestamp'])
            if len(rows) > 2: rows[:] = [rows[0], rows[-1], *rows[1:-1]]
        groups = {name: deque(rows) for name, rows in groups.items()}
        ordered = []
        while any(groups.values()):
            for name in sorted(groups):
                if groups[name]: ordered.append(groups[name].popleft())
        return ordered

    @staticmethod
    def select(pools, maximum, limited):
        selected = []
        quotas = [max(1, int(maximum * .6)), max(1, int(maximum * .25)), max(1, int(maximum * .15))]
        for pool, quota in zip(pools, quotas):
            take = min(quota, len(pool), maximum - len(selected))
            selected.extend(pool[:take]); del pool[:take]
        for pool in pools:
            take = min(len(pool), maximum - len(selected))
            selected.extend(pool[:take]); del pool[:take]
        limited |= any(pools)
        selected.sort(key=lambda row: (row['requested_timestamp'], row['original_url']))
        return selected, limited

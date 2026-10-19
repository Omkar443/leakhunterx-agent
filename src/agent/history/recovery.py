"""Persisted, bounded retries within the original assignment and scan allowance."""
import asyncio
import time
import math
from dataclasses import dataclass

from agent.history.archive import ArchiveError


@dataclass(frozen=True)
class RecoveryPolicy:
    attempts: int = 3
    first_backoff: float = 10
    maximum_backoff: float = 60


class ArchiveRecovery:
    TRANSIENT={'archive_timeout','archive_service_unavailable','archive_network_error','archive_rate_limited'}

    def __init__(self, state, cancelled, deadline, notify, policy=None,*,provider='wayback'):
        self.state,self.cancelled,self.deadline,self.notify=state,cancelled,deadline,notify
        self.policy=policy or RecoveryPolicy()
        if provider not in ('wayback','commoncrawl'):raise ValueError('Unsupported archive provider')
        self.provider=provider

    async def execute(self, name, operation, phase, *, cache_result=False):
        key='recovery:'+name
        saved=self.state.get(key) or {'attempt':0,'retry_at':0,'reason':'archive_unavailable'}
        if not isinstance(saved,dict) or set(saved)-{'attempt','retry_at','reason','result'} or type(saved.get('attempt')) is not int or not 0<=saved['attempt']<=self.policy.attempts or type(saved.get('retry_at')) not in (int,float) or not math.isfinite(saved['retry_at']) or saved['retry_at']<0:
            raise ArchiveError('invalid_content')
        from agent.history.failures import HISTORICAL_FAILURES
        if saved.get('reason') not in HISTORICAL_FAILURES:raise ArchiveError('invalid_content')
        while True:
            if self.cancelled():raise InterruptedError()
            if cache_result and 'result' in saved:return saved['result']
            while time.time()<saved['retry_at']:
                if self.cancelled():raise InterruptedError()
                if time.time()>=self.deadline():raise ArchiveError('budget_limit')
                await asyncio.sleep(min(.25,max(0,saved['retry_at']-time.time())))
            if self.cancelled():raise InterruptedError()
            if saved['attempt']>=self.policy.attempts:
                raise ArchiveError('archive_unavailable',failure_reason=saved['reason'])
            attempt=saved['attempt']+1
            await self.notify(phase,{'state':'retrieving','attempt':attempt,'retry_at':0,'provider':self.provider})
            try:
                remaining=self.deadline()-time.time()
                if remaining<=0:raise ArchiveError('budget_limit')
                try:result=await asyncio.wait_for(operation(),timeout=remaining)
                except asyncio.TimeoutError:raise ArchiveError('budget_limit') from None
                if cache_result:
                    saved['result']=result;self.state.put(key,saved)
                return result
            except ArchiveError as error:
                saved.update(attempt=attempt,reason=error.failure_reason)
                self.state.put(key,saved)
                if error.failure_reason not in self.TRANSIENT or attempt>=self.policy.attempts:raise
                delay=min(self.policy.maximum_backoff,self.policy.first_backoff*2**(saved['attempt']-1))
                delay=max(delay,error.retry_after or 0)
                if time.time()+delay>=self.deadline():raise
                saved.update(retry_at=math.ceil(time.time()+delay) if delay else 0,reason=error.failure_reason)
                self.state.put(key,saved)
                await self.notify(phase,{'state':'waiting','attempt':saved['attempt'],'retry_at':saved['retry_at'],'provider':self.provider})

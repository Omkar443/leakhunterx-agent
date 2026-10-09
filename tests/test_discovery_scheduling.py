import asyncio
from unittest.mock import AsyncMock
import pytest
from agent.discovery import DiscoveryConfig, DiscoveryEngine
from agent.utils.pipeline import PipelineError


def test_independent_discovery_sources_start_concurrently():
    async def scenario():
        engine = DiscoveryEngine('app.example.invalid', DiscoveryConfig(use_second_pass=False))
        entered = set()
        ready = asyncio.Event()
        async def source(name):
            entered.add(name)
            if len(entered) == 4: ready.set()
            await asyncio.wait_for(ready.wait(), 1)
            return []
        engine._detect_wildcard_dns = AsyncMock(return_value=False)
        engine._verify_results = AsyncMock(return_value=[])
        engine._discover_from_ct_logs = lambda: source('ct')
        engine._discover_from_common_prefixes = lambda: source('prefix')
        engine._discover_from_cname_patterns = lambda: source('cname')
        engine._discover_from_http = lambda _: source('http')
        assert await engine._run_discovery_pipeline() == []
        assert entered == {'ct', 'prefix', 'cname', 'http'}
    asyncio.run(scenario())


def test_discovery_deadline_cancels_sources_and_never_reports_completion():
    async def scenario():
        config = DiscoveryConfig(max_total_time=.01, use_ct_logs=False,
            use_http_extraction=False, use_js_extraction=False)
        engine = DiscoveryEngine('app.example.invalid', config)
        engine._ensure_resolver = lambda: None
        stopped = asyncio.Event()
        async def slow():
            try: await asyncio.Event().wait()
            finally: stopped.set()
        engine._run_discovery_pipeline = slow
        with pytest.raises(PipelineError, match='timed out'): await engine.discover()
        assert stopped.is_set() and engine.get_metrics()['timed_out']
        assert engine.discovered_results == []
    asyncio.run(scenario())


def test_source_failure_cancels_and_awaits_sibling_tasks():
    async def scenario():
        entered, stopped = asyncio.Event(), asyncio.Event()
        async def waiting():
            entered.set()
            try: await asyncio.Event().wait()
            finally: stopped.set()
        async def failing():
            await entered.wait()
            raise RuntimeError('source failed')
        with pytest.raises(RuntimeError, match='source failed'):
            await DiscoveryEngine._run_sources({'waiting': waiting(), 'failing': failing()})
        assert stopped.is_set()
    asyncio.run(scenario())

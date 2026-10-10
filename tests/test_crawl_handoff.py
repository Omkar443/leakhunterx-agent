"""Acquisition deadlines must not discard reachable assets or invent coverage."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from agent import orchestrator
from agent.crawler import CompleteCrawler, CrawlContext, CrawlUnavailable
from agent.domain_manager import DomainManager


@pytest.mark.parametrize('acquisition,usable_http,usable_browser,succeeds', [
    ('timeout', True, False, True),
    ('timeout', False, True, True),
    ('timeout', False, False, False),
    ('unreachable', False, True, True),
    ('unreachable', False, False, False),
    ('defect', True, True, False),
])
def test_http_failure_hands_off_only_acquisition_errors(monkeypatch, acquisition, usable_http, usable_browser, succeeds):
    from agent import browser_rendering
    async def scenario():
        monkeypatch.setattr(orchestrator, 'emit_event', AsyncMock())
        failure = {'timeout':orchestrator.CrawlTimeout, 'unreachable':CrawlUnavailable,
                   'defect':ValueError}[acquisition]
        scan = orchestrator.ScanOrchestrator('https://example.invalid', {}, AsyncMock(), scan_id='test')
        scan._context = SimpleNamespace(shared_state={})
        scan._crawl_context = SimpleNamespace(shared_state={'metrics':{'urls_crawled':int(usable_http)}})
        scan._domain_manager = DomainManager('https://example.invalid')
        scan._run_discovery_phase = AsyncMock(return_value=[])
        scan._discover_js_urls = AsyncMock(side_effect=failure())
        scan._analyze_js_files = AsyncMock(); scan._record_recheck_coverage = lambda: None
        scan._flush_artifacts = AsyncMock(); scan._complete_scan = AsyncMock()
        result = {'rendering_status':'completed' if usable_browser else 'unavailable',
                  'doms':[{'url':'https://example.invalid', 'content':'<html>usable</html>'}] if usable_browser else [],
                  'rendering_limited':not usable_browser}
        browser = AsyncMock(return_value=result)
        monkeypatch.setattr(browser_rendering, 'run_browser_discovery', browser)
        monkeypatch.setattr(browser_rendering, 'integrate_browser_result', AsyncMock())
        if succeeds:
            await scan._run_scan_logic()
            scan._complete_scan.assert_awaited_once()
            assert scan.metrics.analysis_limited
        else:
            with pytest.raises(failure): await scan._run_scan_logic()
            scan._complete_scan.assert_not_awaited()
        if acquisition == 'defect': browser.assert_not_awaited()
        else: browser.assert_awaited_once()
    asyncio.run(scenario())


def test_each_page_deadline_covers_alternate_header_attempts(monkeypatch):
    async def scenario():
        manager = DomainManager('https://example.invalid')
        context = CrawlContext('scan', manager, AsyncMock())
        crawler = CompleteCrawler(manager, {'request_timeout':.02})
        started, cancelled = [], []
        async def stalled(*args):
            started.append(True)
            try: await asyncio.Event().wait()
            finally: cancelled.append(True)
        monkeypatch.setattr(crawler, 'fetch_url', stalled)
        # Test the final attempt, avoiding real retry backoff.
        context.shared_state['crawler'] = {'retry_attempts':{'https://example.invalid/':2}}
        assert await asyncio.wait_for(crawler.crawl_single_url('https://example.invalid/', 0, context), .5) == (set(), set())
        assert started == cancelled == [True]
        assert context.shared_state['metrics']['timeouts'] == 1
    asyncio.run(scenario())


def test_real_crawl_timeout_retains_discovered_scripts_and_closes_session(monkeypatch):
    async def scenario():
        async def home(request):
            return web.Response(text='<html><script src="/app.js"></script><a href="/slow">slow</a></html>')
        async def slow(request):
            await asyncio.sleep(1)
            return web.Response(text='<html>slow</html>')
        app = web.Application(); app.router.add_get('/', home); app.router.add_get('/slow', slow)
        server = web.AppRunner(app); await server.setup()
        site = web.TCPSite(server, '127.0.0.1', 0); await site.start()
        target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
        config = {'allow_private_targets':True, 'browser_rendering':'off', 'crawler_delay':0}
        scan = orchestrator.ScanOrchestrator(target, config, AsyncMock(), scan_id='local')
        scan._domain_manager = DomainManager(target); scan._domain_manager.add_seed_urls([target])
        scan._crawl_context = CrawlContext('local', scan._domain_manager, AsyncMock(), config)
        scan._context = scan._crawl_context
        scan._crawler = CompleteCrawler(scan._domain_manager, config)
        scan._crawl_timeout = .4
        try:
            with pytest.raises(orchestrator.CrawlTimeout): await scan._discover_js_urls()
            assert scan._crawl_task.done() and scan._crawler.session is None
            assert scan._domain_manager.get_js_queue_size() == 1
            assert scan._crawl_context.shared_state['metrics']['urls_crawled'] == 1
        finally: await server.cleanup()
    asyncio.run(scenario())

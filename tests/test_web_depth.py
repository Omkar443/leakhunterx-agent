"""Real local HTTP targets exercise discovery through detection, without credentials."""
import asyncio
from unittest.mock import AsyncMock, Mock
from contextlib import asynccontextmanager
import logging

import pytest

from aiohttp import web

from agent.crawler import CompleteCrawler, CrawlContext
from agent.domain_manager import DomainManager
from agent.js.extractor_context import ExtractorContext
from agent.js.js_analyzer import JSAnalysisEngine
from agent.orchestrator import ScanOrchestrator, AnalysisTaskManager, ScanStatus
from agent.utils.url_normalizer import EnterpriseURLNormalizer


def test_clean_install_only_advertises_builtin_compression():
    crawler=CompleteCrawler(DomainManager('https://example.invalid'),{})
    assert crawler._get_enhanced_headers()['Accept-Encoding']=='gzip, deflate'


@asynccontextmanager
async def target_server(resource, receive=None):
    app = web.Application()
    if receive: app.router.add_post('/events', receive)
    app.router.add_get('/{tail:.*}', resource)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0); await site.start()
    try:
        yield f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
    finally: await runner.cleanup()


def test_identical_html_and_hashed_scripts_do_not_hide_distinct_assets():
    async def scenario():
        async def resource(request):
            body = ('<a href="/a/">a</a><a href="/b/">b</a>'
                    '<script src="/assets/app-12345678.js"></script>'
                    '<script src="/assets/app-abcdef12.js"></script>') if request.path == '/' else '<script src="./entry.js"></script>'
            return web.Response(text=f'<html>{body}</html>', content_type='text/html')
        async with target_server(resource) as target:
            manager = DomainManager(target); manager.add_seed_urls([target])
            config = {'allow_private_targets':True, 'crawler_delay':0}
            context = CrawlContext('variants', manager, AsyncMock(), config)
            await CompleteCrawler(manager, config).crawl(context)
            assert set(manager.js_queue) == {target + path for path in (
                'a/entry.js','b/entry.js','assets/app-12345678.js','assets/app-abcdef12.js')}
    asyncio.run(scenario())


@pytest.mark.parametrize('pages,expected', [(100,76), (5,5)])
def test_long_chain_and_exact_page_budget(pages, expected):
    async def scenario():
        visits = []
        async def resource(request):
            number = int(request.path.strip('/') or '0'); visits.append(number)
            body = f'<a href="/{number+1}">next page</a>' if number < 75 else '<script src="/deep.js"></script>'
            return web.Response(text=f'<html>{body}</html>', content_type='text/html')
        async with target_server(resource) as target:
            config = {'allow_private_targets':True, 'max_pages':pages, 'max_depth':90, 'crawler_delay':0}
            manager = DomainManager(target, 90); manager.add_seed_urls([target])
            context = CrawlContext('chain', manager, AsyncMock(), config)
            crawler = CompleteCrawler(manager, config)
            crawler.rate_window = .01  # Same throttle algorithm, faster test clock.
            await asyncio.wait_for(crawler.crawl(context), 15)
            assert len(visits) == expected
            assert (target+'deep.js' in manager.js_queue) == (pages == 100)
            assert manager.has_targets() == (pages == 5)
    asyncio.run(scenario())


def test_module_scope_and_cycle_budgets(monkeypatch):
    from agent import web_discovery
    monkeypatch.setattr(web_discovery, 'MAX_DISCOVERED_RESOURCES', 3)
    context = ExtractorContext('bounded', {}, AsyncMock())
    manager = DomainManager('https://example.invalid')
    context.scope_check = manager.is_in_scope
    source = '''import "./a.mjs"; import "./a.mjs"; export * from "./b.mjs";
        import("./c.mjs"); import("./d.mjs"); import "https://foreign.invalid/x.js";
        import "file:///etc/passwd"; import "node:fs"; import "package-name";'''
    web_discovery.discover_modules(source, 'https://example.invalid/main.js', context)
    assert len(context.shared_state['discovered_module_urls']) == 3
    assert context.shared_state['dependency_discovery_limited']
    for index in range(5): manager.add_discovered(f'https://example.invalid/{index}.js', 0)
    assert manager.js_urls_enqueued == 3
    assert manager.get_stats()['resource_limit_skipped'] == 2


@pytest.mark.parametrize('url', [
    'https://example.invalid/a%2Fb.js?sig=a%2Bb',
    'https://example.invalid/folder/?page=2&page=3',
    'https://example.invalid/x.js?return=https://other.invalid/a//b',
])
def test_resource_url_identity_is_preserved(url):
    assert EnterpriseURLNormalizer().normalize(url).normalized_url == url


def test_document_base_and_extensionless_module_preload():
    async def scenario():
        manager = DomainManager('https://example.invalid')
        context = CrawlContext('base', manager, AsyncMock())
        crawler = CompleteCrawler(manager, {})
        links, scripts = await crawler.parse_links('https://example.invalid/page/', '''<html>
            <base href="/resources/"><a href="next">next</a>
            <link rel="modulepreload" href="runtime"><script src="entry.mjs"></script>
            <script type="module">import "./child.mjs";</script></html>''', context)
        assert links == {'https://example.invalid/resources/next'}
        assert scripts == {f'https://example.invalid/resources/{name}' for name in ('runtime','entry.mjs','child.mjs')}
        _, scripts = await crawler.parse_links('https://example.invalid/',
            '<base href="https://foreign.invalid/"><script src="x.js"></script>', context)
        assert all('foreign.invalid' not in url for url in scripts)
        assert context.shared_state['document_base_limited']
    asyncio.run(scenario())


def test_fragment_links_share_one_fetch_identity():
    async def scenario():
        manager = DomainManager('https://example.invalid')
        context = CrawlContext('fragments', manager, AsyncMock())
        crawler = CompleteCrawler(manager, {})
        links, scripts = await crawler.parse_links('https://example.invalid/',
            '<html><a href="/docs#one">one</a><a href="/docs#two">two</a></html>', context)
        assert links == {'https://example.invalid/docs'} and not scripts
    asyncio.run(scenario())


def test_resource_queries_and_failure_messages_do_not_enter_logs(caplog):
    from agent.utils.pipeline import display_url
    caplog.set_level(logging.DEBUG)
    marker = 'SYNTHETIC_QUERY_ONLY_DO_NOT_LOG'
    async def scenario():
        async def resource(request):
            if request.path == '/':
                return web.Response(text=f'<html><script src="/missing.js?token={marker}"></script></html>', content_type='text/html')
            return web.Response(status=404)
        async with target_server(resource) as target:
            config = {'allow_private_targets':True, 'crawler_delay':0}
            manager = DomainManager(target+'?token='+marker); manager.add_seed_urls([target])
            crawl = CrawlContext('private-logs', manager, AsyncMock(), config)
            await CompleteCrawler(manager, config).crawl(crawl)
            context = ExtractorContext('private-logs',config,AsyncMock()); context.scope_check = manager.is_in_scope
            engine = JSAnalysisEngine(context)
            try:
                result = await engine.analyze(target+'missing.js?token='+marker)
                assert not result['success']
            finally: await engine.cleanup()
    asyncio.run(scenario())
    # The target server necessarily receives the request query; its access logs
    # are outside the agent. Check the agent's own emitted diagnostics.
    agent_logs = [record.getMessage() for record in caplog.records if
        record.name.startswith('agent.') or record.name in ('crawler', 'domain_manager', 'js_analysis_engine')]
    assert marker not in '\n'.join(agent_logs)
    assert display_url('https://user:password@example.invalid/a.js?token=x#private') == 'https://example.invalid/a.js'
    assert display_url('https://[invalid') == '[invalid source URL]'


def test_linked_plaintext_configuration_is_scanned_without_source_execution():
    async def scenario():
        events = []
        token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
        async def resource(request):
            if request.path == '/':
                return web.Response(text='<html><a href="/public-config.txt">config</a></html>', content_type='text/html')
            return web.Response(text=f'GITHUB_TOKEN={token}', content_type='text/plain')
        async def collect(event): events.append(event)
        emitter = AsyncMock(); emitter.emit.side_effect = collect
        async with target_server(resource) as target:
            manager = DomainManager(target); manager.add_seed_urls([target])
            config = {'allow_private_targets':True, 'crawler_delay':0}
            context = CrawlContext('text', manager, emitter, config)
            await CompleteCrawler(manager, config).crawl(context)
            assert any(event['event_type'] == 'secret_found' for event in events)
            assert token not in str(events)
            assert context.shared_state['metrics']['urls_crawled'] == 2
    asyncio.run(scenario())


def test_host_throttle_waits_and_is_cancellable():
    async def scenario():
        manager = DomainManager('https://example.invalid')
        context = CrawlContext('throttle', manager, AsyncMock())
        crawler = CompleteCrawler(manager, {}); crawler.rate_requests = 1; crawler.rate_window = .03
        await asyncio.gather(*(crawler._check_rate_limit('example.invalid', context) for _ in range(3)))
        # Slots are reserved rather than discarded, including concurrent waiters.
        assert len(context.shared_state['crawler']['rate_limit_tracker']['example.invalid']) == 1
        crawler.rate_window = 15
        task = asyncio.create_task(crawler._check_rate_limit('example.invalid', context))
        await asyncio.sleep(.01); context.should_stop.set()
        assert await asyncio.wait_for(task, .5) is False
    asyncio.run(scenario())


@pytest.mark.parametrize('mode', ['clean', 'missing_resource', 'retry'])
def test_complete_scan_delivers_redacted_evidence_before_completion(tmp_path, mode):
    """Actual orchestrator and durable HTTP delivery, isolated receiver fixture."""
    from agent.events.event_emitter import HTTPBatchEmitter
    from agent.events.router_emitter import RouterEmitter
    async def scenario():
        received, attempts = [], []
        token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
        async def resource(request):
            if request.path == '/':
                scripts = '<script src="/main.js"></script>'
                if mode == 'missing_resource': scripts += '<script src="/missing.js"></script>'
                return web.Response(text=f'<html>{scripts}</html>', content_type='text/html')
            if request.path == '/missing.js': return web.Response(status=404)
            attempts.append(request.path)
            if mode == 'retry' and len(attempts) == 1: return web.Response(status=503)
            return web.Response(text=f'const token="{token}";', content_type='application/javascript')
        async def receive(request):
            payload = await request.json()
            received.extend(row['event'] for row in payload['events'])
            return web.json_response({'status':'accepted', 'received':len(payload['events']), 'batch_id':payload['batch_id']}, status=202)
        async with target_server(resource, receive) as target:
            batch = HTTPBatchEmitter(target+'events', agent_id='isolated-test', dlq_dir=tmp_path, max_retries=0)
            emitter = RouterEmitter(AsyncMock(), batch)
            scan = ScanOrchestrator(target, {'allow_private_targets':True, 'browser_rendering':'off',
                'crawler_delay':0, 'js_fetch_retries':2}, emitter, state_manager=AsyncMock(), scan_id='durable')
            scan._run_discovery_phase = AsyncMock(return_value=[])  # No external discovery traffic.
            try:
                await asyncio.wait_for(scan.start_scan(), 20)
                assert scan.status == ScanStatus.COMPLETED
                assert scan.metrics.analysis_limited == (mode == 'missing_resource')
                kinds = [event['event_type'] for event in received]
                assert kinds.count('scan_completed') == 1
                assert kinds.index('secret_found') < kinds.index('scan_completed')
                assert token not in str(received)
                assert batch.outbox.count() == 0
                assert len(attempts) == (2 if mode == 'retry' else 1)
                assert scan._crawler is None and scan._analyzer is None
            finally: await emitter.close()
    asyncio.run(scenario())


def test_query_pages_and_nested_modules_reach_deep_secret():
    async def scenario():
        visits, events = [], []
        token = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
        async def resource(request):
            visits.append(request.path_qs)
            if request.path == '/':
                return web.Response(text='<html><a href="/catalog?page=1">1</a></html>', content_type='text/html')
            if request.path == '/catalog':
                page = int(request.query.get('page', 1))
                body = f'<a href="/catalog?page={page+1}">next</a>' if page < 4 else '<script type="module" src="/modules/main.mjs"></script>'
                return web.Response(text=f'<html>{body}</html>', content_type='text/html')
            sources = {'/modules/main.mjs':'import "./level1.mjs";',
                       '/modules/level1.mjs':'export {x} from "./level2.mjs";',
                       '/modules/level2.mjs':f'export const x = "{token}";'}
            return web.Response(text=sources[request.path], content_type='application/javascript')
        app = web.Application(); app.router.add_get('/{tail:.*}', resource)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0); await site.start()
        target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
        async def collect(event): events.append(event)
        emitter = AsyncMock(); emitter.emit.side_effect = collect
        config = {'allow_private_targets':True, 'browser_rendering':'off', 'max_depth':8, 'crawler_delay':0}
        manager = DomainManager(target, 8); manager.add_seed_urls([target])
        crawl_context = CrawlContext('depth', manager, emitter, config)
        crawler = CompleteCrawler(manager, config)
        context = ExtractorContext('depth', config, emitter); context.scope_check = manager.is_in_scope
        engine = JSAnalysisEngine(context)
        scan = ScanOrchestrator(target, config, emitter, state_manager=AsyncMock(), scan_id='depth')
        scan.status = ScanStatus.RUNNING
        scan._context = context; scan._domain_manager = manager; scan._analyzer = engine
        scan._task_manager = AnalysisTaskManager(2)
        try:
            await asyncio.wait_for(crawler.crawl(crawl_context), 15)
            assert '/catalog?page=4' in visits
            await asyncio.wait_for(scan._analyze_js_files(), 15)
            assert '/modules/level2.mjs' in visits
            assert scan.metrics.processed_js_files == scan.metrics.total_js_files == 3
            secrets = [e for e in events if e.get('event_type') == 'secret_found']
            assert any(e['data'].get('type') == 'Github Token' for e in secrets), secrets
            assert token not in str(events)
            assert not scan.metrics.analysis_limited
        finally:
            await engine.cleanup(); await runner.cleanup()
    asyncio.run(scenario())


def test_signed_query_encoding_and_order_are_not_rewritten():
    url = 'https://example.invalid/app.js?z=2&sig=a%2Bb%26c%3Dd&empty=&a=1'
    assert EnterpriseURLNormalizer().normalize(url).normalized_url == url


def test_relative_dependencies_are_discovered_even_for_duplicate_content():
    async def scenario():
        context = ExtractorContext('relative', {}, AsyncMock())
        context.scope_check = DomainManager('https://example.invalid').is_in_scope
        engine = JSAnalysisEngine(context)
        try:
            await engine.analyze_js_content('https://example.invalid/a/main.js', 'import "./child.mjs";')
            await engine.analyze_js_content('https://example.invalid/b/main.js', 'import "./child.mjs";')
            assert context.shared_state.get('discovered_module_urls') == {
                'https://example.invalid/a/child.mjs', 'https://example.invalid/b/child.mjs'}
        finally: await engine.cleanup()
    asyncio.run(scenario())

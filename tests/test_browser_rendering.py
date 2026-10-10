"""Controlled fixtures only: no external targets or real credentials."""
import asyncio
from collections import Counter
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from aiohttp import web
import pytest

from agent.browser_rendering import bounded, run_browser_discovery, integrate_browser_result
from agent.browser_worker import BrowserBridge
from agent.config.config import AgentConfig
from agent.crawler import CrawlContext
from agent.domain_manager import DomainManager
from agent.events.outbox import DeliveryPending
from agent.js.extractor_context import ExtractorContext
from agent.js.js_analyzer import JSAnalysisEngine
from agent.asset_coverage import detector_policy


def test_rendering_defaults_on_can_be_disabled_and_is_bounded(monkeypatch):
    context = ExtractorContext('scan',{},AsyncMock())
    monkeypatch.delenv('LHX_BROWSER_RENDERING', raising=False)
    assert AgentConfig.from_env().browser_rendering == 'on'
    assert asyncio.run(run_browser_discovery('https://example.invalid',{'browser_rendering':'off'},context))['rendering_status'] == 'disabled'
    context.event_emitter.emit.assert_not_called()
    monkeypatch.setenv('LHX_BROWSER_RENDERING','on')
    assert AgentConfig.from_env().browser_rendering == 'on'
    for field,value in (('browser_rendering','auto'),('browser_timeout',0),('browser_max_pages',99)):
        config = AgentConfig(); setattr(config,field,value)
        with pytest.raises(ValueError): config.validate()
    assert bounded({'pages':999},'pages',3,5) == 5


def test_bridge_never_forwards_unsafe_requests_or_credentials():
    async def scenario():
        session = AsyncMock()
        bridge = BrowserBridge(session,'https://app.example.invalid',{'requests':5,'bytes':10})
        for url,method,kind in (
            ('http://169.254.169.254/latest/meta-data','GET','fetch'),
            ('https://app.example.invalid:8443/','GET','document'),
            ('https://user:pass@app.example.invalid/','GET','document'),
            ('file:///etc/passwd','GET','document'),
            ('https://app.example.invalid/api','POST','fetch'),
            ('https://app.example.invalid/image','GET','image')):
            route = SimpleNamespace(request=SimpleNamespace(url=url,method=method,resource_type=kind),abort=AsyncMock())
            await bridge.route(route)
            route.abort.assert_awaited_once()
        session.get.assert_not_called()
    asyncio.run(scenario())


def test_link_local_is_denied_even_with_explicit_private_targets():
    async def scenario():
        session=Mock()
        bridge=BrowserBridge(session,'http://169.254.169.254/',{'requests':5,'bytes':10,'allow_private':True})
        route=SimpleNamespace(request=SimpleNamespace(url='http://169.254.169.254/latest/meta-data',method='GET',resource_type='fetch'),abort=AsyncMock())
        await bridge.route(route)
        route.abort.assert_awaited_once(); session.get.assert_not_called()
    asyncio.run(scenario())


def test_bridge_response_budget_and_request_limit_fail_closed():
    async def scenario():
        class Response:
            status=200; headers={'Content-Type':'application/javascript'}; charset='utf-8'
            async def __aenter__(self): return self
            async def __aexit__(self,*_): pass
            async def chunks(self, size): yield b'const oversized=true;'
            @property
            def content(self): return SimpleNamespace(iter_chunked=self.chunks)
        session=Mock(); session.get.return_value=Response()
        bridge=BrowserBridge(session,'https://app.example.invalid/',{'requests':1,'bytes':5})
        route=SimpleNamespace(request=SimpleNamespace(url='https://app.example.invalid/a.js',method='GET',resource_type='script'),abort=AsyncMock(),fulfill=AsyncMock())
        await bridge.route(route); await bridge.route(route)
        assert route.abort.await_count==2 and session.get.call_count==1
        route.fulfill.assert_not_called()
        assert not bridge.scripts
        assert session.get.call_args.kwargs=={'allow_redirects':False}
    asyncio.run(scenario())


def test_browser_dom_has_distinct_policy_and_captured_js_uses_durable_analyzer():
    async def scenario():
        url = 'https://app.example.invalid/runtime.js'
        emitter = AsyncMock()
        config = {'extraction_timeout':5}
        manager = DomainManager('https://app.example.invalid')
        crawl = CrawlContext('scan',manager,emitter,config)
        analysis = ExtractorContext('scan',config,emitter)
        runtime = {'scripts':{url:'const route = "/api/public";'},'doms':[], 'rendering_status':'completed'}
        await integrate_browser_result(runtime,crawl,analysis)
        assert manager.get_js_queue_size() == 1
        engine = JSAnalysisEngine(analysis)
        engine._fetch_js_content_with_retry = AsyncMock(side_effect=AssertionError('must not refetch'))
        try:
            assert (await engine.analyze(url))['success'] is True
            receipts = [call.args[0]['data'] for call in emitter.emit.await_args_list if call.args[0]['event_type']=='asset_observation']
            assert receipts[0]['outcome']=='analyzed'
            assert receipts[0]['detector_policy'] != detector_policy(analysis)
            assert analysis.shared_state['observed_assets'][receipts[0]['asset_id']] == 'analyzed'
            assert url not in analysis.shared_state['browser_scripts']
            assert not any(row.get('asset_url')==manager.target_url for row in receipts)
            original = detector_policy(crawl,False)
            crawl.shared_state['acquisition_policy']='rendered_dom_v1'
            assert detector_policy(crawl,False) != original
        finally: await engine.cleanup()
    asyncio.run(scenario())


def test_optional_worker_launch_failure_is_visible_and_delivery_failure_stays_fatal(monkeypatch):
    async def scenario():
        config = {'browser_rendering':'on'}
        context = ExtractorContext('scan',config,AsyncMock())
        monkeypatch.setattr('asyncio.create_subprocess_exec',AsyncMock(side_effect=OSError('private info')))
        result = await run_browser_discovery('https://example.invalid',config,context)
        assert result['rendering_status']=='unavailable' and result['rendering_limited']
        assert 'private info' not in str(result)
        context = ExtractorContext('scan',config,AsyncMock())
        context.event_emitter.emit.side_effect = DeliveryPending('offline')
        with pytest.raises(DeliveryPending): await run_browser_discovery('https://example.invalid',config,context)
    asyncio.run(scenario())


def test_supervisor_cancellation_kills_owned_worker(monkeypatch):
    async def scenario():
        config = {'browser_rendering':'on'}
        context = ExtractorContext('scan',config,AsyncMock())
        process = SimpleNamespace(pid=987654321,stdin=Mock(),stdout=Mock(),wait=AsyncMock())
        process.stdin.drain=AsyncMock()
        process.stdout.readline=AsyncMock(side_effect=lambda: asyncio.sleep(100))
        # AsyncMock's nested awaitable must itself be awaited to simulate read.
        async def blocked(): await asyncio.sleep(100)
        process.stdout.readline=blocked
        monkeypatch.setattr('asyncio.create_subprocess_exec',AsyncMock(return_value=process))
        kill = Mock(); monkeypatch.setattr('os.killpg',kill)
        original_process=__import__('psutil').Process
        def owned_process(pid=None):
            if pid == process.pid: raise __import__('psutil').NoSuchProcess(pid)
            return original_process(pid)
        monkeypatch.setattr('agent.browser_rendering.psutil.Process',owned_process)
        task=asyncio.create_task(run_browser_discovery('https://example.invalid',config,context))
        await asyncio.sleep(.05); task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        kill.assert_called_once(); process.wait.assert_awaited_once()
    asyncio.run(scenario())


@pytest.mark.parametrize('reason', ['timeout', 'memory_limit'])
def test_supervisor_exhausted_budgets_close_worker_and_preserve_http_fallback(monkeypatch, reason):
    async def scenario():
        process=SimpleNamespace(pid=987654321,stdin=Mock(),stdout=Mock(),wait=AsyncMock())
        process.stdin.drain=AsyncMock()
        async def blocked(): await asyncio.sleep(100)
        process.stdout.readline=blocked
        monkeypatch.setattr('asyncio.create_subprocess_exec',AsyncMock(return_value=process))
        kill=Mock();monkeypatch.setattr('os.killpg',kill)
        original_process=__import__('psutil').Process
        root=SimpleNamespace(children=lambda **_:[],is_running=lambda:True,
                             memory_info=lambda:SimpleNamespace(rss=2*1024*1024 if reason=='memory_limit' else 0))
        monkeypatch.setattr('agent.browser_rendering.psutil.Process',lambda pid=None:root if pid==process.pid else original_process(pid))
        context=ExtractorContext('scan',{},AsyncMock())
        result=await run_browser_discovery('https://example.invalid',{'browser_rendering':'on','browser_timeout':3 if reason=='memory_limit' else 1,'browser_memory_mb':1},context)
        assert result['rendering_reason']==reason and result['rendering_limited'] is True
        kill.assert_called_once();process.wait.assert_awaited_once()
    asyncio.run(scenario())


@pytest.mark.skipif(os.environ.get('LHX_TEST_BROWSER')!='1', reason='Requires installed sandboxed Chromium; set LHX_TEST_BROWSER=1')
def test_real_headless_browser_discovers_lazy_chunks_blocks_actions_and_exits_cleanly():
    async def scenario():
        calls=Counter()
        async def resource(request):
            calls[request.path]+=1
            assert 'Authorization' not in request.headers and 'Cookie' not in request.headers
            if request.path=='/':
                return web.Response(text='''<html><body><script>
                  setTimeout(()=>{ const s=document.createElement('script');
                    s.src='/runtime';document.body.appendChild(s);},100);
                  fetch('/api/public'); fetch('/forbidden',{method:'POST'});
                  const f=document.createElement('iframe');f.src='/redirect';document.body.appendChild(f);
                </script></body></html>''',content_type='text/html')
            if request.path=='/runtime':
                return web.Response(text='const endpoint="/api/runtime";',content_type='application/javascript')
            if request.path=='/redirect': raise web.HTTPFound('http://169.254.169.254/latest/meta-data')
            return web.json_response({'ok':True})
        app=web.Application();app.router.add_route('*','/{tail:.*}',resource)
        runner=web.AppRunner(app);await runner.setup()
        site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
        target=f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
        context=ExtractorContext('scan',{},AsyncMock())
        try:
            result=await run_browser_discovery(target,{'browser_rendering':'on','allow_private_targets':True,'browser_max_pages':1,'browser_timeout':30,'browser_settle_ms':500},context)
            assert result['rendering_status']=='completed', result
            assert target+'runtime' in result['scripts']
            assert target+'api/public' in result['endpoints']
            assert calls['/forbidden']==0 and result['rendering_limited']
            assert result['rendered_pages']==1
            frames=[call.args[0]['data'] for call in context.event_emitter.emit.await_args_list]
            assert frames[0]['rendering_status']=='running' and frames[-1]['rendering_status']=='completed'
            assert all('scripts' not in frame for frame in frames)
        finally: await runner.cleanup()
    asyncio.run(scenario())

"""Complete local scans using real HTTP, Chromium, detection and persistence."""
import asyncio
import os
import uuid
from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from agent import orchestrator
from agent.state_manager import StateManager


@pytest.mark.skipif(os.environ.get('LHX_TEST_BROWSER') != '1', reason='Requires sandboxed Chromium')
@pytest.mark.parametrize('kind', ['static', 'spa', 'slow_partial', 'blocked'])
def test_complete_target_scan(monkeypatch, tmp_path, kind):
    async def scenario():
        seen = []
        async def resource(request):
            seen.append(request.path)
            if kind == 'blocked': return web.Response(status=403)
            if request.path == '/slow':
                await asyncio.sleep(1)
                return web.Response(text='<html>Slow page</html>', content_type='text/html')
            if request.path == '/app.js':
                key = 'AKIA' + 'E2Z7Q9B3X8C1M5N6'
                return web.Response(text=f'const aws={{configure() {{}}}}; const awsAccessKey = "{key}";\naws.configure({{accessKey:awsAccessKey}});\nfetch("/api/items");', content_type='application/javascript')
            if request.path == '/api/items': return web.json_response({'items':[]})
            html = ('<html><body><script>setTimeout(()=>{let s=document.createElement("script");s.src="/app.js";document.body.appendChild(s)},100)</script></body></html>'
                    if kind == 'spa' else '<html><body><script src="/app.js"></script>' + ('<a href="/slow">Slow</a>' if kind == 'slow_partial' else '') + '</body></html>')
            return web.Response(text=html, content_type='text/html')
        app = web.Application(); app.router.add_get('/{tail:.*}', resource)
        server = web.AppRunner(app); await server.setup()
        site = web.TCPSite(server, '127.0.0.1', 0); await site.start()
        target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
        emitter = AsyncMock()
        config = {'allow_private_targets':True, 'browser_rendering':'on', 'browser_max_pages':1,
                  'browser_settle_ms':500, 'browser_timeout':20, 'crawler_delay':0,
                  'crawl_timeout':.4 if kind == 'slow_partial' else 5, 'max_pages':3,
                  'request_timeout':1, 'scan_timeout':45, 'extraction_timeout':5}
        scan = orchestrator.ScanOrchestrator(target, config, emitter, scan_id=str(uuid.uuid4()),
                    state_manager=StateManager(str(tmp_path)))
        # Local fixtures do not need public certificate-transparency discovery.
        scan._run_discovery_phase = AsyncMock(return_value=[])
        try:
            if kind == 'blocked':
                with pytest.raises(orchestrator.CrawlUnavailable): await asyncio.wait_for(scan.start_scan(), 50)
            else:
                await asyncio.wait_for(scan.start_scan(), 50)
            events = [call.args[0] for call in emitter.emit.await_args_list]
            kinds = [event['event_type'] for event in events]
            if kind == 'blocked':
                assert any(kind in kinds for kind in ('scan_failed', 'scan_error')) and 'scan_completed' not in kinds
            else:
                assert scan.status == orchestrator.ScanStatus.COMPLETED, kinds
                assert kinds.count('scan_completed') == 1 and 'scan_failed' not in kinds
                assert scan.metrics.successful_analyses == 1
                assert 'secret_found' in kinds and '/app.js' in seen
                assert scan.metrics.analysis_limited is (kind == 'slow_partial')
            assert scan._crawler is None  # Cleanup releases crawler/session references.
        finally: await server.cleanup()
    asyncio.run(scenario())

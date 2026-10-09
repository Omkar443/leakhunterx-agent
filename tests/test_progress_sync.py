import asyncio
import httpx
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from agent import orchestrator as module
from agent.lhx_agent import PhaseConsoleInterceptor
from agent.scan_control import monitor_assignment


@pytest.mark.parametrize('failure', [RuntimeError, asyncio.CancelledError])
def test_interrupted_phase_never_reports_completion(monkeypatch, failure):
    emitter = AsyncMock()
    monkeypatch.setattr(module, 'emit_event', emitter)
    runner = SimpleNamespace(_phase_start_times={}, _context=object(), scan_id='scan')
    async def scenario():
        with pytest.raises(failure):
            async with module.ScanOrchestrator._phase_tracker(runner, 'crawling'):
                raise failure()
    asyncio.run(scenario())
    assert [call.kwargs['event_type'] for call in emitter.await_args_list] == ['phase_started', 'phase_failed']


def test_crawl_timeout_is_distinct_from_global_timeout(monkeypatch):
    async def blocked(_):
        await asyncio.Event().wait()
    monkeypatch.setattr(module, 'emit_event', AsyncMock())
    runner = SimpleNamespace(_context=object(), _crawler=SimpleNamespace(crawl=blocked),
        _crawl_context=object(), _crawl_timeout=.01, _safe_emit_phase=AsyncMock())
    async def scenario():
        with pytest.raises(module.CrawlTimeout):
            await module.ScanOrchestrator._discover_js_urls(runner)
        assert runner._crawl_task.done()
    asyncio.run(scenario())


def test_timeout_failure_is_visible_once_even_when_transport_fails(capsys):
    transport = SimpleNamespace(emit=AsyncMock(side_effect=httpx.ConnectError('offline')))
    console = PhaseConsoleInterceptor(transport)
    async def scenario():
        with pytest.raises(httpx.ConnectError):
            await console.emit({'event_type': 'scan_failed', 'data': {'reason': 'crawl_timeout'}})
        transport.emit.side_effect = None
        await console.emit({'event_type': 'scan_progress', 'data': {'phase': 'analysis', 'current': 10, 'total': 10}})
        await console.emit({'event_type': 'scan_completed', 'data': {}})
    asyncio.run(scenario())
    output = capsys.readouterr().out
    assert output.count('Crawling timed out') == 1
    assert 'Scan finished' not in output and '100%' not in output


@pytest.mark.parametrize('status,reason', [('failed', 'runtime_limit'), ('cancelled', 'cancelled')])
def test_backend_terminal_state_cancels_actual_work_and_reports_reason(status, reason):
    async def scenario():
        task = asyncio.create_task(asyncio.Event().wait())
        client = SimpleNamespace(get=AsyncMock(return_value=httpx.Response(200,
            request=httpx.Request('GET', 'https://backend.invalid'),
            json={'scan_id': 'scan', 'status': status, 'reason': reason})))
        runner, console = SimpleNamespace(), SimpleNamespace(show_terminal=lambda *a, **kw: None)
        await monitor_assignment(client, 'scan', task, runner, console, interval=.001)
        with pytest.raises(asyncio.CancelledError): await task
        assert runner._backend_terminal_status == status
    asyncio.run(scenario())


def test_network_loss_and_wrong_assignment_never_cancel_work():
    async def scenario():
        task = asyncio.create_task(asyncio.Event().wait())
        request = httpx.Request('GET', 'https://backend.invalid')
        client = SimpleNamespace(get=AsyncMock(side_effect=[
            httpx.ConnectError('offline'), httpx.Response(200, request=request,
                json={'scan_id': 'other', 'status': 'failed'}),
            httpx.Response(200, request=request, json={'scan_id': 'scan', 'status': 'running'})]))
        runner, console = SimpleNamespace(), SimpleNamespace(show_terminal=AsyncMock())
        monitor = asyncio.create_task(monitor_assignment(client, 'scan', task, runner, console, interval=.001))
        while client.get.await_count < 3: await asyncio.sleep(.001)
        assert not task.done() and not hasattr(runner, '_backend_terminal_status')
        monitor.cancel(); task.cancel()
        await asyncio.gather(monitor, task, return_exceptions=True)
    asyncio.run(scenario())

import asyncio
import inspect
from unittest.mock import AsyncMock, Mock
import pytest
from aiohttp import web
from agent import orchestrator
from agent.domain_manager import DomainManager
from agent.js.extractor_context import ExtractorContext
from agent.js import js_analyzer
from agent.lhx_agent import PhaseConsoleInterceptor


def test_real_downloader_handles_empty_scripts_and_reports_safe_failure_codes():
    async def scenario():
        async def resource(request):
            name = request.match_info['name']
            if name == 'empty': return web.Response(text='', content_type='application/javascript')
            if name == 'no-content': return web.Response(status=204)
            if name == 'denied': return web.Response(status=403, text='private response body')
            if name == 'missing': return web.Response(status=404)
            if name == 'html': return web.Response(text='<html>challenge</html>', content_type='text/html')
            if name == 'large': return web.Response(text='a'*500, content_type='application/javascript')
            return web.Response(body=b'const x = 1;', headers={'Content-Type':'application/javascript; charset=unknown-encoding'})
        app = web.Application(); app.router.add_get('/{name}', resource)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0); await site.start()
        target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
        emitter = AsyncMock()
        config = {'allow_private_targets':True, 'max_js_file_size':100}
        engine = js_analyzer.JSAnalysisEngine(ExtractorContext('scan', config, emitter))
        try:
            for name in ('empty', 'no-content', 'charset'):
                result = await engine.analyze(target + name)
                assert result['success'], result
            for name, reason in [('denied','access_denied'), ('missing','resource_missing'), ('html','invalid_content'), ('large','response_limit')]:
                result = await engine.analyze(target + name)
                assert not result['success'] and result['failure_reason'] == reason
                assert 'private response body' not in str(result)
            session = await engine.http_manager.get_session()
            # The runtime negotiates supported codecs; no forced Brotli header.
            assert 'Accept-Encoding' not in session.headers
        finally:
            await engine.cleanup(); await runner.cleanup()
    asyncio.run(scenario())


def test_extraction_timeout_never_successfully_deduplicates_an_incomplete_file():
    async def scenario():
        engine = js_analyzer.JSAnalysisEngine(ExtractorContext('scan', {}, AsyncMock()))
        engine.secret_scanner.scan = AsyncMock(side_effect=[TimeoutError(), None])
        try:
            with pytest.raises(TimeoutError):
                await engine.analyze_js_content('https://example.invalid/a.js', 'const x = 1;')
            assert not engine.context.shared_state.get('content_hashes')
            result = await engine.analyze_js_content('https://example.invalid/b.js', 'const x = 1;')
            assert result.success and not result.metadata.get('duplicate_skipped')
            assert engine.secret_scanner.scan.await_count == 2
        finally: await engine.cleanup()
    asyncio.run(scenario())


def test_retry_and_extraction_budgets_fit_the_task_deadline():
    config = {'analysis_timeout':30, 'js_fetch_timeout':30, 'js_fetch_retries':3, 'extraction_timeout':60}
    assert js_analyzer.fetch_deadline(config) == 120
    assert js_analyzer.analysis_deadline(config) == 185
    assert js_analyzer.analysis_deadline({**config, 'analysis_timeout':240}) == 240


def test_transient_server_error_recovers_before_coherent_task_deadline():
    async def scenario():
        attempts = []
        async def script(request):
            attempts.append(True)
            if len(attempts) == 1:
                return web.Response(status=503)
            return web.Response(text='const x = 1;', content_type='application/javascript')
        app = web.Application(); app.router.add_get('/retry.js', script)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0); await site.start()
        target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/retry.js'
        config = {'allow_private_targets':True, 'analysis_timeout':1, 'js_fetch_timeout':3,
                  'js_fetch_retries':2, 'extraction_timeout':1}
        engine = js_analyzer.JSAnalysisEngine(ExtractorContext('scan', config, AsyncMock()))
        manager = orchestrator.AnalysisTaskManager(1)
        try:
            result, error = await manager.submit(engine.analyze(target), target, timeout=js_analyzer.analysis_deadline(config))
            assert error is None and result['success']
            assert len(attempts) == 2
        finally: await engine.cleanup(); await runner.cleanup()
    asyncio.run(scenario())


def test_failed_analysis_sends_final_real_counts_and_still_fails(monkeypatch):
    async def scenario():
        emit = AsyncMock(); monkeypatch.setattr(orchestrator, 'emit_event', emit)
        scan = orchestrator.ScanOrchestrator('https://example.invalid', {}, AsyncMock(), operator_id='test', state_manager=Mock())
        scan._context = object(); scan._safe_emit_phase = AsyncMock()
        scan._domain_manager = DomainManager('https://example.invalid')
        for name in ('slow.js', 'ok.js', 'denied.js'):
            scan._domain_manager.add_discovered(f'https://example.invalid/{name}', 0)
        async def analyze(url):
            if url.endswith('slow.js'): await asyncio.sleep(.04)
            if url.endswith('denied.js'): return {'success':False, 'failure_reason':'access_denied', 'http_status':403}
            return {'success':True}
        scan._analyzer = AsyncMock(); scan._analyzer.analyze.side_effect = analyze
        scan._task_manager = orchestrator.AnalysisTaskManager(3)
        scan._process_analysis_result = AsyncMock(return_value=(0, 0))
        with pytest.raises(orchestrator.AnalysisIncomplete) as error:
            await scan._analyze_js_files()
        assert orchestrator.safe_failure_reason(error.value) == 'analysis_incomplete'
        progress = [call.kwargs['data'] for call in emit.await_args_list if call.kwargs['event_type'] == 'scan_progress' and call.kwargs['data'].get('total_files') == 3]
        assert progress[0]['processed_files'] == 1
        assert progress[-1]['processed_files'] == progress[-1]['total_files'] == 3
        assert progress[-1]['successful_analyses'] == 2
        assert progress[-1]['analysis_errors'] == {'access_denied':1}
        assert not scan._task_manager.active_tasks
    asyncio.run(scenario())


def test_cancelled_queued_submission_closes_unstarted_coroutine():
    async def scenario():
        manager = orchestrator.AnalysisTaskManager(1)
        await manager.semaphore.acquire()
        coro = asyncio.sleep(0)
        task = asyncio.create_task(manager.submit(coro, 'https://example.invalid/a.js'))
        await asyncio.sleep(0); task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert inspect.getcoroutinestate(coro) == inspect.CORO_CLOSED
        manager.semaphore.release()
    asyncio.run(scenario())


def test_cli_reports_actual_counts_without_leaking_arbitrary_error_text(capsys):
    async def scenario():
        console = PhaseConsoleInterceptor(AsyncMock())
        await console.emit({'event_type':'analysis_resource_failed','data':{'reason':'access_denied','http_status':403,'js_url':'secret-value'}})
        await console.emit({'event_type':'scan_error','data':{'reason':'analysis_incomplete','metrics':{'processed_js_files':45,'total_js_files':45,'successful_analyses':35,'failed_analyses':8,'timed_out_analyses':2}}})
    asyncio.run(scenario())
    output = capsys.readouterr().out
    assert 'HTTP 403' in output and '35 successful, 8 failed, 2 timed out' in output
    assert 'secret-value' not in output

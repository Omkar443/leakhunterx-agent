import asyncio
from collections import Counter
from unittest.mock import AsyncMock, Mock
import pytest
from aiohttp import web
from agent.asset_coverage import asset_id, canonical_asset_url, detector_policy, validated_rechecks, recheck_documents
from agent.crawler import CrawlContext, CompleteCrawler
from agent.domain_manager import DomainManager
from agent.js.extractor_context import ExtractorContext
from agent.js.js_analyzer import JSAnalysisEngine
from agent.events.outbox import DeliveryPending
from agent import orchestrator


def test_manifest_validation_keeps_exact_queries_and_rejects_foreign_urls():
    manager = DomainManager('https://app.example.invalid')
    manifest = {'assets':[
        {'url':'https://APP.example.invalid:443/a.js?version=One#fragment', 'kind':'javascript'},
        {'url':'https://app.example.invalid/a.js?version=One', 'kind':'javascript'},
        {'url':'https://app.example.invalid/a.js?version=one', 'kind':'javascript'},
        {'url':'https://other.invalid/a.js', 'kind':'javascript'},
        {'url':'https://user:pass@app.example.invalid/a.js', 'kind':'javascript'},
        {'url':'file:///etc/passwd', 'kind':'document'}, None]}
    assets = validated_rechecks(manifest, manager.is_in_scope)
    assert len(assets) == 2 and assets[0]['url'].endswith('?version=One')
    assert asset_id(assets[0]['url']) != asset_id(assets[1]['url'])
    assert canonical_asset_url('https://app.example.invalid') == 'https://app.example.invalid/'


def test_real_previous_asset_checks_download_hidden_files_once_and_record_truth():
    async def scenario():
        calls = Counter()
        async def resource(request):
            name = request.match_info['name']; calls[name] += 1
            if name == 'missing.js': return web.Response(status=404)
            if name == 'redirect.js': raise web.HTTPFound('/clean.js')
            if name == 'challenge.js': return web.Response(text='<html>cf-chl-challenge</html>', content_type='text/html')
            if name == 'home': return web.Response(text='<html>No scripts here</html>', content_type='text/html')
            if name == 'login': return web.Response(text='<input type="password">', content_type='text/html')
            if name == 'hidden': return web.Response(text='<html>Clean content</html>', content_type='text/html')
            return web.Response(text='const apiPath = "/api/v1/users";', content_type='application/javascript')
        app = web.Application(); app.router.add_get('/{name}', resource)
        runner = web.AppRunner(app); await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0); await site.start()
        target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
        config = {'allow_private_targets':True, 'crawler_delay':0, 'max_pages':1, 'max_depth':1}
        manager = DomainManager(target); manager.add_seed_urls([target+'home'])
        emitter = AsyncMock(); crawl_context = CrawlContext('scan', manager, emitter, config)
        engine = JSAnalysisEngine(ExtractorContext('scan', config, emitter))
        engine.context.scope_check = manager.is_in_scope
        try:
            await CompleteCrawler(manager, config).crawl(crawl_context)
            assert manager.get_js_queue_size() == 0  # Target does not rediscover the historical file.
            assets = validated_rechecks({'assets':[{'url':target+'clean.js','kind':'javascript'}]*2}, manager.is_in_scope)
            for item in assets: assert (await engine.analyze(item['url']))['success']
            for name in ('missing.js','challenge.js','redirect.js'):
                await engine.analyze(target+name)
            await recheck_documents(crawl_context, [{'url':target+'hidden','kind':'document'}, {'url':target+'login','kind':'document'}])
            receipts = [call.args[0]['data'] for call in emitter.emit.await_args_list if call.args[0]['event_type'] == 'asset_observation']
            outcomes = {row['asset_url']:row['outcome'] for row in receipts}
            assert outcomes[target+'clean.js'] == 'analyzed' and calls['clean.js'] == 2  # One exact check, one redirected request.
            assert outcomes[target+'missing.js'] == outcomes[target+'challenge.js'] == 'unavailable'
            assert outcomes[target+'redirect.js'] in ('duplicate','redirected')
            assert outcomes[target+'hidden'] == 'analyzed' and outcomes[target+'login'] == 'unavailable'
            assert all(row.get('content_sha256') for row in receipts if row['outcome'] == 'analyzed')
            assert all(row['detector_policy'] == detector_policy(engine.context, row['kind'] == 'javascript') for row in receipts)
            before = calls['hidden']
            await recheck_documents(crawl_context, [{'url':target+'hidden','kind':'document'}])
            assert calls['hidden'] == before
        finally:
            await engine.cleanup(); await runner.cleanup()
    asyncio.run(scenario())


def test_ignore_rule_or_detector_mode_change_prevents_compatible_resolution(tmp_path):
    context = ExtractorContext('scan', {}, AsyncMock())
    initial = detector_policy(context)
    context.config['aggressive_secrets'] = False
    assert detector_policy(context) != initial
    ignore = tmp_path / '.lhxignore'; ignore.write_text('path:assets/*\n')
    changed = ExtractorContext('scan', {'ignore_file':str(ignore)}, AsyncMock())
    assert detector_policy(changed) != initial


def test_receipt_delivery_failure_is_fatal_not_verified():
    async def scenario():
        emitter = AsyncMock(); emitter.emit.side_effect = DeliveryPending('offline')
        engine = JSAnalysisEngine(ExtractorContext('scan', {}, emitter))
        from agent.js.js_analyzer import JSAnalysisResult
        engine.analyze_js_content = AsyncMock(return_value=JSAnalysisResult(
            js_url='https://app.example.invalid/a.js', endpoints=[], secrets=[], content_hash='b'*64,
            file_size=10, analysis_time=0, confidence_score=1, success=True, http_status=200))
        engine._fetch_final_urls['https://app.example.invalid/a.js'] = 'https://app.example.invalid/a.js'
        try:
            with pytest.raises(DeliveryPending): await engine.analyze('https://app.example.invalid/a.js')
            assert not engine.context.shared_state.get('observed_assets')
        finally: await engine.cleanup()
    asyncio.run(scenario())


def test_optional_missing_previous_asset_does_not_fail_an_otherwise_valid_scan(monkeypatch):
    async def scenario():
        monkeypatch.setattr(orchestrator, 'emit_event', AsyncMock())
        job = orchestrator.ScanOrchestrator('https://example.invalid', {}, AsyncMock(), operator_id='test', state_manager=Mock())
        job._context = object(); job._safe_emit_phase = AsyncMock()
        job._domain_manager = DomainManager('https://example.invalid')
        url = 'https://example.invalid/old.js'; job._domain_manager.add_discovered(url, 0, resource_type='javascript')
        job._optional_recheck_urls.add(url)
        job._analyzer = AsyncMock(); job._analyzer.analyze.return_value = {'success':False,'failure_reason':'resource_missing'}
        job._task_manager = orchestrator.AnalysisTaskManager(1)
        await job._analyze_js_files()
        assert job.metrics.processed_js_files == 1 and job.metrics.failed_analyses == 1
        assert job.metrics.analysis_limited is True
        assert not job._task_manager.active_tasks
    asyncio.run(scenario())


def test_unavailable_document_and_deferred_checks_reach_report_coverage():
    target = 'https://example.invalid/previous'
    job = orchestrator.ScanOrchestrator('https://example.invalid', {}, AsyncMock(), operator_id='test', state_manager=Mock(),
        recheck_assets={'assets':[{'url':target,'kind':'document'}], 'deferred_assets':0})
    job._recheck_assets = [{'url':target,'kind':'document'}]
    job._context = ExtractorContext(job.scan_id, {}, AsyncMock())
    job._crawl_context = CrawlContext(job.scan_id, DomainManager('https://example.invalid'), AsyncMock())
    job._record_recheck_coverage()
    assert job.metrics.analysis_limited
    job.metrics.analysis_limited = False
    job._crawl_context.shared_state['observed_assets'] = {asset_id(target):'analyzed'}
    job._record_recheck_coverage()
    assert not job.metrics.analysis_limited
    job._recheck_manifest['deferred_assets'] = 1
    job._record_recheck_coverage()
    assert job.metrics.analysis_limited

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from agent.utils.pipeline import PipelineError, ScanResolver, bounded_text, guarded_get, normalize_target
from agent import orchestrator as scan_module
from agent.crawler import CompleteCrawler, CrawlContext
from agent.domain_manager import DomainManager
from agent.js.extractor_context import ExtractorContext
from agent.js.js_analyzer import JSAnalysisEngine


def test_target_rejects_credentials_and_unsafe_schemes():
    for target in ("file:///etc/passwd", "https://user:pass@example.test/", "https://example.test\\@other.test"):
        with pytest.raises(ValueError):
            normalize_target(target)
    assert normalize_target("example.test") == "https://example.test/"


def test_redirect_scope_is_checked_before_second_request():
    class Response:
        status = 302
        headers = {"Location": "https://other.test/secret"}
        def release(self):
            pass

    class Session:
        def __init__(self):
            self.urls = []
        async def get(self, url, **kwargs):
            self.urls.append(url)
            assert kwargs["allow_redirects"] is False
            return Response()

    async def scenario():
        session = Session()
        with pytest.raises(PipelineError):
            async with guarded_get(session, "https://example.test/", in_scope=lambda url: url.startswith("https://example.test/")):
                pass
        assert session.urls == ["https://example.test/"]
    asyncio.run(scenario())


def test_streamed_page_limit_is_enforced():
    class Stream:
        async def iter_chunked(self, size):
            yield b"a" * 3
            yield b"b" * 3

    async def scenario():
        response = SimpleNamespace(headers={}, content=Stream(), charset="utf-8")
        with pytest.raises(PipelineError):
            await bounded_text(response, limit=5)
    asyncio.run(scenario())


def test_resolver_rejects_private_destination_before_connecting():
    async def scenario():
        resolver = ScanResolver()
        try:
            with patch.object(resolver.resolver, "resolve", new_callable=AsyncMock) as resolve:
                resolve.return_value = [{"host": "169.254.169.254"}]
                with pytest.raises(PipelineError):
                    await resolver.resolve("example.test", 443)
                resolver.allow_private = True
                with pytest.raises(PipelineError):
                    await resolver.resolve("example.test", 443)
        finally:
            await resolver.close()
    asyncio.run(scenario())


def test_script_resources_are_queued_for_analysis_even_without_js_suffix():
    manager = DomainManager("https://example.test/")
    accepted, _ = manager.add_discovered("https://example.test/assets/runtime", 0, resource_type="javascript")
    assert accepted
    assert manager.get_js_queue_size() == 1
    assert not manager.has_targets()


def test_pause_gate_blocks_crawl_until_resumed():
    async def scenario():
        context = CrawlContext("scan", object(), AsyncMock())
        assert not await context.check_pause_stop()
        context.should_pause.clear()
        pending = asyncio.create_task(context.check_pause_stop())
        await asyncio.sleep(0.02)
        assert not pending.done()
        context.should_pause.set()
        assert not await asyncio.wait_for(pending, 1)
    asyncio.run(scenario())


def test_artifact_batch_failure_requeues_without_lock_deadlock():
    async def scenario():
        scan = scan_module.ScanOrchestrator.__new__(scan_module.ScanOrchestrator)
        scan._artifact_lock = asyncio.Lock()
        scan._batch_emit_lock = asyncio.Lock()
        scan._seen_artifact_hashes = set()
        scan._current_artifact_batch = []
        scan._batch_size = 1
        scan._batch_counter = 0
        scan.metrics = scan_module.ScanMetrics()
        scan.scan_id = "scan"
        scan.operator_id = "operator"
        scan._context = object()
        with patch.object(scan_module, "emit_event", new_callable=AsyncMock) as emit:
            emit.side_effect = RuntimeError("storage unavailable")
            with pytest.raises(RuntimeError):
                await asyncio.wait_for(scan._add_artifact({"type": "endpoint", "source_url": "https://example.test/a.js", "sha256": "digest"}), 1)
            assert len(scan._current_artifact_batch) == 1
            emit.side_effect = None
            await scan._flush_artifacts()
            assert not scan._current_artifact_batch
            assert scan.metrics.artifacts_emitted == 1
    asyncio.run(scenario())


def test_string_endpoints_and_secret_occurrences_survive_processing():
    async def scenario():
        scan = scan_module.ScanOrchestrator.__new__(scan_module.ScanOrchestrator)
        artifacts = []
        async def collect(artifact):
            artifacts.append(artifact)
            return True
        scan._add_artifact = collect
        scan.scan_id = "scan"
        scan.operator_id = "operator"
        endpoints, secrets = await scan._process_analysis_result("https://example.test/app.js", {
            "endpoints": ["/api/items"],
            "secrets": [
                {"type": "key", "line_number": 1, "fingerprint": "one"},
                {"type": "key", "line_number": 2, "fingerprint": "two"},
            ],
        })
        assert (endpoints, secrets) == (1, 2)
        assert len({item["sha256"] for item in artifacts}) == 3
    asyncio.run(scenario())


def test_completion_delivery_failure_does_not_mark_scan_successful():
    async def scenario():
        scan = scan_module.ScanOrchestrator.__new__(scan_module.ScanOrchestrator)
        scan._finalizing = False
        scan.status = scan_module.ScanStatus.RUNNING
        scan.metrics = scan_module.ScanMetrics()
        scan._context = object()
        scan.scan_id = "scan"
        scan.operator_id = "operator"
        scan.agent_version = "test"
        scan.agent_id = "agent"
        scan._batch_counter = 0
        scan._seen_summary_hash = None
        scan.emitter = AsyncMock()
        scan.state_manager = None
        scan._safe_emit_phase = AsyncMock()
        with patch.object(scan_module, "emit_event", new_callable=AsyncMock) as emit:
            async def reject_completion(*args, **kwargs):
                if kwargs["event_type"] == "scan_completed":
                    raise PipelineError("Backend acknowledgement unavailable")
            emit.side_effect = reject_completion
            with pytest.raises(PipelineError):
                await scan._complete_scan()
            assert scan.status == scan_module.ScanStatus.RUNNING
            assert not scan._finalizing
    asyncio.run(scenario())


def test_local_html_to_javascript_to_evidence_pipeline():
    from aiohttp import web

    async def scenario():
        key = "AKIA" + "E2Z7Q9B3X8C1M5N6"
        html = f'<html><body><script>const accessKey = "{key}";\naws.configure({{accessKey}});</script><script src="/app.js"></script></body></html>'
        js = 'fetch("/api/items");\n' + ('function work() { return "/api/items"; }\n' * 4)

        async def home(request):
            return web.Response(text=html, content_type="text/html")

        async def script(request):
            return web.Response(text=js, content_type="application/javascript")

        app = web.Application()
        app.router.add_get("/", home)
        app.router.add_get("/app.js", script)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        target = f"http://127.0.0.1:{port}/"
        emitter = AsyncMock()
        config = {"allow_private_targets": True, "verify_ssl": True, "crawler_delay": 0, "max_pages": 2, "max_depth": 1}
        manager = DomainManager(target, max_depth=1)
        manager.add_seed_urls([target])
        context = CrawlContext("scan", manager, emitter, config)
        crawler = CompleteCrawler(manager, config)
        try:
            await asyncio.wait_for(crawler.crawl(context), 15)
            assert manager.get_js_queue_size() >= 1
            event_types = [call.args[0]["event_type"] for call in emitter.emit.call_args_list]
            assert "secret_found" in event_types
            serialized = str([call.args[0] for call in emitter.emit.call_args_list])
            assert key not in serialized

            analysis_context = ExtractorContext("scan", config, emitter)
            analysis_context.scope_check = manager.is_in_scope
            engine = JSAnalysisEngine(analysis_context)
            try:
                result = await asyncio.wait_for(engine.analyze(target + "app.js"), 15)
                assert result["success"] is True
                assert result["endpoints"]
            finally:
                await engine.cleanup()
        finally:
            await runner.cleanup()

    asyncio.run(scenario())

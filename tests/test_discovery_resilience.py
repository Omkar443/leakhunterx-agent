import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from agent import discovery, orchestrator
from agent.lhx_agent import PhaseConsoleInterceptor


def test_optional_oversized_source_is_skipped_with_coverage_warning(monkeypatch):
    async def scenario():
        engine = discovery.DiscoveryEngine('example.invalid')
        released = []
        @asynccontextmanager
        async def response(*args, **kwargs):
            try:
                yield SimpleNamespace(status=200, headers={'Content-Length':str(10*1024*1024)}, history=[])
            finally:released.append(True)
        monkeypatch.setattr(discovery, 'guarded_get', response)
        assert await engine._fetch_with_retry('https://crt.sh/?output=json') is None
        assert engine.coverage_limited and engine.discovery_metrics['errors'] == 1
        assert released == [True]
    asyncio.run(scenario())


@pytest.mark.parametrize('limited', [True, False])
def test_optional_discovery_unavailable_still_runs_required_stages(monkeypatch, limited):
    async def scenario():
        emit = AsyncMock(); monkeypatch.setattr(orchestrator, 'emit_event', emit)
        lookup = AsyncMock(side_effect=discovery.DiscoveryUnavailable('optional source unavailable')) if limited else AsyncMock(return_value=[])
        monkeypatch.setattr(orchestrator, 'discover_subdomains_from_url', lookup)
        scan = orchestrator.ScanOrchestrator('https://example.invalid', {}, AsyncMock(), 'test')
        scan._context = object()
        scan._safe_emit_phase = AsyncMock()
        scan._discover_js_urls = AsyncMock(); scan._analyze_js_files = AsyncMock()
        scan._flush_artifacts = AsyncMock(); scan._complete_scan = AsyncMock()
        await scan._run_scan_logic()
        scan._discover_js_urls.assert_awaited_once(); scan._analyze_js_files.assert_awaited_once()
        scan._complete_scan.assert_awaited_once()
        completed = next(call.kwargs['data'] for call in emit.await_args_list if call.kwargs['event_type'] == 'discovery_completed')
        assert completed.get('discovery_limited', False) is limited
    asyncio.run(scenario())


def test_required_work_errors_and_programming_errors_are_not_hidden(monkeypatch):
    async def scenario():
        monkeypatch.setattr(orchestrator, 'emit_event', AsyncMock())
        monkeypatch.setattr(orchestrator, 'discover_subdomains_from_url', AsyncMock(side_effect=RuntimeError('programming defect')))
        scan = orchestrator.ScanOrchestrator('https://example.invalid', {}, AsyncMock(), 'test')
        scan._context = object(); scan._safe_emit_phase = AsyncMock(); scan._discover_js_urls = AsyncMock()
        with pytest.raises(RuntimeError):await scan._run_scan_logic()
        scan._discover_js_urls.assert_not_awaited()
    asyncio.run(scenario())
    assert orchestrator.safe_failure_reason(RuntimeError('No target pages were fetched successfully')) == 'target_unreachable'
    assert orchestrator.safe_failure_reason(ValueError('secret-value')) == 'scan_failed'


def test_cli_shows_safe_error_stage_without_printing_exception_text(capsys):
    console = PhaseConsoleInterceptor(AsyncMock())
    console.show_terminal('failed', 'scan_failed', error_type='PipelineError', phase='discovery')
    output = capsys.readouterr().out
    assert 'Stage: discovery' in output and 'PipelineError' in output
    console = PhaseConsoleInterceptor(AsyncMock())
    console.show_terminal('failed', 'secret-value', error_type='secret-value', phase='secret-value')
    assert 'secret-value' not in capsys.readouterr().out

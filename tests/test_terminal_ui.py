import asyncio
import io
import os
from unittest.mock import AsyncMock

import pytest

from agent.terminal_ui import AgentWorkspace, cells, clean, safe_url
from agent import lhx_agent


def event(kind, **data):
    return {'scan_id': 'scan-1', 'event_type': kind, 'data': data}


def view():
    result = AgentWorkspace(stream=io.StringIO(), clock=lambda: 12)
    result.color = False
    result.begin('scan-1', 'https://user:private@example.com/app?token=private#private')
    return result


def test_local_events_populate_measured_counts_and_never_store_secret_payloads():
    ui = view()
    ui.observe(event('phase_started', phase='discovery'))
    ui.observe(event('discovery_completed', discovery_limited=True))
    ui.observe(event('phase_started', phase='crawling'))
    ui.observe(event('scan_progress', phase='crawling', pages_fetched=12))
    ui.observe(event('crawling_completed', routes_discovered=421, total_js_files=420))
    ui.observe(event('phase_started', phase='analysis'))
    ui.observe(event('scan_progress', phase='analysis', processed_files=230, total_files=420,
                     successful_analyses=227, failed_analyses=3, timed_out_analyses=0))
    ui.observe(event('artifact_batch_ready', batch_index=1,
                     artifacts=[{'type': 'potential_secret', 'raw_value': 'private'},
                                {'type': 'endpoint', 'context': 'private'}]))
    frame = ui.render(150, 40)
    assert '230 / 420' in frame and '54%' in frame  # floor, never round early to 100
    assert '421 routes' in frame and '12 pages fetched' in frame
    assert '1 secret candidates' in frame and '1 endpoint candidates' in frame
    assert 'Partial' in frame and 'private' not in frame
    assert ui.stages['discovery'] == ui.stages['crawling'] == 'Complete'
    assert not any(word in frame.lower() for word in ('ai validation', 'validating', 'confirmed exposures'))
    assert 'artifacts' not in vars(ui)  # retain counts, not evidence


def test_duplicate_batches_and_stale_counts_do_not_inflate_or_regress_progress():
    ui = view()
    batch = event('artifact_batch_ready', batch_index=1, artifacts=[{'type':'potential_secret'}])
    ui.observe(batch); ui.observe(batch)
    ui.observe(event('scan_progress', phase='analysis', processed_files=20, total_files=30))
    ui.observe(event('scan_progress', phase='analysis', processed_files=10, total_files=30))
    foreign = event('scan_progress', phase='analysis', processed_files=30, total_files=30)
    foreign['scan_id'] = 'someone-else'
    ui.observe(foreign)
    assert ui.counts['secrets'] == 1 and ui.counts['processed'] == 20
    ui.observe(event('js_analysis_summary', total_secrets_found=1, total_endpoints_found=0))
    assert ui.counts['endpoints'] == 0


@pytest.mark.parametrize('status', ['failed', 'cancelled'])
def test_terminal_states_freeze_progress_and_next_scan_resets_every_counter(status):
    ui = view()
    ui.observe(event('scan_progress', phase='analysis', processed_files=2, total_files=3))
    ui.terminal(status)
    ui.observe(event('scan_completed', metrics={'processed_js_files':3, 'total_js_files':3}))
    assert ui.counts['processed'] == 2 and ui.state == status.title()
    assert ui.finished == 12
    ui.begin('scan-2', 'https://example.com/')
    assert not ui.counts and not ui.partial and ui.delivery == 'Not started'
    assert ui.finished is None and ui.state == 'Starting'


@pytest.mark.parametrize('columns,rows', [(180,40), (120,30), (100,30), (80,26), (60,24), (36,18), (20,8), (1,2)])
def test_layout_fits_terminal_without_wrapping_or_overflow(columns, rows):
    ui = view()
    ui.note('warning', 'Long message ' * 30 + '\x1b[2J')
    ui.observe(event('scan_progress', phase='analysis', processed_files=230, total_files=420))
    frame = ui.render(columns, rows)
    assert len(frame.splitlines()) <= rows - 1
    assert all(cells(line) <= max(1, columns - 1) for line in frame.splitlines())
    assert '\x1b' not in frame


def test_missing_metrics_are_unknown_and_only_known_zero_counts_show_zero():
    ui = view()
    frame = ui.render(150,40)
    assert '— secret candidates' in frame and '— analyzed successfully' in frame
    assert 'Waiting for measured resource progress' in frame
    ui.observe(event('js_analysis_summary', total_secrets_found=0, successful_analyses=0))
    assert '0 secret candidates' in ui.render(150,40)


def test_completed_zero_resource_scan_does_not_wait_for_nonexistent_progress():
    ui = view()
    ui.observe(event('scan_completed', metrics={'processed_js_files':0,'total_js_files':0,
                                               'potential_secrets':0,'discovered_endpoints':0}))
    ui.delivered()
    frame = ui.render(150,40)
    assert 'No JavaScript resources reported' in frame
    assert 'Waiting for measured resource progress' not in frame
    assert '0 secret candidates' in frame


def test_untrusted_urls_and_terminal_escape_sequences_are_not_rendered():
    assert safe_url('https://user:password@example.com:8443/path?key=secret#token') == 'https://example.com:8443/path'
    assert safe_url('https://[::1]/a?q=secret') == 'https://[::1]/a'
    assert clean('hello\x1b[2J\x1b]0;spoofed-title\x07\nworld\u202e') == 'helloworld'
    ui = view()
    for _ in range(10000): ui.note('info', 'hello')
    assert len(ui.events) <= 4


def test_redirected_output_never_enters_live_screen_and_no_color_is_respected(monkeypatch):
    monkeypatch.setenv('NO_COLOR', '')
    stream = io.StringIO()
    ui = AgentWorkspace(stream=stream)
    assert not ui.open('agent', 'https://backend.invalid/', '1.1')
    assert not ui.active and ui.thread is None and stream.getvalue() == ''
    assert '\x1b' not in ui.render(120,30)


def test_ascii_terminal_has_readable_fallback():
    ui = view(); ui.unicode = False
    frame = ui.render(120,30)
    frame.encode('ascii')
    assert '+' in frame and '|' in frame


def test_renderer_failure_stops_refresh_and_restores_cursor_without_raising():
    class Broken(io.StringIO):
        def isatty(self): return True
        def write(self, text): raise OSError('terminal unavailable')
    ui = AgentWorkspace(stream=Broken())
    assert not ui.open('agent', 'https://backend.invalid', '1.1')
    assert not ui.active and ui.stop.is_set() and ui.muted


def test_lost_terminal_cannot_interrupt_event_delivery(monkeypatch, capsys):
    ui = view(); ui.muted = True
    monkeypatch.setattr(lhx_agent, 'workspace', ui)
    transport = AsyncMock()
    console = lhx_agent.PhaseConsoleInterceptor(transport)
    progress = event('scan_progress', phase='analysis', processed_files=10, total_files=20)
    asyncio.run(console.emit(progress))
    transport.emit.assert_awaited_once_with(progress)
    assert capsys.readouterr().out == ''


def test_interceptor_uses_existing_emitter_only_and_waits_for_delivery(monkeypatch):
    ui = view(); ui.active = True
    monkeypatch.setattr(lhx_agent, 'workspace', ui)
    emitter = AsyncMock()
    console = lhx_agent.PhaseConsoleInterceptor(emitter)
    async def scenario():
        progress = event('scan_progress', phase='analysis', processed_files=230, total_files=420)
        await console.emit(progress)
        emitter.emit.assert_awaited_once_with(progress)
        assert ui.counts['processed'] == 230
        complete = event('scan_completed', metrics={'processed_js_files':420,'total_js_files':420,
                                                   'potential_secrets':3, 'discovered_endpoints':42})
        await console.emit(complete)
        assert ui.delivery == 'Sending' and ui.state != 'Completed'
        assert ui.stages['finalizing'] == 'Running'
        await console.flush()
        assert ui.state == 'Completed' and ui.delivery == 'Acknowledged'
        assert emitter.emit.await_count == 2 and emitter.flush.await_count == 1
        # The presentation layer neither fetches status nor drains the transport.
        assert emitter.get.await_count == emitter.drain.await_count == 0
    asyncio.run(scenario())


def test_failed_delivery_never_shows_success_even_with_completion_event(monkeypatch):
    ui = view(); ui.active = True
    monkeypatch.setattr(lhx_agent, 'workspace', ui)
    transport = AsyncMock()
    transport.emit.side_effect = RuntimeError('private delivery detail')
    console = lhx_agent.PhaseConsoleInterceptor(transport)
    async def scenario():
        with pytest.raises(RuntimeError):
            await console.emit(event('scan_completed', metrics={'processed_js_files':1, 'total_js_files':1}))
        console.show_terminal('failed', 'evidence_delivery_failed')
    asyncio.run(scenario())
    assert ui.state == 'Failed' and ui.delivery == 'Pending recovery'
    assert 'private delivery detail' not in ui.render(150,40)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX pseudo-terminal')
def test_real_pseudo_terminal_updates_one_screen_and_restores_it():
    import pty
    import select
    master, slave = pty.openpty()
    with os.fdopen(slave, 'w', buffering=1) as stream:
        ui = AgentWorkspace(stream=stream, size=lambda: (120,32))
        try:
            assert ui.open('lhx-agent-test', 'https://backend.invalid/', '1.1')
            ui.begin('scan-1', 'https://example.com/')
            ui.observe(event('scan_progress', phase='analysis', processed_files=230, total_files=420))
            ui.draw()
        finally:
            ui.close()
            if ui.thread: ui.thread.join(timeout=1)
        output = bytearray()
        while select.select([master], [], [], .1)[0]:
            output.extend(os.read(master, 65536))
    os.close(master)
    assert b'\x1b[?1049h' in output and b'230 / 420' in output
    assert b'\x1b[?25h\x1b[?1049l' in output
    assert b'AI validation' not in output

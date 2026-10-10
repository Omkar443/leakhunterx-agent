"""Bounded browser worker supervision and existing-pipeline integration."""
import asyncio
import json
import os
from pathlib import Path
import signal
import sys

import psutil

from .asset_coverage import canonical_asset_url
from .utils.events import emit_event

REASONS = {'bounded_coverage', 'browser_unavailable', 'dependency_missing',
           'timeout', 'memory_limit', 'disabled', 'worker_failed', 'unsupported_runtime'}


def bounded(config, key, default, maximum):
    value = config.get(key, default)
    return min(max(value, 1), maximum) if type(value) is int else default


async def run_browser_discovery(target, config, context):
    from .events.outbox import DeliveryPending
    mode = config.get('browser_rendering', 'off')
    if mode == 'off': return {'rendering_status':'disabled', 'rendering_reason':'disabled'}
    if mode != 'on': raise ValueError('browser_rendering must be off or on')
    result = {'rendering_status':'unavailable', 'rendering_limited':True, 'rendering_reason':'worker_failed'}
    process = None
    owned_children = {}
    async def progress(values):
        await emit_event(context, event_type='scan_progress', data={'phase':'crawling', 'substage':'rendering', **values})
    await progress({'rendering_status':'running', 'rendered_pages':0, 'browser_requests':0})
    try:
        import importlib.util
        if getattr(sys, 'frozen', False):
            result['rendering_reason'] = 'unsupported_runtime'; return result
        if importlib.util.find_spec('playwright') is None:
            result['rendering_reason'] = 'dependency_missing'; return result
        limits = {'pages':bounded(config,'browser_max_pages',3,5),
                  'requests':bounded(config,'browser_max_requests',200,300),
                  'bytes':20*1024*1024,
                  'settle_ms':bounded(config,'browser_settle_ms',1500,5000),
                  'allow_private':config.get('allow_private_targets') is True}
        # No backend URL, API tokens, proxy credentials or arbitrary Python hooks.
        environment = {key:value for key,value in os.environ.items() if key in {
            'PATH','HOME','USERPROFILE','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP',
            'LOCALAPPDATA','PLAYWRIGHT_BROWSERS_PATH','LD_LIBRARY_PATH'}}
        environment['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'agent.browser_worker',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=environment, limit=32*1024*1024,
            **({'start_new_session':True} if os.name != 'nt' else {}))
        process.stdin.write((json.dumps({'target':target,'limits':limits, 'parent_pid':os.getpid(),
                                        'parent_created':psutil.Process().create_time()})+'\n').encode())
        await process.stdin.drain(); process.stdin.close()
        async def supervise():
            read = asyncio.create_task(process.stdout.readline())
            ticks = 0
            try:
                while True:
                    done, _ = await asyncio.wait({read}, timeout=1)
                    try:
                        root = psutil.Process(process.pid)
                        children = root.children(recursive=True)
                        for child in children: owned_children[(child.pid, child.create_time())] = child
                        memory = sum(p.memory_info().rss for p in [root, *children] if p.is_running())
                        if memory > bounded(config,'browser_memory_mb',768,1024)*1024*1024:
                            result['rendering_reason'] = 'memory_limit'; return
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
                    if not done:
                        ticks += 1
                        if ticks % 5 == 0: await progress({'rendering_status':'running'})
                        continue
                    line = read.result()
                    if not line: return
                    message = json.loads(line)
                    if isinstance(message.get('result'),dict):
                        result.clear(); result.update(message['result']); return
                    values = message.get('progress',{})
                    await progress({key:value for key,value in values.items()
                                    if key in ('rendered_pages','browser_requests') and type(value) is int and 0<=value<=300})
                    read = asyncio.create_task(process.stdout.readline())
            finally:
                if not read.done(): read.cancel()
                await asyncio.gather(read, return_exceptions=True)
        try:
            await asyncio.wait_for(supervise(), bounded(config,'browser_timeout',75,120))
        except asyncio.TimeoutError: result['rendering_reason'] = 'timeout'
        return result
    except DeliveryPending:
        raise
    except (OSError, ValueError, RuntimeError):
        # Failure to launch/parse an optional browser is not evidence that
        # the successfully crawled target failed its existing assessment.
        return result
    finally:
        if process:
            # Kill the owned process group/tree on success, timeout AND cancellation.
            # Chromium may create its own process group; collect and terminate
            # descendants too. Cached Process handles protect against PID reuse.
            try:
                for child in psutil.Process(process.pid).children(recursive=True):
                    owned_children[(child.pid, child.create_time())] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            for child in reversed(list(owned_children.values())):
                try: child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            if os.name != 'nt':
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            else:
                try:
                    root = psutil.Process(process.pid)
                    root.kill()
                except psutil.NoSuchProcess: pass
            await process.wait()
        if not asyncio.current_task().cancelling():
            await progress({key:value for key,value in result.items() if key in {
                'rendering_status','rendering_reason','rendering_limited','rendered_pages',
                'browser_requests','browser_blocked_requests'}})


async def integrate_browser_result(result, crawl_context, analysis_context):
    """Scan bounded DOM context without claiming it verifies an HTTP asset."""
    import copy
    from .js.leak_detector import SecretScanner
    rendered_context = copy.copy(crawl_context)
    rendered_context.shared_state = {**crawl_context.shared_state, 'acquisition_policy':'rendered_dom_v1'}
    for document in result.get('doms', []):
        if await crawl_context.check_pause_stop(): return
        url = canonical_asset_url(document['url'])
        if crawl_context.domain_manager.is_in_scope(url):
            await SecretScanner().scan(document['content'], url, rendered_context)
    bodies = analysis_context.shared_state.setdefault('browser_scripts', {})
    for url, content in result.get('scripts', {}).items():
        url = canonical_asset_url(url)
        if crawl_context.domain_manager.is_in_scope(url):
            bodies[url] = content
            crawl_context.domain_manager.add_discovered(url, 0, resource_type='javascript')
    for url in result.get('script_urls', []):
        url = canonical_asset_url(url)
        if crawl_context.domain_manager.is_in_scope(url):
            crawl_context.domain_manager.add_discovered(url, 0, resource_type='javascript')
    from .utils.pipeline import display_url
    for url, status in result.get('endpoints', {}).items():
        if crawl_context.domain_manager.is_in_scope(url):
            await emit_event(analysis_context, event_type='endpoint_found', data={
                'source_url':display_url(crawl_context.domain_manager.target_url),
                'finding_type':'endpoint', 'raw_value':display_url(url),
                'confidence':0.5, 'severity':'INFO', 'method':'GET',
                'http_status':status, 'observed_by':'browser'})
    # Browser DOM may differ from the initial document. Its findings need
    # follow-up rendering; a clean static page must not falsely resolve them.
    analysis_context.shared_state['rendering_coverage'] = {key:value for key,value in result.items()
        if key not in ('scripts','script_urls','documents','doms','endpoints')}

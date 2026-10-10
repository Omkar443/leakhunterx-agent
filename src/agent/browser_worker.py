"""Isolated, anonymous Chromium discovery. No agent credentials enter this process.

All permitted HTTP responses are fulfilled by our guarded aiohttp transport.
Chromium has a deny proxy as a second boundary for requests not intercepted by
Playwright (workers, browser services, WebSockets). Never route.continue().
"""
import asyncio
import json
import sys
from urllib.parse import urljoin, urlsplit

import aiohttp

from .utils.pipeline import ScanResolver, check_address, normalize_target, PipelineError
from .asset_coverage import canonical_asset_url, challenge_response


def send(data):
    print(json.dumps(data, separators=(',', ':'), ensure_ascii=False), flush=True)


class BrowserBridge:
    def __init__(self, session, target, limits):
        self.session, self.target, self.limits = session, target, limits
        self.host = urlsplit(target).hostname
        self.scripts = {}
        self.script_urls = set()
        self.captured_bytes = 0
        self.endpoints = {}
        self.requests = 0
        self.bytes = 0
        self.blocked = 0
        self.failures = 0
        self.semaphore = asyncio.Semaphore(4)

    def allowed(self, url):
        # Rendering has narrower scope than HTTP discovery: exact hostname.
        parsed = urlsplit(url)
        origin = urlsplit(self.target)
        return (parsed.hostname == self.host and parsed.scheme in ('http', 'https')
                and (origin.scheme != 'https' or parsed.scheme == 'https')
                and (parsed.port or (443 if parsed.scheme == 'https' else 80))
                == (origin.port or (443 if origin.scheme == 'https' else 80)))

    async def route(self, route):
        request = route.request
        try:
            url = canonical_asset_url(request.url)
            if (not self.allowed(url) or request.method != 'GET'
                    or request.resource_type not in ('document', 'script', 'stylesheet', 'fetch', 'xhr')):
                self.blocked += 1
                await route.abort(); return
            if self.requests >= self.limits['requests']:
                self.failures += 1
                await route.abort(); return
            self.requests += 1
            check_address(urlsplit(url).hostname, self.limits.get('allow_private', False))
            async with self.semaphore:
                # Do not forward browser cookies, authorization, referer or target
                # controlled headers. The resolver checks the actual destination.
                async with self.session.get(url, allow_redirects=False) as response:
                    status = response.status
                    if status in (301, 302, 303, 307, 308):
                        destination = normalize_target(urljoin(url, response.headers.get('Location', '')))
                        if not response.headers.get('Location') or not self.allowed(destination):
                            raise PipelineError('Unsafe browser redirect')
                        await route.fulfill(status=status, headers={'location':destination}, body=b'')
                        return
                    kind = request.resource_type
                    if kind in ('fetch', 'xhr'):
                        from .utils.pipeline import display_url
                        self.endpoints.setdefault(display_url(url), status)
                    limit = 2 * 1024 * 1024 if kind == 'document' else 5 * 1024 * 1024
                    body = bytearray()
                    async for chunk in response.content.iter_chunked(65536):
                        self.bytes += len(chunk)
                        if len(body) + len(chunk) > limit or self.bytes > self.limits['bytes']:
                            raise PipelineError('Browser body budget exceeded')
                        body.extend(chunk)
                    mime = response.headers.get('Content-Type', '').lower()
                    if status >= 400:
                        self.failures += 1
                    if status == 200:
                        text = bytes(body).decode(response.charset or 'utf-8', errors='replace')
                        if kind == 'script' and ('javascript' in mime or 'ecmascript' in mime):
                            self.script_urls.add(url)
                            size = len(text.encode('utf-8'))
                            if (self.captured_bytes + size <= 8*1024*1024
                                and not text.lstrip().lower().startswith(('<html', '<!doctype'))
                                and '\x00' not in text):
                                if url not in self.scripts:
                                    self.scripts[url] = text
                                    self.captured_bytes += size
                            else: self.failures += 1
                    # Never forward cookies, compressed lengths, attachment headers,
                    # authentication challenges or hop-by-hop transport headers.
                    headers = {key:value for key,value in response.headers.items()
                               if key.lower() in ('content-type', 'content-security-policy',
                                                  'access-control-allow-origin', 'x-content-type-options')}
                    await route.fulfill(status=status, headers=headers, body=bytes(body))
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, LookupError, PipelineError):
            self.failures += 1
            await route.abort()


async def render(target, limits):
    from playwright.async_api import async_playwright, Error as BrowserError
    target = canonical_asset_url(target)
    connector = aiohttp.TCPConnector(limit=4, resolver=ScanResolver(limits.get('allow_private', False)), ssl=True)
    async with aiohttp.ClientSession(connector=connector, cookie_jar=aiohttp.DummyCookieJar(),
                                    trust_env=False, timeout=aiohttp.ClientTimeout(total=10),
                                    headers={'User-Agent':'LeakHunterX/1 Browser discovery'}) as session:
        bridge = BrowserBridge(session, target, limits)
        # A real deny server avoids dependence on an unused localhost port.
        async def deny(reader, writer):
            bridge.failures += 1
            writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain(); writer.close(); await writer.wait_closed()
        async with await asyncio.start_server(deny, '127.0.0.1', 0) as proxy:
            port = proxy.sockets[0].getsockname()[1]
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True, chromium_sandbox=True, timeout=20000,
                    proxy={'server':f'http://127.0.0.1:{port}'},
                    args=['--proxy-bypass-list=<-loopback>', '--disable-quic',
                          '--host-resolver-rules=MAP * ~NOTFOUND', '--dns-prefetch-disable',
                          '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
                          '--disable-background-networking', '--disable-extensions',
                          '--js-flags=--max-old-space-size=128'])
                context = None
                try:
                    context = await browser.new_context(accept_downloads=False, service_workers='block')
                    await context.route('**/*', bridge.route)
                    await context.route_web_socket('**/*', lambda socket: socket.close())
                    context.on('page', lambda page: page.on('dialog', lambda dialog: dialog.dismiss()))
                    page = await context.new_page()
                    def page_error(_): bridge.failures += 1
                    page.on('pageerror', page_error)
                    async def close_popup(opened):
                        if opened != page: await opened.close()
                    context.on('page', close_popup)
                    pending, visited, doms = [target], set(), []
                    while pending and len(visited) < limits['pages']:
                        url = pending.pop(0)
                        if url in visited or not bridge.allowed(url): continue
                        visited.add(url)
                        try:
                            navigation = await page.goto(url, wait_until='domcontentloaded', timeout=15000)
                            if navigation is None or not navigation.ok:
                                bridge.failures += 1
                                continue
                            await page.wait_for_timeout(limits['settle_ms'])
                            await page.evaluate('window.scrollTo(0, Math.min(document.body.scrollHeight, 2000))')
                            await page.wait_for_timeout(500)
                            final = canonical_asset_url(page.url)
                            if bridge.allowed(final):
                                # JS evaluation returns only bounded document text/links.
                                dom = await page.evaluate('(limit) => document.documentElement.outerHTML.slice(0, limit)', 1024*1024)
                                if len(dom) >= 1024*1024:
                                    bridge.failures += 1
                                elif not challenge_response(dom): doms.append({'url':final, 'content':dom})
                                links = await page.evaluate('Array.from(document.querySelectorAll("a[href]")).slice(0,100).map(a=>a.href)')
                                for link in links:
                                    try: link = canonical_asset_url(link)
                                    except (ValueError, TypeError): continue
                                    # Never follow logout/delete/action URLs or query routes.
                                    path = urlsplit(link).path.lower()
                                    if (bridge.allowed(link) and not urlsplit(link).query
                                        and not any(word in path for word in ('logout','signout','delete','remove','purchase','checkout'))
                                        and link not in visited and link not in pending): pending.append(link)
                        except BrowserError:
                            bridge.failures += 1
                        send({'progress':{'rendered_pages':len(doms), 'browser_requests':bridge.requests}})
                    # Rendered DOM is supplementary context, not a coverage receipt
                    # for the original HTTP document: never use it to prove removal.
                    return {'scripts':bridge.scripts, 'script_urls':sorted(bridge.script_urls),
                            'doms':doms, 'endpoints':bridge.endpoints,
                            'rendered_pages':len(doms), 'browser_requests':bridge.requests,
                            'browser_blocked_requests':bridge.blocked,
                            'rendering_limited':bool(bridge.blocked or bridge.failures or pending),
                            'rendering_reason':'bounded_coverage', 'rendering_status':'completed'}
                finally:
                    if context: await context.close()
                    await browser.close()


async def supervised_render(payload):
    import psutil
    task = asyncio.create_task(render(payload['target'], payload['limits']))
    async def parent_watch():
        while True:
            await asyncio.sleep(.5)
            try:
                parent = psutil.Process(payload['parent_pid'])
                alive = parent.is_running() and parent.create_time() == payload['parent_created']
            except psutil.NoSuchProcess: alive = False
            if not alive:
                task.cancel()
                await asyncio.sleep(3)
                # A wedged browser teardown must not survive the agent exit.
                for child in reversed(psutil.Process().children(recursive=True)):
                    try: child.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied): pass
                __import__('os')._exit(1)
    watcher = asyncio.create_task(parent_watch())
    try: return await task
    finally:
        watcher.cancel(); await asyncio.gather(watcher, return_exceptions=True)


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    try:
        payload = json.loads(sys.stdin.readline())
        result = asyncio.run(supervised_render(payload))
        send({'result':result})
    except (Exception, KeyboardInterrupt):
        # Browser errors can contain page bodies, tokens, paths and launch args.
        send({'result':{'rendering_status':'unavailable', 'rendering_limited':True,
                        'rendering_reason':'browser_unavailable'}})


if __name__ == '__main__': main()

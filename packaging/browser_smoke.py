"""Exercise the downloadable binary's real browser against a local fixture.

No Python, Playwright cache, credentials or network target are supplied to the
binary. Run after building: python packaging/browser_smoke.py dist/<binary>
"""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

from aiohttp import web
import psutil


async def check(binary):
    requests = []
    async def fixture(request):
        requests.append(request.path)
        if request.path == '/':
            return web.Response(text='''<html><body><script>
                setTimeout(()=>{const s=document.createElement('script');
                  s.src='/lazy.js';document.body.appendChild(s)},100);
                fetch('/data');fetch('/blocked',{method:'POST'});
            </script></body></html>''', content_type='text/html')
        if request.path == '/lazy.js':
            return web.Response(text='const discoveredEndpoint="/api/lazy";', content_type='application/javascript')
        return web.json_response({'ok': True})
    app = web.Application(); app.router.add_route('*', '/{tail:.*}', fixture)
    server = web.AppRunner(app); await server.setup()
    site = web.TCPSite(server, '127.0.0.1', 0); await site.start()
    target = f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/'
    try:
        with tempfile.TemporaryDirectory() as home:
            env = {key: value for key, value in os.environ.items() if key in
                   ('PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP')}
            env.update(HOME=home, USERPROFILE=home, LOCALAPPDATA=home,
                       PLAYWRIGHT_BROWSERS_PATH=str(Path(home) / 'empty-cache'))
            process = await asyncio.create_subprocess_exec(str(Path(binary).resolve()), '--lhx-browser-worker',
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env)
            payload = {'target': target, 'parent_pid': os.getpid(),
                       'parent_created': psutil.Process().create_time(),
                       'limits': {'pages': 1, 'requests': 20, 'bytes': 1024*1024,
                                  'settle_ms': 500, 'allow_private': True}}
            try:
                output, errors = await asyncio.wait_for(
                    process.communicate((json.dumps(payload)+'\n').encode()), 90)
            except asyncio.TimeoutError:
                for child in reversed(psutil.Process(process.pid).children(recursive=True)):
                    try: child.kill()
                    except psutil.NoSuchProcess: pass
                process.kill(); await process.wait(); raise
            assert process.returncode == 0, errors.decode(errors='replace')[:2000]
            frames = [json.loads(line) for line in output.splitlines()]
            result = next(row['result'] for row in frames if 'result' in row)
            assert result['rendering_status'] == 'completed', result
            assert target+'lazy.js' in result['scripts'], result
            assert target+'data' in result['endpoints'], result
            assert '/blocked' not in requests
            assert not (Path(home)/'empty-cache').exists(), 'Binary used an external browser cache'
            print('Bundled browser smoke passed: delayed JavaScript, GET endpoint, blocked POST, empty user cache.')
    finally:
        await server.cleanup()


if __name__ == '__main__':
    asyncio.run(check(sys.argv[1]))

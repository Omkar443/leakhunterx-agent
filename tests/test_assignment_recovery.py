import asyncio
from types import SimpleNamespace
from uuid import uuid4
import httpx
from agent.lhx_agent import poll_for_scan
from unittest.mock import AsyncMock
from agent import lhx_agent as module


def test_lost_claim_response_retries_same_key_and_exposes_network_error(capsys):
    async def scenario():
        requests = []
        scan_id = str(uuid4())
        def backend(request):
            requests.append(request.headers['X-Assignment-Request-Id'])
            if len(requests) == 1:
                raise httpx.ReadTimeout('hidden-secret-url', request=request)
            if len(requests) == 2:
                return httpx.Response(200, json={'scan_id':scan_id,'target':'https://example.invalid'})
            return httpx.Response(200, json=None)
        async with httpx.AsyncClient(base_url='https://backend.invalid', transport=httpx.MockTransport(backend)) as client:
            signal = SimpleNamespace(should_exit=False)
            assert await poll_for_scan(client, signal) is None
            assert (await poll_for_scan(client, signal))['scan_id'] == scan_id
            assert await poll_for_scan(client, signal) is None
        assert requests[0] == requests[1] and requests[2] != requests[1]
    asyncio.run(scenario())
    output = capsys.readouterr().out
    assert 'ReadTimeout' in output and 'restored' in output
    assert 'hidden-secret-url' not in output


def test_invalid_reply_retains_claim_key_and_auth_failure_stops_runtime(capsys):
    async def scenario():
        keys = []
        def backend(request):
            keys.append(request.headers['X-Assignment-Request-Id'])
            return httpx.Response(200, json={'bad':'secret'}) if len(keys) == 1 else httpx.Response(401)
        async with httpx.AsyncClient(base_url='https://backend.invalid', transport=httpx.MockTransport(backend)) as client:
            signal = SimpleNamespace(should_exit=False)
            assert await poll_for_scan(client, signal) is None
            assert await poll_for_scan(client, signal) is None
            assert signal.should_exit and signal.agent_revoked
        assert keys[0] == keys[1]
    asyncio.run(scenario())
    assert 'secret' not in capsys.readouterr().out


def test_setup_failure_is_delivered_instead_of_stranding_running_scan(monkeypatch, capsys):
    async def scenario():
        signal = SimpleNamespace(should_exit=False, set_scan_task=lambda _:None,
            set_orchestrator=lambda _:None, mark_shutdown_complete=lambda:None)
        transport = SimpleNamespace(start=AsyncMock(), emit=AsyncMock(), close=AsyncMock())
        monkeypatch.setattr(module, 'create_emitter', lambda *a, **k:transport)
        monkeypatch.setattr(module, 'recover_interrupted_scans', AsyncMock())
        monkeypatch.setattr(module, 'send_disconnect', AsyncMock())
        monkeypatch.setattr(module, '_interruptible_sleep', AsyncMock())
        async def background(**kwargs):
            await asyncio.Event().wait()
        monkeypatch.setattr(module, 'heartbeat_loop', background)
        monkeypatch.setattr(module, 'action_polling_loop', background)
        sid = str(uuid4())
        polls = 0
        async def poll(*args):
            nonlocal polls
            polls += 1
            if polls == 1:return {'scan_id':sid,'target':'https://example.invalid'}
            signal.should_exit = True
            return None
        monkeypatch.setattr(module, 'poll_for_scan', poll)
        def broken(**kwargs):raise ValueError('invalid configuration')
        monkeypatch.setattr(module, 'ScanOrchestrator', broken)
        await module.run_backend_agent_loop({}, SimpleNamespace(), 'test', signal)
        sent = transport.emit.await_args.args[0]
        assert sent['scan_id'] == sid and sent['event_type'] == 'scan_failed'
        transport.close.assert_awaited_once()
    asyncio.run(scenario())
    assert 'Scan failed' in capsys.readouterr().out

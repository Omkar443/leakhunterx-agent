import asyncio
from types import SimpleNamespace
from uuid import uuid4
import httpx
from agent.lhx_agent import poll_for_scan
from unittest.mock import AsyncMock
from agent import lhx_agent as module
import pytest


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
        monkeypatch.setattr(module, 'recover_interrupted_scans', AsyncMock(return_value=[]))
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


@pytest.mark.parametrize('during_setup', [True, False])
def test_github_failure_code_and_temporary_token_cleanup(monkeypatch,caplog,during_setup):
    from agent.local import github_app, runtime
    from agent.local.failures import GitHubScanError
    async def scenario():
        signal=SimpleNamespace(should_exit=False,set_scan_task=lambda _:None,set_orchestrator=lambda _:None,mark_shutdown_complete=lambda:None)
        transport=SimpleNamespace(start=AsyncMock(),emit=AsyncMock(),close=AsyncMock())
        monkeypatch.setattr(module,'create_emitter',lambda *a,**k:transport)
        monkeypatch.setattr(module,'recover_interrupted_scans',AsyncMock(return_value=[]))
        monkeypatch.setattr(module,'send_disconnect',AsyncMock())
        monkeypatch.setattr(module,'_interruptible_sleep',AsyncMock())
        async def background(**kwargs):await asyncio.Event().wait()
        monkeypatch.setattr(module,'heartbeat_loop',background)
        monkeypatch.setattr(module,'action_polling_loop',background)
        sid=str(uuid4());polled=False
        async def poll(*args):
            nonlocal polled
            if not polled:
                polled=True
                return {'scan_id':sid,'target':'github://target','source_type':'GITHUB','github_app':{}}
            signal.should_exit=True
        monkeypatch.setattr(module,'poll_for_scan',poll)
        # A nonempty App assignment selects prepare_assignment.
        original_poll=poll
        async def app_poll(*args):
            job=await original_poll(*args)
            if job:job['github_app']={'repository_id':77}
            return job
        monkeypatch.setattr(module,'poll_for_scan',app_poll)
        access=SimpleNamespace(clear=lambda:setattr(access,'token',None),token='PRIVATE_PROVIDER_TOKEN')
        async def prepare(*args):
            if during_setup:raise GitHubScanError('github_signing_unavailable')
            return access
        monkeypatch.setattr(github_app,'prepare_assignment',prepare)
        async def start_scan():
            assert access.token=='PRIVATE_PROVIDER_TOKEN'
            raise RuntimeError('PRIVATE_PROVIDER_TOKEN')
        def constructor(*args,**kwargs):
            return SimpleNamespace(start_scan=start_scan,_scan_timeout=600)
        monkeypatch.setattr(runtime,'LocalScanOrchestrator',constructor)
        await module.run_backend_agent_loop({},SimpleNamespace(),'test',signal)
        failed=transport.emit.await_args.args[0]
        assert failed['data']['reason']==('github_signing_unavailable' if during_setup else 'scan_failed')
        if not during_setup:assert access.token is None
    asyncio.run(scenario())
    assert 'PRIVATE_PROVIDER_TOKEN' not in caplog.text

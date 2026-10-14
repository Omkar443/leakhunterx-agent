import asyncio
import signal
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from agent import lhx_agent


@pytest.mark.parametrize('signum,reason',[(signal.SIGINT,'cancelled'),(signal.SIGTERM,'agent_interrupted')])
def test_signal_preserves_intent_in_durable_transport(monkeypatch,signum,reason):
    async def scenario():
        handler=lhx_agent.SignalHandler()
        handler._orchestrator=SimpleNamespace(scan_id='test-scan')
        handler._event_transport=SimpleNamespace(emit=AsyncMock())
        task=asyncio.create_task(asyncio.sleep(60));handler.set_scan_task(task)
        handler._handle_signal(signum,None)
        handler._orchestrator=None  # Cleanup must not lose the captured scan ID.
        await asyncio.sleep(0);await asyncio.sleep(0)
        await asyncio.gather(task,return_exceptions=True)
        await asyncio.sleep(0)
        event=handler._event_transport.emit.await_args.args[0]
        assert event['data']['reason']==reason
        assert event['event_type']==('scan_stopped' if reason=='cancelled' else 'scan_failed')
        assert handler.should_exit
    monkeypatch.setattr(lhx_agent,'AGENT_SHUTTING_DOWN',False)
    asyncio.run(scenario())

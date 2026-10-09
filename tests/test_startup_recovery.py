import asyncio
from uuid import uuid4
from unittest.mock import AsyncMock, Mock
import pytest
from agent.lhx_agent import recover_interrupted_scans
from agent.events.outbox import DeliveryPending


def test_restart_replays_completion_before_reconciling_interrupted_scan():
    async def scenario():
        calls = []
        scan_id = str(uuid4())
        transport = Mock()
        transport.drain = AsyncMock(side_effect=lambda: calls.append('drain'))
        transport.emit = AsyncMock(side_effect=lambda event: calls.append(event))
        response = Mock(); response.json.return_value = {'scan_ids': [scan_id], 'delivery_pending': False}
        async def get(url):
            calls.append('query'); return response
        await recover_interrupted_scans(Mock(get=get), transport)
        assert calls[0:2] == ['drain', 'query']
        assert calls[2]['event_type'] == 'scan_failed'
        assert calls[2]['scan_id'] == scan_id
        assert calls[3] == 'drain'
    asyncio.run(scenario())


def test_restart_waits_for_server_processing_before_failing_any_scan():
    async def scenario():
        transport = Mock(drain=AsyncMock(), emit=AsyncMock())
        response = Mock(); response.json.return_value = {'scan_ids': [], 'delivery_pending': True}
        with pytest.raises(DeliveryPending):
            await recover_interrupted_scans(Mock(get=AsyncMock(return_value=response)), transport)
        transport.emit.assert_not_called()
    asyncio.run(scenario())

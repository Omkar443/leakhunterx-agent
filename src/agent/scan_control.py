"""Observe the authoritative assignment without confusing an outage with cancellation."""
import asyncio
import httpx

TERMINAL_STATUSES = {'completed', 'failed', 'cancelled'}


async def monitor_assignment(client, scan_id, task, orchestrator, console, interval=5):
    while not task.done():
        try:
            response = await client.get(f'/api/v1/agent/scans/{scan_id}/state', timeout=5)
            if response.status_code in {401, 403}:
                state = {'status': 'failed', 'reason': 'access_revoked'}
            elif response.status_code == 404:
                error = response.json()
                state = {'status': 'failed', 'reason': 'assignment_unavailable'} if isinstance(error, dict) and error.get('detail') == 'Scan unavailable' else {}
            else:
                response.raise_for_status()
                state = response.json()
                if not isinstance(state, dict) or state.get('scan_id') != scan_id:
                    state = {}
            if state.get('status') in TERMINAL_STATUSES and not task.done():
                orchestrator._backend_terminal_status = state['status']
                console.show_terminal(state['status'], state.get('reason'), backend=True)
                task.cancel()
                return
        except (httpx.HTTPError, ValueError, TypeError):
            # A lost response/older backend cannot prove that a scan ended.
            # The local deadline still bounds execution during a network loss.
            pass
        await asyncio.sleep(interval)

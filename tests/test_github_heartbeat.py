import asyncio
from types import SimpleNamespace
import httpx
from agent import lhx_agent as module


def test_github_only_registry_does_not_break_older_backend_heartbeat(monkeypatch):
    async def scenario():
        signal=SimpleNamespace(should_exit=False)
        bodies=[]
        def backend(request):
            import json
            body=json.loads(request.content);bodies.append(body)
            if 'github-v1' in body.get('capabilities',[]):return httpx.Response(422)
            signal.should_exit=True
            return httpx.Response(200,json={})
        monkeypatch.setattr(module,'AGENT_SHUTTING_DOWN',False)
        monkeypatch.setattr(module,'local_scan_enabled',lambda:True)
        monkeypatch.setattr(module,'collect_os_metrics',lambda:{})
        monkeypatch.setattr('agent.local.runtime.target_heartbeat',lambda:{'capabilities':['web-v1','local-v1','github-v1'],'local_targets':[],'github_targets':[]})
        async with httpx.AsyncClient(base_url='https://fixture.invalid',transport=httpx.MockTransport(backend)) as client:
            await asyncio.wait_for(module.heartbeat_loop(client,signal,lambda:'connected',interval=0),timeout=3)
        assert len(bodies)==2 and 'github_targets' not in bodies[1] and bodies[1]['capabilities']==['web-v1','local-v1']
    asyncio.run(scenario())


def test_app_capability_fallback_preserves_legacy_github(monkeypatch):
    async def scenario():
        import json
        signal=SimpleNamespace(should_exit=False);bodies=[]
        def backend(request):
            body=json.loads(request.content);bodies.append(body)
            if 'github-app-v1' in body.get('capabilities',[]):return httpx.Response(422)
            signal.should_exit=True;return httpx.Response(200,json={})
        monkeypatch.setattr(module,'AGENT_SHUTTING_DOWN',False)
        monkeypatch.setattr(module,'local_scan_enabled',lambda:True)
        monkeypatch.setattr(module,'collect_os_metrics',lambda:{})
        monkeypatch.setattr('agent.local.runtime.target_heartbeat',lambda:{'capabilities':['web-v1','local-v1','github-v1','github-app-v1'],'local_targets':[],'github_targets':[]})
        async with httpx.AsyncClient(base_url='https://fixture.invalid',transport=httpx.MockTransport(backend)) as client:
            await asyncio.wait_for(module.heartbeat_loop(client,signal,lambda:'connected',interval=0),timeout=3)
        assert len(bodies)==2 and 'github_targets' in bodies[1] and 'github-v1' in bodies[1]['capabilities']
    asyncio.run(scenario())

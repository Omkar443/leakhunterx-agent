"""CI dispatch and policy wait. Uses a rule-scoped secret, never an account JWT.

Execution stays on the selected registered agent, which may be a customer-owned
runner. This client neither downloads private source nor receives agent secrets.
"""
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit
from uuid import UUID, uuid4
import httpx

STATES={'queued','waiting_agent','waiting_allowance','running','evaluating','passed','exposure_detected','inconclusive','failed','cancelled','expired'}
TERMINAL={'passed','exposure_detected','inconclusive','failed','cancelled','expired'}


def backend_url(value):
    parsed=urlsplit(value)
    if (parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/') or not parsed.hostname
            or parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in ('localhost','127.0.0.1','::1'))):
        raise ValueError('Use a trusted HTTPS backend origin')
    return value.rstrip('/')


def read_response(response):
    if response.status_code not in (200,202):raise ValueError('CI request refused (HTTP '+str(response.status_code)+')')
    if len(response.content)>65536:raise ValueError('CI response exceeds limit')
    data=response.json()
    if (not isinstance(data,dict) or data.get('state') not in STATES or type(data.get('blocks_pipeline')) is not bool
            or not isinstance(data.get('id'),str)):
        raise ValueError('Invalid CI result')
    UUID(data['id'])
    if data.get('scan_id') is not None:UUID(data['scan_id'])
    if data['state']=='passed' and (data['blocks_pipeline'] or not isinstance(data.get('result'),dict)
            or data['result'].get('outcome')!='passed' or data['result'].get('reason')!='policy_satisfied'):
        raise ValueError('Unverified CI pass')
    return data


def request_bounded(client,method,path,body,clock,deadline):
    with client.stream(method,path,**({'json':body} if body is not None else {})) as response:
        if response.status_code in (429,502,503,504):return httpx.Response(response.status_code)
        data=bytearray()
        for chunk in response.iter_bytes():
            data.extend(chunk)
            if len(data)>65536 or clock()>deadline:raise ValueError('CI response exceeds request limits')
        return httpx.Response(response.status_code,content=bytes(data))


def execute(*,backend,commit,request_id=None,timeout=2400,client=None,sleep=time.sleep,clock=time.monotonic):
    url=backend_url(backend)
    token=os.getenv('LHX_CI_TOKEN','')
    if not token.startswith('lhx_ci_') or len(token)>128 or any(ord(c)<33 or ord(c)>126 for c in token):raise ValueError('Set LHX_CI_TOKEN to a monitor credential')
    if not re.fullmatch(r'[a-f0-9]{40}(?:[a-f0-9]{24})?',commit):raise ValueError('Provide the exact default-branch commit SHA')
    if not 30<=timeout<=3600:raise ValueError('CI timeout must be 30–3600 seconds')
    identifier=str(UUID(request_id)) if request_id else str(uuid4())
    owned=client is None
    client=client or httpx.Client(base_url=url,headers={'Authorization':'Bearer '+token},timeout=httpx.Timeout(15,connect=5),follow_redirects=False)
    started=clock();last=None;run=None
    try:
        while clock()-started<timeout:
            try:
                response=request_bounded(client,'POST' if run is None else 'GET',
                    '/api/v1/monitoring/ci/trigger' if run is None else '/api/v1/monitoring/ci/runs/'+run['id'],
                    {'request_id':identifier,'commit_sha':commit} if run is None else None,clock,started+timeout)
                if response.status_code in (429,502,503,504):sleep(10);continue
                received=read_response(response)
                if run is not None and received['id']!=run['id']:
                    raise ValueError('CI assessment identity changed')
                run=received
                if run.get('commit_sha')!=commit or (run['state']=='passed' and run['result'].get('commit_sha')!=commit):
                    raise ValueError('CI assessment commit mismatch')
            except httpx.TransportError:
                sleep(10);continue
            if run['state']!=last:
                print('LeakHunterX · '+run['state'].replace('_',' '),flush=True);last=run['state']
            if run['state'] in TERMINAL:
                # Never print private/provider payloads or secrets.
                print(json.dumps({key:run.get(key) for key in ('id','scan_id','state','commit_sha','blocks_pipeline')}))
                return 0 if run['state']=='passed' else 2 if run['state']=='inconclusive' and not run['blocks_pipeline'] else 1
            sleep(10)
        print('LeakHunterX · CI wait timed out; inspect the monitoring run. No security pass was issued.',file=sys.stderr)
        return 1
    finally:
        if owned:client.close()


def run(args):
    try:raise SystemExit(execute(backend=args.backend,commit=args.commit,request_id=args.request_id,timeout=args.timeout))
    except (ValueError,KeyError,TypeError,OSError,httpx.HTTPError):
        print('LeakHunterX CI request unavailable. Check the backend, monitor credential, current default-branch SHA and scan allowance.',file=sys.stderr)
        raise SystemExit(1)

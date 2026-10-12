import httpx,pytest
from uuid import uuid4
from agent.ci import execute,backend_url
from test_github_sources import repository,git
from agent.sources.github import snapshot


@pytest.mark.parametrize('state,blocks,code',[('passed',False,0),('exposure_detected',True,1),('inconclusive',True,1),('inconclusive',False,2),('failed',True,1),('cancelled',True,1),('expired',True,1)])
def test_ci_outcomes_never_treat_inconclusive_as_clean(monkeypatch,state,blocks,code,capsys):
    monkeypatch.setenv('LHX_CI_TOKEN','lhx_ci_'+'synthetic'*5)
    identifier=str(uuid4());requests=[]
    def handler(request):
        requests.append(request)
        return httpx.Response(202 if request.method=='POST' else 200,json=dict(id=identifier,state=state,blocks_pipeline=blocks,commit_sha='a'*40,scan_id=None,
            result={'outcome':state,'reason':'policy_satisfied','commit_sha':'a'*40}))
    client=httpx.Client(base_url='https://backend.example.invalid',transport=httpx.MockTransport(handler))
    assert execute(backend='https://backend.example.invalid',commit='a'*40,client=client)==code
    assert 'lhx_ci_' not in capsys.readouterr().out and len(requests)==1


def test_ci_transport_retry_reuses_request_identity(monkeypatch):
    monkeypatch.setenv('LHX_CI_TOKEN','lhx_ci_'+'synthetic'*5);requests=[];identifier=str(uuid4());clock=[0]
    def handler(request):
        requests.append(request)
        if len(requests)==1:raise httpx.ConnectTimeout('PRIVATE_DETAIL')
        return httpx.Response(202,json=dict(id=identifier,state='passed',blocks_pipeline=False,commit_sha='a'*40,result={'outcome':'passed','reason':'policy_satisfied','commit_sha':'a'*40}))
    client=httpx.Client(base_url='https://backend.example.invalid',transport=httpx.MockTransport(handler))
    assert execute(backend='https://backend.example.invalid',commit='a'*40,client=client,sleep=lambda v:clock.__setitem__(0,clock[0]+v),clock=lambda:clock[0])==0
    assert requests[0].content==requests[1].content


@pytest.mark.parametrize('value',['https://token@backend.example.invalid','https://backend.example.invalid?token=x','http://backend.example.invalid','https://backend.example.invalid/api'])
def test_ci_refuses_unsafe_backend(value):
    with pytest.raises(ValueError):backend_url(value)


def test_commit_pin_checked_before_download_and_kept_in_checkpoint(repository):
    registry,target,root=repository
    target['commit_pin']={'commit_sha':'a'*40,'branch':'main'}
    with pytest.raises(ValueError,match='Requested commit'):snapshot(registry,target,str(uuid4()))
    target['commit_pin']={'commit_sha':git(root,'rev-parse','HEAD'),'branch':'main'}
    result=snapshot(registry,target,str(uuid4()))
    assert result[1]['commit_sha']==target['commit_pin']['commit_sha']


@pytest.mark.parametrize('change',[{'commit_sha':'b'*40},{'result':None},{'blocks_pipeline':True},{'result':{'outcome':'passed','reason':'policy_satisfied','commit_sha':'b'*40}}])
def test_ci_refuses_unproved_or_wrong_commit_pass(monkeypatch,change):
    monkeypatch.setenv('LHX_CI_TOKEN','lhx_ci_'+'synthetic'*5)
    data=dict(id=str(uuid4()),state='passed',blocks_pipeline=False,commit_sha='a'*40,
        result={'outcome':'passed','reason':'policy_satisfied','commit_sha':'a'*40})
    client=httpx.Client(base_url='https://backend.example.invalid',transport=httpx.MockTransport(lambda request:httpx.Response(202,json={**data,**change})))
    with pytest.raises(ValueError):execute(backend='https://backend.example.invalid',commit='a'*40,client=client)


def test_ci_bounds_response_memory_before_parsing(monkeypatch):
    monkeypatch.setenv('LHX_CI_TOKEN','lhx_ci_'+'synthetic'*5)
    client=httpx.Client(base_url='https://backend.example.invalid',transport=httpx.MockTransport(lambda request:httpx.Response(200,content=b'x'*65537)))
    with pytest.raises(ValueError,match='limits'):execute(backend='https://backend.example.invalid',commit='a'*40,client=client)


def test_ci_refuses_changed_run_identity_during_wait(monkeypatch):
    monkeypatch.setenv('LHX_CI_TOKEN','lhx_ci_'+'synthetic'*5)
    identifiers=[str(uuid4()),str(uuid4())];requests=[]
    def handler(request):
        requests.append(request)
        return httpx.Response(202 if len(requests)==1 else 200,json=dict(id=identifiers[len(requests)-1],
            state='queued' if len(requests)==1 else 'passed',blocks_pipeline=len(requests)==1,commit_sha='a'*40,
            result={'outcome':'passed','reason':'policy_satisfied','commit_sha':'a'*40}))
    client=httpx.Client(base_url='https://backend.example.invalid',transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError,match='identity changed'):
        execute(backend='https://backend.example.invalid',commit='a'*40,client=client,sleep=lambda _:None)
    assert requests[1].url.path.endswith(identifiers[0])

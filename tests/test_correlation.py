import base64,hashlib,json
from uuid import uuid4
import pytest
from agent.correlation import fields
from agent.local.asset_references import references
from agent.local.scanner import scan_local
from test_github_sources import repository,git,SECRET


def config():
    key=b'c'*32
    return {'version':1,'key_id':hashlib.sha256(key).hexdigest()[:32],'key':base64.urlsafe_b64encode(key).decode()}


def test_workspace_identity_private_case_sensitive_and_detector_scoped():
    c=config();a=fields(c,'github_token',SECRET)
    assert a==fields(c,'github_token','"'+SECRET+'"')
    assert a!=fields(c,'github_token',SECRET.lower())
    assert a!=fields(c,'generic_api_key',SECRET)
    assert SECRET not in json.dumps(a) and c['key'] not in json.dumps(a)
    assert not fields({**c,'key_id':'0'*32},'github_token',SECRET)


def test_encoded_token_urls_are_never_inventory_metadata():
    encoded=''.join('%%%02X'%ord(c) for c in SECRET)
    assert references('https://api.example/'+encoded)==[]
    assert references('https://user:password@api.example/v1')==[]
    assert references('https://api.example/v1/users?api_key=secret')==[{'kind':'ENDPOINT','locator':'https://api.example/v1/users','method':'UNKNOWN'}]


def test_real_git_origin_bounded_private_and_scan_continues_without_history(repository):
    registry,target,root=repository
    target={**target,'correlation_identity':config()}
    introducing=git(root,'rev-parse','HEAD')
    (root/'other.js').write_text('const safe=1;');git(root,'add','.');git(root,'commit','-m','Unrelated change')
    events=[]
    outcome=scan_local(registry,target,on_event=lambda kind,data:events.append((kind,data)))
    assert outcome['status']=='completed'
    finding=next(d for k,d in events if k=='secret_found')
    assert finding['git_origin']['introduced_commit']==introducing
    assert finding['git_origin']['last_containing_commit']==outcome['commit_sha']
    assert finding['correlation_fingerprint']==fields(config(),'github_token',SECRET)['correlation_fingerprint']
    assert SECRET not in json.dumps(events) and config()['key'] not in json.dumps(events)
    from agent.sources import github
    actual=github.git_command
    def unavailable(cache,args,**kwargs):
        if args[0]=='fetch' and '--depth=32' in args:raise RuntimeError('History unavailable')
        return actual(cache,args,**kwargs)
    events=[]
    result=scan_local(registry,target,github_runner=unavailable,on_event=lambda k,d:events.append((k,d)))
    assert result['status']=='completed'
    assert next(d for k,d in events if k=='secret_found')['git_origin']['status']=='not_established'

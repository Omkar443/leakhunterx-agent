import asyncio
import importlib.util
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
import pytest
from agent.js.leak_detector import EnterpriseLeakDetector, SecretScanner
from agent.js.ignore_policy import IgnorePolicy
from agent.js.provider_validation import verify_github
from agent.js.extractor_context import ExtractorContext


def corpus():
    spec=importlib.util.spec_from_file_location('benchmark_corpus',Path(__file__).resolve().parents[1]/'benchmarks/corpus.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def test_frozen_corpus_exact_identity_and_negative_cases():
    for case in corpus().cases():
        rows=EnterpriseLeakDetector(aggressive=True).check_content(case['content'])
        assert {(row['type'],row['value']) for row in rows} == set(case['expected']),case['id']


def test_case_sensitive_dedup_real_credentials_in_tests_and_safe_context():
    key,rule=corpus().token('github','case-sensitive')
    variant=key[:4]+key[4:].swapcase()
    detector=EnterpriseLeakDetector();detector.source_path='tests/vendor/generated.spec.js'
    rows=detector.check_content(f'const api_key="{key}"; const other="{variant}";')
    assert {row['value'] for row in rows}=={key,variant}
    assert all(key not in row['code_context'] and variant not in row['code_context'] for row in rows)
    assert all(row['severity']=='HIGH' for row in rows)


def test_complete_private_key_parsing_and_body_redaction():
    key,rule=corpus().token('private_keys','disposable-parse-test')
    rows=EnterpriseLeakDetector(aggressive=True).check_content(key+'\nclient.load(privateKey);')
    assert len(rows)==1 and rows[0]['type']==rule
    assert key.splitlines()[1] not in rows[0]['code_context']
    assert not EnterpriseLeakDetector().check_content('-----BEGIN PRIVATE KEY-----\nnot-a-private-key\n-----END PRIVATE KEY-----')


def test_ignore_policy_is_explicit_bounded_and_never_removes_evidence(tmp_path):
    key,rule=corpus().token('github','ignore-policy-test')
    fingerprint=EnterpriseLeakDetector()._generate_leak_signature(rule,key)
    policyfile=tmp_path/'.lhxignore';policyfile.write_text(f'# explicit operator policy\npath:vendor/*\nrule:stripe_key\ntest:{fingerprint}\n')
    policy=IgnorePolicy.load(policyfile)
    assert policy.matches('https://example.invalid/vendor/app.js','generic_api_key','other')
    assert policy.matches('src/main.js',rule,fingerprint)
    assert not policy.matches('src/main.js',rule,'other')
    emitter=AsyncMock();context=ExtractorContext('scan',{'ignore_file':str(policyfile)},emitter)
    asyncio.run(SecretScanner().scan(f'const key="{key}";','https://example.invalid/app.js',context))
    event=emitter.emit.call_args.args[0]
    assert event['data']['suppressed_by_local_policy'] is True
    assert key not in json.dumps(event)
    assert event['data']['ignore_policy_sha256']==policy.digest
    policyfile.write_text('finding:RAW-CREDENTIAL')
    with pytest.raises(ValueError):IgnorePolicy.load(policyfile)
    policyfile.write_text('x'*65537)
    with pytest.raises(ValueError):IgnorePolicy.load(policyfile)


@pytest.mark.parametrize('status,expected',[(200,'authenticated'),(401,'rejected'),(403,'unknown'),(302,'unknown'),(429,'unknown')])
def test_provider_checks_fixed_endpoint_without_redirects_or_account_data(status,expected):
    key,_=corpus().token('github','provider-test')
    requests=[]
    def respond(request):
        requests.append(request)
        assert str(request.url)=='https://api.github.com/user'
        return httpx.Response(status,headers={'Location':'https://evil.example.invalid'})
    original=httpx.AsyncClient
    with patch('agent.js.provider_validation.httpx.AsyncClient',side_effect=lambda **kwargs:original(transport=httpx.MockTransport(respond),**kwargs)):
        assert asyncio.run(verify_github(key,False))['status']=='not_attempted'
        assert requests==[]
        data=asyncio.run(verify_github(key,True))
    assert len(requests)==1 and data=={'provider':'github','status':expected}
    assert key not in json.dumps(data)


def test_provider_network_failure_never_breaks_a_scan_candidate():
    with patch('agent.js.provider_validation.httpx.AsyncClient',side_effect=httpx.ConnectError('offline')):
        assert asyncio.run(verify_github('ghp_'+'syntheticbody',True))['status']=='unavailable'


def test_ai_benchmark_does_not_count_failures_as_agreement():
    import sys
    directory = str(Path(__file__).resolve().parents[1]/'benchmarks')
    sys.path.insert(0,directory)
    from run import ai_metrics
    data={'provider':'fixture','model':'fixture','policy_version':'v1','corpus_sha256':'corpus','items':[
        {'case_id':'a','expected':'VALID','verdict':'FALSE_POSITIVE','status':'completed'},
        {'case_id':'b','expected':'VALID','verdict':'UNCERTAIN','status':'failed'}]}
    metric=ai_metrics(data,{'a':True,'b':True},'corpus')
    assert metric['rate']==1 and metric['coverage']==.5 and metric['undetermined']==1
    with pytest.raises(ValueError):ai_metrics(data,{'a':True,'b':True},'different-corpus')
    data['items'][1]['expected']='FALSE_POSITIVE'
    with pytest.raises(ValueError):ai_metrics(data,{'a':True,'b':True},'corpus')


@pytest.mark.parametrize('kind',['rsa','ec','ssh','encrypted'])
def test_real_private_key_containers_are_parsed_without_disclosing_bodies(kind):
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    from cryptography.hazmat.primitives import serialization as ser
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048) if kind=='rsa' else ec.generate_private_key(ec.SECP256R1()) if kind=='ec' else ed25519.Ed25519PrivateKey.generate()
    fmt=ser.PrivateFormat.OpenSSH if kind=='ssh' else ser.PrivateFormat.PKCS8
    encryption=ser.BestAvailableEncryption(b'local-test-password') if kind=='encrypted' else ser.NoEncryption()
    value=key.private_bytes(ser.Encoding.PEM,fmt,encryption).decode()
    rows=EnterpriseLeakDetector().check_content(value)
    assert len(rows)==1 and value.splitlines()[1] not in rows[0]['code_context']



def test_private_url_components_never_reach_durable_finding_payload():
    key,_=corpus().token('github','url-hygiene-test')
    emitter=AsyncMock();context=ExtractorContext('scan',{},emitter)
    asyncio.run(SecretScanner().scan(f'const key="{key}";',f'https://user:password@example.invalid/config.js?token={key}#secret',context))
    data=emitter.emit.call_args.args[0]['data']
    assert data['source_url']==data['file_path']=='https://example.invalid/config.js'
    assert key not in json.dumps(data) and 'password' not in json.dumps(data)

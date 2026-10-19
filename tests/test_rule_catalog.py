"""Catalog integrity, full-pipeline precision, redaction and independent abuse cases."""
import asyncio,hashlib,json,re,time,sys
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from agent.js.leak_detector import EnterpriseLeakDetector,SecretScanner
from agent.js.rule_catalog import load_catalog,matcher
from agent.js.extractor_context import ExtractorContext

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'benchmarks'))
from catalog_fixtures import cases
CASES=cases()

def test_five_hundred_distinct_exercised_rules_and_packaged_integrity():
    for aggressive in (False,True):
        detector=EnterpriseLeakDetector(aggressive=aggressive)
        assert len(detector.PATTERNS)==500
        assert len({value['pattern'] for value in detector.PATTERNS.values()})==500
    rows,digest=load_catalog()
    assert len(rows)==462 and len({case['rule'] for case in CASES})==462
    assert digest==hashlib.sha256((ROOT/'src/agent/js/catalog.json').read_bytes()).hexdigest()
    assert all(row['references'] and row['upstream_id'] and row['source_path'] for row,_ in rows)

@pytest.mark.parametrize('split',['regression','challenge'])
def test_every_catalog_rule_survives_full_detector_and_placeholder_negatives(split):
    for case in CASES:
        if case['split']!=split:continue
        rows=EnterpriseLeakDetector().check_content(case['content'])
        assert {row['value'] for row in rows}=={case['secret']},case['rule']
        assert case['secret'] not in '\n'.join(row['code_context'] for row in rows)
        for placeholder in ('[REDACTED]','your_api_key_here','x'*len(case['secret'])):
            assert not EnterpriseLeakDetector().check_content(case['content'].replace(case['secret'],placeholder)),case['rule']

def test_keyword_index_never_loses_any_compiled_rule_candidate():
    rows={row['id']:(row,compiled) for row,compiled in load_catalog()[0]}
    for case in CASES:
        row,compiled=rows[case['rule']]
        assert row['keyword'] in case['content'].lower()
        assert compiled.search(case['content'],timeout=.1)
        assert any(rule['id']==case['rule'] for rule,_ in matcher().candidates(case['content'])),case['rule']

def test_unrelated_hashes_public_identifiers_and_template_references_do_not_become_credentials():
    rules={row['id']:row for row,_ in load_catalog()[0]}
    for case in CASES[::2]:
        row=rules[case['rule']];provider=row['upstream_id'].split('.')[1]
        digest=hashlib.sha256(('independent-benign:'+provider).encode()).hexdigest()
        for content in (f'{provider}_checksum = "{digest}";',f'// {provider} API docs\nconst integrity = "sha256-{digest}";',f'{provider}_api_key = process.env.{provider.upper()}_API_KEY;',f'{{"{provider}_public_id":"{digest}"}}'):
            assert not EnterpriseLeakDetector().check_content(content),row['id']

def test_all_detected_neighbor_credentials_are_redacted_for_live_and_private_flows():
    examples=[case for case in CASES if case['split']=='regression' and 'api_key' in case['rule']][:16]
    content='\n'.join(case['content'] for case in examples)
    rows=EnterpriseLeakDetector().check_content(content)
    contexts='\n'.join(row['code_context'] for row in rows)
    for case in examples:assert case['secret'] not in contexts
    async def scan():
        emitter=AsyncMock();context=ExtractorContext('catalog-redaction',{},emitter)
        await SecretScanner().scan(content,'https://example.invalid/assets/app.js',context)
        payload=json.dumps([call.args[0] for call in emitter.emit.call_args_list])
        for case in examples:assert case['secret'] not in payload
    asyncio.run(scan())

def test_rule_budget_failure_is_not_silently_treated_as_a_clean_file(monkeypatch):
    def failed(source):raise RuntimeError('Detector rule budget exceeded')
    monkeypatch.setattr(matcher(),'candidates',failed)
    with pytest.raises(RuntimeError):EnterpriseLeakDetector().check_content('ordinary source')

def test_large_minified_file_and_boundary_tokens_remain_fast_and_complete():
    case=next(case for case in CASES if case['rule']=='pinecone_api_key_pcsk_2')
    content='a'*1_000_000+';'+case['content']+';'+'b'*1_000_000
    started=time.monotonic();rows=EnterpriseLeakDetector().check_content(content)
    assert any(row['value']==case['secret'] for row in rows)
    assert time.monotonic()-started<5

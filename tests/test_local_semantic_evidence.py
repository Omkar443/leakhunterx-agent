import json
from types import SimpleNamespace
from uuid import uuid4
import pytest
from agent.js.leak_detector import EnterpriseLeakDetector
from agent.local.scanner import envelope
from agent.local.semantic_evidence import extract

TOKEN = 'ghp_' + 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5'


def observe(source, path='config.js'):
    finding = EnterpriseLeakDetector().check_content(source)[0]
    return extract(source, path, finding)


def test_authentication_use_is_structured_and_source_free():
    source = f'const proprietaryGithubToken = "{TOKEN}";\nfetch(url, {{headers: {{Authorization: `Bearer ${{proprietaryGithubToken}}`}}}});'
    evidence = observe(source)
    assert evidence['assignment'] == 'literal_assignment'
    assert evidence['variable_role'] == 'credential'
    assert evidence['format_check'] == 'detector_pattern_match'
    assert evidence['usage_categories'] == ['authorization_header']
    assert not evidence['placeholder_detected'] and evidence['entropy_bits_per_character'] > 3
    assert evidence['candidate_references_in_window'] >= 2
    target = dict(id=str(uuid4()), key=b'x'*32, key_id=str(uuid4()))
    artifact = SimpleNamespace(content=source, locator='config.js', language='javascript', content_hash='a'*64)
    record = envelope(target, artifact, EnterpriseLeakDetector().check_content(source)[0])
    for prohibited in (TOKEN, 'proprietaryGithubToken', 'fetch(url', 'Authorization:'):
        assert prohibited not in json.dumps(record)
    assert record['evidence_version'] == 3 and record['semantic_evidence'] == evidence


def test_generic_capture_includes_assignment_but_context_finds_actual_value():
    source = 'const api_key = "n2Jr9Fv6Qp3Mz8Wx5Ks0Tb7Hy4Dc1Ua"; client.configure({api_key});'
    evidence = observe(source)
    assert evidence['assignment'] == 'literal_assignment' and evidence['variable_role'] == 'credential'
    assert evidence['format_check'] == 'generic_assignment_pattern'
    assert 'client_configuration' in evidence['usage_categories']


@pytest.mark.parametrize('path, role', [('tests/config.js','test'), ('docs/config.js','documentation'),
    ('vendor/config.js','generated'), ('.env','configuration'), ('src/config.js','application')])
def test_file_roles_are_observations_not_false_positive_verdicts(path, role):
    evidence = observe(f'const token="{TOKEN}";', path)
    assert evidence['file_role'] == role
    assert 'verdict' not in evidence and not evidence['placeholder_detected']


def test_comment_does_not_claim_executed_authentication():
    evidence = observe(f'// const token="{TOKEN}"; client.configure({{token}});')
    assert evidence['assignment'] == 'literal_without_assignment'
    assert evidence['usage_categories'] == ['comment_or_documentation']


def test_window_is_bounded_and_empty_usage_is_not_unused_claim():
    source = 'a'*10000 + f';const token="{TOKEN}";' + 'b'*10000 + ';client.configure({token});'
    evidence = observe(source)
    assert evidence['window_truncated'] and evidence['window_chars'] <= 4096
    assert evidence['usage_categories'] == []
    assert len(json.dumps(evidence)) < 650


def test_parsed_private_key_exposes_no_key_material():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    value = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    evidence = observe(value, 'config.pem')
    assert evidence['format_check'] == 'parsed_private_key'
    assert 'BEGIN' not in json.dumps(evidence)

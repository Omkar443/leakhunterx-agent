"""Additional detector challenges: real parsed containers, no live credentials."""
import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec

from agent.js.leak_detector import EnterpriseLeakDetector, SecretScanner
from agent.js.extractor_context import ExtractorContext


@pytest.mark.parametrize('newline', ['\\n', '\\r\\n'])
def test_escaped_pem_is_parsed_and_redacted(newline):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()).decode()
    literal = pem.strip().replace('\n', newline)
    source = f'const signingKey="{literal}";\nclient.sign(signingKey);'
    findings = EnterpriseLeakDetector().check_content(source)
    assert len(findings) == 1 and findings[0]['type'] == 'generic_pem_private_key'
    assert pem.splitlines()[1] not in findings[0]['code_context']
    emitter = AsyncMock(); context = ExtractorContext('pem', {}, emitter)
    asyncio.run(SecretScanner().scan(source, 'https://example.invalid/config.js', context))
    payload = json.dumps([call.args[0] for call in emitter.emit.call_args_list])
    assert literal not in payload and pem.splitlines()[1] not in payload


def test_malformed_escaped_key_is_not_a_valid_private_key():
    assert not EnterpriseLeakDetector().check_content(
        'const k="-----BEGIN PRIVATE KEY-----\\nnot-a-private-key\\n-----END PRIVATE KEY-----";')


def test_detector_failure_is_not_silently_reported_as_clean(caplog):
    detector = EnterpriseLeakDetector()
    def failure(value): raise ValueError('private source MUST NOT enter logs')
    detector.PATTERNS['github_token']['validation'] = failure
    with pytest.raises(RuntimeError, match='Detector rule failed: github_token'):
        detector.check_content('const k="ghp_'+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'+'";')
    assert 'MUST NOT' not in caplog.text

"""The direct event, structured result and artifact must preserve review policy."""
import asyncio
import json
from unittest.mock import AsyncMock

from agent.js.extractor_context import ExtractorContext
from agent.js.js_analyzer import EventCollector
from agent.js.leak_detector import SecretScanner
from agent.orchestrator import ScanOrchestrator


def test_structured_artifact_retains_local_policy_and_redacted_evidence(tmp_path):
    key = 'AKIA' + 'E2Z7Q9B3X8C1M5N6'
    ignore = tmp_path / '.lhxignore'
    ignore.write_text('rule:aws_access_key\n', encoding='utf-8')
    emitter = AsyncMock()
    context = ExtractorContext('scan', {'ignore_file': str(ignore)}, emitter)
    asyncio.run(SecretScanner().scan(f'const accessKey = "{key}";', 'https://example.invalid/app.js', context))
    emitted = emitter.emit.call_args.args[0]
    collector = EventCollector()
    collector.collect_secret(emitted)
    scan = ScanOrchestrator.__new__(ScanOrchestrator)
    scan._add_artifact = AsyncMock(return_value=True)
    asyncio.run(scan._process_analysis_result('https://example.invalid/app.js', {'secrets': collector.secrets}))
    artifact = scan._add_artifact.call_args.args[0]
    for field in ('detector_policy', 'suppressed_by_local_policy', 'ignore_policy_sha256', 'provider_validation', 'fingerprint', 'source_sha256', 'code_context'):
        assert artifact[field] == emitted['data'][field]
    assert artifact['suppressed_by_local_policy'] is True
    assert key not in json.dumps(artifact)


def test_provider_observation_survives_structured_collection_without_account_payload():
    collector = EventCollector()
    collector.collect_secret({'event_type': 'secret_found', 'data': {
        'type': 'Github Token', 'fingerprint': 'fixture', 'file_path': '/app.js',
        'provider_validation': {'provider': 'github', 'status': 'unavailable'},
        'detector_policy': 'detector-v1', 'raw_value': 'NEVER-TRANSPORT',
        'account_data': 'NEVER-TRANSPORT',
    }})
    assert collector.secrets[0]['provider_validation']['status'] == 'unavailable'
    assert 'NEVER-TRANSPORT' not in json.dumps(collector.secrets)

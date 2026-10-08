import asyncio
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from agent.events.event_emitter import Event, HTTPBatchEmitter
from agent.events.outbox import DurableOutbox, DeliveryPending
from agent.events.router_emitter import RouterEmitter
from agent.js.js_analyzer import EventCollector, JSAnalysisEngine
from agent.js.extractor_context import ExtractorContext
from agent.js.leak_detector import extract_code_context, build_match_evidence_mask


def test_outbox_restart_stable_receipt_and_bounded_batches(tmp_path):
    path = tmp_path/'private'/'outbox.sqlite3'
    box = DurableOutbox(path)
    for i in range(405):
        box.append(Event('secret_found', 'scan', data={'index':i}).to_dict())
    batch_id, records = box.next_batch()
    reopened = DurableOutbox(path)
    assert reopened.next_batch() == (batch_id, records)
    assert len(records) == 200
    reopened.acknowledge(batch_id)
    assert reopened.count() == 205
    assert len(reopened.next_batch()[1]) == 200
    with pytest.raises(ValueError): box.append(Event('secret_found','scan',data={'text':'x'*(256*1024)}).to_dict())


def test_failed_delivery_blocks_completion_then_replays_before_terminal(tmp_path):
    async def scenario():
        batch = HTTPBatchEmitter('http://127.0.0.1/unused', dlq_dir=tmp_path, batch_size=100)
        batch._send_batch_attempt = AsyncMock(return_value=False)
        realtime = AsyncMock()
        router = RouterEmitter(realtime, batch)
        await router.emit(Event('secret_found','scan',data={'confidence':.95}))
        with pytest.raises(DeliveryPending): await router.emit(Event('scan_completed','scan'))
        assert batch.outbox.count() == 2
        realtime.emit.assert_not_called()
        first_id, first_events = batch.outbox.next_batch()
        replay = HTTPBatchEmitter('http://127.0.0.1/unused', dlq_dir=tmp_path)
        sent = []
        async def acknowledge(identity, events):
            sent.append((identity, [item.event_type for item in events])); return True
        replay._send_batch_attempt = acknowledge
        await replay.drain()
        assert sent[0] == (first_id, ['secret_found', 'scan_completed'])
        assert replay.outbox.count() == 0
    asyncio.run(scenario())


def test_close_and_cancellation_keep_unacknowledged_evidence(tmp_path):
    async def scenario():
        emitter = HTTPBatchEmitter('http://127.0.0.1/unused', dlq_dir=tmp_path)
        emitter._send_batch_attempt = AsyncMock(return_value=False)
        await emitter.emit(Event('secret_found','scan'))
        await emitter.close()
        assert emitter.outbox.count() == 1
    asyncio.run(scenario())


def test_delivery_acknowledges_only_matching_batch_and_never_redirects(tmp_path):
    class Response:
        status = 202
        receipt = {'status': 'accepted', 'received': 1, 'batch_id': 'other-batch'}

        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def json(self): return self.receipt

    class Session:
        closed = False
        response = Response()

        def post(self, endpoint, **kwargs):
            assert kwargs['allow_redirects'] is False
            return self.response

    async def scenario():
        emitter = HTTPBatchEmitter('https://example.invalid/events', dlq_dir=tmp_path, max_retries=0)
        emitter._session = Session()
        event = Event('secret_found', 'scan')
        await emitter.emit(event)
        with pytest.raises(DeliveryPending): await emitter.drain()
        batch_id, _ = emitter.outbox.next_batch()
        assert emitter.outbox.count() == 1
        emitter._session.response.receipt['batch_id'] = batch_id
        await emitter.drain()
        assert emitter.outbox.count() == 0
        emitter._session.response.status = 307
        assert not await emitter._send_batch_attempt('redirect', [event])
    asyncio.run(scenario())


def test_matched_line_survives_large_neighbors_and_credentials_stay_redacted():
    token = 'AKIA' + 'E2Z7Q9B3X8C1M5N6'
    neighbor = 'ghp_' + 'ABCDEFGHIJKLMN0123456789abcdefghijklmno'
    source = '\n'.join(['/*'+'a'*250+'*/']*30 + [f'const accessKey = "{token}";', f'const other = "{neighbor}";', 'client.authenticate(accessKey);'])
    evidence = extract_code_context(source, line_number=31, raw_value=token)
    assert len(evidence['code_context']) <= 3000
    assert '[MATCH]' in evidence['code_context'] and 'authenticate' in evidence['code_context']
    assert token not in evidence['code_context'] and neighbor not in evidence['code_context']
    assert evidence['is_truncated'] and evidence['context_start_line'] <= 31 <= evidence['context_end_line']
    deceptive = 'sk_' + 'live_' + 'realExampleCredential0123456789'
    assert deceptive not in build_match_evidence_mask(deceptive)


def test_collector_preserves_canonical_wrapped_evidence_and_occurrences():
    collector = EventCollector()
    data = dict(type='AWS Access Key', fingerprint='same-key', file_path='config.js', line_number=2,
        code_context='2 | const key="AKIA[REDACTED_16_CHARS]"; <-- [MATCH]',
        match_evidence_mask='AKIA[REDACTED_16_CHARS]', match_length=20, source_sha256='a'*64,
        evidence_version=2, context_truncated=True, raw_value='NEVER-RETURN-RAW')
    collector.collect_secret({'event_type':'secret_found','data':data})
    collector.collect_secret({'event_type':'secret_found','data':data})
    collector.collect_secret({'event_type':'secret_found','data':{**data,'file_path':'other.js'}})
    assert len(collector.secrets) == 2
    assert collector.secrets[0]['code_context'] == data['code_context']
    assert collector.secrets[0]['match_length'] == 20 and collector.secrets[0]['context_truncated']
    assert 'NEVER-RETURN-RAW' not in json.dumps(collector.secrets)


def test_concurrent_assets_keep_separate_results_and_source_provenance():
    async def scenario():
        emitter = AsyncMock()
        context = ExtractorContext('test-scan', {}, emitter)
        engine = JSAnalysisEngine(context)
        try:
            # Construct synthetic detector inputs at runtime, never store complete
            # credential-shaped strings in source or Git history.
            keys = ['AKIA' + suffix for suffix in ('E2Z7Q9B3X8C1M5N6', 'Z6P4R7D9K2X5B3C8')]
            sources = ['const accessKey = "' + key + '";\naws.configure({accessKey});' for key in keys]
            results = await asyncio.gather(*[engine.analyze_js_content(f'https://app.example.invalid/{i}.js', code) for i,code in enumerate(sources)])
            assert context.event_emitter is emitter
            for index, result in enumerate(results):
                assert result.secrets
                for secret in result.secrets:
                    assert secret['source_url'].endswith(f'/{index}.js')
                    assert secret['source_sha256'] == hashlib.sha256(sources[index].encode()).hexdigest()
                    assert '[MATCH]' in secret['code_context'] and secret['evidence_version'] == 2
            serialized = json.dumps([call.args[0] for call in emitter.emit.call_args_list])
            assert all(key not in serialized for key in keys)
        finally:
            await engine.cleanup()
    asyncio.run(scenario())

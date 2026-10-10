import asyncio
import json
from agent.js.extractor_context import ExtractorContext
from agent.js.js_analyzer import JSAnalysisEngine
from agent.events.outbox import DurableOutbox


def test_large_real_bundle_streams_evidence_without_oversized_completion_event():
    async def scenario():
        class BoundedEmitter:
            def __init__(self): self.events = []
            async def emit(self, event):
                if len(json.dumps(event).encode()) > DurableOutbox.MAX_EVENT_BYTES:
                    raise ValueError('Event exceeds the evidence size limit')
                self.events.append(event)
        emitter = BoundedEmitter()
        urls = [f'/api/items/{i}/' + 'x'*250 for i in range(1100)]
        content = 'const apiRoutes = ' + json.dumps(urls) + ';'
        engine = JSAnalysisEngine(ExtractorContext('test-scan', {}, emitter))
        try:
            result = await engine.analyze_js_content('https://example.invalid/app.js', content)
            assert result.success and len(result.endpoints) == 1100
            complete = next(event for event in emitter.events if event['event_type'] == 'js_analysis_complete')
            assert len(json.dumps(complete).encode()) < 4096
            assert sum(event['event_type'] == 'endpoint_found' for event in emitter.events) == 1100
        finally: await engine.cleanup()
    asyncio.run(scenario())

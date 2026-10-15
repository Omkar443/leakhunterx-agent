"""Heartbeats/configuration cannot deadlock source checkpoint transactions."""
from concurrent.futures import ThreadPoolExecutor
from agent.local.registry import Registry
from agent.local.scanner import scan_local


def test_registry_heartbeat_needs_no_write_lock_after_initialization(tmp_path):
    registry = Registry(tmp_path/'private'/'agent.db')
    project = tmp_path/'project'; project.mkdir()
    target = registry.add(project)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with registry.connect() as db:
            db.execute('UPDATE targets SET name=name WHERE id=?', (target['id'],))
            # A writer is deliberately active while another thread initializes
            # the same registry, as each ordinary heartbeat does.
            future = executor.submit(lambda: Registry(registry.path).get(target['id']))
            assert future.result(timeout=3)['id'] == target['id']


def test_event_backpressure_holds_no_checkpoint_lock_or_stale_read_cursor(tmp_path):
    registry = Registry(tmp_path/'private'/'agent.db')
    project = tmp_path/'project'; project.mkdir()
    for index in range(140):
        (project/f'app-{index:03}.js').write_text('const endpoint="https://example.com/api/items";')
    target = registry.add(project)
    emitted = []
    def configuration_read_write():
        latest = Registry(registry.path)
        with latest.connect() as db:
            db.execute('UPDATE targets SET name=name WHERE id=?', (target['id'],))
    with ThreadPoolExecutor(max_workers=1) as executor:
        def event(kind, data):
            if kind == 'asset_reference':
                # The emitter can wait for the event loop while a heartbeat or
                # configuration operation reads/writes this database elsewhere.
                executor.submit(configuration_read_write).result(timeout=3)
                emitted.append(kind)
        result = scan_local(registry, target, on_event=event)
    assert result['status'] == 'completed' and result['complete']
    assert result['processed_files'] == len(emitted) == 140  # crosses pagination boundary

import sys
import json
from unittest.mock import Mock
from agent import cli
from agent.local.registry import Registry


def test_local_only_cli_never_initializes_cloud_browser_or_credentials(tmp_path,monkeypatch,capsys):
    private=tmp_path/'private'; private.mkdir(mode=0o700); root=tmp_path/'project'; root.mkdir()
    (root/'config.js').write_text('const token="ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";')
    registry=Registry(private/'agent.db')
    monkeypatch.setattr('agent.local.registry.Registry',lambda:registry)
    legacy=Mock(side_effect=AssertionError('Cloud/browser initialization prohibited'))
    monkeypatch.setattr(cli,'_legacy',legacy)
    monkeypatch.setattr(sys,'argv',['lhx','scan',str(root),'--local-only','--json'])
    cli.canonical_run()
    report=json.loads(capsys.readouterr().out)
    assert report['summary']['complete'] and report['summary']['findings_count']==1
    assert 'ghp_' not in json.dumps(report) and str(root) not in json.dumps(report)
    legacy.assert_not_called()
    assert not registry.list()[0]['dashboard_allowed']

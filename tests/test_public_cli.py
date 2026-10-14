import json
import sys
from unittest.mock import Mock

import pytest
from agent import cli
from agent.config.config import AgentConfig, DEFAULT_BACKEND_URL
from agent.version import VERSION


@pytest.mark.parametrize('executable', ['lhx', 'lhx-agent'])
def test_public_help_lists_current_commands_without_starting_runtime(monkeypatch, capsys, executable):
    monkeypatch.setattr(sys,'argv',[executable,'--help'])
    launch=Mock(side_effect=AssertionError('Help must not launch a runtime'))
    monkeypatch.setattr(cli,'_legacy',launch)
    with pytest.raises(SystemExit) as exit: cli.run()
    assert exit.value.code == 0
    helptext=capsys.readouterr().out
    for command in ('auth','agent','status','project','scan','resume','ci'): assert command in helptext
    launch.assert_not_called()


def test_runtime_flags_map_to_actual_config_and_restore_environment(monkeypatch):
    monkeypatch.setenv('LHX_BACKEND_URL','https://prior.example.invalid')
    monkeypatch.delenv('LHX_BROWSER_RENDERING',raising=False)
    monkeypatch.setattr(sys,'argv',['lhx','agent','--backend','https://chosen.example.invalid/',
        '--browser','off','--log-level','DEBUG','--log-file','agent.log'])
    def launch(arguments):
        assert arguments == ['--log-level','DEBUG','--log-file','agent.log','run']
        config=AgentConfig.from_env()
        assert config.backend_url == 'https://chosen.example.invalid'
        assert config.browser_rendering == 'off'
    monkeypatch.setattr(cli,'_legacy',launch)
    cli.canonical_run()
    import os
    assert os.environ['LHX_BACKEND_URL']=='https://prior.example.invalid'
    assert 'LHX_BROWSER_RENDERING' not in os.environ


@pytest.mark.parametrize('backend',['http://backend.invalid','https://user:pass@backend.invalid','https://backend.invalid/api','https://backend.invalid?key=x'])
def test_unsafe_runtime_origin_is_rejected_before_connection(monkeypatch,backend):
    monkeypatch.setattr(sys,'argv',['lhx','agent','--backend',backend])
    launch=Mock(); monkeypatch.setattr(cli,'_legacy',launch)
    with pytest.raises(SystemExit) as exit: cli.canonical_run()
    assert exit.value.code == 2
    launch.assert_not_called()


@pytest.mark.parametrize('option',['--json','--local-only','--profile'])
def test_web_options_are_not_silently_ignored(monkeypatch,option):
    arguments=['lhx','scan','https://example.invalid',option]
    if option=='--profile': arguments.append('deep')
    monkeypatch.setattr(sys,'argv',arguments)
    launch=Mock(); monkeypatch.setattr(cli,'_local_command',launch)
    with pytest.raises(SystemExit) as exit: cli.canonical_run()
    assert exit.value.code == 2
    launch.assert_not_called()


def test_pairing_uses_runtime_backend_and_package_version(monkeypatch,tmp_path):
    from agent import pair_agent
    monkeypatch.delenv('LHX_BACKEND_URL',raising=False)
    assert AgentConfig.from_env().backend_url == DEFAULT_BACKEND_URL == 'https://backend-leakhunterx.onrender.com'
    monkeypatch.setenv('LHX_BACKEND_URL','https://selected.example.invalid')
    response=Mock(status_code=201); response.json.return_value={'agent_id':'fixture-id','agent_secret':'fixture-secret'}
    request=Mock(return_value=response)
    monkeypatch.setattr(pair_agent.httpx,'post',request)
    monkeypatch.setattr(pair_agent,'exec_agent',Mock())
    monkeypatch.setattr(pair_agent,'SECRET_PATH',tmp_path/'private/agent_secret.json')
    pair_agent.pair_agent('fixture-token')
    assert request.call_args.args[0]=='https://selected.example.invalid/api/v1/agents/pair'
    assert request.call_args.kwargs['json']['version']==VERSION
    assert json.loads(pair_agent.SECRET_PATH.read_text())['backend_url']=='https://selected.example.invalid'


def test_log_file_without_directory_is_supported(monkeypatch,tmp_path):
    from agent.lhx_agent import AgentCLI
    monkeypatch.chdir(tmp_path)
    import logging
    root=logging.getLogger(); handlers=list(root.handlers); level=root.level
    try:
        AgentCLI.setup_logging('INFO','agent.log')
        logging.getLogger('agent-test').info('safe-log')
        for handler in root.handlers: handler.flush(); handler.close()
    finally:
        root.handlers=handlers; root.setLevel(level)
    assert 'safe-log' in (tmp_path/'agent.log').read_text()


@pytest.mark.parametrize('arguments',[
    ['lhx-agent','--log-level','DEBUG','run'],
    ['lhx-agent','run','--log-level','DEBUG'],
])
def test_legacy_logging_flags_work_on_either_side_of_subcommand(monkeypatch,arguments):
    from agent.lhx_agent import AgentCLI
    monkeypatch.setattr(sys,'argv',arguments)
    assert AgentCLI.parse_args().log_level=='DEBUG'

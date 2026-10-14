"""Public CLI vocabulary; existing scanning and connection logic stays in place."""
import argparse
from contextlib import contextmanager
import getpass
import json
import os
import sys
from urllib.parse import urlsplit

import httpx

LOG_LEVELS = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')


def _https_backend(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.path not in ('', '/') or any(c.isspace() for c in value)):
            raise ValueError()
        parsed.port
        return value.rstrip('/')
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError('Backend must be an HTTPS origin without credentials, query or path') from None


def _seconds(value):
    try:
        result = int(value)
        if not 1 <= result <= 86400: raise ValueError()
        return result
    except ValueError:
        raise argparse.ArgumentTypeError('Timeout must be 1–86400 seconds') from None


@contextmanager
def _connection_options(args):
    selected = {}
    if getattr(args, 'backend', None): selected['LHX_BACKEND_URL'] = args.backend
    if getattr(args, 'browser', None): selected['LHX_BROWSER_RENDERING'] = args.browser
    previous = {key: os.environ.get(key) for key in selected}
    os.environ.update(selected)
    try: yield
    finally:
        for key, value in previous.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value


def _status(as_json: bool = False) -> None:
    from agent.config.config import AgentConfig
    from agent.lhx_agent import load_agent_credentials

    try:
        config = AgentConfig.from_env()
        agent_id, secret = load_agent_credentials()
        parsed = urlsplit(config.backend_url)
        if (parsed.username or parsed.password or parsed.query or parsed.fragment
                or not parsed.hostname or (parsed.scheme != 'https'
                and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')))):
            raise ValueError('Unsafe backend URL')
        # GET only: never claim an assignment, consume a command or refresh presence.
        with httpx.stream('GET', f'{config.backend_url.rstrip("/")}/api/v1/agent/status',
                          headers={'X-Agent-Id': agent_id, 'X-Agent-Secret': secret,
                                   'Accept': 'application/json'}, timeout=10, follow_redirects=False) as response:
            if response.status_code != 200:
                print(f'Status unavailable (HTTP {response.status_code}). No registration changed.', file=sys.stderr)
                raise SystemExit(1)
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > 65536:
                    raise ValueError('Oversized status response')
        data = json.loads(body)
        states = ('connected', 'idle', 'scanning', 'updating', 'disconnected')
        if (not isinstance(data, dict) or type(data.get('connected')) is not bool
                or data.get('state') not in states
                or data['connected'] != (data['state'] != 'disconnected')):
            raise ValueError('Invalid status response')
        result = {'agent_id': agent_id, 'connected': data['connected'], 'state': data['state']}
        if as_json:
            print(json.dumps(result))
        else:
            print(f'Agent: {agent_id}\nStatus: {data["state"]}')
    except (httpx.HTTPError, RuntimeError, ValueError, OSError):
        # Never expose server bodies, URLs containing credentials, or credential-file contents.
        print('Status unavailable. Check your connection and agent credentials; use lhx auth to connect.', file=sys.stderr)
        raise SystemExit(1)


def _legacy(arguments: list[str]) -> None:
    from agent.lhx_agent import main
    previous = sys.argv
    try:
        sys.argv = [previous[0], *arguments]
        main()
    finally:
        sys.argv = previous


def canonical_run() -> None:
    arguments = sys.argv[1:]
    # Compatibility for installed supervisors, launchers, and existing operators.
    if arguments and arguments[0] in ('run', 'pair'):
        _legacy(arguments)
        return
    parser = argparse.ArgumentParser(prog='lhx', description='LeakHunterX local scanning agent',
        epilog='Connect: lhx auth · Start: lhx agent · Inspect: lhx status · Command options: lhx <command> --help')
    from agent.utils.helpers import get_version
    parser.add_argument('--version', action='version', version=f'LeakHunterX Agent v{get_version()}')
    commands = parser.add_subparsers(dest='command', required=True)
    service = commands.add_parser('service', help='Manage an optional Linux systemd user service (no sudo)')
    service.add_argument('action', choices=('install', 'start', 'stop', 'restart', 'status', 'logs', 'uninstall'))
    service.add_argument('--backend', type=_https_backend, help='Install only: persist the trusted HTTPS backend origin')
    auth = commands.add_parser('auth', help='Connect using a hidden dashboard connection-token prompt and start')
    auth.add_argument('--backend', type=_https_backend, help='HTTPS backend origin; defaults to the production backend or LHX_BACKEND_URL')
    for name in ('agent', 'start'):
        runtime = commands.add_parser(name, help='Start the agent for dashboard assignments' if name == 'agent' else 'Alias for agent')
        runtime.add_argument('--backend', type=_https_backend, help='HTTPS backend origin; defaults to the production backend or LHX_BACKEND_URL')
        runtime.add_argument('--browser', choices=('on','off'), help='Headless rendering alongside HTTP crawling (default: on or LHX_BROWSER_RENDERING)')
        runtime.add_argument('--log-level', choices=LOG_LEVELS, default='INFO', help='Diagnostic logging level (default: INFO)')
        runtime.add_argument('--log-file', help='Write diagnostic logs to this file')
    status = commands.add_parser('status', help='Read backend-confirmed agent status without changing it')
    status.add_argument('--backend', type=_https_backend, help='HTTPS backend origin; defaults to production or LHX_BACKEND_URL')
    status.add_argument('--json', action='store_true', help='Output the minimal status fields as JSON')
    project = commands.add_parser('project', help='Manage machine-local targets and dashboard consent')
    actions = project.add_subparsers(dest='action', required=True)
    add = actions.add_parser('add')
    add.add_argument('path',help='Local directory or https://github.com/owner/repository')
    add.add_argument('--name')
    add.add_argument('--project-id', help='Owning dashboard project ID; required to sync this target')
    add.add_argument('--profile', choices=('quick', 'standard', 'deep'), default='standard')
    actions.add_parser('list')
    for operation in ('show', 'allow-dashboard', 'deny-dashboard', 'remove', 'set-path'):
        command = actions.add_parser(operation)
        command.add_argument('target_id')
        if operation == 'set-path': command.add_argument('path')
    scan = commands.add_parser('scan', help='Scan a local directory, GitHub repository or live website')
    scan.add_argument('target')
    scan.add_argument('--local-only', action='store_true', help='Local directories only: prohibit cloud, browser, repository downloads and provider requests')
    scan.add_argument('--profile', choices=('quick', 'standard', 'deep'), help='Local/repository resource profile; does not apply to live websites')
    scan.add_argument('--json', action='store_true', help='Redacted local/repository JSON result; not supported for live website scans')
    resume = commands.add_parser('resume', help='Resume an interrupted local scan using its protected checkpoint')
    resume.add_argument('scan_id')
    resume.add_argument('--json', action='store_true')
    ci=commands.add_parser('ci',help='Request a pinned scan and wait for its security policy result')
    from agent.config.config import DEFAULT_BACKEND_URL
    ci.add_argument('--backend',type=_https_backend,default=DEFAULT_BACKEND_URL,help='Trusted HTTPS backend origin (default: production)')
    ci.add_argument('--commit',required=True,help='Exact default-branch commit SHA')
    ci.add_argument('--policy-id',required=True,help='Exact configured security policy UUID')
    ci.add_argument('--request-id',help='Stable UUID for retrying the same CI request')
    ci.add_argument('--timeout',type=_seconds,default=2400,help='Wait budget in seconds, 1–86400 (default: 2400)')
    args = parser.parse_args(arguments)
    if args.command == 'service':
        from agent.service import manage
        if args.backend and args.action != 'install':
            parser.error('--backend applies only to service install')
        manage(args.action, args.backend)
    elif args.command == 'ci':
        from agent.ci import run as ci_run
        ci_run(args)
    elif args.command == 'status':
        with _connection_options(args):
            _status(args.json)
    elif args.command in ('agent', 'start'):
        legacy = [] if args.log_level == 'INFO' else ['--log-level', args.log_level]
        if args.log_file: legacy.extend(['--log-file', args.log_file])
        with _connection_options(args):
            _legacy([*legacy, 'run'])
    elif args.command in ('project', 'scan', 'resume'):
        if (args.command == 'scan' and args.target.startswith(('http://','https://'))
                and not args.target.startswith('https://github.com/')
                and (args.local_only or args.profile or args.json)):
            parser.error('Live website scans do not support --local-only, --profile or --json; use these with a local directory or repository as described in --help')
        _local_command(args)
    elif args.command == 'auth':
        try:
            token = getpass.getpass('Connection token: ').strip()
        except (KeyboardInterrupt, EOFError):
            raise SystemExit(130)
        if not token:
            parser.error('Connection token cannot be empty')
        with _connection_options(args):
            from agent.pair_agent import pair_agent
            pair_agent(pairing_token=token)


def _local_command(args):
    # Keep imports lazy: local-only never initializes cloud clients, browser
    # downloads, credential providers, telemetry or the backend agent loop.
    from agent.local.registry import Registry
    from agent.local.scanner import scan_local, result, local_delta
    try:
        registry = Registry()
        if args.command == 'project':
            if args.action == 'add':
                target = (registry.add_repository(args.path,args.name,args.project_id,args.profile) if args.path.startswith('https://github.com/')
                          else registry.add(args.path, args.name, args.project_id, args.profile))
            elif args.action == 'list':
                print(json.dumps([dict(id=t['id'], name=t['name'], dashboard_allowed=bool(t['dashboard_allowed']), profile=t['profile']) for t in registry.list()], indent=2))
                return
            elif args.action == 'remove':
                registry.remove(args.target_id)
                print('Target unregistered. Project files retained.')
                return
            elif args.action == 'set-path': target = registry.update(args.target_id, path=args.path)
            elif args.action in ('allow-dashboard', 'deny-dashboard'): target = registry.update(args.target_id, allowed=args.action == 'allow-dashboard')
            else: target = registry.get(args.target_id)
            print(json.dumps(dict(id=target['id'], name=target['name'], source_type=target['source_type'], repository_url=target['repository_url'], profile=target['profile'], dashboard_allowed=bool(target['dashboard_allowed']), project_id=target['project_id']), indent=2))
            return
        if args.command == 'resume':
            with registry.connect() as db:
                checkpoint = db.execute('SELECT target_id FROM scans WHERE id=?', (str(__import__('uuid').UUID(args.scan_id)),)).fetchone()
            if not checkpoint: raise ValueError('Checkpoint unavailable')
            target = registry.get(checkpoint['target_id'])
            summary = scan_local(registry, target, scan_id=args.scan_id, resume=True)
        else:
            if args.target.startswith('https://github.com/'):
                if args.local_only: raise ValueError('Local-only scanning cannot download a repository')
                from agent.sources.github import repository_url
                url=repository_url(args.target)
                target=next((t for t in registry.list() if t.get('repository_url')==url),None) or registry.add_repository(url)
                summary=scan_local(registry,target,profile=args.profile)
            elif args.target.startswith(('http://', 'https://')):
                if args.local_only: raise ValueError('Local-only scanning requires a local directory')
                if args.profile: raise ValueError('Profiles apply to local directories')
                # Existing URL orchestration remains the source of web behavior.
                _legacy(['run', args.target, '--cli'])
                return
            else:
                target = registry.find_path(args.target) or registry.add(args.target)
                summary = scan_local(registry, target, profile=args.profile)
        report = dict(summary=summary, delta=local_delta(registry, summary['scan_id']), assessment=result(registry, summary['scan_id'])) if summary['scope_fingerprint'] else dict(summary=summary)
        if args.json: print(json.dumps(report, indent=2))
        else:
            print(f"Scan {summary['scan_id']} · {summary['status']}\n{summary['processed_files']} files · {summary['findings_count']} candidates · {summary['elapsed_seconds']}s\nSource and credentials stayed on this machine.")
        if summary['status'] in ('cancelled','interrupted'): raise SystemExit(130)
        if summary['status'] != 'completed': raise SystemExit(1)
        if not summary['complete']: raise SystemExit(2)
    except (ValueError, OSError, RuntimeError):
        print('Local operation unavailable. Check the registered target, path access and scan scope.', file=sys.stderr)
        raise SystemExit(1)


def run() -> None:
    """Legacy executable keeps its existing options; new commands also work in binaries."""
    legacy_options = {'--log-level','--log-file','--operator-id','--mode',
                      '--shutdown-timeout','--cli','--resume-scan'}
    if not sys.argv[1:] or sys.argv[1] in legacy_options:
        _legacy(sys.argv[1:])
    else:
        canonical_run()

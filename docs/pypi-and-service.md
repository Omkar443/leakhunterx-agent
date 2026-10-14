# Python installation and background operation

The distribution is `leakhunterx-agent`; the executable is `lhx`. Python 3.10+
is required. Use a persistent virtual environment (or pipx) rather than sudo pip.
After publication:

```sh
python3 -m venv ~/.venvs/leakhunterx
~/.venvs/leakhunterx/bin/python -m pip install leakhunterx-agent
~/.venvs/leakhunterx/bin/lhx auth
```

For a release candidate, pip requires `--pre`. Registration requires a connection
token from the dashboard. Headless Chromium is prepared on first runtime start;
Linux browser OS libraries may require administrator installation using
`python -m playwright install-deps chromium` in this environment. Browser or
network restrictions are reported honestly; pip alone cannot install OS libraries.

## Optional Linux systemd service

Run as the same non-root user that registered the agent. Stop the foreground
runtime first. No token is written in the service unit or command arguments.

```sh
lhx service install
lhx service start
lhx service status
lhx service logs
lhx service restart
lhx service stop
lhx service uninstall
```

Install creates `~/.config/systemd/user/leakhunterx-agent.service`, but does not
start it. Start enables login startup; stop disables startup as well as stopping
the runtime. Uninstall retains credentials and local scan history. Use
`--backend https://your-backend.example` on install for another environment;
the installation captures that origin, not secrets or arbitrary environment.
Runtime overrides in your interactive shell are not inherited by the service.
Reinstall to change its backend; restart to apply it. The virtual environment
must remain in its original location. Local targets must be readable by this user.

For operation after logout/reboot without login, an administrator can enable
`loginctl enable-linger USERNAME`. This is explicitly opt-in. No sudo/root service
is created by the agent. On WSL, systemd must be enabled; otherwise use foreground
mode. macOS and Windows service managers are not supported by these commands.
SIGTERM uses existing scan interruption/recovery and disconnect logic; systemd
allows 60 seconds before terminating the process group. Failed runtimes restart
with a delay and bounded restart attempts. Logs go to the user journal; apply
your host's journal retention policy and do not share unredacted debug logs.

## Maintainer publication

Build with `python -m build`, validate with `python -m twine check dist/*`, and
test the wheel in a fresh environment. The release workflow uses PyPI Trusted
Publishing: configure a publisher for repository `Omkar443/leakhunterx-agent`,
workflow `release.yml`, environment `pypi` on PyPI. No API token goes in the repo.
Package name availability and publisher setup must be completed by the owner.
Stable publication retains the existing release acceptance gates; changing the
package name does not manufacture acceptance evidence. Do not tag a stable
release until those gates pass. A main push builds no public release.

An exact `v1.1.0rc1` tag on main history publishes the matching candidate after
automated verification and both binary smoke tests. GitHub marks it prerelease;
PyPI retains its `rc1` version, installed explicitly with `--pre`. Manual workflow
runs never publish. Candidate publication does not satisfy stable acceptance.

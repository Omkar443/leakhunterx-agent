# Headless browser discovery

Browser rendering supplements HTTP crawling inside the local agent. It does
not change deterministic detectors, AI validation or evidence-delivery barriers.
No browser dependencies or browser binaries are downloaded during a scan.

## Download, register and run

Standalone Windows x64 and Linux x64 builds include headless Chromium, the
Playwright driver and Python. Register once with a dashboard connection token:

```sh
lhx-agent pair
# On subsequent starts:
lhx agent
```

Rendering is enabled by default alongside normal HTTP crawling. The CLI alias
`lhx` is installed with the package/installer; existing `lhx-agent` and
`python3 src/lhx_agent_entry.py` starts also enable rendering. Python installations
include Playwright as a required dependency and automatically populate its
versioned browser cache on first start (internet required). Released executables
always use their embedded browser and ignore external browser-cache overrides.
There are no browser enablement commands or configuration files to edit.

Run as an ordinary OS user. Chromium's sandbox is mandatory; the agent never
silently adds `--no-sandbox` if the host cannot support it.

An operator can explicitly disable rendering with `LHX_BROWSER_RENDERING=off`.
A missing browser, unsupported OS, crash, timeout or memory limit records unavailable
or limited browser coverage; successful HTTP analysis can still complete.
Never launch a personal browser profile to work around missing dependencies.
Supported Linux hosts need Chromium's OS libraries and working user namespaces;
minimal containers may need those installed by their administrator. Windows builds
are native x64 executables. macOS currently uses the Python installation.

## Build verification

`python packaging/build.py` prepares the matching browser inside the Playwright
package before PyInstaller runs. Only headless Chromium is embedded. The release
workflow builds each OS natively and runs `packaging/browser_smoke.py` against the
produced executable with an empty user/cache directory. That test loads delayed
JavaScript, discovers a GET endpoint and verifies POST blocking without registering
an agent or contacting a backend. Workers reuse the already unpacked bundle.

## Budgets

| Setting | Default | Hard maximum |
| --- | ---: | ---: |
| `LHX_BROWSER_TIMEOUT` | 75 seconds | 120 seconds |
| `LHX_BROWSER_MAX_PAGES` | 3 | 5 |
| `LHX_BROWSER_MAX_REQUESTS` | 200 | 300 |
| `LHX_BROWSER_SETTLE_MS` | 1500 ms | 5000 ms |
| `LHX_BROWSER_MEMORY_MB` | 768 MiB | 1024 MiB |

One tab explores pages sequentially. Navigation has a 15-second timeout; each
guarded network request has a 10-second timeout and concurrency is capped at 4.
Network bodies total at most approximately 20 MiB (one chunk of overshoot per
concurrent request), each document is at most 2 MiB and other responses at most
5 MiB. Retained JavaScript totals 8 MiB. Successfully observed scripts beyond
that retained-content limit enter the regular bounded HTTP analysis queue.
DOM snapshots are capped at 1 MiB characters per page; truncated DOM is excluded.
The supervisor measures RSS of the worker and its descendants once per second,
so this is a watchdog budget rather than a kernel memory reservation.

## Network and isolation

The worker receives only target, budgets and parent identity; agent credentials,
backend URL, proxy credentials and arbitrary Python environment hooks are not
forwarded. Each scan creates a new anonymous browser context. Downloads, popups,
WebSockets and service workers are disabled; no forms or login actions run.
Only HTTP GET document/script/style/fetch/XHR requests to the target hostname
and port are eligible. HTTPS cannot downgrade to HTTP. Other hosts, protocols,
ports and mutation methods are blocked and reflected in coverage limitations.
Images/fonts/media are intentionally skipped; sites depending on blocked
resources may render incompletely.

Playwright never continues a network request directly. Permitted responses are
fetched by aiohttp with ScanResolver, checking actual resolved IPs on every
connection. Redirect destinations are validated before the browser follows them.
TLS verification is mandatory. A per-worker deny proxy, disabled QUIC and
non-proxied WebRTC policy also constrain channels not intercepted by routing.
Private addresses require the existing explicit `LHX_ALLOW_PRIVATE_TARGETS=true`
setting. Link-local, cloud metadata, multicast and unspecified addresses stay
prohibited even then. This is browser-level isolation, not a substitute for an
OS/container egress policy when operating a hosted multi-tenant agent service.

Workers are killed on cancellation/timeout/memory overrun, and watch parent
process identity so ordinary parent exit does not leave scans running. Linux
cleanup kills the worker's own process group; Windows cleanup terminates its
owned process tree. Abnormal host power loss is handled by the existing scan
assignment recovery contract. The renderer has no durable credentials or state.

## Evidence, Delta and progress

Actual 200 JavaScript responses are consumed by the existing analyzer without a
second download. Coverage receipts are written only after successful detector
analysis and evidence delivery. Failed or cancelled scans remain excluded from
published findings and reports. Observed GET endpoints are informational, not
claims of exploitable vulnerabilities. Query strings are removed from observed
endpoint telemetry. API response bodies are not sent to backend AI by rendering.

Rendered DOM supplements detection context, but its acquisition policy is
distinct from a static document. A clean static HTTP response cannot resolve a
browser-only detection. Such detections remain Unverified if absent in a later
scan: automatic DOM remediation verification is deliberately conservative.
Loaded JavaScript uses existing per-asset Delta verification and historical URL
rechecks. Browser response acquisition has a distinct policy too: browser and
static HTTP can receive different representations of the same URL. Resolution
requires a successful check under a compatible acquisition/detector policy.
Rendering does not guarantee execution of every route or lazy chunk.

The CLI, dashboard and scan analysis show Rendering within Discovery, with real
page/request counters. Rendering status and coverage warnings survive refresh
and appear in report previews/PDFs. Rendering completion is never advertised as
complete website coverage. Browser limitations do not disable successful HTTP
findings or turn an unchecked historical asset into Resolved.

## Verification

```sh
LHX_TEST_BROWSER=1 PYTHONPATH=src python3 -m pytest tests/test_browser_rendering.py
```

The integration fixture is a local server containing delayed script loading,
API requests, prohibited POST and a metadata redirect. No external target is
scanned. Unit regressions cover configuration, scope/credential blocking,
captured-content analysis, distinct DOM policy, evidence delivery failure and
owned-worker cancellation. Backend tests cover persisted snapshots, late events,
public field filtering and report contracts. Staging rollout requires restarting
the updated agent; rendering is on automatically. Existing explicit `off` settings
are respected.

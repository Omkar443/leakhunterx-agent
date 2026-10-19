# Historical acquisition reliability

Historical scans inspect supported archived text on the agent. Archived JavaScript
is never executed. A live website response is never substituted for archive evidence.

## Components and recovery

- `ArchiveClient` validates Wayback CDX and replay responses. `ArchiveDiscovery`
  partitions dates fairly across JavaScript, maps and supported text without
  narrowing the authorized domain or subdomain scope.
- `ArchiveRecovery` persists retry attempts and retry times within the original
  scan deadline. It respects Retry-After, supports cancellation during a stalled
  request or backoff, and does not create another scan or restore allowance.
- `HistoryState` persists index cursors, completed query partitions and the selected
  manifest in the private agent registry. Restarting does not reset the request
  budget or original assignment deadline.
- `WaybackProvider` is primary. A `history-v2` assignment can use Common Crawl if
  Wayback cannot establish any usable captures after bounded recovery. Available
  partial Wayback captures are retained instead of discarded. Access/scope refusals
  are not bypassed. There is no live-fetch fallback.
- `CommonCrawlProvider` queries at most four collections sampled across the requested
  period and 16 index requests across retries/restarts. Selected captures remain
  explicitly limited coverage, not a complete archive inventory.

The default assignment deadline remains ten minutes. With a second provider, the
primary discovery window is at most four minutes, leaving recovery and analysis
headroom. Wayback discovery permits 24 requests across restarts and 180 seconds
per planning pass, two bounded response pages per query, and a circuit stop after
four consecutive failures. HTTP requests have total deadlines; raw and decoded
bodies, scan bytes, selected captures, analysis CPU and memory are bounded. These
operational safety limits are separate from Free/Pro scan allowances and do not
reduce detector quality on Free.

## Evidence and privacy

Common Crawl downloads only the indexed byte range from `data.commoncrawl.org`.
The agent verifies HTTP 206, Content-Range, exact length, gzip integrity, the single
WARC response, original URL, capture time and payload digest. The `warcio` parser
runs in a disposable process with CPU, memory and time bounds. Both providers
reject arbitrary storage URLs, unsupported encodings, unsafe redirects and content
outside the authorized target/date scope.

The local artifact cache uses authenticated encryption derived from the target
identity key. Entries are bound to scope, provider, record locator and requested
capture time, expire after seven days, and share a 100 MB/4096-entry storage cap.
Source text and unredacted secrets stay on the agent. Redacted findings and approved
capture provenance alone enter the cloud. Provider bodies never enter failure
messages. Corrupt cache entries become misses; they cannot establish clean coverage.

Common Crawl provenance includes collection, object locator, byte range and digest;
Wayback provenance retains its existing identity format. Source-map associations
retain their own provider provenance and cannot use a map newer than the bundle.
Reports, AI context and exposure correlation keep historical observations separate
from current presence and credential activity.

No usable captures is an explicit failure with a finite cause. Missing evidence
never means no exposure. Partial discovery remains partial after restart. If both
providers are unavailable, scanning stops within its deadline; it cannot guarantee
archive availability. Waiting/retrieving states appear in the agent, dashboard and
scan detail without replacing measured analysis percentages.

## Compatibility and deployment

1. Deploy the backend's validated failure codes, recovery states, provider metadata
   and `history-v2` capability negotiation. Existing agents still receive v1 scopes.
2. Deploy the frontend's matching progress, provider labels and evidence links.
3. Publish a newly versioned agent, upgrade it and restart the service. Do not
   publish the changed candidate over the already released rc11 version.

`HISTORICAL_SCAN_V1=true` remains the existing backend feature flag. No additional
provider credential, paid archive account or new environment variable is required.
The negotiated protocol is frozen when the backend claims the scan. New agents
can downgrade their heartbeat capability for an older backend; v1 assignments keep
legacy evidence fields and Wayback-only acquisition. No historical schema migration
is required. Unrelated unreleased changes require their own review.

## Verification and acceptance

See `test_historical_resilience.py`, `test_history_durability.py` and
`test_history_commoncrawl.py`. Backend integration tests run the actual detector,
private event delivery, finalization, Delta, AI fixture, PDF/JSON reports and repeated
scans through both providers. Provider responses and AI results in these tests are
controlled fixtures; they are not hosted acceptance evidence.

Read-only live checks on 19 October 2026 reproduced Wayback server errors/timeouts.
Common Crawl returned real catalog/index responses earlier, but the final real
range probe could not reach a usable record because both tested indexes returned
server errors. No successful hosted historical assessment or real WARC acquisition
is claimed. The local candidate is not deployed or uploaded to PyPI.

After deployment/release, manual acceptance remains:

1. Scan the requested target/period with the installed agent and inspect actual
   provider provenance, recorded limitations and matching dashboard/detail progress.
2. Cancel while waiting, then restart the agent during another active assessment;
   verify bounded recovery without duplicate findings or another allowance charge.
3. Repeat from a second machine/service installation. Windows standalone binaries
   and protected PyPI publishing still require the release workflow checks.

Local automated results are recorded in `docs/historical-verification-2026-10-19.md`.
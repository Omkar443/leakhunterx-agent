# Historical recovery verification — 19 October 2026

Status: combined historical recovery and 500-rule source candidate, 1.1.0rc12.
The earlier historical-only QA wheel used rc11 locally; the combined candidate has
its own version. Git publication does not establish hosted deployment, a successful
live archive scan, or PyPI publication. PyPI remains rc11 pending a protected release.

| Check | Actual result | Evidence under Full-Site/tmp |
| --- | --- | --- |
| Full agent regression | 381 passed, 8 skipped | history-final-agent.log |
| Agent installed by pip into a separate QA directory | 75 passed | history-installed-tests.log; history-final-wheel.log |
| Backend historical/progress/event/browser/workspace regression | 79 passed | history-final-backend.log |
| Actual detector → backend → AI fixture → Delta → PDF/JSON; both providers, AI available/unavailable, repeated scans | 4 passed | history-provider-integration.log |
| Isolated PostgreSQL ownership, migration and admission | 3 passed | history-postgres.log |
| Full frontend Vitest regression | 366 passed | history-final-vitest.log |
| Node frontend suites | 51 passed | history-node.log |
| Latest dashboard/detail archive waiting states and measured progress | 18 passed | history-progress-ui.log |
| Provider evidence, retry presentation, parser and store focused UI | 31 passed | history-focused-ui.log |
| TypeScript + production build | Passed | history-final-types.log; history-final-build.log |
| Real Chromium, compiled application, both themes, widths 390/768/1440/2560 | 8 layouts passed, no root overflow/page errors; deferred evidence, empty/error/retry states | history-production-ui/results.json; history-production-browser.log |

Counts overlap across focused/regression suites; do not add them together as
independent coverage. Skipped tests are not verified checks. Browser auth/API and
AI are isolated fixtures, not production accounts or live AI confirmation.

The installed runtime import path was checked as
`/tmp/lhx-history-installed-qa/agent/history/runtime.py`. Installed tests include
WARC checksum/range/URI/time validation, compressed-content bounds, parser crash,
provider route restrictions, fallback evidence privacy, persisted retry budgets,
index-cursor recovery, cancellation and protocol downgrade.

Actual live evidence: Wayback returned 503/timeouts; Common Crawl catalog/index
responses sometimes succeeded, but the final record-range attempt received server
errors from CC-MAIN-2026-39 and CC-MAIN-2026-34. No real WARC acquisition or hosted
historical scan passed in this run. Logs: history-commoncrawl-probe.log and
history-live-warc.log. Do not promote fixture success to external acceptance.

Remaining release/manual gates:

1. Deploy the combined backend first and frontend next, then install the rc12 source
   candidate. Unrelated local notification changes are excluded from this delivery.
2. Upgrade/restart an installed agent and run the requested target/date range;
   inspect provider provenance, limited coverage, reports and synchronized progress.
3. Verify cancellation and restart on the real service installation, then a second
   machine. Run the protected Linux/Windows release checks before public publishing.

No new archive account, provider secret or environment variable is needed. The
existing backend `HISTORICAL_SCAN_V1=true` gate remains. Archive availability is
external; when no provider supplies verified evidence, the correct outcome remains
unavailable/incomplete rather than a clean result.

## Combined detector candidate verification

After detector expansion, the complete agent suite passed 390 tests (8 skipped).
The exact staged backend/agent pair passed 95 integration/regression tests without
the unrelated notification changes. The final pip-installed wheel passed 68 focused
detector/historical tests; its imports resolve inside the disposable installation,
not repository source. A clean dependency install and `pip check` passed; wheel and
sdist passed `twine check`, including packaged catalog and third-party notices.
The exact scoped frontend also passed TypeScript, 51 Node tests, 38 focused
component/utility tests and its production build with public browser configuration.

All 500 canonical rule identities are finite at cloud ingestion. The new challenge
passed 924 synthetic positives and 2,772 negatives. The unchanged 400-file and
120-case benchmark sets still passed with no missed expected findings or false
positives. These are offline synthetic results, not production accuracy guarantees.
The expanded corpus was used during development and is not an untouched holdout.

Existing redacted historical analysis checkpoints from an older detector policy
cannot silently become a complete scan under v4; those assignments require a fresh
assessment. Local/GitHub per-file analysis is already keyed by detector policy.

Final run evidence: `catalog-final-agent.log`, `catalog-staged-backend.log`,
`catalog-installed-tests.log`, `catalog-final-build.log` and the committed
`benchmarks/results/catalog-*.json`. Temporary logs live in `Full-Site/tmp`.

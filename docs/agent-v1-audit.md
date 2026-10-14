# Agent v1 release-candidate audit — 14 October 2026

Engineering and automated verification completed for this patch. Public v1
acceptance remains pending the hosted and release gates below; acceptance flags
were not set to true and no main merge or stable release was performed.

## Fixed coverage and reliability defects

- Follow literal static/dynamic imports, re-exports and worker dependencies through
  the existing JavaScript queue. Discovery precedes content deduplication so the
  same module body under different directories resolves its own relative imports.
  Requests retain the existing scope, DNS, TLS and redirect checks.
- Preserve query encoding/order, encoded path separators and trailing-slash
  directories. Pagination is distinct; fragment-only links share one fetch.
- Honor scoped HTML base URLs, inline modules and extensionless module preload.
- Stop deduplicating different hashed bundles before fetching. Identical HTML
  documents can still lead to different directory-relative assets.
- The host throttle waits for its slot instead of dropping the ninth discovered
  page. Cancellation remains responsive. A batch-count shortcut no longer cuts
  off long chains, and the configured successful-page budget is exact.
- Default linked-document depth is eight rather than three. Existing explicit
  configurations remain honored. A 20,000 unique-resource safety budget bounds
  cyclic/infinite discovery; skipped work is reported as incomplete coverage.
- Scan explicitly served, linked text/configuration resources with the shared
  detector. This does not retrieve server-side PHP source or invent hidden paths.
- Parse complete newline-escaped PEM containers in JSON/.env without evaluating
  source. Keep original bytes for redaction. Unexpected detector failures fail
  visibly instead of silently claiming a clean assessment.
- Bound cached JavaScript strings to 32 MiB, using Python storage size including
  Unicode; oversized resources are analyzed without cache retention. LRU, TTL,
  replacement and cleanup account correctly. This is a cache budget, not a claim
  that the entire agent can only consume 32 MiB.
- Strip query strings, fragments and URL credentials from acquisition diagnostics;
  use safe exception types rather than private exception values in those paths.
- Avoid creating an unawaited state-save coroutine outside a running event loop.

Detector policy is now `detector-v3`. Backend ingestion and validation accept this
version alongside v1/v2. New acquisition/detection coverage must not be treated as
proof that an unchecked older exposure was fixed. No database migration or new
environment variable is required for this compatibility patch.

## Automated evidence

The staged source was exported with `git archive` to exclude unrelated working
edits. Tests did not consume hosted scan allowance or stop the user's runtime.

| Check | Result |
| --- | --- |
| Exact staged agent, WSL Python 3.13, real sandboxed Chromium enabled | 274 passed; 3 native-Windows-only checks skipped |
| Native Windows Python 3.12, targeted acquisition/detection/cache/security checks | 28 passed, including all 3 skipped Windows handle/junction tests |
| Exact staged backend regression/agent evidence integration | 586 passed; 31 isolated PostgreSQL opt-in tests skipped |
| Frozen Benchmark v1 | 400 synthetic files; TP256, FP0, FN0; all regression gates passed |
| Frozen external-format challenge | 120 synthetic files; TP48, FP0, FN0; all regression gates passed |

The 400-file corpus has SHA256
`7ce137d29612ae57d243c01b05901f2c6cf67f222156b85a5ec3593917592c6f`.
Benchmark receipts include detector source hashes, wall time, RSS, files/sec and
MiB/sec. The final 400-file run took 5.07 seconds, approximately 78.92 files/sec
and 1.60 MiB/sec, with 68,005,888 bytes peak sampled RSS on this WSL host. The
immutable receipts are `docs/agent-v1-benchmark.json` and
`docs/agent-v1-external-benchmark.json`. Both corpora are synthetic and previously available to development:
100% precision/recall here is **not** a real-world accuracy or live-AI claim.
Fresh provider AI disagreement was not measured by this audit.

Real local targets cover static/SPA rendering, lazy scripts, a 76-page linked
chain, paginated modules with a deep secret, duplicate HTML/hashed variants,
base/preload resolution, plain-text configuration, transient 503 recovery,
unavailable 404 resources, blocked targets, cancellation, privacy and cleanup.
Complete orchestrator tests also send through the durable HTTP outbox to an
isolated receiver and verify redacted evidence arrives before terminal completion.
Existing suite checks cover duplicate delivery/restart, ownership rejections,
interrupted assignments, browser restrictions and Local/GitHub/History regressions.
These fixture servers and mocked AI providers are not hosted acceptance.

Local evidence, under the parent Full-Site `tmp/` directory:

- `agent-v1-snapshot-agent-verified.log`
- `agent-v1-native-verified.log`
- `agent-v1-snapshot-backend.log`
- `agent-v1-benchmark-final.json` / `agent-v1-external-final.json`
- `agent-v1-trees.json` records exact staged source tree identifiers.

## Coverage limits that remain intentional

No finite crawler can promise every asset on an arbitrary website. Authenticated
pages, WAF challenges, network-denied resources, pages beyond budgets, unlinked
assets and never-executed dynamically constructed module paths may remain
unchecked. Headless rendering only follows permitted traffic and bounded pages;
it does not log in, submit forms, execute downloaded source outside Chromium or
disable Chromium's sandbox. Bare package names require browser/import-map
resolution. Partial coverage never proves remediation. Provider activity and
exploitability remain separate from syntactic detection and AI assessment.

## Final acceptance gates

1. Deploy the compatible backend dev patch before upgrading the agent; pull the
   updated agent and restart it at a convenient time. Confirm completed findings,
   contextual AI reasoning, reports and a repeated New/Existing/Resolved scan on
   an owned staging fixture. Also check real cancellation, disconnect/reconnect
   and pending-evidence recovery against the hosted backend.
2. Run and record the required continuous 24-hour staging soak. It has not been
   performed by this patch; no scheduled task was created.
3. Build the actual distributable packages and smoke-test install, registration,
   browser startup, scan and shutdown on clean Linux, Windows and macOS hosts.
   Native Windows source-level tests passed here; frozen binaries and macOS were
   not tested here.
4. Review the pre-existing unrelated edits before assembling a clean release,
   record tested commit IDs and actual manual acceptance in
   `docs/release-acceptance.json`, then apply the existing release gate. Do not
   advertise synthetic benchmark performance as production accuracy.

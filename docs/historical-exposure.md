# Agent Historical Exposure

Historical Exposure is configured and launched from the existing web New scan UI.
Connect the updated agent normally; heartbeat advertises `history-v1`. The backend
must deploy the matching dev version before this agent (`detector-v2` evidence).
The backend feature flag is `HISTORICAL_SCAN_V1=true`; no archive API key or new
local configuration is required. Keep the normal agent registration and workspace
correlation key stable.

The agent queries Internet Archive and retrieves archived bytes only. Browser
rendering is not used for History and archived code is never executed. Live Web
crawling and browser behavior remain their separate scan source. Bounded selection
prioritizes scripts, maps and HTML; unavailable index/resource categories mean
limited archive coverage. An empty healthy index is a no-results success, not a
claim that the domain has never exposed a secret.

Raw minified text is scanned directly. JSON-compatible static string assignments
may be reconstructed without execution. Source maps recover only supplied
`sourcesContent`. External maps must be declared in a real comment and have an
in-scope earlier indexed capture; nearest prior means within the selected manifest,
not proof of a matching build. Missing maps do not block bundle detection.

The private registry stores the immutable manifest, keyed identities and redacted
checkpoints; source bodies are not persisted. Stable event IDs use the shared
outbox. Capture URL/date/hash receipts preserve every inspected occurrence while
a secret repeated across captures produces one scan finding identity. Cancellation
and memory/time limits clean up the owned analysis worker. Provider/AI results are
owned by the backend; the terminal does not open another AI status connection.

Run automated tests from this repository with `PYTHONPATH=src .venv/bin/python -m
pytest -q`. The synthetic archive benchmark is `benchmarks/historical/run.py`.
Actual hosted rollout, device acceptance and packaged native runtime checks are
listed in the backend Phase 7 document. Do not infer current remediation or token
activity from historical absence or AI classification.

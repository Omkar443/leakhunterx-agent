# Phase 10 agent verification

The provider-neutral commercialization phase does not change scan acquisition,
detectors, privacy envelopes or the agent protocol. Python package metadata now
requires Python 3.10+, matching the bundled Playwright requirement; Python 3.9 is
not advertised as installable. Personal tool settings are removed from tracking
while retained locally. No scan scheduler or backend/AI request is added.
Persisted runtime/scan epochs now use timezone-aware UTC, preventing native
non-UTC machines from storing timestamps hours away from the backend clock.
Subprocess tests cover Asia/Kolkata, America/Los_Angeles and UTC independently.

The working-tree agent suite and synthetic detector benchmark were run as
regressions. The benchmark is synthetic and detector-only, not a general accuracy
claim or a fresh live AI assessment. Dependency resolution was audited separately.
Native platform installation, frozen artifact signatures, production distribution
and live interruption/restart checks remain operator acceptance gates. No release
artifact or main branch is published by this phase.

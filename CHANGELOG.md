# Changelog

## Unreleased
### 1.1.0rc1 production-source preparation
- Production backend is the default for registration, runtime and CI; explicit
  HTTPS overrides remain supported.
- Updated `lhx` / `lhx-agent` help, runtime browser/logging flags and option
  validation. Pairing reports the package version and honors the runtime backend.
- Deep web acquisition and detector-v3 hardening; measured synthetic benchmark
  receipts and hosted/soak acceptance checklist in `docs/agent-v1-audit.md`.
- Stable publication remains gated; merging source to main does not publish it.

- Published on PyPI as `lhx-agent` (`pip install lhx-agent`)
- Standalone single-file binaries for Windows x64 and Linux x64
- LeakHunterX icon embedded in the Windows executable; `.desktop` entry and
  icon registered by the Linux installer
- `packaging/build.py` for local builds and a `Release` workflow that builds
  both platforms and publishes to PyPI on a tag push
- Completion summary no longer prints a line when there are no candidates

## v1.0.0
- Initial public release
- Backend agent mode
- Scan orchestration
- JS leak detection

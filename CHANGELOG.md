# Changelog

## Unreleased

### 1.1.0rc11 production API domain
- Use `https://api.leakhunterx.com` by default for authentication, runtime and CI.
- Keep explicit backend overrides supported for private and staging installations.
- Update versioned documentation and installation examples for this candidate.

### 1.1.0rc10 progress confirmation
- Wait for the existing authenticated assignment control connection to confirm backend completion before displaying completed status.
- Keep delivered evidence pending during a backend outage instead of reporting a false failure.
- Wake the control check when terminal evidence is ready; no AI status requests or separate telemetry connection.

### 1.1.0rc2 PyPI presentation and dependency compatibility
- PyPI-compatible PNG banner and architecture, with versioned absolute artwork
  and documentation URLs.
- Pin tested direct dependencies, preventing `--pre` from selecting HTTPX 1.0
  development builds. Mirror constraints in requirements.txt.
- Correct package download link and document exact candidate installation.

### 1.1.0rc1 production-source preparation
- Production backend is the default for registration, runtime and CI; explicit
  HTTPS overrides remain supported.
- Updated `lhx` / `lhx-agent` help, runtime browser/logging flags and option
  validation. Pairing reports the package version and honors the runtime backend.
- Deep web acquisition and detector-v3 hardening; measured synthetic benchmark
  receipts and hosted/soak acceptance checklist in `docs/agent-v1-audit.md`.
- Stable publication remains gated; merging source to main does not publish it.

- Candidate distribution is `leakhunterx-agent`; CLI aliases remain `lhx` and `lhx-agent`.
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

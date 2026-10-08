# Changelog

## Unreleased
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

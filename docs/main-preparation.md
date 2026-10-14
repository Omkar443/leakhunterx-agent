# Production-source preparation — 14 October 2026

Agent-only source promotion to main. Runtime and pairing default to
`https://backend-leakhunterx.onrender.com`; explicit HTTPS command options and
`LHX_BACKEND_URL` overrides are retained. Pairing metadata uses the embedded
`1.1.0rc1` version. Existing stored credentials are not deleted by this update;
use a production workspace token with `lhx auth` when switching environments.

The CLI now advertises the actual current commands through both entry points.
Agent/start accept backend, browser and logging options. Status accepts backend
and JSON; CI defaults to production and validates its wait budget. Live website
scans reject unsupported JSON/local-profile/offline flags before starting work.
Legacy run/pair, empty-argument startup and logging placement remain compatible.
Relative log-file paths work. The README includes the architecture, installation,
supported flags, privacy boundaries and package/release limitations.

The old main history was merged while retaining the tested dev runtime. Obsolete
main conflict hunks containing a synthetic finding injection and pre-durable
shutdown behavior were not restored. Text line endings are normalized for Windows
and WSL; private credential files, runtime state and test output are ignored.
Previously uncommitted release guards are included. Browser/benchmark CI also
checks main. Stable publication still requires real recorded acceptance and is
not triggered by merely pushing main; the version remains a candidate.

## Automated checks

- Exact staged source: **290 passed**, three native-Windows-only checks skipped;
  real sandboxed Chromium integration enabled.
- Native Windows new CLI and release checks: **16 passed**. Previous native
  filesystem/junction and acquisition checks remain in the v1 audit.
- Both frozen synthetic benchmark suites passed with TP256/FP0/FN0 on 400 files,
  and TP48/FP0/FN0 on the 120-file external-format challenge. These are not
  production accuracy or live AI measurements.
- No hosted scan was started and no user runtime was stopped by this preparation.

Logs/receipts: parent Full-Site `tmp/agent-main-verified-tests.log`,
`tmp/agent-main-native.log`, `tmp/agent-main-benchmark-final.json`,
`tmp/agent-main-external-final.json`, and `tmp/agent-main-trees.json`.
Only documentation/workflow metadata was added after executable-source checks.

## Deployment dependency

This request promotes the agent repository only. At preparation, the remote
backend main was `d4ef158d58043f6366957beaa2ce672b5608ab0d`; it did not contain
the new local-evidence service. The compatible tested backend dev was
`dfdd35e79a8f01fcff6eceeadf600a2cec3dd556`. Deploy compatible backend source and its
required existing migrations/configuration before using the newer agent features
against production. No backend or frontend main merge was performed here.
Hosted acceptance, soak and actual distributable-package checks remain separate
from this source promotion; see `docs/agent-v1-audit.md`.

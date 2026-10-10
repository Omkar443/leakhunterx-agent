# Local project scanning

The packaged agent supports local scanning and existing website analysis. Local
CLI scans run without cloud upload. `--local-only` explicitly prohibits cloud,
AI, provider checks, telemetry and browser initialization.

```bash
lhx scan ./project --local-only
lhx scan ./project --local-only --json
lhx resume <scan-id> --json
```

Resume rechecks files and removes changed/deleted provisional evidence. It does
not blindly trust a cached result. Exit codes: 0 complete, 2 limited coverage,
1 failed operation, 130 cancelled/interrupted. Candidate counts do not mean
AI-confirmed exposure. JSON contains redacted findings and deterministic Delta.

To permit a dashboard scan, create a dashboard project and use its project ID:

```bash
lhx project add ./project --name Application --project-id <project-id>
lhx project list
lhx project show <target-id>
lhx project allow-dashboard <target-id>
lhx agent
```

Use `lhx auth` to connect a new installation with its dashboard connection token.
The backend's staging rollout flag must be enabled for LOCAL target selection.
Target metadata uses the existing heartbeat; no extra AI-status connections are
opened. One heavy scan can run per machine.

```bash
lhx project deny-dashboard <target-id>
lhx project set-path <target-id> ./moved-project
lhx project remove <target-id>
```

Removal unregisters the target and deletes its private checkpoints, retaining
project files. Moving a registered folder preserves keyed finding identities.
Keep the private registry safe: resetting it generates new keys and prevents
comparison with old local baselines. Dashboard permission is off by default.

Profiles are locally authorized ceilings. Quick: 10,000 entries, 100 MB total,
1 MB per file. Standard: 100,000 entries, 500 MB total, 5 MB per file. Deep:
200,000 entries, 1 GB total, 10 MB per file. Dashboard jobs cannot exceed the
registered ceiling. Generated/vendor folders are excluded, supported UTF-8 text
files are scanned, and `.lhxignore` uses the existing ignore-policy syntax.
Skipped unsafe, unreadable, binary or oversized resources make coverage partial;
partial coverage does not prove that a previous exposure was fixed.

Source and credentials stay on the machine. Dashboard evidence uses safe relative
locators, redacted values, keyed fingerprints and boolean semantic signals. Local
files are never used for credential-provider requests. Denied symlinks, hard links,
devices, directory escapes and Windows reparse points fail safely.

Linux and native Windows filesystem/CLI tests passed. macOS and hosted staging
acceptance are still required before declaring Phase 4 released.

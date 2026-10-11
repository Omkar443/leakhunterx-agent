# GitHub scanning v1

## Recommended: configure and start in the web UI

Connect the updated agent normally. In Settings → Integrations, connect GitHub,
install the LeakHunterX GitHub App for selected repositories, then refresh. From
Overview or Projects, choose New scan → GitHub, select the authorized repository
and connected execution agent, choose a profile and grant explicit consent.
Use this repository, then Start scan. Per-repository CLI registration and local
PAT configuration are unnecessary for this flow.

The backend must have the GitHub App configuration and feature gate. See the
backend's `docs/github-app-setup.md` for operator setup. The agent advertises
`github-app-v1`; older agents must be updated before selecting them in the UI.
Existing Free/Pro agent allowances remain enforced.

For each running App assignment, the agent obtains one short-lived, read-only,
repository-scoped token through its authenticated scan channel. It stays in
memory, is passed only to Git's subprocess environment and is cleared after use.
There is no local PAT fallback for managed assignments. Source is fetched directly
from GitHub to this machine; only sanitized findings reach the cloud. Interrupted
downloads retain the already-persisted commit pin, so resume never switches to a
newer branch head. Revoked authorization or expired temporary access cannot be
reported as an empty successful scan.

## Compatible standalone CLI workflow

Run the updated agent with Git installed. Public repositories need no credential.
Private repositories use `GH_TOKEN` or `GITHUB_TOKEN` set locally in the agent's
environment, with read-only Contents access limited to the intended repository.
Never put the token in the URL or share it with the dashboard/backend.

```sh
lhx project add https://github.com/OWNER/REPOSITORY --project-id PROJECT_UUID
lhx project allow-dashboard TARGET_UUID
lhx start
```

The GitHub source appears in new-scan dialogs after the backend's
`GITHUB_SCAN_V1=true` gate is enabled and the updated agent syncs registration.
The dashboard sends an opaque target ID; the agent checks local consent and
configuration again. Free/Pro runtime registration limits remain unchanged.

Standalone commands:

```sh
lhx scan https://github.com/OWNER/REPOSITORY
lhx resume SCAN_UUID
lhx project deny-dashboard TARGET_UUID
lhx project remove TARGET_UUID
```

The current default branch is pinned to a commit SHA before analysis. No history,
checkout, hooks, filters, LFS downloads, submodule fetches or repository code are
executed. The existing detector, `.lhxignore`, profiles, generated/vendor policy,
redaction and keyed identities apply. Delta compares complete same-scope scans
between commits; missing coverage never claims a finding was resolved.

Private source, raw secrets, variable names and filesystem paths stay local.
Only bounded redacted evidence and finite semantic observations are delivered.
The terminal shows agent activity without extra AI-status requests.

Interrupted acquisitions retain their original pin and private cache for resume.
Completed/failed/cancelled working snapshots are cleaned up; redacted completion
checkpoints can replay after a lost delivery without rescanning changed source.
Removing a registration clears its owned repository cache and checkpoints while
leaving the user's other files intact. Stop an active scan before deregistration.

Downloads are bounded to 256 MB of Git objects. Profile file/byte limits still
apply. Unsupported paths, symlinks, submodules and LFS pointers record incomplete
coverage rather than following references or claiming a clean assessment. Large
or inaccessible repositories may fail with a safe access/limit message. GitHub
authorization errors are never replaced with an empty successful scan.

Linux and native Windows lifecycle checks passed. macOS and real private GitHub
credentials remain operator acceptance checks. This dev change is not a released
agent binary.

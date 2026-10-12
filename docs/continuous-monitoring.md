# Continuous monitoring and CI

Configure schedules and policies in **Monitoring** or **Project → Monitoring**.
Keep the selected registered agent connected using `lhx agent`. Website, local
and GitHub schedules reuse the same detector, protected evidence outbox and
restart/cancellation behavior. The normal terminal does not poll AI status.

GitHub App targets support pinned default-branch CI requests. Create a scoped
credential in **Policy & CI** and store it as the protected `LHX_CI_TOKEN` CI
secret. Do not put that token in command arguments or repository files.

```bash
lhx ci --backend https://your-backend.example --commit <default-branch-SHA>
```

The command dispatches to the monitor's registered agent, which can run on a
customer-owned runner or another authorized machine. It does not automatically
register an ephemeral agent or download source into the cloud. A CI credential
cannot replace agent authentication or authorize another repository/project.

The request UUID remains stable across connection retries. Use `--request-id`
to resume waiting for the same authorized request after restarting the client.
Responses are bounded and an accepted pass must match the requested commit and
its recorded policy result. Progress output contains only safe run states/IDs.

Exit status `0`: verified policy pass. `1`: violated policy, execution/request
failure, cancellation, expiry or wait timeout. `2`: inconclusive result explicitly
allowed by policy, requiring caller review rather than claiming a clean scan.

Unchanged completed findings become Existing in Delta; new qualifying validated
findings can violate policy. Missing validation or limited coverage remains
inconclusive. Failed/cancelled scans never establish remediation. CI currently
supports GitHub App default-branch targets; Local/Web scheduled monitoring works
without a GitHub CI credential. Do not use this workflow for fork PRs or arbitrary
branches. Full setup and operator acceptance are documented in the backend's
`docs/phase8-continuous-monitoring.md`.

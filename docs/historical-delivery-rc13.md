# Historical delivery correction — rc13

Production scan `d0b8994d-0ca4-4bf6-bcff-6c8abe728c2b` reached 50/50 resources,
44 successful and 6 unavailable, then recorded `historical_analysis_unavailable`
during finalization. Its received deliveries were processed on their first attempt.
This was distinct from an archive discovery outage.

Historical events used a content-derived event ID but a fresh timestamp on every
emission. Repeating the same archive retry/progress state while its first envelope
was still queued violated the durable outbox's immutable-ID check. The resulting
ValueError could be misclassified as invalid archived content, latch the transport's
evidence-failure guard and prevent terminal delivery. A restart could trigger the
same collision when replaying evidence. Both failures were reproduced against the
actual PyPI rc12 installation before changing the production code.

rc13 gives each progress observation a distinct ID. Immutable evidence events keep
their content-derived IDs and persist their first timestamp transactionally, so
checkpoint replay reproduces the complete original envelope. The strict outbox
collision check is preserved. Only timestamps and hashes are added to checkpoint
metadata; source and credentials are not stored in this event ledger.

Journal/transport errors propagate as delivery-pending conditions. They cannot be
counted as malformed archived resources or enqueue a contradictory scan_failed
after durable completion. The assignment loop re-enters receipt/recovery handling
before polling for another scan. Actual acquisition and analysis failures retain
their existing fail-closed behavior.

Regression coverage includes repeated observations across timestamp changes, exact
envelope replay after restart, and real local HTTP/outbox delivery with all 50
captures, one synthetic finding, 44 successful analyses and 6 deliberately invalid
resources. Both a backlog cleared before completion and an outage spanning
completion/restart are exercised. Partial archive coverage stays explicitly partial;
unavailable resources are never relabelled as successful. Archive responses in this
reproduction are controlled fixtures, not a hosted 50-capture acceptance scan.

After upgrading, verify `lhx --version`, restart the service if used, and create a
fresh historical assessment. This change does not rewrite or relabel the already
failed production scan. Archive availability and real target coverage still require
manual acceptance; no guarantee of error-free operation is implied.

Local verification: complete agent suite 396 passed / 8 skipped; backend privacy,
historical/event/AI/report regression 95 passed; clean pip-installed rc13 wheel
83 focused tests passed. Wheel and source distribution passed `twine check` and
the installation passed `pip check`. Temporary reproduction and verification logs
are in `Full-Site/tmp/rc12-pypi-delivery-reproduction.log`,
`history-delivery-fifty.log`, `rc13-full-agent.log`, `rc13-backend.log` and
`rc13-installed-tests.log`. Hosted release checks and a fresh real scan are separate
from these local results.

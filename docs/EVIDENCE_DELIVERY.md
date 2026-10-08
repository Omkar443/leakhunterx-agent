# Agent evidence delivery

The event path journals events locally before returning from `emit`. The HTTP sender replays the oldest pending batch first, uses stable event/batch IDs, and removes journal rows only after a complete backend acknowledgement. Completion signals are journaled behind finding evidence and cannot overtake it. Disk-write failures prevent completion; network failures retain the entire pending sequence for replay.

Each concurrent JavaScript analysis owns its result collector. Findings retain location, source URL, a SHA-256 of decoded UTF-8 source, a structural credential mask, match length, bounded redacted code, truncation and evidence version `2`. Code budgets preserve the matched line. Occurrences in different assets/locations are retained so the backend can review differing usage. Raw matched credentials are not sent in new finding events or result batches. Recognizable credential literals are rejected as false endpoint candidates.

Deploy the compatible backend migration before releasing this agent. Rebuild and update installed binaries, then restart them; an old running binary does not acquire source changes. Preserve the private persistent delivery directory across upgrades. Outbox namespaces are tied to the backend endpoint and runtime identity. Do not move evidence between tenant identities.

Pending payloads are limited to 256 MiB, individual events to 256 KiB and HTTP batches to 200 events / approximately 1 MiB. Storage or permanent authentication/validation rejection is surfaced and retained, not discarded. Review the backend status and logs when delivery remains pending. POSIX journal directories/files are restricted to `0700`/`0600`; verify Windows account directory ACLs separately. Legacy `failed_*.jsonl` journals are imported before being marked imported.

AI receives observed, redacted source evidence; static detection does not establish that a credential is active or exploitable. Missing usage information must remain uncertain. End-to-end staging verification and a real-model quality benchmark are still required before a production rollout.

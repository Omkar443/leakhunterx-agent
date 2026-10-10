# Agent terminal workspace

Run `lhx agent` as usual, or run `python3 lhx_agent_entry.py` from `src`.
Interactive terminals display the operations workspace automatically. Wide
terminals show assessment and environment panels side by side. Smaller terminals
use stacked or compact layouts. Redirected output and `TERM=dumb` use plain logs.
`NO_COLOR` disables colors; ASCII encodings use ASCII borders.

The display uses existing local lifecycle events and monotonic elapsed time.
It does not open connections, poll backend status, or display AI validation.
Resource progress measures processed resources, including unavailable resources;
successful, failed, and timed-out counts remain separate. Missing counters show
an unknown marker until the agent reports them, rather than invented zeroes.
Detection counts are candidates, not confirmed security findings.

Evidence delivery uses the existing authenticated transport. Terminal completion
is displayed after that transport accepts the completion event and the existing
flush returns. Failed delivery never displays success. Backend validation and
final report results remain in the dashboard.

Only four recent activity messages are retained in the display. Raw evidence and
secret values are not stored by the renderer. Displayed URLs omit user information,
query strings, and fragments. Control sequences in displayed values are removed.
The renderer updates at most four times per second and skips unchanged frames.
Unsupported terminals use plain output. If the output stream becomes unusable,
terminal output is silenced without interrupting scanning or evidence delivery.
The alternate screen and cursor are restored on ordinary shutdown and process exit.

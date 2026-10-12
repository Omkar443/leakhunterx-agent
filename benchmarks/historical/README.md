# Historical fixtures v1

Run `PYTHONPATH=src .venv/bin/python benchmarks/historical/run.py` from the agent
repository. Six deterministic synthetic fixtures cover a literal, minified code,
placeholder, ordinary hash, long prefix and static string concatenation. Forged
fixture values are not issued credentials. This checks the shared detection and
historical semantic-envelope path without network or AI requests.

`results.json` records precision, recall, false-positive rate, elapsed time,
files/sec, MB/sec and peak Python allocations traced by tracemalloc. This memory
number is not total process RSS. AI disagreement is null because it is not measured.
Timing is machine-specific. These six fixtures are regression evidence, **not** a
representative real-world accuracy study or a marketing claim. Source-map recovery,
archive pagination, response limits, privacy, restart and cancellation are tested
separately in `tests/test_historical.py`.

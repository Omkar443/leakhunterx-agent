# LeakHunterX Benchmark v1

This is a versioned **synthetic, detector-only regression benchmark**, not a measurement of real-world SaaS accuracy. No fixture credential has been registered with a provider. Disposable private keys exist only in memory. Git stores JSON fixture recipes, never registered credentials.

## Reproduce

```bash
python -m pip install -e . pytest
PYTHONPATH=src python -m pytest tests -q
python benchmarks/run.py --check --output benchmarks/results/local.json
python benchmarks/run.py --check --ai-results benchmarks/results/ai-validation-v1.json --output benchmarks/results/local-with-ai.json
```

`--baseline` evaluates the trusted immutable local revision `383f6f1`; it requires that revision in Git history. Normal CI does not require historical commits. The separate live AI script is in `../backend-leakhunterx/scripts/benchmark_ai_validation.py`. It sends only redacted synthetic snippets, makes no database writes, and paces provider requests. Provider calls are opt-in and are not part of CI.

## Corpus and labels

400 files, 8,482,554 UTF-8 bytes; 256 distinct expected `(rule, credential bytes)` identities and 144 negative files. Folders cover AWS (including temporary IDs), GitHub, Stripe, JWT, credential-bearing database URLs, private keys, additional providers, documentation, tests, placeholders, hashes, random strings, minified JavaScript, generated files, huge files and edge cases. Inputs and labels are generated independently of the detector implementation from checked-in recipes and SHAKE-256 seeds. Positive labels mean syntactic credential exposure, **not verified active accounts or exploitable permissions**.

Corpus SHA-256: `7ce137d29612ae57d243c01b05901f2c6cf67f222156b85a5ec3593917592c6f`.

The files named `holdout` use additional seeds with the same generator and families. They are **not an independently collected or blinded evaluation set**. The detector was improved against this corpus; passing it does not prove generalization. Add separately reviewed, authorized real-world and adversarial fixtures before publishing a broad accuracy claim.

## Recorded detector results

| Metric | Baseline 383f6f1 | detector-v1 |
| --- | ---: | ---: |
| True positives / false positives / false negatives | 102 / 286 / 154 | 256 / 0 / 0 |
| Precision | 26.29% | 100% |
| Recall | 39.84% | 100% |
| Negative-file false-positive rate | 75% | 0% |
| Instrumented duration | 6.38 s | 7.35 s |
| Files/sec | 62.70 | 54.40 |
| MiB/sec | 1.27 | 1.10 |
| Peak sampled process RSS | about 60.2 MiB | 64.5 MiB |

See `results/baseline.json` and `results/detector-v1.json` for exact values, counts, environment and failures. Windows/WSL machine load and instrumentation affect timing; these sequential runs are not a controlled performance comparison. The run includes fixture generation, key parsing and Python allocation tracing; it excludes crawling, network time, durable event delivery, backend processing and live AI. RSS is sampled after files, so it is not an OS-enforced maximum; Python traced allocation peak is recorded separately.

Precision = TP/(TP+FP); recall = TP/(TP+FN). A detection must match **both rule and exact case-sensitive bytes**. Wrong types and extra detections count as FP; missed expected identities count as FN. Negative-file FPR = negative files with any finding / all negative files. Extra findings on positive files are reflected in precision.

The gate currently requires precision >=98%, recall >=95%, negative-file FPR <=2%, instrumented duration <=60s and sampled RSS <=512 MiB. This is a regression gate, **not a published <2% production false-positive claim**. CI uploads per-runtime measured results on Python 3.11 and 3.13.

## Recorded AI validation results

Groq `openai/gpt-oss-120b`, `validation-v4`: 40 stratified single-candidate fixtures, all 40 calls completed; 38 determinate raw verdicts and 2 uncertain (95% verdict coverage). Raw AI disagreement = **5/38 = 13.16%**, with no provider failures in the final paced run. The two uncertain verdicts are excluded from that denominator and explicitly disclosed. Never count an outage or uncertainty as agreement.

Of the 31 candidates accepted by detector-v1, 30 had determinate raw AI verdicts; one disagreed (3.33%) and one was uncertain. Both remain review-required, and no positive was automatically discarded. A separate nine-case **legacy noise challenge**, rejected by detector-v1, had eight determinate verdicts and four disagreements. Those legacy samples would not enter the current pipeline. Raw model verdicts and final policy assessments are both recorded; the conservative policy does not rewrite the raw verdict to improve the metric.

This sample is small, synthetic, stochastic and model-specific. The detector scores are not AI scores or end-to-end accuracy. Do not advertise these numbers without their scope and coverage. The harness refuses AI results from another corpus, incomplete runs, duplicate identities, invalid verdicts or mismatched labels.

## Operator controls

No vendor, generated or test directories are ignored automatically: a real credential there remains a candidate. Copy `.lhxignore.example` to `.lhxignore` in the agent launch directory, or explicitly set `LHX_IGNORE_FILE`. Supported lines are case-sensitive glob paths, `path:`, `rule:<detector_id>`, `finding:<fingerprint>` and `test:<fingerprint>`. Limits: 64 KiB, 256 rules, 512 characters/rule; symlinks and traversal are rejected. No negation/re-inclusion syntax is supported. Never store raw credentials in ignore rules.

Local exclusions are annotated with a policy digest and delivered as redacted evidence. They are hidden from dashboard/report publication while raw detection history and Delta identity are retained. Edit the local policy and rescan to change local exclusions; dashboard policies are separately reversible per project. An ignored detection is not a resolved exposure.

Optional provider validation is disabled by default. `LHX_VERIFY_PROVIDERS=true` permits bounded, read-only GitHub authentication checks from the local agent: fixed TLS endpoint, no redirects/environment proxy, 5-second timeout, max 20 unique credentials per scan. Only the provider/status observation is delivered; no account response is read or stored. Other providers remain explicitly unsupported. This is credential verification, not GitHub repository/history scanning. AI and provider failures cannot fail the scan.

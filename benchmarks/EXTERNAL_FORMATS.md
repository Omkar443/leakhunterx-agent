# External-format challenge v1

120 frozen synthetic cases, evaluated separately from the existing 400-file
corpus. 48 positive candidate identities and 72 negative files cover eight
credential families in INI, JSON, multiline XML, YAML, Go backticks and Logstash
presentations. These are content-format checks; they do not add repository
ingestion or new scanner features.

Templates and explicit placeholder examples were adapted from Gitleaks at
immutable revision `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`:

- [Presentation templates](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/utils/generate.go)
- [AWS examples](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/aws.go)
- [GitHub examples](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/github.go)

The upstream MIT notice is retained in GITLEAKS-LICENSE.txt. No upstream code is
executed and no upstream registered credential is copied or verified. Candidate
values are generated locally. Additional JWT/database/private-key and malformed
cases use LeakHunterX's stated candidate and test-key policy. Labels indicate
credential-shaped candidates, not evidence of active permissions. This is not
the full Gitleaks suite or an externally audited production accuracy study.

The fixture recipe was frozen before fixes. Its SHA-256 stays
`4b53f9ae3fae8a9a805572a9a9a07978402978f2692106d10f3d2728351c8c7e`
in both result files:

| Metric | Before corrections | After corrections |
|---|---:|---:|
| True positives | 47 | 48 |
| False positives | 25 | 0 |
| False negatives | 1 | 0 |
| Precision | 65.28% | 100% |
| Recall | 97.92% | 100% |
| Negative-file false-positive rate | 33.33% | 0% |

Corrections reject repeated-character provider bodies and malformed fine-grained
PAT lengths, and exclude backtick/XML delimiters from database URL identities.
Results are `results/external-before.json` and `results/external-after.json`.
The original v1 corpus checksum and all 256 labelled positives are unchanged.

```sh
python benchmarks/run.py --external --check --output benchmarks/results/ci-external.json
```

The challenge now participates in regression CI. Once evaluated and used to fix
the detector it is no longer an untouched holdout. Independently reviewed,
authorized real-world samples are still required for production accuracy claims.

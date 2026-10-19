# Detection catalog: 500 active offline rules

The rc12 source candidate has 500 distinct rules in normal and aggressive modes:
38 existing canonical rules and 462 curated additions. A second SSH/PEM alias is
canonicalized to the existing parsed private-key detector rather than counted twice.
The number is rules/formats/context combinations, not 500 providers or proof of
active credentials. Free and Pro use the same detector quality.

Coverage includes cloud/AI credentials, SaaS/developer tokens, CI/CD credentials,
connection credentials and private-key material. Additional formats include AWS
Bedrock, Azure App Configuration/PATs and GitLab runner/deployment tokens. Public
identifiers, hidden helpers, dependent multi-component rules and unsupported
checksum validators are excluded. No upstream live validator/revoker is executed.

## Structure and safety

`src/agent/js/catalog.json` is the checked-in catalog. Every added rule has a stable
identity, display description, original source identity/path, documentation links,
entropy/character requirements, confidence, severity and format/context mode.
The loader verifies a pinned content checksum before compiling. Startup cannot
silently replace a broken/missing catalog with an empty detector.

A reusable Aho-Corasick keyword index selects relevant rules in one pass. Required
literals come from the regex syntax tree, not guessed window boundaries. Selected
expressions inspect the complete source with strict regex and total work budgets;
multiline/minified content keeps its real offsets. Exceeding a budget fails analysis
explicitly. It must not establish absence of findings or remediation.

Contextual opaque keys require a credential assignment. Public IDs, checksums,
hashes and template references are not credentials. Format rules retain their
case/length constraints, entropy and character requirements. Prefix handling does
not misclassify other providers' legitimate test-environment credentials as Stripe
publishable/test keys. Generic Bearer/Basic/assignment matches yield to provider
rules, and overlapping partial tokens yield to the complete credential.

Evidence uses two passes: identify candidates, then mask all detected neighbors
before context is cropped. Private/local/GitHub/historical source remains local.
Rule failures and provider activity are separate; detector confidence is never
provider authentication. The backend uses the same finite 500 identities and
`detector-v4` policy; arbitrary agent type strings are still refused.

## Provenance and regeneration

Added rules are adapted from MongoDB Kingfisher at immutable revision
`82d050530cdef9af070b8f9a75701c9c27a948c3` (v1.113.0), under Apache-2.0 and the
upstream attribution notices. Source:
https://github.com/mongodb/kingfisher/tree/82d050530cdef9af070b8f9a75701c9c27a948c3/crates/kingfisher-rules/data/rules

Retained license/NOTICE: `docs/third-party/KINGFISHER-LICENSE.txt` and
`KINGFISHER-NOTICE.txt`; both are included in Python distributions and standalone
binary specifications. Rules are adapted
to LeakHunterX's stricter offline context, extraction, privacy and failure policy.
The source collection is larger than the selected catalog; this is not an import
of all upstream capabilities or a claim of current provider verification.

Developer environment: Python 3.13, PyYAML, regex and the agent dependencies.
Download the pinned source archive, then run:

```bash
python tools/build_rule_catalog.py /path/to/pinned-source.zip
python tools/promote_rule_catalog.py
python benchmarks/catalog_run.py --check
python benchmarks/run.py --check --output benchmarks/results/catalog-legacy-regression.json
python benchmarks/run.py --external --check --output benchmarks/results/catalog-external-regression.json
```

The importer verifies the source archive SHA-256, reads data without extracting or
executing upstream code, and omits unsupported rules instead of weakening them.
Promotion emits the runtime catalog, identity checksum, cloud allowlist and new
synthetic specimens together. Update the detector policy for behavior changes;
do not silently reuse old per-file or historical redacted analysis checkpoints.
Specimens are stored as deterministic seeds/draw counts, source templates and
SHA-256 expectations. The test runner generates the synthetic values locally;
no complete credential-shaped values are checked into the fixture data. Hashes
verify that this representation preserves the original frozen test cases.

## Measured scope and remaining acceptance

The expansion challenge has 924 synthetic positives (two per added rule) and
2,772 placeholder/negative cases. All passed with zero missed expected identities
and zero unexpected findings. The existing frozen 400-file corpus (256 positive
identities) and 120-case external-format challenge (48 positive identities) also
passed without modifying their labels or checksums. These are synthetic offline
results, not 100% production accuracy or an independent field evaluation.

Tests additionally check unrelated hashes/public IDs, environment references,
redaction among mixed providers, minified files, unsafe rule failure and every
added type across the backend privacy/AI contract. The expanded synthetic corpus
is derived from rule structures and was used during development; it is not an
untouched holdout. Authorized human-labelled real-world samples and manual
acceptance remain necessary. AI/provider disagreement was not measured here.

Deploy backend support first, then historical UI support, then install rc12 from
the tested main source. PyPI remains rc11 until a separate protected release is
approved. Historical archive outages remain an external acceptance gate. During
manual testing, inspect representative providers, useful false-positive/negative
cases, privacy, cancellation/reconnect and the reported historical limitations.
